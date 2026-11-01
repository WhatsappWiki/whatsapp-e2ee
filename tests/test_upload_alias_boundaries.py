"""Database aliases share ownership, including workers using the old lock name."""

import errno
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import (
    Reconciliation,
    Response,
    UploadReceipt,
    Uploads,
    UploadUncertain,
)

URL = "https://media.invalid/upload"


def alias_pair(tmp_path, mode):
    directory = tmp_path / "storage"
    directory.mkdir()
    path = directory / "media.db"
    db = Database(path)
    alias = path.with_name("MEDIA.DB") if mode == "file" else tmp_path / "STORAGE" / path.name
    if not alias.exists() or not os.path.samefile(path, alias):
        db.close()
        pytest.skip("Requires a case-insensitive filesystem")
    peer = Database(alias)
    return path, db, peer


@pytest.mark.parametrize("outer", ["send", "reconcile"])
@pytest.mark.parametrize("competing", ["send", "reconcile"])
@pytest.mark.parametrize("owner_alias", [False, True])
@pytest.mark.parametrize("alias_mode", ["file", "directory"])
def test_case_alias_competitor_cannot_reconcile_or_post(
    tmp_path, outer, competing, owner_alias, alias_mode
):
    _, db, peer_db = alias_pair(tmp_path, alias_mode)
    try:
        jobs = MediaJobs(SQLiteStore(db, 1 if owner_alias else "owner"), clock_ms=lambda: 123000)
        peer_jobs = MediaJobs(SQLiteStore(peer_db, "1" if owner_alias else "owner"))
        media = jobs.prepare("m", b"media", "image")
        uploads, peer = Uploads(jobs), Uploads(peer_jobs)
        receipt = UploadReceipt("/uploaded", 123000, media.encrypted_hash)

        def success(request):
            b"".join(request.body)
            return Response(200, {}, b"ok")

        def reject_competing():
            before = uploads.pending("m")
            with pytest.raises(UploadUncertain):
                if competing == "send":
                    peer.send("m", URL, lambda _: pytest.fail("Duplicate POST"), lambda *_: receipt)
                else:
                    peer.reconcile("m", lambda _: pytest.fail("Lookup under active owner"))
            assert uploads.pending("m") == before

        if outer == "send":

            def transport(request):
                b"".join(request.body)
                reject_competing()
                return Response(200, {}, b"ok")

            assert uploads.send("m", URL, transport, lambda *_: receipt) == receipt
        else:

            def timeout(request):
                b"".join(request.body)
                raise TimeoutError("response lost")

            with pytest.raises(TimeoutError):
                uploads.send("m", URL, timeout, lambda *_: receipt)

            def lookup(_):
                reject_competing()
                return Reconciliation("absent")

            assert uploads.reconcile("m", lookup) is None
            assert peer.send("m", URL, success, lambda *_: receipt) == receipt
        assert peer.pending("m")["state"] == "uploaded"
    finally:
        peer_db.close()
        db.close()


CHILD = """
import sys
from whatsapp_e2ee import Database,SQLiteStore
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import Uploads,Response,UploadReceipt
j=MediaJobs(SQLiteStore(Database(sys.argv[1]),'owner'),clock_ms=lambda:123000)
m=j.load('m')
def transport(request):
 b''.join(request.body)
 print('READY',flush=True)
 sys.stdin.readline()
 return Response(200,{},b'ok')
Uploads(j).send('m','https://media.invalid/upload',transport,lambda *_:UploadReceipt('/uploaded',123000,m.encrypted_hash))
"""


@pytest.mark.parametrize("alias_mode", ["file", "directory"])
def test_case_alias_cross_process_excludes_lookup(tmp_path, alias_mode):
    path, db, peer_db = alias_pair(tmp_path, alias_mode)
    process = None
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        jobs.prepare("m", b"media", "image")
        peer = Uploads(MediaJobs(SQLiteStore(peer_db, "owner")))
        process = subprocess.Popen(
            [sys.executable, "-c", CHILD, str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            waiting = pool.submit(process.stdout.readline)
            try:
                assert waiting.result(timeout=5).strip() == "READY"
            except BaseException:
                process.kill()
                raise
        with pytest.raises(UploadUncertain):
            peer.reconcile("m", lambda _: pytest.fail("Lookup while child is uploading"))
        stdout, stderr = process.communicate("continue\n", timeout=5)
        assert process.returncode == 0, (stdout, stderr)
        assert peer.pending("m")["state"] == "uploaded"
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        peer_db.close()
        db.close()


def legacy_name(path, owner, id):
    # Frozen naming rule from the previous implementation for rolling upgrades.
    payload = json.dumps(
        (str(path.resolve()), owner, id), ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@pytest.mark.skipif(os.name == "nt", reason="POSIX legacy-worker compatibility")
@pytest.mark.parametrize("legacy_first", [False, True])
def test_previous_lock_naming_remains_compatible(tmp_path, legacy_first):
    import fcntl

    path = tmp_path / "media.db"
    db = Database(path)
    fd = None
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        media = jobs.prepare("m", b"media", "image")
        uploads = Uploads(jobs)
        directory = path.parent / ".wa-upload-locks"
        directory.mkdir(exist_ok=True)
        fd = os.open(directory / legacy_name(path, "owner", "m"), os.O_CREAT | os.O_RDWR, 0o600)

        def success(request):
            b"".join(request.body)
            if not legacy_first:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return Response(200, {}, b"ok")

        if legacy_first:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(UploadUncertain):
                uploads.send(
                    "m", URL, lambda _: pytest.fail("POST during legacy ownership"), lambda *_: None
                )
            assert uploads.pending("m") is None
            fcntl.flock(fd, fcntl.LOCK_UN)
        receipt = UploadReceipt("/uploaded", 123000, media.encrypted_hash)
        assert uploads.send("m", URL, success, lambda *_: receipt) == receipt
    finally:
        if fd is not None:
            os.close(fd)
        db.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX lock lifecycle")
@pytest.mark.parametrize("failure", ["second_open", "second_flock", "unlock", "close"])
def test_partial_acquisition_and_cleanup_release_every_lock(tmp_path, monkeypatch, failure):
    import fcntl

    import whatsapp_e2ee.upload_coordination as coordination

    db = Database(tmp_path / "media.db")
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        media = jobs.prepare("m", b"media", "image")
        uploads = Uploads(jobs)
        receipt = UploadReceipt("/uploaded", 123000, media.encrypted_hash)
        error = OSError(errno.EIO, failure)
        original_open, original_close, original_flock = os.open, os.close, fcntl.flock
        opens = acquisitions = 0
        failed = False
        posts = []

        def open_file(*args):
            nonlocal opens
            opens += 1
            if failure == "second_open" and opens == 2:
                raise error
            return original_open(*args)

        def flock(fd, operation):
            nonlocal acquisitions, failed
            if operation == fcntl.LOCK_EX | fcntl.LOCK_NB:
                acquisitions += 1
                if failure == "second_flock" and acquisitions == 2:
                    raise error
            if failure == "unlock" and operation == fcntl.LOCK_UN and not failed:
                failed = True
                raise error
            return original_flock(fd, operation)

        def close_file(fd):
            nonlocal failed
            original_close(fd)
            if failure == "close" and not failed:
                failed = True
                raise error

        def transport(request):
            posts.append(request)
            b"".join(request.body)
            return Response(200, {}, b"ok")

        with monkeypatch.context() as patch:
            patch.setattr(coordination.os, "open", open_file)
            patch.setattr(coordination.os, "close", close_file)
            patch.setattr(fcntl, "flock", flock)
            with pytest.raises(OSError) as caught:
                uploads.send("m", URL, transport, lambda *_: receipt)
            assert caught.value is error
        assert len(posts) == (0 if failure.startswith("second_") else 1)
        # Inspect every created file through independent descriptors; checking
        # only the local mutex would miss a leaked legacy or canonical flock.
        for path in (tmp_path / ".wa-upload-locks").iterdir():
            fd = original_open(path, os.O_RDWR)
            try:
                original_flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                original_close(fd)
        assert uploads.send("m", URL, transport, lambda *_: receipt) == receipt
        assert len(posts) == 1
    finally:
        db.close()
