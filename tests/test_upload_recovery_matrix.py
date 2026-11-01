"""Recovery outcomes and independent-worker progress after upload failures."""

import errno
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest
from test_upload_concurrency_boundaries import (
    URL,
    ambiguous,
    receipt,
    successful,
)
from test_upload_concurrency_boundaries import factory as factory

from whatsapp_e2ee import Database
from whatsapp_e2ee.media_transfer import (
    Reconciliation,
    Response,
    TransferError,
    UploadReceipt,
    Uploads,
    UploadUncertain,
)


@pytest.mark.parametrize("initial", ["unknown", "in_flight"])
@pytest.mark.parametrize("outcome", ["found", "absent", "unknown"])
def test_reconciliation_transition_matrix(factory, initial, outcome):
    jobs = factory()
    media, uploads = ambiguous(jobs)
    before = uploads.pending("m")
    if initial == "in_flight":
        before = dict(before, state=initial)
        uploads._write("m", before)  # Same durable shape left by the process-crash test.
    calls = []

    def lookup(attempt):
        assert not jobs.store.db.connection.in_transaction
        calls.append(attempt)
        return Reconciliation(outcome, receipt(media) if outcome == "found" else None)

    result = uploads.reconcile("m", lookup)
    final = uploads.pending("m")
    assert calls == [before]
    assert final["count"] == before["count"]
    assert final["request_id"] == before["request_id"]
    assert result == (receipt(media) if outcome == "found" else None)
    assert final["state"] == {"found": "uploaded", "absent": "absent", "unknown": initial}[outcome]
    posts = []

    def transport(request):
        posts.append(request)
        return successful(request)

    if outcome == "unknown":
        with pytest.raises(UploadUncertain):
            uploads.send("m", URL, transport, lambda *_: receipt(media))
    else:
        assert uploads.send("m", URL, transport, lambda *_: receipt(media)) == receipt(media)
    assert len(posts) == (1 if outcome == "absent" else 0)
    if posts:
        assert uploads.pending("m")["count"] == before["count"] + 1
        assert uploads.pending("m")["request_id"] != before["request_id"]


@pytest.mark.parametrize(
    "case", ["none", "status", "found_empty", "absent_receipt", "unknown_receipt", "hash", "time"]
)
def test_invalid_lookup_never_implies_absence(factory, case):
    jobs = factory()
    media, uploads = ambiguous(jobs)
    before = uploads.pending("m")
    cases = {
        "none": None,
        "status": Reconciliation("invalid"),
        "found_empty": Reconciliation("found"),
        "absent_receipt": Reconciliation("absent", receipt(media)),
        "unknown_receipt": Reconciliation("unknown", receipt(media)),
        "hash": Reconciliation("found", UploadReceipt("/uploaded", 123000, bytes(32))),
        "time": Reconciliation("found", UploadReceipt("/uploaded", None, media.encrypted_hash)),
    }
    with pytest.raises(TransferError):
        uploads.reconcile("m", lambda _: cases[case])
    assert uploads.pending("m") == before
    with pytest.raises(UploadUncertain):
        uploads.send(
            "m", URL, lambda _: pytest.fail("Invalid lookup allowed POST"), lambda *_: None
        )
    assert uploads.reconcile("m", lambda _: Reconciliation("found", receipt(media))) == receipt(
        media
    )


@pytest.mark.parametrize(
    "failure",
    ["prefix_only", "no_suffix", "iterate_twice", "close", "oversized", "text_body", "parser"],
)
def test_stream_failure_releases_ownership_and_requires_reconciliation(factory, failure):
    jobs = factory()
    media = jobs.prepare("m", b"media", "image")
    uploads, closed, posts = Uploads(jobs), [], []

    def close():
        closed.append(True)
        if failure == "close":
            raise OSError("close failed")

    def transport(request):
        assert not jobs.store.db.connection.in_transaction
        posts.append(request)
        if failure in ("prefix_only", "no_suffix"):
            iterator = iter(request.body)
            for _ in range(1 if failure == "prefix_only" else 2):
                next(iterator)
        else:
            b"".join(request.body)
            if failure == "iterate_twice":
                with pytest.raises(TransferError):
                    b"".join(request.body)
                raise TransferError("transport attempted to replay body")
        body = (
            b"x" * (1024 * 1024 + 1)
            if failure == "oversized"
            else ("text" if failure == "text_body" else b"ok")
        )
        return Response(200, {}, body, close)

    def parser(*_):
        if failure == "parser":
            raise ValueError("invalid adapter payload")
        return receipt(media)

    with pytest.raises((TransferError, OSError, ValueError)):
        uploads.send("m", URL, transport, parser)
    assert closed == ([] if failure == "iterate_twice" else [True])
    assert uploads.pending("m")["state"] == "unknown"
    before = uploads.pending("m")
    assert uploads.reconcile("m", lambda _: Reconciliation("unknown")) is None
    assert uploads.pending("m") == before
    assert uploads.reconcile("m", lambda _: Reconciliation("found", receipt(media))) == receipt(
        media
    )
    assert len(posts) == 1


@pytest.mark.parametrize("scope", ["job", "owner", "database"])
def test_unrelated_uploads_progress_while_one_operation_is_active(factory, tmp_path, scope):
    jobs = factory()
    first = jobs.prepare("m", b"first", "image")
    peer_jobs = (
        factory(owner="other")
        if scope == "owner"
        else (factory(db=Database(tmp_path / "other.db")) if scope == "database" else jobs)
    )
    peer_id = "other" if scope == "job" else "m"
    second = peer_jobs.prepare(peer_id, b"second", "image")
    peer = Uploads(peer_jobs)

    def transport(request):
        b"".join(request.body)
        assert peer.send(peer_id, URL, successful, lambda *_: receipt(second)) == receipt(second)
        return Response(200, {}, b"ok")

    assert Uploads(jobs).send("m", URL, transport, lambda *_: receipt(first)) == receipt(first)
    assert peer.pending(peer_id)["count"] == 1


def test_reentrant_recovery_fails_promptly_without_interrupting_sender(factory):
    jobs = factory()
    media = jobs.prepare("m", b"media", "image")
    uploads = Uploads(jobs)

    def transport(request):
        b"".join(request.body)
        with pytest.raises(UploadUncertain):
            uploads.reconcile("m", lambda _: pytest.fail("Lookup inside active POST"))
        with pytest.raises(UploadUncertain):
            uploads.send("m", URL, lambda _: pytest.fail("Reentrant POST"), lambda *_: None)
        return Response(200, {}, b"ok")

    assert uploads.send("m", URL, transport, lambda *_: receipt(media)) == receipt(media)


def test_symlink_database_alias_shares_operation_owner(factory, tmp_path):
    jobs = factory()
    media = jobs.prepare("m", b"media", "image")
    alias = tmp_path / "alias.db"
    try:
        alias.symlink_to(tmp_path / "media.db")
    except OSError:
        pytest.skip("Filesystem cannot create symlinks")
    peer = Uploads(factory(db=Database(alias)))

    def transport(request):
        b"".join(request.body)
        with pytest.raises(UploadUncertain):
            peer.reconcile("m", lambda _: Reconciliation("absent"))
        return Response(200, {}, b"ok")

    assert Uploads(jobs).send("m", URL, transport, lambda *_: receipt(media)) == receipt(media)


def test_concurrent_file_preparations_preserve_one_root_and_ciphertext(
    factory, tmp_path, monkeypatch
):
    from whatsapp_e2ee import media_jobs

    jobs, peer = factory(), factory()
    source = tmp_path / "source"
    source.write_bytes(b"media" * 20000)
    encrypt = media_jobs.encrypt_file
    barrier = Barrier(2)

    def overlapping(*args, **kwargs):
        barrier.wait(timeout=5)
        return encrypt(*args, **kwargs)

    monkeypatch.setattr(media_jobs, "encrypt_file", overlapping)
    with ThreadPoolExecutor(2) as executor:
        futures = [
            executor.submit(j.prepare_file, "m", source, "image", tmp_path / "cache")
            for j in (jobs, peer)
        ]
        values = [f.result(timeout=10) for f in futures]
    assert values[0] == values[1]
    assert jobs.load("m", verify_file=True) == values[0]
    assert jobs.key_timestamp_ms("m") == 123000
    assert not list((tmp_path / "cache").glob(".wa-job-*"))


def test_process_exit_during_lookup_leaves_recoverable_attempt(factory, tmp_path):
    jobs = factory()
    media, uploads = ambiguous(jobs)
    before = uploads.pending("m")
    code = """
import os,sys
from whatsapp_e2ee import Database,SQLiteStore
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import Uploads
j=MediaJobs(SQLiteStore(Database(sys.argv[1]),'owner'))
Uploads(j).reconcile('m',lambda _:os._exit(28))
"""
    process = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path / "media.db")],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert process.returncode == 28, process.stderr
    assert uploads.pending("m") == before
    assert uploads.reconcile("m", lambda _: Reconciliation("found", receipt(media))) == receipt(
        media
    )


@pytest.mark.parametrize("code", [errno.EIO, errno.EACCES])
def test_windows_lock_backend_distinguishes_io_failure_from_contention(factory, monkeypatch, code):
    from whatsapp_e2ee import upload_coordination

    jobs = factory()
    media = jobs.prepare("m", b"media", "image")
    uploads = Uploads(jobs)
    failure = OSError(code, "locking failed")

    def lock(*_):
        raise failure

    # Exercise the Windows branch without claiming native Windows execution.
    functions = {
        name: getattr(os, name)
        for name in (
            "open",
            "write",
            "lseek",
            "close",
            "fstat",
            "O_CREAT",
            "O_RDWR",
            "SEEK_SET",
        )
    }
    with monkeypatch.context() as patch:
        patch.setattr(upload_coordination, "os", SimpleNamespace(name="nt", **functions))
        patch.setitem(sys.modules, "msvcrt", SimpleNamespace(locking=lock, LK_NBLCK=1, LK_UNLCK=0))
        with pytest.raises(UploadUncertain if code == errno.EACCES else OSError) as caught:
            uploads.send(
                "m", URL, lambda _: pytest.fail("Lock failure caused POST"), lambda *_: None
            )
        if code == errno.EIO:
            assert caught.value is failure
    assert uploads.pending("m") is None
    assert uploads.send("m", URL, successful, lambda *_: receipt(media)) == receipt(media)
