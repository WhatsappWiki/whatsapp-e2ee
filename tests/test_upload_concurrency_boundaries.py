"""Live upload exclusion, durable reconciliation and multipart boundaries."""

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media import IntegrityError
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import (
    Reconciliation,
    Response,
    TransferError,
    UploadReceipt,
    Uploads,
    UploadUncertain,
)

URL = "https://media.invalid/upload"


@pytest.fixture
def factory(tmp_path):
    opened = []

    def create(*, memory=False, db=None, owner="owner"):
        db = db or Database(":memory:" if memory else tmp_path / "media.db")
        if db not in opened:
            opened.append(db)
        return MediaJobs(SQLiteStore(db, owner), clock_ms=lambda: 123000)

    yield create
    for db in opened:
        db.close()


def receipt(media, path="/uploaded"):
    return UploadReceipt(path, 123000, media.encrypted_hash)


def successful(request):
    b"".join(request.body)
    return Response(200, {}, b"ok")


def ambiguous(jobs):
    media = jobs.prepare("m", b"synthetic media", "image")
    uploads = Uploads(jobs)

    def timeout(request):
        b"".join(request.body)
        raise TimeoutError("response lost")

    with pytest.raises(TimeoutError):
        uploads.send("m", URL, timeout, lambda *_: receipt(media))
    return media, uploads


@pytest.mark.parametrize("storage", ["same", "view", "connection", "memory", "owner_alias"])
@pytest.mark.parametrize("operation", ["send", "reconcile"])
def test_live_sender_excludes_competing_operations(factory, storage, operation):
    jobs = factory(memory=storage == "memory", owner=1 if storage == "owner_alias" else "owner")
    media = jobs.prepare("m", b"synthetic media", "image")
    peer_jobs = (
        factory(owner="1")
        if storage == "owner_alias"
        else (factory() if storage == "connection" else factory(db=jobs.store.db))
    )
    uploads = Uploads(jobs)
    peer = uploads if storage == "same" else Uploads(peer_jobs)
    ready, release = Event(), Event()

    def blocked(request):
        b"".join(request.body)
        ready.set()
        assert release.wait(timeout=10)
        return Response(200, {}, b"ok")

    with ThreadPoolExecutor(1) as executor:
        future = executor.submit(uploads.send, "m", URL, blocked, lambda *_: receipt(media))
        try:
            assert ready.wait(timeout=5)
            with pytest.raises(UploadUncertain):
                if operation == "send":
                    peer.send(
                        "m", URL, lambda _: pytest.fail("Duplicate POST"), lambda *_: receipt(media)
                    )
                else:
                    peer.reconcile("m", lambda _: Reconciliation("absent"))
        finally:
            release.set()
        assert future.result(timeout=5) == receipt(media)
    assert uploads.pending("m")["state"] == "uploaded"
    assert uploads.pending("m")["count"] == 1


def test_active_lookup_cannot_be_overtaken_by_second_reconciler(factory):
    jobs = factory()
    media, uploads = ambiguous(jobs)
    peer = Uploads(factory())
    ready, release = Event(), Event()

    def lookup(_):
        ready.set()
        assert release.wait(timeout=10)
        return Reconciliation("found", receipt(media))

    with ThreadPoolExecutor(1) as executor:
        future = executor.submit(uploads.reconcile, "m", lookup)
        try:
            assert ready.wait(timeout=5)
            with pytest.raises(UploadUncertain):
                peer.reconcile("m", lambda _: Reconciliation("absent"))
        finally:
            release.set()
        assert future.result(timeout=5) == receipt(media)


@pytest.mark.parametrize("result", ["found", "absent", "unknown"])
def test_durable_completion_wins_over_stale_lookup(factory, result):
    jobs = factory()
    media, uploads = ambiguous(jobs)
    original = uploads.pending("m")

    def lookup(_):
        jobs.mark_uploaded("m", "/winner", 123000)
        return Reconciliation(result, receipt(media, "/stale") if result == "found" else None)

    assert uploads.reconcile("m", lookup) == receipt(media, "/winner")
    final = uploads.pending("m")
    assert final["state"] == "uploaded" and final["direct_path"] == "/winner"
    assert (final["count"], final["request_id"]) == (original["count"], original["request_id"])
    assert uploads.send(
        "m", URL, lambda _: pytest.fail("Completed upload was posted"), lambda *_: None
    ) == receipt(media, "/winner")


@pytest.mark.parametrize("via_reconciliation", [False, True])
def test_completed_reconciliation_is_idempotent_after_restart(factory, via_reconciliation):
    jobs = factory()
    if via_reconciliation:
        media, uploads = ambiguous(jobs)
        uploads.reconcile("m", lambda _: Reconciliation("found", receipt(media)))
    else:
        media = jobs.prepare("m", b"media", "image")
        Uploads(jobs).send("m", URL, successful, lambda *_: receipt(media))
    jobs.store.db.close()
    uploads = Uploads(factory())
    before = uploads.pending("m")
    assert uploads.reconcile(
        "m", lambda _: pytest.fail("Completed upload queried again")
    ) == receipt(media)
    assert uploads.pending("m") == before


def test_body_consumed_to_content_length_needs_no_extra_iteration(factory):
    jobs = factory()
    media = jobs.prepare("m", b"media", "image")

    def transport(request):
        expected = int(dict(request.headers)["content-length"])
        iterator, count = iter(request.body), 0
        while count < expected:
            count += len(next(iterator))
        assert count == expected
        return Response(200, {}, b"ok")

    assert Uploads(jobs).send("m", URL, transport, lambda *_: receipt(media)) == receipt(media)


def test_file_growth_never_emits_more_than_declared_body(factory, tmp_path):
    jobs = factory()
    source = tmp_path / "source"
    source.write_bytes(b"media")
    media = jobs.prepare_file("m", source, "image", tmp_path / "cache")
    sent, lengths = [], []

    def transport(request):
        lengths.append(int(dict(request.headers)["content-length"]))
        media.path.write_bytes(media.path.read_bytes() + b"x" * 4096)
        for part in request.body:
            sent.append(part)
        pytest.fail("Changed file completed")

    uploads = Uploads(jobs)
    with pytest.raises(IntegrityError):
        uploads.send("m", URL, transport, lambda *_: receipt(media))
    assert sum(map(len, sent)) <= lengths[0]
    assert uploads.pending("m")["state"] == "unknown"


@pytest.mark.parametrize(
    "field,value",
    [
        ("timestamp_ms", None),
        ("timestamp_ms", True),
        ("timestamp_ms", 123001),
        ("direct_path", ""),
        ("encrypted_hash", "not-bytes"),
        ("encrypted_hash", b"short"),
    ],
)
def test_invalid_receipt_cannot_commit_success(factory, field, value):
    jobs = factory()
    media = jobs.prepare("m", b"media", "image")
    values = dict(direct_path="/uploaded", timestamp_ms=123000, encrypted_hash=media.encrypted_hash)
    values[field] = value
    uploads = Uploads(jobs)
    with pytest.raises((TransferError, ValueError)):
        uploads.send("m", URL, successful, lambda *_: UploadReceipt(**values))
    assert jobs.store._get("media-upload", "m") is None
    assert uploads.pending("m")["state"] == "unknown"


@pytest.mark.parametrize(
    "status,headers",
    [
        (200.5, {}),
        (200, {"content-length": "3"}),
        (200, {"content-length": "２"}),
        (200, {"content-length": "-1"}),
    ],
)
def test_malformed_response_rejected_before_receipt_parser(factory, status, headers):
    jobs = factory()
    jobs.prepare("m", b"media", "image")
    closed = []

    def transport(request):
        b"".join(request.body)
        return Response(status, headers, b"ok", lambda: closed.append(True))

    uploads = Uploads(jobs)
    with pytest.raises(TransferError):
        uploads.send("m", URL, transport, lambda *_: pytest.fail("Malformed response parsed"))
    assert closed == [True]
    assert uploads.pending("m")["state"] == "unknown"


@pytest.mark.parametrize("id", [None, "", 1, True])
def test_upload_job_identity_is_a_nonempty_string(factory, id):
    jobs = factory()
    with pytest.raises(ValueError):
        jobs.prepare(id, b"media", "image")
    assert jobs.store.db.connection.execute("SELECT count(*) FROM records").fetchone()[0] == 0


CHILD = """
import os,sys
from whatsapp_e2ee import Database,SQLiteStore
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import Uploads,Response,UploadReceipt
j=MediaJobs(SQLiteStore(Database(sys.argv[1]),'owner'),clock_ms=lambda:123000)
m=j.prepare('m',b'media','image')
def transport(r):
 b''.join(r.body)
 if sys.argv[2]=='crash':os._exit(27)
 print('READY',flush=True)
 sys.stdin.readline()
 return Response(200,{},b'ok')
Uploads(j).send('m','https://media.invalid/upload',transport,lambda *_:UploadReceipt('/uploaded',123000,m.encrypted_hash))
"""


def test_live_process_blocks_reconciliation(factory, tmp_path):
    jobs = factory()
    process = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(tmp_path / "media.db"), "live"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        with ThreadPoolExecutor(1) as executor:
            try:
                assert (
                    executor.submit(process.stdout.readline).result(timeout=10).strip() == "READY"
                )
            except BaseException:
                process.kill()  # Unblock the reader before waiting for the executor.
                raise
        with pytest.raises(UploadUncertain):
            Uploads(jobs).reconcile("m", lambda _: Reconciliation("absent"))
    finally:
        try:
            stdout, stderr = process.communicate("continue\n", timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
    assert process.returncode == 0, (stdout, stderr)
    assert Uploads(jobs).pending("m")["state"] == "uploaded"


def test_crashed_process_releases_operation_for_explicit_recovery(factory, tmp_path):
    jobs = factory()
    process = subprocess.run(
        [sys.executable, "-c", CHILD, str(tmp_path / "media.db"), "crash"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert process.returncode == 27, process.stderr
    uploads = Uploads(jobs)
    before = uploads.pending("m")
    assert before["state"] == "in_flight"
    media = jobs.load("m")
    assert uploads.reconcile("m", lambda _: Reconciliation("found", receipt(media))) == receipt(
        media
    )
    assert uploads.pending("m")["request_id"] == before["request_id"]


@pytest.mark.parametrize("failure", [False, True])
def test_durable_completion_during_post_preserves_winner(factory, failure):
    jobs = factory()
    media = jobs.prepare("m", b"media", "image")
    uploads = Uploads(jobs)

    def transport(request):
        b"".join(request.body)
        jobs.mark_uploaded("m", "/winner", 123000)
        if failure:
            raise TimeoutError("completion callback lost")
        return Response(200, {}, b"ok")

    if failure:
        with pytest.raises(TimeoutError):
            uploads.send("m", URL, transport, lambda *_: receipt(media, "/late"))
    else:
        assert uploads.send("m", URL, transport, lambda *_: receipt(media, "/late")) == receipt(
            media, "/winner"
        )
    assert uploads.pending("m")["state"] == "uploaded"
    assert uploads.pending("m")["direct_path"] == "/winner"
    assert uploads.pending("m")["count"] == 1


@pytest.mark.parametrize("outer", ["atomic", "raw"])
def test_file_preparation_requires_durable_reservation(factory, tmp_path, outer):
    jobs = factory()
    source = tmp_path / "source"
    source.write_bytes(b"media")

    def prepare():
        with pytest.raises(RuntimeError, match="transaction"):
            jobs.prepare_file("m", source, "image", tmp_path / "cache")

    if outer == "atomic":
        with jobs.store.db.atomic():
            prepare()
    else:
        jobs.store.db.connection.execute("BEGIN IMMEDIATE")
        try:
            prepare()
        finally:
            jobs.store.db.connection.rollback()
    assert not (tmp_path / "cache").exists()
    assert jobs.store._get("media-file-reservation", "m") is None


def test_corrupt_file_cache_can_be_explicitly_rebuilt_without_rekey(factory, tmp_path):
    jobs = factory()
    source = tmp_path / "source"
    source.write_bytes(b"media")
    media = jobs.prepare_file("m", source, "image", tmp_path / "cache")
    original = media.path.read_bytes()
    jobs.mark_uploaded("m", "/uploaded", 123000)
    media.path.write_bytes(b"corrupt")
    repaired = jobs.prepare_file("m", source, "image", tmp_path / "cache")
    assert repaired.path.read_bytes() == original
    assert repaired.media_key == media.media_key and repaired.encrypted_hash == media.encrypted_hash
    assert jobs.key_timestamp_ms("m") == 123000
    assert jobs.store._get("media-upload", "m") is not None


@pytest.mark.parametrize("stage", ["success_attempt", "success_checkpoint", "unknown_checkpoint"])
def test_late_sql_failure_remains_recoverable_without_second_post(factory, stage):
    jobs = factory()
    media = jobs.prepare("m", b"media", "image")
    uploads = Uploads(jobs)
    calls = []

    def transport(request):
        calls.append(request)
        b"".join(request.body)
        condition = {
            "success_attempt": "NEW.kind='media-upload-attempt' AND CAST(NEW.value AS TEXT) LIKE '%uploaded%'",
            "success_checkpoint": "NEW.kind='media-upload'",
            "unknown_checkpoint": "NEW.kind='media-upload-attempt' AND CAST(NEW.value AS TEXT) LIKE '%unknown%'",
        }[stage]
        jobs.store.db.connection.execute(
            "CREATE TRIGGER fail_late BEFORE INSERT ON records WHEN "
            + condition
            + " BEGIN SELECT RAISE(ABORT,'late checkpoint'); END"
        )
        if stage == "unknown_checkpoint":
            raise TimeoutError("response lost")
        return Response(200, {}, b"ok")

    with pytest.raises(sqlite3.IntegrityError, match="late checkpoint"):
        uploads.send("m", URL, transport, lambda *_: receipt(media))
    assert uploads.pending("m")["state"] in ("in_flight", "unknown")
    assert jobs.store._get("media-upload", "m") is None
    jobs.store.db.connection.execute("DROP TRIGGER fail_late")
    with pytest.raises(UploadUncertain):
        uploads.send(
            "m", URL, lambda _: pytest.fail("Retried before reconciliation"), lambda *_: None
        )
    assert uploads.reconcile("m", lambda _: Reconciliation("found", receipt(media))) == receipt(
        media
    )
    assert len(calls) == 1
