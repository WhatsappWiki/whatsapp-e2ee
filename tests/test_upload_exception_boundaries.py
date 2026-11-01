"""Upload callbacks keep their original failures and release operation ownership."""

import errno
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest

from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import Reconciliation, Response, UploadReceipt, Uploads
from whatsapp_e2ee.upload_coordination import UploadBusy

URL = "https://media.invalid/upload"


@dataclass(frozen=True)
class FrozenFailure(Exception):
    reason: str


@dataclass(frozen=True)
class FrozenCancellation(BaseException):
    reason: str


@dataclass(frozen=True)
class FrozenStopIteration(StopIteration):
    reason: str


@pytest.mark.parametrize("memory", [False, True])
@pytest.mark.parametrize("stage", ["transport", "receipt", "lookup"])
@pytest.mark.parametrize(
    "error_type",
    [
        FrozenFailure,
        FrozenCancellation,
        FrozenStopIteration,
        UploadBusy,
        KeyboardInterrupt,
        GeneratorExit,
        SystemExit,
    ],
)
def test_callback_failure_identity_and_worker_recovery(tmp_path, memory, stage, error_type):
    db = Database(":memory:" if memory else tmp_path / "media.db")
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        media = jobs.prepare("m", b"media", "image")
        uploads = Uploads(jobs)
        receipt = UploadReceipt("/uploaded", 123000, media.encrypted_hash)
        error = error_type("callback failure")
        calls, closed = [], []

        def transport(request):
            calls.append(request)
            b"".join(request.body)
            if stage == "transport":
                raise error
            if stage == "lookup":
                raise TimeoutError("response lost")
            return Response(200, {}, b"ok", lambda: closed.append(True))

        def fail(*_):
            raise error

        def initial():
            if stage == "lookup":
                with pytest.raises(TimeoutError):
                    uploads.send("m", URL, transport, lambda *_: receipt)
                return uploads.reconcile("m", fail)
            return uploads.send("m", URL, transport, fail)

        def success(request):
            calls.append(request)
            b"".join(request.body)
            return Response(200, {}, b"ok")

        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(error_type) as caught:
                pool.submit(initial).result(timeout=3)
            assert caught.value is error
            assert uploads.pending("m")["state"] == "unknown"
            assert jobs.store._get("media-upload", "m") is None
            assert len(calls) == 1 and db.depth == 0 and not db.connection.in_transaction
            if stage == "receipt":
                assert closed == [True]
            assert (
                pool.submit(uploads.reconcile, "m", lambda _: Reconciliation("absent")).result(
                    timeout=3
                )
                is None
            )
            assert (
                pool.submit(uploads.send, "m", URL, success, lambda *_: receipt).result(timeout=3)
                == receipt
            )
        assert len(calls) == 2 and uploads.pending("m")["count"] == 2
        assert uploads.pending("m")["state"] == "uploaded"
    finally:
        db.close()


@pytest.mark.parametrize("stage", ["open", "flock"])
def test_failed_lock_acquisition_releases_local_ownership(tmp_path, stage, monkeypatch):
    if stage == "flock" and os.name == "nt":
        pytest.skip("POSIX file locking")
    import whatsapp_e2ee.upload_coordination as coordination

    db = Database(tmp_path / "media.db")
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        media = jobs.prepare("m", b"media", "image")
        uploads = Uploads(jobs)
        error = OSError(errno.EIO, "lock acquisition failed")

        def fail(*_):
            raise error

        with monkeypatch.context() as patch:
            if stage == "open":
                patch.setattr(coordination.os, "open", fail)
            else:
                import fcntl

                patch.setattr(fcntl, "flock", fail)
            with pytest.raises(OSError) as caught:
                uploads.send("m", URL, lambda _: pytest.fail("Unexpected POST"), fail)
            assert caught.value is error
        assert uploads.pending("m") is None

        def success(request):
            b"".join(request.body)
            return Response(200, {}, b"ok")

        assert (
            uploads.send(
                "m",
                URL,
                success,
                lambda *_: UploadReceipt("/uploaded", 123000, media.encrypted_hash),
            ).direct_path
            == "/uploaded"
        )
    finally:
        db.close()
