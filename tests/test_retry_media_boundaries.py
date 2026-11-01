"""Real node roundtrips, group retry authorization and upload recovery."""

import pytest
from protocol_tree_node import Codec, TokenDictionary
from test_retry import advertised, incoming_retry
from wire_helpers import endpoint

from whatsapp_e2ee import Database, SQLiteStore, payload
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import (
    Reconciliation,
    Response,
    UploadReceipt,
    Uploads,
    UploadUncertain,
    json_upload_receipt,
)
from whatsapp_e2ee.retry import RetryManager, parse_retry


@pytest.mark.parametrize("group", [None, "1000001@g.us"])
def test_retry_after_real_codec_roundtrip(tmp_path, group):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    targets = {b.address: advertised(b)}
    raw = payload.text("original")
    if group:
        a.prepare_group_delivery("original", group, raw, [b.address], bundles=targets)
    else:
        a.prepare_direct("original", {b.address: raw}, bundles=targets)
    request = incoming_retry(b, bundle=advertised(b), group=group)
    codec = Codec(TokenDictionary.bundled())
    request = parse_retry(codec.read(codec.write(request.raw_node)))
    options = {"current_group_devices": [b.address]} if group else {}
    manager = RetryManager(a)
    attempt = manager.prepare(request, authenticated_transport=True, **options)
    before = a.store.load_session(b.address).serialize()
    assert manager.prepare(request, authenticated_transport=True, **options) == attempt
    assert a.store.load_session(b.address).serialize() == before
    if group:
        b.receive(
            "distribution",
            a.address,
            attempt.packets[0],
            expected_group=group,
            content_slot="distribution",
            retry_count=1,
        )
    assert (
        b.receive("original", a.address, attempt.packets[-1], expected_group=group, retry_count=1)
        == raw
    )
    if group:
        with pytest.raises(ValueError, match="current"):
            manager.prepare(request, authenticated_transport=True, current_group_devices=[])


@pytest.mark.parametrize("state", ["uploaded", "unknown", "reconciled"])
def test_file_upload_outcome_survives_cache_cleanup(tmp_path, state):
    path = tmp_path / "media.db"
    db = Database(path)
    jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
    source = tmp_path / "source"
    source.write_bytes(b"synthetic media")
    media = jobs.prepare_file("m", source, "image", tmp_path / "cache")
    uploads = Uploads(jobs)
    receipt = UploadReceipt("/uploaded", 123000, media.encrypted_hash)

    def transport(request):
        b"".join(request.body)
        if state != "uploaded":
            raise TimeoutError("response lost")
        return Response(200, {}, b"ok")

    if state == "uploaded":
        assert (
            uploads.send("m", "https://media.invalid/upload", transport, lambda *_: receipt)
            == receipt
        )
    else:
        with pytest.raises(TimeoutError):
            uploads.send("m", "https://media.invalid/upload", transport, lambda *_: receipt)
    media.path.unlink()
    db.close()
    db = Database(path)
    try:
        uploads = Uploads(MediaJobs(SQLiteStore(db, "owner")))
        if state == "reconciled":
            assert uploads.reconcile("m", lambda _: Reconciliation("found", receipt)) == receipt

        def forbidden(*args):
            pytest.fail("Recovery must not resend the upload")

        if state == "unknown":
            with pytest.raises(UploadUncertain):
                uploads.send("m", "https://media.invalid/upload", forbidden, json_upload_receipt)
        else:
            assert (
                uploads.send("m", "https://media.invalid/upload", forbidden, json_upload_receipt)
                == receipt
            )
    finally:
        db.close()


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_new_post_still_requires_intact_cache(tmp_path, damage):
    db = Database(tmp_path / "media.db")
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        source = tmp_path / "source"
        source.write_bytes(b"synthetic")
        media = jobs.prepare_file("m", source, "image", tmp_path / "cache")
        if damage == "missing":
            media.path.unlink()
        else:
            media.path.write_bytes(b"changed")
        uploads = Uploads(jobs)
        with pytest.raises((FileNotFoundError, ValueError)):
            uploads.send(
                "m",
                "https://media.invalid/upload",
                lambda *_: pytest.fail("Invalid cache was sent"),
                json_upload_receipt,
            )
        assert uploads.pending("m") is None
    finally:
        db.close()


@pytest.mark.parametrize("outcome", ["uploaded", "unknown"])
def test_upload_rechecks_outcome_after_file_verification(tmp_path, monkeypatch, outcome):
    db = Database(tmp_path / "media.db")
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        media = jobs.prepare("m", b"synthetic", "image")
        uploads = Uploads(jobs)
        real_load = jobs.load
        receipt = UploadReceipt("/concurrent", 123000, media.encrypted_hash)

        def load(id, *, verify_file=False):
            value = real_load(id, verify_file=verify_file)
            if verify_file:
                if outcome == "uploaded":
                    jobs.mark_uploaded(id, receipt.direct_path, receipt.timestamp_ms)
                else:
                    uploads._write(id, dict(state="unknown", count=1, request_id="other"))
            return value

        monkeypatch.setattr(jobs, "load", load)

        def forbidden(*args):
            pytest.fail("A concurrent outcome was ignored")

        if outcome == "uploaded":
            assert (
                uploads.send("m", "https://media.invalid/upload", forbidden, json_upload_receipt)
                == receipt
            )
        else:
            with pytest.raises(UploadUncertain):
                uploads.send("m", "https://media.invalid/upload", forbidden, json_upload_receipt)
    finally:
        db.close()


def test_absent_upload_requires_explicit_cache_rebuild_before_new_post(tmp_path):
    db = Database(tmp_path / "media.db")
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        source = tmp_path / "source"
        source.write_bytes(b"synthetic")
        media = jobs.prepare_file("m", source, "document", tmp_path / "cache")
        uploads, calls = Uploads(jobs), []

        def timeout(request):
            calls.append(request)
            b"".join(request.body)
            raise TimeoutError("response lost")

        with pytest.raises(TimeoutError):
            uploads.send("m", "https://media.invalid/upload", timeout, json_upload_receipt)
        media.path.unlink()
        assert uploads.reconcile("m", lambda _: Reconciliation("absent")) is None
        with pytest.raises(FileNotFoundError):
            uploads.send("m", "https://media.invalid/upload", timeout, json_upload_receipt)
        assert uploads.pending("m")["count"] == 1
        assert uploads.pending("m")["state"] == "absent"
        rebuilt = jobs.prepare_file("m", source, "document", tmp_path / "cache")
        assert rebuilt.media_key == media.media_key
        assert rebuilt.encrypted_hash == media.encrypted_hash
        receipt = UploadReceipt("/second", 123000, media.encrypted_hash)

        def success(request):
            calls.append(request)
            b"".join(request.body)
            return Response(200, {}, b"ok")

        assert (
            uploads.send("m", "https://media.invalid/upload", success, lambda *_: receipt)
            == receipt
        )
        assert uploads.pending("m")["count"] == 2
        assert len(calls) == 2
    finally:
        db.close()


def test_group_retry_commit_failure_rolls_back_both_ratchets(tmp_path):
    import sqlite3

    from signal_protocol.groups import SenderKeyName

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    group = "1000001@g.us"
    a.prepare_group_delivery(
        "original", group, payload.text("body"), [b.address], bundles={b.address: advertised(b)}
    )
    request = incoming_retry(b, group=group, bundle=advertised(b))
    codec = Codec(TokenDictionary.bundled())
    request = parse_retry(codec.read(codec.write(request.raw_node)))
    sender_key = SenderKeyName(group, a.address)
    before_session = a.store.load_session(b.address).serialize()
    before_group = a.store.load_sender_key(sender_key).serialize()
    with a.store.db.atomic() as c:
        c.execute(
            "CREATE TRIGGER fail_group_retry BEFORE INSERT ON records "
            "WHEN NEW.kind='retry-attempt' BEGIN SELECT RAISE(ABORT,'checkpoint'); END"
        )
    manager = RetryManager(a)
    with pytest.raises(sqlite3.IntegrityError):
        manager.prepare(request, authenticated_transport=True, current_group_devices=[b.address])
    assert a.store.load_session(b.address).serialize() == before_session
    assert a.store.load_sender_key(sender_key).serialize() == before_group
    assert a.store.db.connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == 1
    with a.store.db.atomic() as c:
        c.execute("DROP TRIGGER fail_group_retry")
    attempt = manager.prepare(
        request, authenticated_transport=True, current_group_devices=[b.address]
    )
    b.receive(
        "distribution",
        a.address,
        attempt.packets[0],
        expected_group=group,
        content_slot="distribution",
        retry_count=1,
    )
    assert b.receive(
        "original", a.address, attempt.packets[-1], expected_group=group, retry_count=1
    ) == payload.text("body")
