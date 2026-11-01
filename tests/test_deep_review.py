"""Trust-source consistency and durable transport transaction boundaries."""

import pytest
from signal_protocol import SignalProtocolAddress
from test_client import bundle
from test_devices import (
    apply_delta,
    device_notification,
    notification_setup,
    signed_indexes,
)
from wire_helpers import endpoint

from whatsapp_e2ee import Database, SQLiteStore, payload
from whatsapp_e2ee.delivery import Delivery
from whatsapp_e2ee.devices import DeviceDirectory, DeviceNotifications, device_address
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import Uploads, json_upload_receipt
from whatsapp_e2ee.transport import StanzaDelivery


@pytest.mark.parametrize("explicit_override", [False, True])
def test_notifications_share_directory_trust_source(tmp_path, explicit_override):
    original, _, identity, account = notification_setup(tmp_path)
    original.store._remove("identity", original.store.address(device_address(account, 0)))
    calls = []

    def lookup(name):
        calls.append(name)
        return identity.public_key

    directory = DeviceDirectory(original.store, identity_lookup=lookup)
    options = {}
    if explicit_override:
        directory.identity_lookup = lambda name: pytest.fail("Explicit override was ignored")
        options["identity_lookup"] = lookup
    adapter = DeviceNotifications(
        directory, SignalProtocolAddress("local@s.whatsapp.net", 0), **options
    )
    a0, a1, a2 = [device_address(account, i) for i in range(3)]
    node = device_notification(
        "add", account, add=[(a2, 2)], final=[a0, a1, a2], proof=signed_indexes(identity)
    )
    assert apply_delta(adapter, node).added == (a2,)
    assert calls == [account]
    assert [d.address for d in directory.devices(account, now=100)] == [a0, a1, a2]


@pytest.mark.parametrize("whole_stanza", [False, True])
@pytest.mark.parametrize("outer_transaction", ["atomic", "raw"])
def test_dispatch_rejects_uncommitted_outer_transaction(tmp_path, whole_stanza, outer_transaction):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_direct("message", {b.address: payload.text("body")}, bundles={b.address: bundle(b)})
    queue = StanzaDelivery(a.store) if whole_stanza else Delivery(a.store)
    if whole_stanza:
        queue.prepare("message", b.address.name)

    def forbidden(*args):
        pytest.fail("Transport called before the outer transaction committed")

    if outer_transaction == "atomic":
        with a.store.db.atomic():
            with pytest.raises(RuntimeError, match="transaction"):
                queue.dispatch("message", forbidden)
    else:
        a.store.db.connection.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(RuntimeError, match="transaction"):
                queue.dispatch("message", forbidden)
        finally:
            a.store.db.connection.rollback()
    assert a.store.db.connection.execute("SELECT state FROM outbox").fetchone()[0] == "prepared"
    if whole_stanza:
        assert a.store._get("stanza-state", "message")[0] == b"prepared"
    calls = []
    queue.dispatch("message", lambda *args: calls.append(args))
    assert len(calls) == 1


@pytest.mark.parametrize("operation", ["send", "reconcile"])
def test_upload_callbacks_reject_outer_transaction(tmp_path, operation):
    db = Database(tmp_path / "media.db")
    try:
        jobs = MediaJobs(SQLiteStore(db, "owner"), clock_ms=lambda: 123000)
        jobs.prepare("media", b"synthetic", "image")
        uploads = Uploads(jobs)

        def timeout(request):
            b"".join(request.body)
            raise TimeoutError("reply lost")

        if operation == "reconcile":
            with pytest.raises(TimeoutError):
                uploads.send("media", "https://media.invalid/upload", timeout, json_upload_receipt)
        before = uploads.pending("media")

        def forbidden(*args):
            pytest.fail("Upload/reconciliation callback ran inside the outer transaction")

        with db.atomic():
            with pytest.raises(RuntimeError, match="transaction"):
                if operation == "send":
                    uploads.send(
                        "media", "https://media.invalid/upload", forbidden, json_upload_receipt
                    )
                else:
                    uploads.reconcile("media", forbidden)
            assert uploads.pending("media") == before
        assert uploads.pending("media") == before
    finally:
        db.close()
