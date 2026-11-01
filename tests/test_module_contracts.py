"""Contracts at the newly separated persistence and compatibility boundaries."""

import importlib
import pkgutil

import pytest

import whatsapp_e2ee
from whatsapp_e2ee import Conflict, Database, Packet, SQLiteStore
from whatsapp_e2ee.outbox import Outbox


def test_explicit_exports_and_legacy_import_identity():
    for info in pkgutil.iter_modules(whatsapp_e2ee.__path__):
        module = importlib.import_module(f"whatsapp_e2ee.{info.name}")
        assert len(module.__all__) == len(set(module.__all__))
        assert all(hasattr(module, name) for name in module.__all__)
    from whatsapp_e2ee import client, database, devices, packets, store
    from whatsapp_e2ee.device_directory import DeviceDirectory
    from whatsapp_e2ee.device_discovery import Device, parse_discovery
    from whatsapp_e2ee.device_notifications import DeviceNotifications

    assert client.Packet is packets.Packet is Packet
    assert client.Conflict is packets.Conflict is Conflict
    assert store.Database is database.Database is Database
    assert devices.DeviceDirectory is DeviceDirectory
    assert devices.Device is Device
    assert devices.parse_discovery is parse_discovery
    assert devices.DeviceNotifications is DeviceNotifications


def test_outbox_failure_rolls_back_producer_and_allows_retry(tmp_path):
    db = Database(tmp_path / "outbox.db")
    try:
        store = SQLiteStore(db, "owner")
        outbox = Outbox(store)
        packet = Packet("15550002@s.whatsapp.net", 1, "msg", b"synthetic")

        def failing_producer():
            store._put("producer-state", "chain", b"advanced")
            yield packet
            raise RuntimeError("second recipient failed")

        with db.atomic():
            store._put("outer", "state", b"preserved")
            with pytest.raises(RuntimeError, match="second recipient"):
                outbox.prepare("message", b"request", failing_producer)
            assert store._get("producer-state", "chain") is None
            assert store._get("prepared-request", "message") is None
            assert db.connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == 0
        assert store._get("outer", "state")[0] == b"preserved"
        assert outbox.prepare("message", b"request", lambda: [packet]) == (packet,)
    finally:
        db.close()


def test_outbox_restart_reuses_bytes_without_invoking_producer(tmp_path):
    path = tmp_path / "outbox.db"
    packet = Packet("15550002@s.whatsapp.net", 1, "pkmsg", b"\x00\xff")
    db = Database(path)
    try:
        Outbox(SQLiteStore(db, "owner")).prepare("message", b"request", lambda: [packet])
    finally:
        db.close()
    db = Database(path)
    try:
        outbox = Outbox(SQLiteStore(db, "owner"))

        def forbidden():
            pytest.fail("Persisted ciphertext must not be regenerated")

        assert outbox.prepare("message", b"request", forbidden) == (packet,)
        with pytest.raises(Conflict):
            outbox.prepare("message", b"changed", forbidden)
    finally:
        db.close()


@pytest.mark.parametrize(
    "factory,module,name",
    [
        (lambda: Packet("15550002@s.whatsapp.net", 1, "msg", b"\x00\xff"), "client", "Packet"),
        (lambda: Conflict("collision"), "client", "Conflict"),
        (lambda: _device_value("Device"), "devices", "Device"),
        (lambda: _device_value("DeviceResult"), "devices", "DeviceResult"),
        (lambda: _device_value("DeviceNotification"), "devices", "DeviceNotification"),
        (lambda: _device_value("DeviceUpdate"), "devices", "DeviceUpdate"),
    ],
)
def test_public_value_pickle_keeps_legacy_module_path(factory, module, name):
    import pickle
    import pickletools

    value = factory()
    encoded = pickle.dumps(value, protocol=2)
    globals_used = {arg for op, arg, _ in pickletools.genops(encoded) if op.name == "GLOBAL"}
    assert f"whatsapp_e2ee.{module} {name}" in globals_used
    restored = pickle.loads(encoded)
    assert type(restored) is type(value)
    if isinstance(value, Exception):
        assert restored.args == value.args
    else:
        assert restored == value


def _device_value(name):
    from signal_protocol import SignalProtocolAddress

    from whatsapp_e2ee.devices import Device, DeviceNotification, DeviceResult, DeviceUpdate

    address = SignalProtocolAddress("15550001@s.whatsapp.net", 1)
    device = Device(address)
    return {
        "Device": device,
        "DeviceResult": DeviceResult(address.name, (device,)),
        "DeviceNotification": DeviceNotification(
            "event", address.name, None, (device,), (), (), (), "hash", None, None, 1, False
        ),
        "DeviceUpdate": DeviceUpdate((address.name,), (address,)),
    }[name]
