import sqlite3

import pytest
from signal_protocol import (
    WHATSAPP,
    Curve,
    KemKeyType,
    KeyHelper,
    PreKeyRecord,
    SessionRecord,
    SignalProtocolAddress,
)
from signal_protocol.exceptions import InvalidKeyIdException
from signal_protocol.groups import GroupSessionBuilder, SenderKeyName
from signal_protocol.store import Direction, InMemorySignalProtocolStore
from test_client import bundle, endpoint

from whatsapp_e2ee import Database, SQLiteStore, payload


def test_sqlite_and_memory_store_contract(tmp_path):
    db = Database(tmp_path / "store.db")
    sql = SQLiteStore(db, "local")
    sql.initialize()
    memory = InMemorySignalProtocolStore(
        sql.get_identity_key_pair(), sql.get_local_registration_id()
    )
    stores = (sql, memory)
    remote = SignalProtocolAddress('quoted:"user@lid', 2)
    identity = KeyHelper.generate_identity_key_pair().public_key
    changed = KeyHelper.generate_identity_key_pair().public_key
    for s in stores:
        assert s.get_identity(remote) is None
        assert s.is_trusted_identity(remote, identity, Direction.SENDING)
        assert s.save_identity(remote, identity)
        assert not s.save_identity(remote, identity)
        assert not s.is_trusted_identity(remote, changed, Direction.RECEIVING)
        assert s.get_identity(remote) == identity
    pre = PreKeyRecord(0xFFFFFFFF, Curve.generate_key_pair())
    signed = KeyHelper.generate_signed_pre_key(sql.get_identity_key_pair(), 5)
    kem = KeyHelper.generate_kyber_pre_key(
        sql.get_identity_key_pair(), 6, key_type=KemKeyType.ML_KEM_512
    )
    for s in stores:
        s.store_pre_key(-1, pre)
        s.store_signed_pre_key(5, signed)
        s.store_kyber_pre_key(6, kem)
        assert s.load_pre_key(0xFFFFFFFF).serialize() == pre.serialize()
        assert s.load_signed_pre_key(5).serialize() == signed.serialize()
        assert s.load_kyber_pre_key(6).serialize() == kem.serialize()
        s.remove_pre_key(-1)
        s.remove_signed_pre_key(5)
        s.mark_kyber_pre_key_used(6)
        assert not s.contains_pre_key(-1)
        assert not s.contains_signed_pre_key(5)
        assert not s.contains_kyber_pre_key(6)
        with pytest.raises(InvalidKeyIdException):
            s.load_pre_key(0xFFFFFFFF)
    record = SessionRecord(profile=WHATSAPP)
    record.session_state.session_version = 3
    for s in stores:
        for d in (1, 2, 3):
            s.store_session(SignalProtocolAddress(remote.name, d), record)
        assert sorted(s.get_sub_device_sessions(remote.name)) == [2, 3]
        loaded = s.load_session(remote)
        loaded.session_state.session_version = 4
        assert s.load_session(remote).session_state.session_version == 3
        s.store_session(remote, loaded)
        assert s.load_session(remote).session_state.session_version == 4
        s.delete_session(remote)
        assert not s.contains_session(remote)
        s.delete_all_sessions(remote.name)
        assert s.get_sub_device_sessions(remote.name) == []


def test_group_bucket_account_sender_device_isolation_and_reload(tmp_path):
    path = tmp_path / "groups.db"
    db = Database(path)
    main = SQLiteStore(db, "me", bucket="ordinary")
    name = SenderKeyName("g@g.us", SignalProtocolAddress("alice@lid", 1))
    GroupSessionBuilder(main, profile=WHATSAPP).create(name)
    original = main.load_sender_key(name).serialize()
    for s, n in [
        (SQLiteStore(db, "other", bucket="ordinary"), name),
        (SQLiteStore(db, "me", bucket="special"), name),
        (main, SenderKeyName("other@g.us", name.sender)),
        (main, SenderKeyName(name.group_id, SignalProtocolAddress("alice@lid", 2))),
        (main, SenderKeyName(name.group_id, SignalProtocolAddress("alice@s.whatsapp.net", 1))),
    ]:
        assert s.load_sender_key(n).is_empty()
    loaded = main.load_sender_key(name)
    loaded.add_sender_key_state(
        123, 0, bytes(32), KeyHelper.generate_sender_signing_key().public_key
    )
    assert main.load_sender_key(name).serialize() == original
    db.close()
    reopened = SQLiteStore(Database(path), "me", bucket="ordinary")
    assert reopened.load_sender_key(name).serialize() == original


def test_deferred_commit_constraint_restores_outbox_chain_and_input(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    bb = bundle(b)
    c = a.store.db.connection
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY)")
    c.execute("CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)")
    c.execute(
        "CREATE TRIGGER fail_commit AFTER INSERT ON outbox BEGIN INSERT INTO child VALUES(99); END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        a.prepare_direct("bad", {b.address: payload.text("x")}, bundles={b.address: bb})
    assert not a.store.contains_session(b.address)
    assert a.store._get("prepared-request", "bad") is None
    assert c.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM child").fetchone()[0] == 0
    assert not c.in_transaction
    c.execute("DROP TRIGGER fail_commit")
    p = a.prepare_direct("bad", {b.address: payload.text("x")}, bundles={b.address: bb})[0]
    assert b.receive("ok", a.address, p) == payload.text("x")


def test_cached_group_does_not_bypass_bucket_selection(tmp_path):
    from signal_protocol.exceptions import NoSessionException

    from whatsapp_e2ee import Client

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    packets = a.prepare_group_delivery(
        "same-id", "G", payload.text("g"), [b.address], bundles={b.address: bundle(b)}
    )
    b.receive("same-id", a.address, packets[0], expected_group="G", content_slot="distribution")
    assert b.receive("same-id", a.address, packets[-1], expected_group="G") == payload.text("g")
    other = Client(SQLiteStore(b.store.db, b.store.owner, bucket="different"), b.address)
    with pytest.raises(NoSessionException):
        other.receive("same-id", a.address, packets[-1], expected_group="G")
