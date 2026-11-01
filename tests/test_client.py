import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from signal_protocol import (
    WHATSAPP,
    Curve,
    KemKeyType,
    KeyHelper,
    PreKeyBundle,
    PreKeyRecord,
    PreKeySignalMessage,
    SignalProtocolAddress,
)
from signal_protocol.exceptions import InvalidMessageException

from whatsapp_e2ee import Client, Conflict, Database, SQLiteStore, payload


def endpoint(path, name):
    db = Database(path)
    store = SQLiteStore(db, name)
    store.initialize()
    return Client(store, SignalProtocolAddress(name + "@s.whatsapp.net", 1))


def bundle(client, kem=None):
    s = client.store
    pre = PreKeyRecord(7, Curve.generate_key_pair())
    signed = KeyHelper.generate_signed_pre_key(s.get_identity_key_pair(), 8)
    s.store_pre_key(7, pre)
    s.store_signed_pre_key(8, signed)
    kwargs = {}
    if kem:
        k = KeyHelper.generate_kyber_pre_key(s.get_identity_key_pair(), 9, key_type=kem)
        s.store_kyber_pre_key(9, k)
        kwargs = dict(
            kyber_pre_key_id=9,
            kyber_pre_key=k.key_pair.public_key,
            kyber_pre_key_signature=k.signature,
        )
    return PreKeyBundle(
        s.get_local_registration_id(),
        client.address.device_id,
        7,
        pre.key_pair.public_key,
        8,
        signed.key_pair.public_key,
        signed.signature,
        s.get_identity_key_pair().public_key,
        **kwargs,
    )


@pytest.mark.parametrize(
    "kem", [None, KemKeyType.ML_KEM_512, KemKeyType.ML_KEM_768, KemKeyType.ML_KEM_1024]
)
def test_direct_restart_pending_and_reply(tmp_path, kem):
    a = endpoint(tmp_path / "a.db", "a")
    b = endpoint(tmp_path / "b.db", "b")
    bb = bundle(b, kem)
    packets = [
        a.prepare_direct(str(i), {b.address: payload.text(str(i))}, bundles={b.address: bb})[0]
        for i in range(3)
    ]
    assert all(p.kind == "pkmsg" for p in packets)
    for i in (2, 0, 1):
        assert payload.parse(b.receive(str(i), a.address, packets[i])).conversation == str(i)
    assert len(b.pending_events()) == 3
    assert b.receive("0", a.address, packets[0]) == payload.text("0")
    assert len(b.pending_events()) == 3
    reply = b.prepare_direct("reply", {a.address: payload.text("你好🌍")})[0]
    a.receive("reply", b.address, reply)
    assert not b.store.contains_pre_key(7)
    if kem:
        assert not b.store.contains_kyber_pre_key(9)
    identity = a.store.get_identity_key_pair().serialize()
    a.store.db.close()
    a = endpoint(tmp_path / "a.db", "a")
    assert a.store.get_identity_key_pair().serialize() == identity
    p = a.prepare_direct("next", {b.address: payload.text("after restart")})[0]
    assert p.kind == "msg"
    assert b.receive("next", a.address, p) == payload.text("after restart")
    assert a.prepare_direct("next", {b.address: payload.text("after restart")})[0] == p
    with pytest.raises(Conflict):
        a.prepare_direct("next", {b.address: payload.text("different")})


def test_failed_receive_rolls_back_and_original_works(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    b = endpoint(tmp_path / "b.db", "b")
    p = a.prepare_direct("x", {b.address: payload.text("x")}, bundles={b.address: bundle(b)})[0]
    inner = PreKeySignalMessage.from_bytes(p.ciphertext, profile=WHATSAPP).message.serialize()
    pos = p.ciphertext.index(inner) + len(inner) - 1
    damaged = bytearray(p.ciphertext)
    damaged[pos] ^= 1
    bad = replace(p, ciphertext=bytes(damaged))
    with pytest.raises(InvalidMessageException):
        b.receive("x", a.address, bad)
    assert not b.store.contains_session(a.address)
    assert b.store.contains_pre_key(7)
    assert not b.pending_events()
    assert b.receive("x", a.address, p) == payload.text("x")


def test_sql_failure_atomicity(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    b = endpoint(tmp_path / "b.db", "b")
    bb = bundle(b)
    with a.store.db.atomic() as c:
        c.execute(
            "CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        a.prepare_direct("x", {b.address: payload.text("x")}, bundles={b.address: bb})
    assert not a.store.contains_session(b.address)
    with a.store.db.atomic() as c:
        c.execute("DROP TRIGGER fail_outbox")
    p = a.prepare_direct("x", {b.address: payload.text("x")}, bundles={b.address: bb})[0]
    with b.store.db.atomic() as c:
        c.execute(
            "CREATE TRIGGER fail_inbox BEFORE INSERT ON inbox BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        b.receive("x", a.address, p)
    assert b.store.contains_pre_key(7)
    assert not b.store.contains_session(a.address)
    with b.store.db.atomic() as c:
        c.execute("DROP TRIGGER fail_inbox")
    assert b.receive("x", a.address, p) == payload.text("x")


def test_group_distribution_multiple_senders_rotation(tmp_path):
    a, b, c = [endpoint(tmp_path / (n + ".db"), n) for n in "abc"]
    for sender, receivers in ((a, (b, c)), (b, (a, c))):
        d = sender.distribution_payload("G")
        packets = sender.prepare_direct(
            "dist",
            {r.address: d for r in receivers},
            bundles={r.address: bundle(r) for r in receivers},
        )
        for r, p in zip(sorted(receivers, key=lambda x: x.address.name), packets):
            r.receive(sender.address.name + "dist", sender.address, p, expected_group="G")
        msgs = [sender.prepare_group(str(i), "G", payload.text(str(i)))[0] for i in range(3)]
        for r in receivers:
            for i in (2, 0, 1):
                assert r.receive(
                    sender.address.name + str(i),
                    sender.address,
                    msgs[i],
                    expected_group="G",
                ) == payload.text(str(i))
    d = a.rotate_group("G")
    p = a.prepare_group("rotated", "G", payload.text("new"))[0]
    with pytest.raises(InvalidMessageException):
        b.receive("rotated", a.address, p, expected_group="G")
    dp = a.prepare_direct("new-dist", {b.address: d})[0]
    b.receive("new-dist", a.address, dp, expected_group="G")
    assert b.receive("rotated", a.address, p, expected_group="G") == payload.text("new")


def test_group_binding_rollback(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    b = endpoint(tmp_path / "b.db", "b")
    d = a.distribution_payload("G")
    p = a.prepare_direct("d", {b.address: d}, bundles={b.address: bundle(b)})[0]
    with pytest.raises(ValueError):
        b.receive("d", a.address, p, expected_group="wrong")
    assert not b.store.contains_session(a.address)
    b.receive("d", a.address, p, expected_group="G")


def test_concurrent_prepare_and_fanout_rollback(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    b = endpoint(tmp_path / "b.db", "b")
    c = endpoint(tmp_path / "c.db", "c")
    bb = bundle(b)
    with pytest.raises(ValueError):
        a.prepare_direct(
            "all",
            {b.address: payload.text("b"), c.address: payload.text("c")},
            bundles={b.address: bb},
        )
    assert not a.store.contains_session(b.address)
    with ThreadPoolExecutor(4) as executor:
        packets = list(
            executor.map(
                lambda i: a.prepare_direct(
                    str(i), {b.address: payload.text(str(i))}, bundles={b.address: bb}
                )[0],
                range(12),
            )
        )
    for i in reversed(range(12)):
        assert b.receive(str(i), a.address, packets[i]) == payload.text(str(i))
    assert len({p.ciphertext for p in packets}) == 12


def test_store_namespace_and_isolation(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    b = endpoint(tmp_path / "b.db", "b")
    a.prepare_direct("x", {b.address: payload.text("x")}, bundles={b.address: bundle(b)})
    other = SQLiteStore(a.store.db, "a", scope=1)
    assert not other.contains_session(b.address)
    record = a.store.load_session(b.address)
    original = record.serialize()
    record.archive_current_state()
    assert a.store.load_session(b.address).serialize() == original
    other.store_session(b.address, record)
    other.delete_all_sessions(b.address.name)
    assert a.store.contains_session(b.address)


def test_atomic_group_delivery_and_member_addition(tmp_path):
    a, b, c = [endpoint(tmp_path / (n + ".db"), n) for n in "abc"]
    p = a.prepare_group_delivery(
        "g0", "G", payload.text("zero"), [b.address], bundles={b.address: bundle(b)}
    )
    assert [x.kind for x in p] == ["pkmsg", "skmsg"]
    b.receive("distribution0", a.address, p[0], expected_group="G")
    assert b.receive("g0", a.address, p[-1], expected_group="G") == payload.text("zero")
    assert a.prepare_group_delivery("g0", "G", payload.text("zero"), [b.address]) == p
    p = a.prepare_group_delivery(
        "g1",
        "G",
        payload.text("one"),
        [b.address, c.address],
        bundles={c.address: bundle(c)},
    )
    assert len(p) == 2 and p[0].recipient == c.address.name
    c.receive("distribution1", a.address, p[0], expected_group="G")
    for r in (b, c):
        assert r.receive("g1", a.address, p[-1], expected_group="G") == payload.text("one")


def test_media_descriptor_direct_and_group(tmp_path):
    from whatsapp_e2ee import media

    a = endpoint(tmp_path / "a.db", "a")
    b = endpoint(tmp_path / "b.db", "b")
    value = media.encrypt(b"file payload", "document")
    repository = media.MediaStore(a.store)
    repository.save("file", value)
    assert repository.load("file") == value
    raw = payload.media_message(value, "/synthetic/path", 1234567)
    p = a.prepare_direct("file", {b.address: raw}, bundles={b.address: bundle(b)})[0]
    d = payload.parse(b.receive("file", a.address, p)).document_message
    assert d.media_key == value.media_key and d.media_key_timestamp == 1234
    assert (
        media.decrypt(
            value.blob,
            d.media_key,
            "document",
            plaintext_hash=d.file_sha256,
            encrypted_hash=d.file_enc_sha256,
            length=d.file_length,
        )
        == b"file payload"
    )


def test_stanza_codec_roundtrip():
    from protocol_tree_node import Codec, TokenDictionary

    from whatsapp_e2ee import Packet
    from whatsapp_e2ee.stanza import enc_node, parse_enc

    codec = Codec(TokenDictionary.bundled())
    p = Packet("b@s.whatsapp.net", 1, "pkmsg", b"\x33\x00\xff")
    assert parse_enc(codec.read(codec.write(enc_node(p))), recipient=p.recipient, device=1) == p


def test_multidevice_and_device_sent(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    devices = []
    for device in (2, 3):
        store = SQLiteStore(Database(tmp_path / f"b{device}.db"), f"b-device-{device}")
        store.initialize()
        devices.append(Client(store, SignalProtocolAddress(a.address.name, device)))
    target = {
        b.address: payload.device_sent("destination@s.whatsapp.net", payload.text("sync"))
        for b in devices
    }
    packets = a.prepare_direct("multi", target, bundles={b.address: bundle(b) for b in devices})
    for b, p in zip(devices, packets):
        m = payload.parse(
            b.receive(
                "multi",
                a.address,
                p,
                own_device=True,
                expected_destination="destination@s.whatsapp.net",
            )
        )
        assert m.device_sent_message.message.conversation == "sync"
        assert m.device_sent_message.destination_jid == "destination@s.whatsapp.net"
    with pytest.raises(ValueError):
        Client(a.store, SignalProtocolAddress(a.address.name, 2))
