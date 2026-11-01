"""Prekey retirement, explicit identity changes and durable message identities."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from signal_protocol import Curve, KemKeyType, KeyHelper, PreKeyRecord
from signal_protocol.exceptions import InvalidKeyException, UntrustedIdentityException
from test_retry import advertised, incoming_retry
from wire_helpers import endpoint

from whatsapp_e2ee import payload
from whatsapp_e2ee.prekeys import PreKeys
from whatsapp_e2ee.retry import RetryManager


@pytest.fixture
def clients(tmp_path):
    opened = []

    def create(name, filename=None):
        client = endpoint(tmp_path / ((filename or name) + ".db"), name)
        opened.append(client)
        return client

    yield create
    for client in opened:
        client.store.db.close()


def establish(a, b, kem=None):
    first = a.prepare_direct(
        "original", {b.address: payload.text("body")}, bundles={b.address: advertised(b, kem)}
    )[0]
    assert b.receive("original", a.address, first) == payload.text("body")
    reply = b.prepare_direct("reply", {a.address: payload.text("reply")})[0]
    assert a.receive("reply", b.address, reply) == payload.text("reply")
    return first


@pytest.mark.parametrize("kind", ["pre", "signed", "kem"])
def test_allocator_does_not_reuse_retired_imported_id_after_restart(clients, kind):
    b = clients("b")
    identity = b.store.get_identity_key_pair()
    if kind == "pre":
        b.store.store_pre_key(1, PreKeyRecord(1, Curve.generate_key_pair()))
        b.store.remove_pre_key(1)
    elif kind == "signed":
        b.store.store_signed_pre_key(1, KeyHelper.generate_signed_pre_key(identity, 1))
        b.store.remove_signed_pre_key(1)
    else:
        b.store.store_kyber_pre_key(
            1, KeyHelper.generate_kyber_pre_key(identity, 1, key_type=KemKeyType.ML_KEM_512)
        )
        b.store.mark_kyber_pre_key_used(1)
    b.store.db.close()
    b = clients("b")
    keys = PreKeys(b)
    if kind == "pre":
        allocated = keys.generate(1)[0]
    elif kind == "signed":
        allocated = keys.rotate_signed()
    else:
        allocated = keys.generate_kem(KemKeyType.ML_KEM_512)
    assert allocated != 1, "A retired imported ID was silently assigned new key material"


@pytest.mark.parametrize("cursor", [b"-1", b"0", b"not-a-number"])
def test_invalid_allocator_cursor_fails_without_new_material(clients, cursor):
    b = clients("b")
    b.store._put("key-next", "pre", cursor)
    with pytest.raises(ValueError):
        PreKeys(b).generate(1)
    assert b.store._get("key-next", "pre")[0] == cursor
    assert (
        b.store.db.connection.execute("SELECT count(*) FROM records WHERE kind='pre'").fetchone()[0]
        == 0
    )


def test_retirement_rolls_back_with_failed_receive(clients):
    a, b = clients("a"), clients("b")
    public = advertised(b, KemKeyType.ML_KEM_512)
    packet = a.prepare_direct("x", {b.address: payload.text("x")}, bundles={b.address: public})[0]
    # Fail after both key removals; the enclosing receive must restore inventory
    # and any retirement metadata before an identical ciphertext is retried.
    b.store.db.connection.execute(
        "CREATE TRIGGER fail_kem AFTER DELETE ON records WHEN OLD.kind='kem' "
        "BEGIN SELECT RAISE(ABORT,'late consumption failure'); END"
    )
    before = b.store.db.connection.execute(
        "SELECT * FROM records ORDER BY kind,space,id"
    ).fetchall()
    with pytest.raises(sqlite3.IntegrityError, match="late consumption"):
        b.receive("x", a.address, packet)
    assert (
        b.store.db.connection.execute("SELECT * FROM records ORDER BY kind,space,id").fetchall()
        == before
    )
    assert not b.pending_events()
    b.store.db.connection.execute("DROP TRIGGER fail_kem")
    assert b.receive("x", a.address, packet) == payload.text("x")
    # A recovered allocator cursor must still skip consumed IDs.
    b.store._put("key-next", "pre", str(public.pre_key_id).encode())
    b.store._put("key-next", "kem", str(public.kyber_pre_key_id).encode())
    assert PreKeys(b).generate(1)[0] != public.pre_key_id
    assert PreKeys(b).generate_kem(KemKeyType.ML_KEM_512) != public.kyber_pre_key_id


def test_prekey_batch_failure_and_two_connection_allocation(clients):
    b, other = clients("b"), clients("b")
    b.store.db.connection.execute(
        "CREATE TRIGGER fail_batch BEFORE INSERT ON records WHEN NEW.kind='pre' AND NEW.id='2' "
        "BEGIN SELECT RAISE(ABORT,'second key'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="second key"):
        PreKeys(b).generate(3)
    assert b.store._get("key-next", "pre") is None
    assert not b.store.contains_pre_key(1)
    b.store.db.connection.execute("DROP TRIGGER fail_batch")
    barrier = Barrier(2)

    def allocate(client):
        barrier.wait(timeout=5)
        return PreKeys(client).generate(3)

    with ThreadPoolExecutor(2) as executor:
        futures = [executor.submit(allocate, client) for client in (b, other)]
        ids = [id for future in futures for id in future.result(timeout=10)]
    assert sorted(ids) == list(range(1, 7))
    assert len({b.store.load_pre_key(id).key_pair.public_key.serialize() for id in ids}) == 6


def test_last_resort_keys_remain_usable_by_distinct_senders(clients):
    a, b, c = clients("a"), clients("b"), clients("c")
    keys = PreKeys(b)
    keys.rotate_signed()
    b.store.store_pre_key(0xFFFFFF, PreKeyRecord(0xFFFFFF, Curve.generate_key_pair()))
    kem = keys.generate_kem(KemKeyType.ML_KEM_512, last_resort=True)
    public = keys.bundle(pre_key_id=0xFFFFFF, kem_id=kem)
    for sender in (a, c):
        packet = sender.prepare_direct(
            "same-id", {b.address: payload.text(sender.address.name)}, bundles={b.address: public}
        )[0]
        assert b.receive("same-id", sender.address, packet) == payload.text(sender.address.name)
        assert b.receive("same-id", sender.address, packet) == payload.text(sender.address.name)
        assert b.store.contains_pre_key(0xFFFFFF) and b.store.contains_kyber_pre_key(kem)
    assert len(b.pending_events()) == 2  # Logical IDs are scoped to the sender device.


@pytest.mark.parametrize("kind", ["signed", "kem"])
def test_bundle_rejects_signature_from_previous_local_identity(clients, kind):
    b, replacement = clients("b"), clients("b", "replacement")
    keys = PreKeys(b)
    keys.rotate_signed()
    kem = keys.generate_kem(KemKeyType.ML_KEM_512)
    b.store._put("local", "identity", replacement.store.get_identity_key_pair().serialize())
    if kind == "kem":
        keys.rotate_signed()  # Current SPK is valid; the old KEM must also be checked.
    with pytest.raises(ValueError, match="signature"):
        keys.bundle(kem_id=kem if kind == "kem" else None)
    # Explicit rotation under the new identity restores export without deleting
    # the old records which may still be required for in-flight handshakes.
    keys.rotate_signed()
    kem = keys.generate_kem(KemKeyType.ML_KEM_512)
    valid = keys.bundle(kem_id=kem)
    assert valid.identity_key == replacement.store.get_identity_key_pair().public_key


@pytest.mark.parametrize("kind", ["pre", "signed", "kem"])
def test_bundle_rejects_record_id_different_from_storage_slot(clients, kind):
    b = clients("b")
    keys = PreKeys(b)
    signed = keys.rotate_signed()
    pre = keys.generate(1)[0]
    kem = keys.generate_kem(KemKeyType.ML_KEM_512)
    identity = b.store.get_identity_key_pair()
    if kind == "pre":
        b.store.store_pre_key(pre, PreKeyRecord(99, Curve.generate_key_pair()))
    elif kind == "signed":
        b.store.store_signed_pre_key(signed, KeyHelper.generate_signed_pre_key(identity, 99))
    else:
        b.store.store_kyber_pre_key(
            kem, KeyHelper.generate_kyber_pre_key(identity, 99, key_type=KemKeyType.ML_KEM_512)
        )
    with pytest.raises(ValueError, match="ID"):
        keys.bundle(pre_key_id=pre, kem_id=kem)


@pytest.mark.parametrize("changed", ["local", "remote"])
@pytest.mark.parametrize("operation", ["send", "receive"])
def test_changed_identity_rejects_new_work_on_old_session(clients, changed, operation):
    a, b = clients("a"), clients("b")
    establish(a, b)
    late = a.prepare_direct("late", {b.address: payload.text("late")})[0]
    replacement = clients("b", "replacement")
    if changed == "local":
        b.store._put("local", "identity", replacement.store.get_identity_key_pair().serialize())
    else:
        b.store.save_identity(a.address, replacement.store.get_identity_key_pair().public_key)
    state = b.store.load_session(a.address).serialize()
    events = b.pending_events()
    expected = InvalidKeyException if changed == "local" else UntrustedIdentityException
    with pytest.raises(expected):
        if operation == "send":
            b.prepare_direct("blocked", {a.address: payload.text("blocked")})
        else:
            b.receive("late", a.address, late)
    assert b.store.load_session(a.address).serialize() == state
    assert b.pending_events() == events
    assert b.store._get("prepared-request", "blocked") is None


def test_explicit_identity_replacement_blocks_archived_old_peer_after_restart(clients):
    a, b = clients("a"), clients("b")
    first = establish(a, b)
    late = a.prepare_direct("late", {b.address: payload.text("old identity")})[0]
    replacement = clients("a", "replacement")
    b.store.save_identity(a.address, replacement.store.get_identity_key_pair().public_key)
    public = advertised(b)
    fresh = replacement.prepare_direct(
        "fresh", {b.address: payload.text("new identity")}, bundles={b.address: public}
    )[0]
    assert b.receive("fresh", replacement.address, fresh) == payload.text("new identity")
    b.store.db.close()
    b = clients("b")
    state = b.store.load_session(a.address).serialize()
    assert b.store.load_session(a.address).previous_states
    with pytest.raises(UntrustedIdentityException):
        b.receive("late", a.address, late)
    assert b.store.load_session(a.address).serialize() == state
    assert len(b.pending_events()) == 2
    # A historical duplicate reads accepted plaintext and creates no new event
    # or chain advancement, even after the trusted identity has changed.
    assert b.receive("original", a.address, first) == payload.text("body")
    assert b.store.load_session(a.address).serialize() == state
    followup = b.prepare_direct("followup", {replacement.address: payload.text("new peer")})[0]
    assert replacement.receive("followup", b.address, followup) == payload.text("new peer")


@pytest.mark.parametrize("group", [False, True])
def test_identity_failure_rolls_back_earlier_fanout_recipients(clients, group):
    from signal_protocol.groups import SenderKeyName

    a, b, c = clients("a"), clients("b"), clients("c")
    a.prepare_direct(
        "initial", {c.address: payload.text("initial")}, bundles={c.address: advertised(c)}
    )
    before = a.store.load_session(c.address).serialize()
    replacement = clients("c", "replacement")
    a.store.save_identity(c.address, replacement.store.get_identity_key_pair().public_key)
    with pytest.raises(UntrustedIdentityException):
        if group:
            a.prepare_group_delivery(
                "blocked",
                "1000001@g.us",
                payload.text("group"),
                [b.address, c.address],
                bundles={b.address: advertised(b)},
            )
        else:
            a.prepare_direct(
                "blocked",
                {b.address: payload.text("b"), c.address: payload.text("c")},
                bundles={b.address: advertised(b)},
            )
    assert not a.store.contains_session(b.address)
    assert a.store.load_session(c.address).serialize() == before
    assert a.store.load_sender_key(SenderKeyName("1000001@g.us", a.address)).is_empty()
    assert a.store._get("prepared-request", "blocked") is None
    assert a.store.db.connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == 1


def test_old_identity_distribution_does_not_leave_sender_key_or_event(clients):
    from signal_protocol.groups import SenderKeyName

    a, b = clients("a"), clients("b")
    establish(a, b)
    group = "1000001@g.us"
    packet = a.prepare_direct("distribution", {b.address: a.distribution_payload(group)})[0]
    replacement = clients("a", "replacement")
    b.store.save_identity(a.address, replacement.store.get_identity_key_pair().public_key)
    state = b.store.load_session(a.address).serialize()
    with pytest.raises(UntrustedIdentityException):
        b.receive(
            "distribution", a.address, packet, expected_group=group, content_slot="distribution"
        )
    assert b.store.load_sender_key(SenderKeyName(group, a.address)).is_empty()
    assert b.store.load_session(a.address).serialize() == state
    assert len(b.pending_events()) == 1


@pytest.mark.parametrize("kem", [None, KemKeyType.ML_KEM_512])
def test_unapproved_prekey_identity_change_preserves_inventory_and_recovery(clients, kem):
    a, b = clients("a"), clients("b")
    establish(a, b, kem)
    replacement = clients("a", "replacement")
    public = advertised(b, kem)
    packet = replacement.prepare_direct(
        "changed", {b.address: payload.text("changed")}, bundles={b.address: public}
    )[0]
    state = b.store.load_session(a.address).serialize()
    with pytest.raises(UntrustedIdentityException):
        b.receive("changed", a.address, packet)
    assert b.store.contains_pre_key(public.pre_key_id)
    if kem:
        assert b.store.contains_kyber_pre_key(public.kyber_pre_key_id)
    assert b.store.load_session(a.address).serialize() == state
    assert len(b.pending_events()) == 1
    b.store.save_identity(a.address, replacement.store.get_identity_key_pair().public_key)
    assert b.receive("changed", a.address, packet) == payload.text("changed")
    assert len(b.pending_events()) == 2


@pytest.mark.parametrize("id", [None, "", 1, True])
def test_prepare_rejects_invalid_message_id_before_ratchet_advance(clients, id):
    a, b = clients("a"), clients("b")
    public = advertised(b)
    with pytest.raises(ValueError, match="message ID"):
        a.prepare_direct(id, {b.address: payload.text("x")}, bundles={b.address: public})
    assert not a.store.contains_session(b.address)
    assert a.store.db.connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == 0


@pytest.mark.parametrize("id", [None, "", 1, True])
def test_receive_rejects_invalid_message_id_without_consuming_prekey(clients, id):
    a, b = clients("a"), clients("b")
    public = advertised(b)
    packet = a.prepare_direct("valid", {b.address: payload.text("x")}, bundles={b.address: public})[
        0
    ]
    with pytest.raises(ValueError, match="message ID"):
        b.receive(id, a.address, packet)
    assert b.store.contains_pre_key(public.pre_key_id)
    assert not b.store.contains_session(a.address)
    assert not b.pending_events()
    assert b.receive("valid", a.address, packet) == payload.text("x")


def test_retry_duplicate_after_event_ack_and_restart_stays_single_delivery(clients):
    a, b = clients("a"), clients("b")
    first = establish(a, b)
    request = incoming_retry(b, bundle=advertised(b))
    retry = RetryManager(a).prepare(request, authenticated_transport=True)
    assert b.receive("original", a.address, retry.packets[0], retry_count=1) == payload.text("body")
    event = b.pending_events()[0]
    b.acknowledge_event(event[0])
    b.store.db.close()
    b = clients("b")
    state = b.store.load_session(a.address).serialize()
    for packet, count in ((first, 0), (retry.packets[0], 1)):
        assert b.receive("original", a.address, packet, retry_count=count) == payload.text("body")
    assert not b.pending_events()
    assert b.store.load_session(a.address).serialize() == state
    assert b.store.db.connection.execute("SELECT count(*) FROM events").fetchone()[0] == 1
