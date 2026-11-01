from dataclasses import replace

import pytest
from protocol_tree_node import Node
from signal_protocol import KemKeyType
from signal_protocol.exceptions import UntrustedIdentityException
from test_stanza_delivery import deliver
from wire_helpers import endpoint

from whatsapp_e2ee import Conflict, payload
from whatsapp_e2ee.delivery import Delivery
from whatsapp_e2ee.prekeys import PreKeys
from whatsapp_e2ee.retry import RetryManager, parse_retry, retry_receipt
from whatsapp_e2ee.stanza import attributes, message_node, receive_message
from whatsapp_e2ee.transport import StanzaDelivery


def advertised(client, kem=None):
    p = PreKeys(client)
    if client.store._get("key-active", "signed") is None:
        p.rotate_signed()
    opk = p.generate(1)[0]
    kid = p.generate_kem(kem) if kem else None
    return p.bundle(pre_key_id=opk, kem_id=kid)


def incoming_retry(client, id="original", *, count=1, bundle=None, group=None, stamp=123):
    out = retry_receipt(
        id,
        "15550001:1@s.whatsapp.net",
        count=count,
        registration_id=client.store.get_local_registration_id(),
        timestamp=stamp,
        error=0,
        bundle=bundle,
        participant=client.address.name if group else None,
    )
    attrs = attributes(out)
    attrs.pop("to")
    attrs["from"] = group or client.address.name.replace("@", f":{client.address.device_id}@")
    if group:
        attrs["participant"] = client.address.name.replace("@", f":{client.address.device_id}@")
    return parse_retry(replace(out, attrs=attrs))


@pytest.mark.parametrize(
    "kem", [None, KemKeyType.ML_KEM_512, KemKeyType.ML_KEM_768, KemKeyType.ML_KEM_1024]
)
def test_retry_new_attempt_with_valid_bundle_and_restart(tmp_path, kem):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    original = a.prepare_direct(
        "original", {b.address: payload.text("hello")}, bundles={b.address: advertised(b, kem)}
    )
    request = incoming_retry(b, bundle=advertised(b, kem))
    assert request.bundle.kyber_pre_key is not None if kem else request.bundle.kyber_pre_key is None
    attempt = RetryManager(a).prepare(request, authenticated_transport=True)
    assert attempt.packets[0].ciphertext != original[0].ciphertext
    assert b.receive("original", a.address, attempt.packets[0]) == payload.text("hello")
    assert Delivery(a.store).prepared("original") == original
    wire = StanzaDelivery(a.store)
    raw = wire.prepare(
        attempt.attempt_id, b.address.name, wire_id="original", enc_attributes={"count": "1"}
    )
    assert attributes(wire.codec.read(raw))["id"] == "original"
    a.store.db.close()
    a = endpoint(tmp_path / "a.db", "a")
    assert RetryManager(a).prepare(request, authenticated_transport=True) == attempt
    with pytest.raises(Conflict):
        RetryManager(a).prepare(
            incoming_retry(b, stamp=999, bundle=request.bundle), authenticated_transport=True
        )


def test_retry_registration_change_identity_guard_and_budget(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_direct(
        "original", {b.address: payload.text("hello")}, bundles={b.address: advertised(b)}
    )
    b.store._put("local", "registration", b"12345")
    with pytest.raises(ValueError, match="Changed registration"):
        RetryManager(a).prepare(incoming_retry(b), authenticated_transport=True)
    valid = incoming_retry(b, bundle=advertised(b))
    attempt = RetryManager(a).prepare(valid, authenticated_transport=True)
    assert b.receive("original", a.address, attempt.packets[0]) == payload.text("hello")
    with pytest.raises(ValueError, match="budget"):
        RetryManager(a, max_attempts=1).prepare(
            incoming_retry(b, count=2), authenticated_transport=True
        )
    impostor = endpoint(tmp_path / "impostor.db", "b")
    bad = incoming_retry(impostor, count=2, bundle=advertised(impostor))
    before = a.store.load_session(b.address).serialize()
    with pytest.raises(UntrustedIdentityException):
        RetryManager(a).prepare(bad, authenticated_transport=True)
    assert a.store.load_session(b.address).serialize() == before
    with pytest.raises(ValueError, match="authenticated"):
        RetryManager(a).prepare(valid, authenticated_transport=False)


def test_group_retry_force_distribution_current_recipient_only(tmp_path):
    a, b, c = [endpoint(tmp_path / (n + ".db"), n) for n in "abc"]
    original = a.prepare_group_delivery(
        "original",
        "1000001@g.us",
        payload.text("hello group"),
        [b.address],
        bundles={b.address: advertised(b)},
    )
    request = incoming_retry(b, bundle=advertised(b), group="1000001@g.us")
    manager = RetryManager(a)
    with pytest.raises(ValueError):
        manager.prepare(request, authenticated_transport=True, current_group_devices=[c.address])
    attempt = manager.prepare(
        request, authenticated_transport=True, current_group_devices=[b.address]
    )
    assert len(attempt.packets) == 2
    assert attempt.packets[-1].ciphertext != original[-1].ciphertext
    incoming = deliver(
        message_node("original", "1000001@g.us", attempt.packets), a.address, group="1000001@g.us"
    )
    assert receive_message(b, incoming, authenticated_transport=True)[1][-1] == payload.text(
        "hello group"
    )
    # A newly added member cannot demand old payloads merely by forging a retry.
    with pytest.raises(ValueError, match="original"):
        manager.prepare(
            incoming_retry(c, bundle=advertised(c), group="1000001@g.us"),
            authenticated_transport=True,
            current_group_devices=[b.address, c.address],
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "registration_short",
        "identity_short",
        "pq_incomplete",
        "duplicate_retry",
        "mismatched_id",
        "zero_count",
        "wrong_version",
    ],
)
def test_malformed_retry_rejected(tmp_path, mutation):
    b = endpoint(tmp_path / "b.db", "b")
    n = incoming_retry(b, bundle=advertised(b, KemKeyType.ML_KEM_512)).raw_node
    nodes = list(n.children)
    if mutation == "registration_short":
        nodes[1] = Node("registration", data=b"\x01")
    elif mutation in ("identity_short", "pq_incomplete"):
        keys = list(nodes[2].children)
        if mutation == "identity_short":
            keys[0] = Node("identity", data=b"x")
        else:
            pq = keys[-1]
            keys[-1] = replace(pq, children=pq.children[:-1])
        nodes[2] = replace(nodes[2], children=keys)
    elif mutation == "duplicate_retry":
        nodes.append(nodes[0])
    else:
        a = attributes(nodes[0])
        a.update(
            {
                "mismatched_id": {"id": "other"},
                "zero_count": {"count": "0"},
                "wrong_version": {"v": "2"},
            }[mutation]
        )
        nodes[0] = replace(nodes[0], attrs=a)
    with pytest.raises(ValueError):
        parse_retry(replace(n, children=nodes))


def test_received_original_then_protocol_retry_updates_chain_once(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    first = a.prepare_direct(
        "original", {b.address: payload.text("same body")}, bundles={b.address: advertised(b)}
    )
    receive_message(
        b,
        deliver(message_node("original", b.address.name, first), a.address),
        authenticated_transport=True,
    )
    assert len(b.pending_events()) == 1
    request = incoming_retry(b, bundle=advertised(b))
    attempt = RetryManager(a).prepare(request, authenticated_transport=True)
    transport = StanzaDelivery(a.store)
    wire = transport.prepare_retry(attempt, request)
    incoming = deliver(transport.codec.read(wire), a.address)
    assert receive_message(b, incoming, authenticated_transport=True)[1] == (
        payload.text("same body"),
    )
    after = b.store.load_session(a.address).serialize()
    assert len(b.pending_events()) == 1
    receive_message(b, incoming, authenticated_transport=True)
    assert b.store.load_session(a.address).serialize() == after
    assert len(b.pending_events()) == 1
    changed = a.prepare_direct("new-local-attempt", {b.address: payload.text("same body")})
    conflicting = deliver(
        message_node("original", b.address.name, changed, enc_attributes={"count": "1"}), a.address
    )
    with pytest.raises(Conflict):
        receive_message(b, conflicting, authenticated_transport=True)
    assert b.store.load_session(a.address).serialize() == after


def test_retry_sql_failure_rolls_back_new_session_and_attempt(tmp_path):
    import sqlite3

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_direct(
        "original", {b.address: payload.text("hello")}, bundles={b.address: advertised(b)}
    )
    request = incoming_retry(b, bundle=advertised(b))
    before = a.store.load_session(b.address).serialize()
    with a.store.db.atomic() as c:
        c.execute(
            "CREATE TRIGGER fail_retry BEFORE INSERT ON records WHEN NEW.kind='retry-attempt' BEGIN SELECT RAISE(ABORT,'fail'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        RetryManager(a).prepare(request, authenticated_transport=True)
    assert a.store.load_session(b.address).serialize() == before
    with a.store.db.atomic() as c:
        assert c.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1
        c.execute("DROP TRIGGER fail_retry")
    assert RetryManager(a).prepare(request, authenticated_transport=True).count == 1


def test_retry_arrives_first_original_late_and_changed_body_rejected(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    first = a.prepare_direct(
        "original", {b.address: payload.text("same")}, bundles={b.address: advertised(b)}
    )
    request = incoming_retry(b, bundle=advertised(b))
    attempt = RetryManager(a).prepare(request, authenticated_transport=True)
    wire = StanzaDelivery(a.store)
    retry_node = wire.codec.read(wire.prepare_retry(attempt, request))
    receive_message(b, deliver(retry_node, a.address), authenticated_transport=True)
    receive_message(
        b,
        deliver(message_node("original", b.address.name, first), a.address),
        authenticated_transport=True,
    )
    assert len(b.pending_events()) == 1
    changed = a.prepare_direct("malicious-body", {b.address: payload.text("different")})
    message = deliver(
        message_node("original", b.address.name, changed, enc_attributes={"count": "2"}), a.address
    )
    before = b.store.load_session(a.address).serialize()
    with pytest.raises(Conflict):
        receive_message(b, message, authenticated_transport=True)
    assert b.store.load_session(a.address).serialize() == before
    assert len(b.pending_events()) == 1


def test_cached_group_retry_rechecks_current_membership(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_group_delivery(
        "original", "1000001@g.us", payload.text("hello"), [b.address], bundles={b.address: advertised(b)}
    )
    request = incoming_retry(b, group="1000001@g.us", bundle=advertised(b))
    manager = RetryManager(a)
    manager.prepare(request, authenticated_transport=True, current_group_devices=[b.address])
    with pytest.raises(ValueError, match="current"):
        manager.prepare(request, authenticated_transport=True, current_group_devices=[])
