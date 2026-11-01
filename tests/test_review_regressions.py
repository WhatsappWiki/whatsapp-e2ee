"""Independent integration-review regressions; no transport or phone access."""

import pytest
from protocol_tree_node import Node
from test_client import bundle
from wire_helpers import endpoint

from whatsapp_e2ee import SQLiteStore, payload
from whatsapp_e2ee.transport import StanzaDelivery


@pytest.mark.parametrize("namespace", [{"scope": 1}, {"session_type": 1}, {"bucket": "wrong"}])
def test_review_wire_prepare_rejects_other_crypto_namespace(tmp_path, namespace):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_group_delivery(
        "g", "1000001@g.us", payload.text("body"), [b.address], bundles={b.address: bundle(b)}
    )
    wrong = SQLiteStore(a.store.db, a.store.owner, **namespace)
    with pytest.raises(ValueError):
        StanzaDelivery(wrong).prepare("g", "1000001@g.us")
    assert a.store._get("stanza-node", "g") is None


def test_review_existing_wire_dispatch_and_receipt_reject_other_namespace(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_direct("d", {b.address: payload.text("body")}, bundles={b.address: bundle(b)})
    StanzaDelivery(a.store).prepare("d", b.address.name)
    wrong = StanzaDelivery(SQLiteStore(a.store.db, a.store.owner, scope=1))
    with pytest.raises(ValueError):
        wrong.dispatch("d", lambda *_: pytest.fail("cross-namespace bytes were sent"))
    ack = Node("ack", attrs={"class": "message", "id": "d", "from": b.address.name})
    with pytest.raises(ValueError):
        wrong.apply_control("d", ack, authenticated_transport=True)
    assert a.store._get("stanza-state", "d")[0] == b"prepared"


def test_review_late_skdm_cannot_enable_ciphertext_replay_under_new_message_id(tmp_path):
    from signal_protocol.exceptions import InvalidMessageException
    from test_retry import advertised, incoming_retry
    from test_stanza_delivery import deliver

    from whatsapp_e2ee import Conflict
    from whatsapp_e2ee.retry import RetryManager
    from whatsapp_e2ee.stanza import message_node, receive_message

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    original = a.prepare_group_delivery(
        "original",
        "1000001@g.us",
        payload.text("once only"),
        [b.address],
        bundles={b.address: advertised(b)},
    )
    request = incoming_retry(b, bundle=advertised(b), group="1000001@g.us")
    retry = RetryManager(a).prepare(
        request, authenticated_transport=True, current_group_devices=[b.address]
    )
    wire = StanzaDelivery(a.store)
    retry_node = wire.codec.read(wire.prepare_retry(retry, request))
    receive_message(b, deliver(retry_node, a.address, group="1000001@g.us"), authenticated_transport=True)
    # Legitimate old distribution and original message arrive after the retry.
    receive_message(
        b,
        deliver(message_node("original", "1000001@g.us", original), a.address, group="1000001@g.us"),
        authenticated_transport=True,
    )
    before = len(b.pending_events())
    # Relabeling a previously accepted ciphertext must not become a new event
    # merely because the late SKDM installed an earlier state of the same key ID.
    replay = deliver(
        message_node("different-logical-id", "1000001@g.us", [retry.packets[-1]]),
        a.address,
        group="1000001@g.us",
    )
    with pytest.raises((Conflict, InvalidMessageException)):
        receive_message(b, replay, authenticated_transport=True)
    assert len(b.pending_events()) == before


def test_review_direct_session_shared_across_group_bucket_views(tmp_path):
    from test_stanza_delivery import deliver

    from whatsapp_e2ee.stanza import attributes, receive_message

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_direct(
        "d", {b.address: payload.text("shared session")}, bundles={b.address: bundle(b)}
    )
    alternate = SQLiteStore(a.store.db, a.store.owner, bucket="group-only-view")
    transport = StanzaDelivery(alternate)
    wire = transport.prepare("d", b.address.name)
    node = transport.codec.read(wire)
    assert "bucket" not in attributes(node.children[0].children[0].children[0])
    assert receive_message(b, deliver(node, a.address), authenticated_transport=True)[1] == (
        payload.text("shared session"),
    )
    assert StanzaDelivery(a.store).prepare("d", b.address.name) == wire


def test_review_authenticated_changed_group_retry_rolls_back_new_distribution(tmp_path):
    from signal_protocol.groups import SenderKeyName
    from test_stanza_delivery import deliver

    from whatsapp_e2ee import Conflict
    from whatsapp_e2ee.stanza import message_node, receive_message

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    original = a.prepare_group_delivery(
        "original", "1000001@g.us", payload.text("immutable"), [b.address], bundles={b.address: bundle(b)}
    )
    receive_message(
        b,
        deliver(message_node("original", "1000001@g.us", original), a.address, group="1000001@g.us"),
        authenticated_transport=True,
    )
    sender_key_name = SenderKeyName("1000001@g.us", a.address)
    sender_state = b.store.load_sender_key(sender_key_name).serialize()
    session_state = b.store.load_session(a.address).serialize()
    events = tuple(b.pending_events())
    new = a.prepare_group_delivery(
        "changed-retry",
        "1000001@g.us",
        payload.text("changed"),
        [b.address],
        force_distribution=[b.address],
    )
    bad = deliver(
        message_node("original", "1000001@g.us", new, enc_attributes={"count": "1"}),
        a.address,
        group="1000001@g.us",
    )
    with pytest.raises(Conflict):
        receive_message(b, bad, authenticated_transport=True)
    assert b.store.load_sender_key(sender_key_name).serialize() == sender_state
    assert b.store.load_session(a.address).serialize() == session_state
    assert tuple(b.pending_events()) == events
    # The rejected distribution's pairwise ciphertext remains usable because
    # none of its chain advancement or attempt markers escaped the transaction.
    valid_content = a.prepare_group("valid-after-failure", "1000001@g.us", payload.text("immutable"))[0]
    good = deliver(
        message_node("original", "1000001@g.us", [new[0], valid_content], enc_attributes={"count": "1"}),
        a.address,
        group="1000001@g.us",
    )
    receive_message(b, good, authenticated_transport=True)
    assert tuple(b.pending_events()) == events


def test_retry_helper_binds_destination_and_participant(tmp_path):
    from test_retry import advertised, incoming_retry

    from whatsapp_e2ee.retry import RetryManager

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_group_delivery(
        "original", "1000001@g.us", payload.text("body"), [b.address], bundles={b.address: advertised(b)}
    )
    request = incoming_retry(b, bundle=advertised(b), group="1000001@g.us")
    attempt = RetryManager(a).prepare(
        request, authenticated_transport=True, current_group_devices=[b.address]
    )
    queue = StanzaDelivery(a.store)
    with pytest.raises(ValueError, match="participant"):
        queue.prepare_retry(attempt, request, participant="someone-else:1@s.whatsapp.net")
    with pytest.raises(ValueError, match="destination"):
        queue.prepare_retry(attempt, request, destination="1000002@g.us")
    assert a.store._get("stanza-node", attempt.attempt_id) is None
    assert queue.prepare_retry(attempt, request)
