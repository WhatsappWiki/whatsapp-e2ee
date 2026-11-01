from dataclasses import replace

import pytest
from protocol_tree_node import Attribute, Codec, Node, TokenDictionary
from test_client import bundle
from wire_helpers import endpoint

from whatsapp_e2ee import Conflict, payload
from whatsapp_e2ee.control import acknowledge, parse_control, receipt_node
from whatsapp_e2ee.stanza import attributes, message_node, parse_message, receive_message
from whatsapp_e2ee.transport import StanzaDelivery


def deliver(node, sender, *, group=None, recipient=None):
    attrs = attributes(node)
    attrs.pop("to")
    attrs["from"] = group or (
        sender.name.split("@")[0] + ":" + str(sender.device_id) + "@" + sender.name.split("@")[1]
    )
    if group:
        attrs["participant"] = (
            sender.name.split("@")[0]
            + ":"
            + str(sender.device_id)
            + "@"
            + sender.name.split("@")[1]
        )
    if recipient:
        attrs["recipient"] = recipient
    return Node(node.tag, attrs=attrs, children=node.children)


def test_direct_full_stanza_codec_and_receive(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    packets = a.prepare_direct(
        "d", {b.address: payload.text("你好")}, bundles={b.address: bundle(b)}
    )
    node = message_node(
        "d", b.address.name, packets, phash="adapter-value", enc_attributes={"count": "1"}
    )
    codec = Codec(TokenDictionary.bundled())
    encoded = codec.write(node)
    recovered = codec.read(encoded)
    # Compact JIDs gain explicit flags=0 when decoded; compare wire and routing.
    assert codec.write(recovered) == encoded
    incoming = deliver(recovered, a.address)
    parsed, raws = receive_message(b, incoming, authenticated_transport=True)
    assert parsed.sender == a.address
    assert raws == (payload.text("你好"),)
    assert parsed.raw_node == incoming
    assert receive_message(b, incoming, authenticated_transport=True)[1] == raws
    with pytest.raises(ValueError):
        receive_message(b, incoming, authenticated_transport=False)


def test_group_one_stanza_distribution_and_content_atomic(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    packets = a.prepare_group_delivery(
        "g", "123@g.us", payload.text("group"), [b.address], bundles={b.address: bundle(b)}
    )
    node = message_node("g", "123@g.us", packets)
    assert [n.tag for n in node.children] == ["enc", "participants"]
    incoming = deliver(node, a.address, group="123@g.us")
    top = incoming.children[0]
    broken = replace(top, data=top.data[:-1] + bytes([top.data[-1] ^ 1]))
    bad = replace(incoming, children=(broken, incoming.children[1]))
    from signal_protocol.exceptions import InvalidMessageException

    with pytest.raises(InvalidMessageException):
        receive_message(b, bad, authenticated_transport=True)
    assert not b.store.contains_session(a.address)
    assert b.store.contains_pre_key(7)
    assert not b.pending_events()
    parsed, outputs = receive_message(b, incoming, authenticated_transport=True)
    assert outputs[-1] == payload.text("group")
    assert len(outputs) == 2
    assert len(b.pending_events()) == 2
    receive_message(b, incoming, authenticated_transport=True)
    assert len(b.pending_events()) == 2


@pytest.mark.parametrize(
    "mutation", ["duplicate_id", "unknown_type", "wrong_device", "wrong_group", "duplicate_target"]
)
def test_envelope_rejects_ambiguous_routing(tmp_path, mutation):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    p = a.prepare_direct("d", {b.address: payload.text("x")}, bundles={b.address: bundle(b)})
    n = deliver(message_node("d", b.address.name, p), a.address)
    if mutation == "duplicate_id":
        n = replace(n, attrs=(*n.attrs, Attribute("id", "other")))
    elif mutation == "unknown_type":
        to = n.children[0].children[0]
        bad = replace(to.children[0], attrs={"v": "2", "type": "otsk"})
        n = replace(n, children=(Node("participants", children=(replace(to, children=(bad,)),)),))
    elif mutation == "wrong_device":
        n = replace(n, attrs={**attributes(n), "to": "15550002:2@s.whatsapp.net"})
    elif mutation == "wrong_group":
        n = replace(n, attrs={**attributes(n), "from": "1000001@g.us"})
    else:
        n = replace(n, children=(Node("participants", children=n.children[0].children * 2),))
    with pytest.raises(ValueError):
        parse_message(n, b.address)
    assert not b.store.contains_session(a.address)


def test_persisted_whole_stanza_timeout_and_receipts(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a.prepare_direct("d", {b.address: payload.text("x")}, bundles={b.address: bundle(b)})
    wire = StanzaDelivery(a.store)
    encoded = wire.prepare("d", b.address.name)
    seen = []

    def fail(id, raw):
        assert not a.store.db.connection.in_transaction
        seen.append(raw)
        raise TimeoutError()

    with pytest.raises(TimeoutError):
        wire.dispatch("d", fail)
    a.store.db.close()
    a = endpoint(tmp_path / "a.db", "a")
    wire = StanzaDelivery(a.store)
    wire.dispatch("d", lambda id, raw: seen.append(raw))
    assert seen == [encoded, encoded]
    with pytest.raises(Conflict):
        wire.prepare("d", b.address.name, phash="changed")
    error = Node(
        "ack", attrs={"class": "message", "id": "d", "from": b.address.name, "error": "421"}
    )
    wire.apply_control("d", error, authenticated_transport=True)
    assert a.store._get("stanza-state", "d")[0] == b"submitted"
    ack = Node("ack", attrs={"class": "message", "id": "d", "from": b.address.name})
    wire.apply_control("d", ack, authenticated_transport=True)
    wire.dispatch("d", lambda *_: pytest.fail("already acknowledged"))
    read = Node("receipt", attrs={"type": "read", "id": "d", "from": "15550002:1@s.whatsapp.net"})
    wire.apply_control("d", read, authenticated_transport=True)
    delivery = replace(read, attrs={"id": "d", "from": "15550002:1@s.whatsapp.net"})
    wire.apply_control("d", delivery, authenticated_transport=True)
    assert int(a.store._get("receipt", '["d","15550002@s.whatsapp.net",1,"pkmsg"]')[0]) == 3
    with pytest.raises(ValueError):
        wire.apply_control(
            "d",
            replace(read, attrs={**attributes(read), "from": "15550003:1@s.whatsapp.net"}),
            authenticated_transport=True,
        )


def test_control_batch_and_ack_fields():
    n = receipt_node("a", "15550002:1@s.whatsapp.net", kind="read", additional_ids=("b", "c"))
    n = replace(n, attrs={"from": "15550002:1@s.whatsapp.net", "id": "a", "type": "read"})
    control = parse_control(n)
    assert control.ids == ("a", "b", "c")
    a = attributes(acknowledge(n))
    assert a["class"] == "receipt" and a["type"] == "read"
    with pytest.raises(ValueError):
        receipt_node("a", "15550002@s.whatsapp.net", additional_ids=("a",))


def test_group_receipts_are_member_scoped(tmp_path):
    a, b, c = [endpoint(tmp_path / (n + ".db"), n) for n in "abc"]
    a.prepare_group_delivery(
        "g",
        "1000001@g.us",
        payload.text("g"),
        [b.address, c.address],
        bundles={b.address: bundle(b), c.address: bundle(c)},
    )
    wire = StanzaDelivery(a.store)
    wire.prepare("g", "1000001@g.us")
    receipt = Node(
        "receipt", attrs={"id": "g", "from": "1000001@g.us", "participant": "15550002:1@s.whatsapp.net"}
    )
    wire.apply_control("g", receipt, authenticated_transport=True)
    assert a.store._get("group-receipt", '["g","15550002@s.whatsapp.net",1]')[0] == b"2"
    assert a.store._get("group-receipt", '["g","15550003@s.whatsapp.net",1]') is None


def test_own_device_receipt_and_device_sent_routing(tmp_path):
    from signal_protocol import SignalProtocolAddress

    from whatsapp_e2ee import Client, Database, SQLiteStore
    from whatsapp_e2ee.routing import prepare_chat

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    s = SQLiteStore(Database(tmp_path / "a2.db"), "a2")
    s.initialize()
    a2 = Client(s, SignalProtocolAddress(a.address.name, 2))
    packets = prepare_chat(
        a,
        "own",
        b.address.name,
        payload.text("copy"),
        [b.address],
        own_devices=[a2.address],
        bundles={b.address: bundle(b), a2.address: bundle(a2)},
    )
    wire = StanzaDelivery(a.store)
    encoded = wire.prepare("own", b.address.name)
    incoming = deliver(wire.codec.read(encoded), a.address, recipient=b.address.name)
    with pytest.raises(ValueError):
        receive_message(a2, incoming, authenticated_transport=True)
    result = receive_message(
        a2,
        incoming,
        authenticated_transport=True,
        own_device_check=lambda sender: sender == a.address,
    )
    assert payload.parse(result[1][0]).device_sent_message.message.conversation == "copy"
    r = Node("receipt", attrs={"id": "own", "from": "15550001:2@s.whatsapp.net"})
    wire.apply_control("own", r, authenticated_transport=True)
    own = next(p for p in packets if p.recipient == a.address.name)
    assert a.store._get("receipt", '["own","15550001@s.whatsapp.net",2,"' + own.kind + '"]')[0] == b"2"


@pytest.mark.parametrize(
    "extra", [{"bucket": "other"}, {"count": "-1"}, {"count": "101"}, {"count": "١"}]
)
def test_receive_checks_crypto_context_before_state_access(tmp_path, extra):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    packets = a.prepare_direct("d", {b.address: payload.text("x")}, bundles={b.address: bundle(b)})
    n = deliver(message_node("d", b.address.name, packets, enc_attributes=extra), a.address)
    with pytest.raises(ValueError):
        receive_message(b, n, authenticated_transport=True)
    assert not b.store.contains_session(a.address)
    assert b.store.contains_pre_key(7)


def test_selected_group_bucket_propagates_into_envelope(tmp_path):
    from whatsapp_e2ee import Client, SQLiteStore

    old_a, old_b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    a = Client(SQLiteStore(old_a.store.db, "a", bucket="alternate"), old_a.address)
    b = Client(SQLiteStore(old_b.store.db, "b", bucket="alternate"), old_b.address)
    a.prepare_group_delivery(
        "g", "1000001@g.us", payload.text("scoped"), [b.address], bundles={b.address: bundle(b)}
    )
    transport = StanzaDelivery(a.store)
    wire = transport.prepare("g", "1000001@g.us")
    incoming = deliver(transport.codec.read(wire), a.address, group="1000001@g.us")
    assert receive_message(b, incoming, authenticated_transport=True)[1][-1] == payload.text(
        "scoped"
    )
    with pytest.raises(ValueError, match="bucket"):
        transport.prepare("g", "1000001@g.us", enc_attributes={"bucket": "different"})
