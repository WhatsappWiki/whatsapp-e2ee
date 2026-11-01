import json

import pytest
from signal_protocol import SignalProtocolAddress
from signal_protocol.exceptions import DuplicateMessageException
from test_client import bundle, endpoint

from whatsapp_e2ee import Client, Conflict, Database, SQLiteStore, payload
from whatsapp_e2ee.media import encrypt


def varint(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def field(number, raw):
    return varint(number * 8 + 2) + varint(len(raw)) + raw


def test_context_golden_wire_and_opaque_fields():
    # Independent wire construction rather than the dynamic descriptor serializer.
    quoted = field(1, "原消息🙂".encode())
    expected = field(1, b"stanza") + field(2, b"alice@s.whatsapp.net") + field(3, quoted)
    expected += field(4, b"group@g.us") + field(15, b"bob@lid") + field(15, b"alice@lid")
    expected += varint(21 * 8) + b"\x02" + varint(22 * 8) + b"\x01"
    c = payload.context_info(
        stanza_id="stanza",
        participant="alice@s.whatsapp.net",
        quoted=quoted,
        remote_jid="group@g.us",
        mentioned=["bob@lid", "alice@lid"],
        forwarding_score=2,
        is_forwarded=True,
    )
    assert c.SerializeToString() == expected
    raw = payload.extended_text("答复\ne\u0301", context=expected)
    assert raw == field(6, field(1, "答复\ne\u0301".encode()) + field(17, expected))
    extra = field(999, b"unknown")
    parsed = payload.parse(raw + extra)
    assert parsed.SerializeToString() == raw + extra
    assert list(parsed.extended_text_message.context_info.mentioned_jid) == ["bob@lid", "alice@lid"]


def test_media_thumbnail_and_scan_wire_fields():
    media = encrypt(b"image", "image")
    raw = payload.media_message(
        media,
        "/main",
        11000,
        thumbnail_direct_path="/thumb",
        thumbnail_sha256=b"p" * 32,
        thumbnail_enc_sha256=b"e" * 32,
        first_scan_sidecar=b"s" * 10,
        first_scan_length=37,
        scan_lengths=[37, 25],
        scans_sidecar=b"z" * 20,
    )
    d = payload.parse(raw).image_message
    serialized = d.SerializeToString()
    assert field(26, b"/thumb") in serialized
    assert field(27, b"p" * 32) in serialized
    assert field(28, b"e" * 32) in serialized
    assert varint(22 * 8) + varint(37) + varint(22 * 8) + varint(25) in serialized
    assert list(d.scan_lengths) == [37, 25]


def test_wrapped_distribution_requires_own_device_and_destination(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    store = SQLiteStore(Database(tmp_path / "a2.db"), "a2")
    store.initialize()
    b = Client(store, SignalProtocolAddress(a.address.name, 2))
    d = a.distribution_payload("g@g.us")
    wrapped = payload.device_sent("g@g.us", d)
    p = a.prepare_direct("dist", {b.address: wrapped}, bundles={b.address: bundle(b)})[0]
    with pytest.raises(ValueError, match="own-device"):
        b.receive("dist", a.address, p, expected_group="g@g.us")
    with pytest.raises(ValueError, match="destination"):
        b.receive("dist", a.address, p, own_device=True, expected_group="other@g.us")
    assert b.store.contains_pre_key(7)
    assert b.receive("dist", a.address, p, own_device=True, expected_group="g@g.us") == wrapped
    packet = a.prepare_group("content", "g@g.us", payload.text("group"))[0]
    assert b.receive("content", a.address, packet, expected_group="g@g.us") == payload.text("group")


def test_forced_distribution_atomic_binding(tmp_path):
    a, b, c = [endpoint(tmp_path / (n + ".db"), n) for n in "abc"]
    recipients = [b.address, c.address]
    first = a.prepare_group_delivery(
        "first",
        "G",
        payload.text("1"),
        recipients,
        bundles={b.address: bundle(b), c.address: bundle(c)},
    )
    assert len(first) == 3
    forced = a.prepare_group_delivery(
        "forced", "G", payload.text("2"), recipients, force_distribution=[b.address]
    )
    assert len(forced) == 2 and forced[0].recipient == b.address.name
    with pytest.raises(Conflict):
        a.prepare_group_delivery("forced", "G", payload.text("2"), recipients)
    assert (
        a.prepare_group_delivery(
            "forced", "G", payload.text("2"), recipients, force_distribution=[b.address]
        )
        == forced
    )
    assert a.invalidate_distributions("G", [b.address]) == 1
    assert len(a.prepare_group_delivery("after", "G", payload.text("3"), recipients)) == 2
    assert a.invalidate_distributions("other") == 0
    request = json.loads(a.store._get("prepared-request", "forced")[0])
    assert request[-1] == [[b.address.name, b.address.device_id]]


def test_multiple_restarts_both_endpoints_and_event_replay(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    first_bundle = bundle(b)
    for turn in range(12):
        sender, receiver = (a, b) if turn % 2 == 0 else (b, a)
        id = str(turn)
        p = sender.prepare_direct(
            id, {receiver.address: payload.text(id)}, bundles={b.address: first_bundle}
        )[0]
        assert receiver.receive(id, sender.address, p) == payload.text(id)
        event = receiver.pending_events()[0]
        receiver.store.db.close()
        reopened = endpoint(
            tmp_path / ("b.db" if receiver is b else "a.db"), "b" if receiver is b else "a"
        )
        assert reopened.pending_events()[0] == event
        assert reopened.receive(id, sender.address, p) == payload.text(id)
        reopened.acknowledge_event(event[0])
        assert reopened.pending_events() == []
        if receiver is b:
            b = reopened
        else:
            a = reopened


def test_same_ciphertext_new_logical_id_rejected(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    p = a.prepare_direct("x", {b.address: payload.text("hello")}, bundles={b.address: bundle(b)})[0]
    b.receive("x", a.address, p)
    with pytest.raises((DuplicateMessageException, Conflict)):
        b.receive("other-id", a.address, p)
    assert len(b.pending_events()) == 1


def test_group_distribution_and_content_share_logical_id(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    packets = a.prepare_group_delivery(
        "one-stanza", "G", payload.text("hello"), [b.address], bundles={b.address: bundle(b)}
    )
    with b.store.db.atomic():
        b.receive(
            "one-stanza", a.address, packets[0], expected_group="G", content_slot="distribution"
        )
        assert b.receive("one-stanza", a.address, packets[1], expected_group="G") == payload.text(
            "hello"
        )
    assert b.receive("one-stanza", a.address, packets[1], expected_group="G") == payload.text(
        "hello"
    )
    with pytest.raises(ValueError):
        b.receive(
            "one-stanza", a.address, packets[1], expected_group="G", content_slot="distribution"
        )


def test_own_wrapper_cached_payload_does_not_bypass_context(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    s = SQLiteStore(Database(tmp_path / "a2.db"), "a2")
    s.initialize()
    a2 = Client(s, SignalProtocolAddress(a.address.name, 2))
    raw = payload.device_sent("friend@lid", payload.text("sync"))
    p = a.prepare_direct("x", {a2.address: raw}, bundles={a2.address: bundle(a2)})[0]
    assert a2.receive("x", a.address, p, own_device=True, expected_destination="friend@lid") == raw
    with pytest.raises(ValueError):
        a2.receive("x", a.address, p)
    with pytest.raises(ValueError):
        a2.receive("x", a.address, p, own_device=True, expected_destination="someone-else@lid")
