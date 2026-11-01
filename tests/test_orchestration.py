import subprocess
import sys

import pytest
from signal_protocol import SignalProtocolAddress
from signal_protocol.exceptions import InvalidMessageException, NoSessionException
from test_client import bundle, endpoint

from whatsapp_e2ee import Client, Conflict, Database, SQLiteStore, payload
from whatsapp_e2ee.delivery import Delivery
from whatsapp_e2ee.media import encrypt
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.routing import prepare_chat, prepare_group_snapshot


def test_own_device_context_and_fanout(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    store = SQLiteStore(Database(tmp_path / "a2.db"), "a2")
    store.initialize()
    a2 = Client(store, SignalProtocolAddress(a.address.name, 2))
    # Known outer context field containing an unknown inner field; retain it.
    raw = payload.text("hello") + bytes.fromhex("9a02020807")
    packets = prepare_chat(
        a,
        "chat",
        b.address.name,
        raw,
        [b.address],
        own_devices=[a.address, a2.address],
        phash="supplied-by-adapter",
        bundles={b.address: bundle(b), a2.address: bundle(a2)},
    )
    own = next(p for p in packets if p.recipient == a.address.name)
    decoded = payload.parse(
        a2.receive("chat", a.address, own, own_device=True, expected_destination=b.address.name)
    )
    assert decoded.message_context_info.SerializeToString() == bytes.fromhex("0807")
    assert not decoded.device_sent_message.message.HasField("message_context_info")
    assert decoded.device_sent_message.message.conversation == "hello"
    assert decoded.device_sent_message.destination_jid == b.address.name
    assert (
        b.receive("chat", a.address, next(p for p in packets if p.recipient == b.address.name))
        == raw
    )


def test_group_snapshot_removal_and_stale_revision(tmp_path):
    a, b, c = [endpoint(tmp_path / (n + ".db"), n) for n in "abc"]
    first = prepare_group_snapshot(
        a,
        "one",
        "G",
        payload.text("one"),
        [b.address, c.address],
        revision=1,
        bundles={b.address: bundle(b), c.address: bundle(c)},
    )
    for receiver in (b, c):
        receiver.receive(
            "d1",
            a.address,
            next(p for p in first if p.recipient == receiver.address.name),
            expected_group="G",
        )
        receiver.receive("one", a.address, first[-1], expected_group="G")
    second = prepare_group_snapshot(a, "two", "G", payload.text("two"), [b.address], revision=2)
    b.receive("d2", a.address, second[0], expected_group="G")
    assert b.receive("two", a.address, second[-1], expected_group="G") == payload.text("two")
    with pytest.raises(InvalidMessageException):
        c.receive("two", a.address, second[-1], expected_group="G")
    with pytest.raises(ValueError):
        prepare_group_snapshot(
            a, "three", "G", payload.text("three"), [b.address, c.address], revision=1
        )
    with pytest.raises(Conflict):
        prepare_group_snapshot(a, "two", "G", payload.text("two"), [b.address], revision=3)
    assert (
        prepare_group_snapshot(a, "two", "G", payload.text("two"), [b.address], revision=2)
        == second
    )


@pytest.mark.parametrize(
    "kind,field,flag",
    [
        ("ptt", "audio_message", "ptt"),
        ("gif", "video_message", "gif_playback"),
        ("ptv", "ptv_message", None),
        ("image", "image_message", None),
        ("document", "document_message", None),
        ("sticker", "sticker_message", None),
    ],
)
def test_media_descriptor_tags(kind, field, flag):
    m = encrypt(b"content", kind)
    d = payload.parse(payload.media_message(m, "/synthetic", 123456, mimetype="test/type"))
    assert d.HasField(field)
    assert getattr(d, field).mimetype == "test/type"
    assert getattr(d, field).media_key_timestamp == 123
    if flag:
        assert getattr(getattr(d, field), flag)
    with pytest.raises(ValueError):
        payload.media_message(m, "/synthetic", 123456, nonexistent=True)


def test_media_job_resume_failed_message_and_retry(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    jobs = MediaJobs(a.store)
    m = jobs.prepare("media", b"content", "image", media_key_timestamp_ms=123456)
    assert jobs.prepare("media", b"content", "image", media_key_timestamp_ms=123456) == m
    with pytest.raises(ValueError):
        jobs.descriptor("media")
    jobs.mark_uploaded("media", "/synthetic-upload-result", 123456)
    a.store.db.close()
    a = endpoint(tmp_path / "a.db", "a")
    jobs = MediaJobs(a.store)
    assert jobs.prepare("media", b"content", "image", media_key_timestamp_ms=123456) == m
    with pytest.raises(ValueError):
        jobs.prepare_message("media", "msg", a, [b.address])
    assert a.store._get("media-state", "media")[0] == b"uploaded"
    packets = jobs.prepare_message(
        "media",
        "msg",
        a,
        [b.address],
        bundles={b.address: bundle(b)},
        metadata={"mimetype": "image/jpeg"},
    )
    assert (
        payload.parse(b.receive("msg", a.address, packets[0])).image_message.media_key
        == m.media_key
    )
    assert (
        jobs.prepare_message("media", "msg", a, [b.address], metadata={"mimetype": "image/jpeg"})
        == packets
    )
    assert a.store._get("media-state", "media")[0] == b"message_prepared"
    jobs.mark_uploaded("media", "/synthetic-upload-result", 123456)
    assert a.store._get("media-state", "media")[0] == b"message_prepared"


def test_multiprocess_ratchet_atomicity(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    first = a.prepare_direct(
        "initial", {b.address: payload.text("first")}, bundles={b.address: bundle(b)}
    )[0]
    b.receive("initial", a.address, first)
    script = """
import sys
from whatsapp_e2ee import Client, Database, SQLiteStore, payload
from signal_protocol import SignalProtocolAddress
s = SQLiteStore(Database(sys.argv[1]), "a")
c = Client(s, SignalProtocolAddress("a@s.whatsapp.net", 1))
for i in range(4):
    id = sys.argv[2] + ":" + str(i)
    c.prepare_direct(id, {SignalProtocolAddress("b@s.whatsapp.net", 1): payload.text(id)})
s.db.close()
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(tmp_path / "a.db"), str(i)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for i in range(3)
    ]
    for p in processes:
        stdout, stderr = p.communicate(timeout=30)
        assert p.returncode == 0, (stdout, stderr)
    for i in reversed(range(3)):
        for j in reversed(range(4)):
            id = f"{i}:{j}"
            assert b.receive(id, a.address, Delivery(a.store).prepared(id)[0]) == payload.text(id)


def test_unknown_legal_business_payload():
    unknown = bytes.fromhex("a20603616263")
    assert payload.parse(unknown).SerializeToString() == unknown
    assert payload.classify(unknown) == ("unsupported",)


def test_group_missing_distribution_and_signature_recovery(tmp_path):
    from dataclasses import replace

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    packets = a.prepare_group_delivery(
        "g", "G", payload.text("group"), [b.address], bundles={b.address: bundle(b)}
    )
    with pytest.raises(NoSessionException):
        b.receive("g", a.address, packets[-1], expected_group="G")
    b.receive("d", a.address, packets[0], expected_group="G")
    bad = replace(
        packets[-1],
        ciphertext=packets[-1].ciphertext[:-1] + bytes([packets[-1].ciphertext[-1] ^ 1]),
    )
    with pytest.raises(InvalidMessageException):
        b.receive("g", a.address, bad, expected_group="G")
    assert b.receive("g", a.address, packets[-1], expected_group="G") == payload.text("group")


def test_authenticated_invalid_business_rolls_back(tmp_path):
    from google.protobuf.message import DecodeError
    from signal_protocol import WhatsAppSessionBuilder, WhatsAppSessionCipher

    from whatsapp_e2ee import Packet

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    with a.store.db.atomic():
        WhatsAppSessionBuilder(a.store, b.address).process(bundle(b))
        bad = WhatsAppSessionCipher(a.store, b.address).encrypt(b"\xff")
    p = Packet(b.address.name, b.address.device_id, "pkmsg", bad.serialize())
    with pytest.raises(DecodeError):
        b.receive("bad", a.address, p)
    assert b.store.contains_pre_key(7)
    assert not b.store.contains_session(a.address)
    good = a.prepare_direct("good", {b.address: payload.text("ok")})[0]
    assert b.receive("good", a.address, good) == payload.text("ok")
