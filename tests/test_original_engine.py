"""Replay existing original-engine synthetic captures with the SQLite backend.

No phone invocation: fixtures are independently produced historical expectations.
"""

import base64
import json
from pathlib import Path

import pytest
from signal_protocol import (
    WHATSAPP,
    ECPrivateKey,
    ECPublicKey,
    IdentityKey,
    IdentityKeyPair,
    KyberPreKeyRecord,
    PreKeyRecord,
    PreKeySignalMessage,
    SessionCipher,
    SessionRecord,
    SignalMessage,
    SignalProtocolAddress,
    SignedPreKeyRecord,
)
from signal_protocol.groups import (
    GroupCipher,
    GroupSessionBuilder,
    SenderKeyName,
    SenderKeyRecord,
)
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage

from whatsapp_e2ee import Database, SQLiteStore

root = Path(__file__).parent / "vectors"
CASES = (
    json.loads((root / "original-v4.json").read_text())["cases"]
    + json.loads((root / "original-core.json").read_text())["ciphers"]
)
decode = base64.b64decode


@pytest.mark.parametrize("row", CASES, ids=lambda r: r["request"]["id"] + "-" + r["request"]["op"])
def test_original_engine_cipher_sqlite(tmp_path, row):
    source, request, expected = row["store"], row["request"], row["expected"]
    store = SQLiteStore(Database(tmp_path / "fixture.db"), "fixture")
    identity = IdentityKeyPair(
        IdentityKey(ECPublicKey(decode(source["identity_public"]))),
        ECPrivateKey(decode(source["identity_private"])),
    )
    store._put("local", "identity", identity.serialize())
    store._put("local", "registration", str(source["registration_id"]).encode())
    address = SignalProtocolAddress("captured-synthetic-peer", 1)
    for kind, cls, method in [
        ("prekeys", PreKeyRecord, store.store_pre_key),
        ("signed_prekeys", SignedPreKeyRecord, store.store_signed_pre_key),
        ("kem_prekeys", KyberPreKeyRecord, store.store_kyber_pre_key),
    ]:
        for id, raw in source.get(kind, {}).items():
            method(int(id), cls.from_bytes(decode(raw)))
    if source.get("record"):
        store.store_session(address, SessionRecord(decode(source["record"]), profile=WHATSAPP))
    cipher = SessionCipher(store, address, profile=WHATSAPP)
    with store.db.atomic():
        if request["op"] == "encrypt":
            m = cipher.encrypt(decode(request["message"]))
            assert m.type == expected["message_type"]
            assert m.serialize() == decode(expected["message"])
            assert store.load_session(address).serialize() == decode(expected["record"])
        else:
            cls = PreKeySignalMessage if request["message_type"] == 3 else SignalMessage
            assert cipher.decrypt(
                cls.from_bytes(decode(request["message"]), profile=WHATSAPP)
            ) == decode(expected["plaintext"])
            for kind, expected_key in [
                ("pre", "prekey_ids"),
                ("kem", "kem_prekey_ids"),
            ]:
                with store.db.atomic() as c:
                    ids = {
                        int(r[0])
                        for r in c.execute(
                            "SELECT id FROM records WHERE owner=? AND kind=?",
                            ("fixture", kind),
                        )
                    }
                assert ids == set(expected[expected_key])


GROUPS = [
    r
    for r in json.loads((root / "original-core.json").read_text())["core"]
    if r["request"]["op"] == "core-group"
]


@pytest.mark.parametrize("row", GROUPS, ids=lambda r: r["request"]["action"])
def test_original_group_engine_sqlite(tmp_path, row):
    q = row["request"]
    expected = row["response"]["value"]
    store = SQLiteStore(Database(tmp_path / "group.db"), "fixture")
    name = SenderKeyName("synthetic-group", SignalProtocolAddress("bob", 1))
    record = SenderKeyRecord(decode(q["record"]), profile=WHATSAPP)
    store.store_sender_key(name, record)
    cipher = GroupCipher(store, name, profile=WHATSAPP)
    with store.db.atomic():
        if q["action"] == "encrypt":
            ours = SenderKeyMessage.from_bytes(
                cipher.encrypt(decode(q["message"])), profile=WHATSAPP
            )
            native = SenderKeyMessage.from_bytes(decode(expected["data"]), profile=WHATSAPP)
            assert (ours.key_id, ours.iteration, ours.ciphertext) == (
                native.key_id,
                native.iteration,
                native.ciphertext,
            )
            for message in (ours, native):
                message.verify_signature(record.get_sender_key_state().signing_key_public)
        elif q["action"] == "decrypt":
            assert cipher.decrypt(decode(q["message"])) == decode(expected["data"])
        else:
            GroupSessionBuilder(store, profile=WHATSAPP).process(
                name,
                SenderKeyDistributionMessage.from_bytes(decode(q["message"]), profile=WHATSAPP),
            )
        assert store.load_sender_key(name).serialize() == decode(expected["record"])
