"""Authenticated decryption, replay checks and transactional inbox acceptance."""

import base64
import json

from signal_protocol import WHATSAPP, WhatsAppSessionCipher
from signal_protocol.groups import SenderKeyName
from signal_protocol.protocol import SenderKeyDistributionMessage
from signal_protocol.store import Direction

from whatsapp_e2ee import payload
from whatsapp_e2ee.group_sessions import decrypt_group, install_distribution
from whatsapp_e2ee.packets import Conflict, digest
from whatsapp_e2ee.store import key


class MessageReceiver:
    def __init__(self, store, address):
        self.store, self.address = store, address

    def receive(
        self,
        id,
        sender,
        packet,
        *,
        expected_group=None,
        own_device=False,
        expected_destination=None,
        content_slot="message",
        retry_count=0,
    ):
        if not isinstance(id, str) or not id:
            raise ValueError("A nonempty string message ID is required")
        if type(retry_count) is not int or not 0 <= retry_count <= 100:
            raise ValueError("Invalid local retry count")
        if packet.kind not in ("msg", "pkmsg", "skmsg"):
            raise ValueError("Unsupported encrypted message type")
        if packet.kind != "skmsg" and (packet.recipient, packet.device) != (
            self.address.name,
            self.address.device_id,
        ):
            raise ValueError("Wrong recipient device")
        if packet.kind == "skmsg" and (
            not expected_group
            or packet.group != expected_group
            or packet.recipient != expected_group
        ):
            raise ValueError("Group routing mismatch")
        if content_slot not in ("message", "distribution"):
            raise ValueError("Unknown content slot")
        if content_slot == "distribution" and (not expected_group or packet.kind == "skmsg"):
            raise ValueError("Distribution slot requires a group-bound pairwise packet")
        inbox_id = key(sender.name, sender.device_id, expected_group or "", id)
        if content_slot != "message":
            inbox_id = key(sender.name, sender.device_id, expected_group, id, content_slot)

        if self.store.space != key(0, 0) or (expected_group and self.store.bucket):
            inbox_id = key(
                "namespace", self.store.space, self.store.bucket if expected_group else "", inbox_id
            )
        attempt_key = key(inbox_id, retry_count)
        ciphertext_key = key(
            self.store.space,
            self.store.bucket if expected_group else "",
            sender.name,
            sender.device_id,
            expected_group or "",
            packet.kind,
            digest(packet.ciphertext),
        )

        def remember_attempt(raw):
            self.store._put("authenticated-ciphertext", ciphertext_key, inbox_id.encode())
            self.store._put(
                "inbox-attempt",
                attempt_key,
                key(fingerprint, base64.b64encode(raw).decode()).encode(),
            )
            if retry_count:
                self.store._put("inbox-retried", inbox_id, b"1")

        def validate_business(raw):
            m = payload.parse(raw)
            if m.HasField("device_sent_message"):
                wrapped = m.device_sent_message
                if not own_device or not wrapped.HasField("message") or not wrapped.destination_jid:
                    raise ValueError("Untrusted or incomplete own-device wrapper")
                destination = expected_group or expected_destination
                if destination is not None and wrapped.destination_jid != destination:
                    raise ValueError("Own-device destination mismatch")
                m = wrapped.message
                if m.HasField("device_sent_message"):
                    raise ValueError("Nested own-device wrappers are not supported")
            if content_slot == "distribution" and not m.HasField("sender_key_distribution_message"):
                raise ValueError("Distribution slot lacks a sender key distribution")
            if packet.kind == "skmsg" and m.HasField("sender_key_distribution_message"):
                raise ValueError("SenderKey distribution requires a pairwise packet")
            return m

        fingerprint = digest(key(packet.as_dict()).encode())
        with self.store.db.atomic() as c:
            owner = self.store._get("authenticated-ciphertext", ciphertext_key)
            if owner is not None and owner[0] != inbox_id.encode():
                raise Conflict("Authenticated ciphertext replayed under another message ID or slot")
            row = c.execute(
                "SELECT fingerprint,value FROM inbox WHERE owner=? AND id=?",
                (self.store.owner, inbox_id),
            ).fetchone()
            attempt = self.store._get("inbox-attempt", attempt_key)
            if attempt:
                previous_fingerprint, previous_body = json.loads(attempt[0])
                if previous_fingerprint != fingerprint:
                    raise Conflict("Receive attempt count reused with different ciphertext")
                cached = base64.b64decode(previous_body, validate=True)
                validate_business(cached)
                self.store._put("authenticated-ciphertext", ciphertext_key, inbox_id.encode())
                return cached
            if row and row[0] == fingerprint:
                validate_business(row[1])
                remember_attempt(row[1])
                return row[1]
            if row and retry_count == 0 and self.store._get("inbox-retried", inbox_id) is None:
                raise Conflict("Duplicate ID with different ciphertext")

            def accept(raw):
                m = validate_business(raw)
                if row and content_slot != "distribution" and raw != row[1]:
                    raise Conflict("Authenticated retry changed the logical message body")
                if m.HasField("sender_key_distribution_message"):
                    d = m.sender_key_distribution_message
                    if (
                        not expected_group
                        or d.group_id != expected_group
                        or not d.HasField("distribution")
                    ):
                        raise ValueError("Unbound sender key distribution")
                    distribution = SenderKeyDistributionMessage.from_bytes(
                        d.distribution, profile=WHATSAPP
                    )
                    install_distribution(
                        self.store, SenderKeyName(d.group_id, sender), distribution
                    )
                if row is None:
                    c.execute(
                        "INSERT INTO inbox VALUES(?,?,?,?)",
                        (self.store.owner, inbox_id, fingerprint, raw),
                    )
                    c.execute(
                        "INSERT INTO events(owner,id,value) VALUES(?,?,?)",
                        (self.store.owner, inbox_id, raw),
                    )
                remember_attempt(raw)

            if packet.kind == "skmsg":
                return decrypt_group(
                    self.store, SenderKeyName(expected_group, sender), packet.ciphertext, accept
                )
            raw = WhatsAppSessionCipher(self.store, sender).decrypt(
                packet.ciphertext,
                accept,
                message_type={"msg": 2, "pkmsg": 3}[packet.kind],
            )
            self.store.validate_session_identity(sender, Direction.RECEIVING)
            return raw


__all__ = ["MessageReceiver"]
