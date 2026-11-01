"""Offline message preparation: durable ciphertext before transport dispatch."""

import base64
import json
import secrets

from signal_protocol import (
    WHATSAPP,
    WhatsAppGroupCipher,
    WhatsAppSessionBuilder,
    WhatsAppSessionCipher,
)
from signal_protocol.groups import GroupSessionBuilder, SenderKeyName, SenderKeyRecord
from signal_protocol.store import Direction

from whatsapp_e2ee import payload
from whatsapp_e2ee.outbox import Outbox
from whatsapp_e2ee.packets import Conflict, Packet, digest
from whatsapp_e2ee.receiving import MessageReceiver
from whatsapp_e2ee.store import key


class Client:
    def __init__(self, store, address):
        self.store, self.address = store, address
        with store.db.atomic():
            binding = key(address.name, address.device_id).encode()
            old = store._get("local", "address")
            if old is not None and old[0] != binding:
                raise ValueError("Local store belongs to another device")
            store._put("local", "address", binding)

    def _prepared(self, id, request, producer):
        return Outbox(self.store).prepare(id, request, producer)

    def prepare_direct(self, id, targets, *, bundles=None):
        """targets maps canonical SignalProtocolAddress to business protobuf bytes."""
        if not targets:
            raise ValueError("No recipient devices")
        ordered = sorted(targets.items(), key=lambda item: (item[0].name, item[0].device_id))
        request = key(
            "direct",
            self.store.space,
            [(a.name, a.device_id, base64.b64encode(b).decode()) for a, b in ordered],
        ).encode()

        def produce():
            for address, raw in ordered:
                yield self._encrypt_direct(address, raw, bundles)

        return self._prepared(id, request, produce)

    def _encrypt_direct(self, address, raw, bundles):
        payload.parse(raw)
        if not self.store.contains_session(address):
            if bundles is None or address not in bundles:
                raise ValueError("Missing recipient prekey bundle")
            bundle = bundles[address]
            if bundle.device_id != address.device_id:
                raise ValueError("Bundle device mismatch")
            WhatsAppSessionBuilder(self.store, address).process(bundle)
        message = WhatsAppSessionCipher(self.store, address).encrypt(raw)
        self.store.validate_session_identity(address, Direction.SENDING)
        return Packet(
            address.name,
            address.device_id,
            {2: "msg", 3: "pkmsg"}[message.type],
            message.serialize(),
        )

    def prepare_group_delivery(
        self,
        id,
        group,
        raw,
        recipients,
        *,
        bundles=None,
        snapshot_revision=None,
        force_distribution=(),
    ):
        """Freeze a recipient snapshot. Distribution is prepared, not receipt-confirmed.

        Pending outbox batches must be retried in order. Explicit redistribution
        uses the persisted original batch; a later chain snapshot cannot recover
        an earlier missing message key.
        """
        recipients = sorted(set(recipients), key=lambda a: (a.name, a.device_id))
        if not recipients:
            raise ValueError("No group recipient devices")
        forced = set(force_distribution)
        if not forced.issubset(recipients):
            raise ValueError("Forced distribution device is not a recipient")
        request = key(
            "group-delivery",
            snapshot_revision,
            self.store.space,
            group,
            self.store.bucket,
            [(a.name, a.device_id) for a in recipients],
            base64.b64encode(raw).decode(),
            sorted((a.name, a.device_id) for a in forced),
        ).encode()

        def produce():
            payload.parse(raw)
            name = SenderKeyName(group, self.address)
            d = GroupSessionBuilder(self.store, profile=WHATSAPP).create(name)
            wrapped = payload.distribution(group, d.serialize())
            for address in recipients:
                marker = key(
                    group,
                    self.address.name,
                    self.address.device_id,
                    self.store.bucket,
                    d.id,
                    self.store.space,
                    (self.store._get("group-generation", key(group, self.store.bucket)) or (b"0",))[
                        0
                    ].hex(),
                    address.name,
                    address.device_id,
                )
                if address in forced or self.store._get("distribution-prepared", marker) is None:
                    yield self._encrypt_direct(address, wrapped, bundles)
                    self.store._put("distribution-prepared", marker, id.encode())
            yield Packet(
                group,
                0,
                "skmsg",
                WhatsAppGroupCipher(self.store, name).encrypt(raw),
                group,
            )

        return self._prepared(id, request, produce)

    def invalidate_distributions(self, group, recipients=None):
        """Invalidate only local prepared markers; never delete remote sessions."""
        targets = None if recipients is None else {(a.name, a.device_id) for a in recipients}
        with self.store.db.atomic() as c:
            rows = c.execute(
                "SELECT id FROM records WHERE owner=? AND kind='distribution-prepared'",
                (self.store.owner,),
            ).fetchall()
            removed = 0
            for (marker,) in rows:
                values = json.loads(marker)
                if (
                    len(values) == 9
                    and values[:4]
                    == [group, self.address.name, self.address.device_id, self.store.bucket]
                    and values[5] == self.store.space
                    and (targets is None or tuple(values[-2:]) in targets)
                ):
                    self.store._remove("distribution-prepared", marker)
                    removed += 1
            return removed

    def distribution_payload(self, group):
        with self.store.db.atomic():
            name = SenderKeyName(group, self.address)
            d = GroupSessionBuilder(self.store, profile=WHATSAPP).create(name)
            return payload.distribution(group, d.serialize())

    def rotate_group(self, group):
        """Explicit rotation primitive; membership policy belongs to the caller."""
        with self.store.db.atomic():
            self.store.store_sender_key(
                SenderKeyName(group, self.address), SenderKeyRecord(profile=WHATSAPP)
            )
            self.store._put(
                "group-generation", key(group, self.store.bucket), secrets.token_bytes(16)
            )
            return self.distribution_payload(group)

    def prepare_group(self, id, group, raw):
        request = key("group", group, self.store.bucket, base64.b64encode(raw).decode()).encode()

        def produce():
            payload.parse(raw)
            name = SenderKeyName(group, self.address)
            GroupSessionBuilder(self.store, profile=WHATSAPP).create(name)
            yield Packet(
                group,
                0,
                "skmsg",
                WhatsAppGroupCipher(self.store, name).encrypt(raw),
                group,
            )

        return self._prepared(id, request, produce)

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
        return MessageReceiver(self.store, self.address).receive(
            id,
            sender,
            packet,
            expected_group=expected_group,
            own_device=own_device,
            expected_destination=expected_destination,
            content_slot=content_slot,
            retry_count=retry_count,
        )

    def pending_events(self):
        with self.store.db.atomic() as c:
            return c.execute(
                "SELECT id,value FROM events WHERE owner=? AND done=0 ORDER BY rowid",
                (self.store.owner,),
            ).fetchall()

    def acknowledge_event(self, id):
        with self.store.db.atomic() as c:
            c.execute(
                "UPDATE events SET done=1 WHERE owner=? AND id=?",
                (self.store.owner, id),
            )


__all__ = ["Client", "Conflict", "Packet", "digest"]
