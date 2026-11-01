"""Durable encoded stanza dispatch through an injected transport, no sockets."""

import json

from protocol_tree_node import Codec, Node, TokenDictionary

from whatsapp_e2ee.control import parse_control
from whatsapp_e2ee.delivery import LEVELS, Delivery
from whatsapp_e2ee.packets import Conflict
from whatsapp_e2ee.stanza import address_from_jid, message_node, parse_jid
from whatsapp_e2ee.store import key


class StanzaDelivery:
    def __init__(self, store, *, codec=None):
        self.store = store
        self.codec = codec or Codec(TokenDictionary.bundled())
        self.delivery = Delivery(store)

    def prepare(self, prepared_id, destination, *, wire_id=None, **options):
        """Freeze the entire node and encoded bytes after crypto preparation.

        For protocol retry, prepared_id is the local attempt key while wire_id
        remains the original logical message ID. Options must include the
        protocol retry count on enc, as appropriate to the caller's attempt.
        """
        wire_id = prepared_id if wire_id is None else wire_id
        enc_attributes = dict(options.get("enc_attributes") or {})
        envelope_bucket = self.store.bucket if parse_jid(destination).server == "g.us" else ""
        if enc_attributes.get("bucket", envelope_bucket) != envelope_bucket:
            raise ValueError("Envelope bucket differs from selected store")
        if envelope_bucket:
            enc_attributes["bucket"] = envelope_bucket
        options["enc_attributes"] = enc_attributes
        with self.store.db.atomic():
            packets = self.delivery.prepared(prepared_id)
            node = message_node(wire_id, destination, packets, **options)
            representation = json.dumps(node.to_dict(), sort_keys=True).encode()
            old = self.store._get("stanza-node", prepared_id)
            if old:
                if old[0] != representation:
                    raise Conflict("Prepared stanza already bound to different envelope")
                return self.store._get("stanza-wire", prepared_id)[0]
            wire = self.codec.write(node)
            self.store._put("stanza-node", prepared_id, representation)
            self.store._put("stanza-wire", prepared_id, wire)
            self.store._put("stanza-state", prepared_id, b"prepared")
            self.store._put("stanza-logical", prepared_id, wire_id.encode())
            return wire

    def prepare_retry(self, attempt, request, destination=None, **options):
        if attempt.logical_id != request.id or attempt.count != request.count:
            raise ValueError("Retry attempt/request mismatch")
        if "wire_id" in options or "enc_attributes" in options:
            raise ValueError("Retry count and logical ID are bound by the attempt")
        expected_destination = (
            request.chat if request.chat.endswith("@g.us") else request.sender.name
        )
        destination = destination or expected_destination
        expected_jid, actual_jid = parse_jid(expected_destination), parse_jid(destination)
        if (actual_jid.user, actual_jid.server) != (expected_jid.user, expected_jid.server):
            raise ValueError("Retry destination does not match verified request")
        if actual_jid.device not in (0, request.sender.device_id):
            raise ValueError("Retry destination device mismatch")
        if expected_jid.server == "g.us":
            from whatsapp_e2ee.stanza import jid_for_address

            if (
                "participant" in options
                and address_from_jid(options["participant"]) != request.sender
            ):
                raise ValueError("Retry participant does not match verified request")
            options["participant"] = jid_for_address(request.sender)
        return self.prepare(
            attempt.attempt_id,
            destination,
            wire_id=attempt.logical_id,
            enc_attributes={"count": str(attempt.count)},
            **options,
        )

    def dispatch(self, prepared_id, send):
        self.delivery.prepared(prepared_id)  # Validate namespace even for cached wire.
        row = self.store._get("stanza-wire", prepared_id)
        if row is None:
            raise KeyError(prepared_id)
        state = self.store._get("stanza-state", prepared_id)
        if state and state[0] == b"server_ack":
            return
        send(prepared_id, row[0])
        with self.store.db.atomic():
            current = self.store._get("stanza-state", prepared_id)
            if current and current[0] == b"prepared":
                self.store._put("stanza-state", prepared_id, b"submitted")

    def apply_control(self, prepared_id, node, *, authenticated_transport):
        if authenticated_transport is not True:
            raise ValueError("Untrusted control routing")
        control = parse_control(node)
        with self.store.db.atomic():
            self.delivery.prepared(prepared_id)
            row = self.store._get("stanza-node", prepared_id)
            if row is None:
                raise KeyError(prepared_id)
            envelope = Node.from_dict(json.loads(row[0]))
            a = {x.name: x.value for x in envelope.attrs}
            if a["id"] not in control.ids:
                raise ValueError("Control ID does not match prepared stanza")
            # This method updates one explicitly resolved attempt. A batched
            # receipt must be applied to each ID by the caller's lookup layer.
            destination = parse_jid(a["to"])
            source = parse_jid(control.source)
            if (control.kind in ("server_ack", "error") or destination.server == "g.us") and (
                source.user,
                source.server,
            ) != (destination.user, destination.server):
                raise ValueError("Control source does not match destination")
            if control.kind == "error":
                self.store._put(
                    "stanza-error",
                    prepared_id,
                    json.dumps(dict(error=control.error, raw=node.to_dict())).encode(),
                )
                return control
            if control.kind == "server_ack":
                self.store._put("stanza-state", prepared_id, b"server_ack")
                for p in self.delivery.prepared(prepared_id):
                    self.delivery.receipt(prepared_id, p, "server_ack")
                return control
            sender = address_from_jid(
                control.participant if destination.server == "g.us" else source
            )
            packets = self.delivery.prepared(prepared_id)
            if destination.server == "g.us":
                original = self.store._get("prepared-request", prepared_id)
                q = json.loads(original[0]) if original else None
                recipients = q[5] if q and q[0] == "group-delivery" else None
                if recipients is None or [sender.name, sender.device_id] not in recipients:
                    raise ValueError("Group receipt device not in frozen recipient snapshot")
                marker = key(prepared_id, sender.name, sender.device_id)
                old = self.store._get("group-receipt", marker)
                rank = max(LEVELS[control.kind], int(old[0]) if old else 0)
                self.store._put("group-receipt", marker, str(rank).encode())
            else:
                targets = [
                    p for p in packets if (p.recipient, p.device) == (sender.name, sender.device_id)
                ]
                if len(targets) != 1:
                    raise ValueError("Receipt device not in prepared recipients")
                self.delivery.receipt(prepared_id, targets[0], control.kind)
            return control


__all__ = ["StanzaDelivery"]
