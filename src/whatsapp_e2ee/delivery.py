"""Durable at-least-once dispatch through an explicitly supplied transport."""

import json

from whatsapp_e2ee.packets import Packet
from whatsapp_e2ee.store import key

LEVELS = {"server_ack": 1, "delivered": 2, "read": 3}


class Delivery:
    def __init__(self, store):
        self.store = store

    def prepared(self, id):
        with self.store.db.atomic() as c:
            row = c.execute(
                "SELECT value FROM outbox WHERE owner=? AND id=?",
                (self.store.owner, id),
            ).fetchone()
            if row is None:
                raise KeyError(id)
            request = self.store._get("prepared-request", id)
            if request is None:
                raise ValueError(
                    "Legacy outbox lacks namespace metadata; explicit migration required"
                )
            q = json.loads(request[0])
            if q[0] == "direct":
                valid = q[1] == self.store.space
            elif q[0] == "group-delivery":
                valid = q[2] == self.store.space and q[4] == self.store.bucket
            elif q[0] == "group":
                valid = q[2] == self.store.bucket
            else:
                raise ValueError("Unknown prepared request schema")
            if not valid:
                raise ValueError("Prepared message namespace mismatch")
            return tuple(Packet.from_dict(d) for d in json.loads(row[0]))

    def dispatch(self, id, send):
        """send(id, packet) may be called again after an ambiguous failure.

        This callback is never invoked under a SQLite transaction. Receipt state
        is packet-target scoped; group-member delivery is not inferred from it.
        """
        self.store.db.require_no_transaction()
        packets = self.prepared(id)
        for p in packets:
            marker = key(id, p.recipient, p.device, p.kind)
            row = self.store._get("receipt", marker)
            if row and int(row[0]) >= 1:
                continue
            send(id, p)
        with self.store.db.atomic() as c:
            c.execute(
                "UPDATE outbox SET state='submitted' WHERE owner=? AND id=? AND state='prepared'",
                (self.store.owner, id),
            )

    def receipt(self, id, packet, level):
        rank = LEVELS[level]
        with self.store.db.atomic():
            if packet not in self.prepared(id):
                raise ValueError("Receipt target not in prepared message")
            marker = key(id, packet.recipient, packet.device, packet.kind)
            row = self.store._get("receipt", marker)
            self.store._put("receipt", marker, str(max(rank, int(row[0]) if row else 0)).encode())


__all__ = ["LEVELS", "Delivery"]
