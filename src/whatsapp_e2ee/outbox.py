"""Atomic preparation: ciphertext and protocol state commit together."""

import json

from whatsapp_e2ee.packets import Conflict, Packet, digest


class Outbox:
    def __init__(self, store):
        self.store = store

    def prepare(self, id, request, producer):
        fingerprint = digest(request)
        with self.store.db.atomic() as c:
            row = c.execute(
                "SELECT fingerprint,value FROM outbox WHERE owner=? AND id=?",
                (self.store.owner, id),
            ).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise Conflict("Message ID already bound to different content or targets")
                return tuple(Packet.from_dict(d) for d in json.loads(row[1]))
            packets = tuple(producer())
            raw = json.dumps([p.as_dict() for p in packets], separators=(",", ":")).encode()
            c.execute(
                "INSERT INTO outbox(owner,id,fingerprint,value) VALUES(?,?,?,?)",
                (self.store.owner, id, fingerprint, raw),
            )
            self.store._put("prepared-request", id, request)
            return packets


__all__ = ["Outbox"]
