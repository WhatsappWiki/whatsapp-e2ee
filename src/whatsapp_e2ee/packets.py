"""Shared encrypted packet values and message conflict errors."""

import base64
import hashlib
from dataclasses import dataclass


class Conflict(ValueError):
    # Keep pickle references readable by releases predating the module split.
    __module__ = "whatsapp_e2ee.client"

    pass


@dataclass(frozen=True)
class Packet:
    # Keep pickle references readable by releases predating the module split.
    __module__ = "whatsapp_e2ee.client"

    recipient: str
    device: int
    kind: str
    ciphertext: bytes
    group: str = ""

    def as_dict(self):
        return dict(
            recipient=self.recipient,
            device=self.device,
            kind=self.kind,
            ciphertext=base64.b64encode(self.ciphertext).decode(),
            group=self.group,
        )

    @classmethod
    def from_dict(cls, d):
        return cls(**{**d, "ciphertext": base64.b64decode(d["ciphertext"], validate=True)})


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


__all__ = ["Conflict", "Packet", "digest"]
