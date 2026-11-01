"""Bounded-memory file cryptography and durable authenticated range assembly.

Only a fully verified result is published. Private temporary plaintext may exist
while a full-file stream is being authenticated; it is never returned as success.
"""

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from whatsapp_e2ee.media import IntegrityError, chunks, decrypt_chunk, derive
from whatsapp_e2ee.store import key

BLOCK = 65536


@contextmanager
def atomic_output(destination):
    destination = Path(destination)
    fd, temporary = tempfile.mkstemp(prefix=".wa-media-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            yield out
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@dataclass(frozen=True)
class MediaFile:
    media_key: bytes
    kind: str
    length: int
    plaintext_hash: bytes
    encrypted_hash: bytes
    path: Path


def encrypt_file(source, destination, kind, *, media_key=None):
    root = secrets.token_bytes(32) if media_key is None else bytes(media_key)
    iv, aes, mac_key = derive(root, kind)
    cipher = Cipher(algorithms.AES(aes), modes.CBC(iv)).encryptor()
    padder = padding.PKCS7(128).padder()
    plain_hash, enc_hash = hashlib.sha256(), hashlib.sha256()
    mac = hmac.new(mac_key, iv, "sha256")
    size = 0
    with open(source, "rb") as source_file, atomic_output(destination) as out:

        def write_cipher(raw):
            out.write(raw)
            enc_hash.update(raw)
            mac.update(raw)

        while raw := source_file.read(BLOCK):
            size += len(raw)
            plain_hash.update(raw)
            write_cipher(cipher.update(padder.update(raw)))
        write_cipher(cipher.update(padder.finalize()) + cipher.finalize())
        tag = mac.digest()[:10]
        out.write(tag)
        enc_hash.update(tag)
    return MediaFile(root, kind, size, plain_hash.digest(), enc_hash.digest(), Path(destination))


def decrypt_file(
    source, destination, media_key, kind, *, plaintext_hash, encrypted_hash, length=None
):
    iv, aes, mac_key = derive(media_key, kind)
    cipher = Cipher(algorithms.AES(aes), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    plain_hash, enc_hash = hashlib.sha256(), hashlib.sha256()
    mac = hmac.new(mac_key, iv, "sha256")
    total, size, pending = 0, 0, b""
    with open(source, "rb") as source_file, atomic_output(destination) as out:

        def write_plain(raw):
            nonlocal size
            size += len(raw)
            out.write(raw)
            plain_hash.update(raw)

        while raw := source_file.read(BLOCK):
            total += len(raw)
            enc_hash.update(raw)
            pending += raw
            # Keep the final MAC and any partial block out of CBC.
            count = max(0, (len(pending) - 10) // 16 * 16)
            encrypted, pending = pending[:count], pending[count:]
            mac.update(encrypted)
            write_plain(unpadder.update(cipher.update(encrypted)))
        if total < 26 or len(pending) != 10:
            raise IntegrityError("Invalid encrypted length")
        if not hmac.compare_digest(enc_hash.digest(), encrypted_hash):
            raise IntegrityError("Encrypted hash mismatch")
        if not hmac.compare_digest(mac.digest()[:10], pending):
            raise IntegrityError("MAC mismatch")
        try:
            write_plain(unpadder.update(cipher.finalize()) + unpadder.finalize())
        except ValueError as e:
            raise IntegrityError("Invalid padding") from e
        if not hmac.compare_digest(plain_hash.digest(), plaintext_hash):
            raise IntegrityError("Plaintext hash mismatch")
        if length is not None and size != length:
            raise IntegrityError("Plaintext length mismatch")
    return size


class RangeDownload:
    """Persistent chunk cache. Caller supplies bytes; no HTTP is performed.

    A job ID is permanently bound to its descriptor. Each accepted chunk is
    authenticated before storage. Finalization verifies main MAC and both hashes.
    """

    def __init__(self, store, id):
        self.store, self.id = store, id

    def initialize(
        self, media_key, kind, *, total, sidecar, plaintext_hash, encrypted_hash, length, sizes=None
    ):
        derive(media_key, kind)
        layout = chunks(total, sizes)
        if (
            len(sidecar) != 10 * len(layout)
            or len(plaintext_hash) != 32
            or len(encrypted_hash) != 32
        ):
            raise ValueError("Invalid range descriptor")
        if type(length) is not int or length < 0 or (length // 16 + 1) * 16 + 10 != total:
            raise ValueError("Invalid plaintext length")
        raw = json.dumps(
            dict(
                media_key=media_key.hex(),
                kind=kind,
                total=total,
                sidecar=sidecar.hex(),
                plaintext_hash=plaintext_hash.hex(),
                encrypted_hash=encrypted_hash.hex(),
                length=length,
                sizes=[n for _, n in layout],
            ),
            sort_keys=True,
        ).encode()
        with self.store.db.atomic():
            old = self.store._get("range-job", self.id)
            if old and old[0] != raw:
                raise ValueError("Range job already bound to another descriptor")
            self.store._put("range-job", self.id, raw)

    def _spec(self):
        row = self.store._get("range-job", self.id)
        if row is None:
            raise KeyError(self.id)
        return json.loads(row[0])

    def missing(self):
        with self.store.db.atomic():
            s = self._spec()
            return [
                (i, max(0, start - 16), start + n - 1)
                for i, (start, n) in enumerate(chunks(s["total"], s["sizes"]))
                if self.store._get("range-chunk", key(self.id, i)) is None
            ]

    def accept(self, index, data):
        with self.store.db.atomic():
            s = self._spec()
            decrypt_chunk(
                data,
                bytes.fromhex(s["media_key"]),
                s["kind"],
                total=s["total"],
                index=index,
                sidecar_bytes=bytes.fromhex(s["sidecar"]),
                sizes=s["sizes"],
            )
            id = key(self.id, index)
            old = self.store._get("range-chunk", id)
            if old and old[0] != data:
                raise IntegrityError("Conflicting authenticated range")
            self.store._put("range-chunk", id, data)

    def finalize(self, destination):
        # The descriptor and accepted chunks are immutable, so file I/O need not
        # hold the write transaction. Finalization is repeatable after a crash.
        s = self._spec()
        if self.missing():
            raise IntegrityError("Incomplete download")
        fd, tmp = tempfile.mkstemp(prefix=".wa-encrypted-", dir=Path(destination).parent)
        try:
            with os.fdopen(fd, "wb") as out:
                for i in range(len(s["sizes"])):
                    row = self.store._get("range-chunk", key(self.id, i))
                    if row is None:
                        raise IntegrityError("Missing cached chunk")
                    out.write(row[0][16:] if i else row[0])
            decrypt_file(
                tmp,
                destination,
                bytes.fromhex(s["media_key"]),
                s["kind"],
                plaintext_hash=bytes.fromhex(s["plaintext_hash"]),
                encrypted_hash=bytes.fromhex(s["encrypted_hash"]),
                length=s["length"],
            )
        finally:
            os.unlink(tmp)


def hash_file(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as source:
        while raw := source.read(BLOCK):
            size += len(raw)
            digest.update(raw)
    return size, digest.digest()


def sidecar_file(path, media_key, kind, *, sizes=None):
    """Compute sidecar with bounded memory, including the main MAC10 tail."""
    total = Path(path).stat().st_size
    layout = chunks(total, sizes)
    iv, _, mac_key = derive(media_key, kind)
    result = bytearray()
    previous = iv
    with open(path, "rb") as source:
        for _, size in layout:
            mac = hmac.new(mac_key, previous, "sha256")
            tail = b""
            remaining = size
            while remaining:
                raw = source.read(min(remaining, BLOCK))
                if not raw:
                    raise IntegrityError("Encrypted file changed or truncated")
                mac.update(raw)
                tail = (tail + raw)[-16:]
                remaining -= len(raw)
            result.extend(mac.digest()[:10])
            previous = tail
        if source.read(1):
            raise IntegrityError("Encrypted file grew during sidecar generation")
    return bytes(result)


__all__ = [
    "BLOCK",
    "atomic_output",
    "MediaFile",
    "encrypt_file",
    "decrypt_file",
    "RangeDownload",
    "hash_file",
    "sidecar_file",
]
