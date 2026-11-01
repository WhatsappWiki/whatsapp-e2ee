"""Ordinary media CBC/HMAC format, authenticated ranges and atomic file output."""

import hashlib
import hmac
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = {
    "image": "WhatsApp Image Keys",
    "sticker": "WhatsApp Image Keys",
    "video": "WhatsApp Video Keys",
    "gif": "WhatsApp Video Keys",
    "ptv": "WhatsApp Video Keys",
    "audio": "WhatsApp Audio Keys",
    "ptt": "WhatsApp Audio Keys",
    "document": "WhatsApp Document Keys",
    "image-thumbnail": "WhatsApp Image Thumbnail Keys",
    "video-thumbnail": "WhatsApp Video Thumbnail Keys",
    "document-thumbnail": "WhatsApp Document Thumbnail Keys",
    "link-thumbnail": "WhatsApp Link Thumbnail Keys",
    "sticker-pack": "WhatsApp Sticker Pack Keys",
    "sticker-pack-thumbnail": "WhatsApp Sticker Pack Thumbnail Keys",
}


class IntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class Media:
    media_key: bytes
    kind: str
    length: int
    plaintext_hash: bytes
    encrypted_hash: bytes
    blob: bytes


def derive(media_key, kind):
    if len(media_key) != 32:
        raise ValueError("mediaKey must contain 32 bytes")
    material = HKDF(
        algorithm=hashes.SHA256(), length=80, salt=bytes(32), info=INFO[kind].encode()
    ).derive(media_key)
    return material[:16], material[16:48], material[48:80]


def sha(raw):
    return hashlib.sha256(raw).digest()


def tag(key, raw):
    return hmac.digest(key, raw, "sha256")[:10]


def encrypt(raw, kind, *, media_key=None):
    media_key = secrets.token_bytes(32) if media_key is None else bytes(media_key)
    iv, aes, mac = derive(media_key, kind)
    p = padding.PKCS7(128).padder()
    padded = p.update(raw) + p.finalize()
    c = Cipher(algorithms.AES(aes), modes.CBC(iv)).encryptor()
    ciphertext = c.update(padded) + c.finalize()
    blob = ciphertext + tag(mac, iv + ciphertext)
    return Media(media_key, kind, len(raw), sha(raw), sha(blob), blob)


def decrypt(blob, media_key, kind, *, plaintext_hash, encrypted_hash, length=None):
    if len(blob) < 26 or (len(blob) - 10) % 16:
        raise IntegrityError("Invalid encrypted length")
    if len(encrypted_hash) != 32 or not hmac.compare_digest(sha(blob), encrypted_hash):
        raise IntegrityError("Encrypted hash mismatch")
    iv, aes, mac = derive(media_key, kind)
    if not hmac.compare_digest(tag(mac, iv + blob[:-10]), blob[-10:]):
        raise IntegrityError("MAC mismatch")
    c = Cipher(algorithms.AES(aes), modes.CBC(iv)).decryptor()
    padded = c.update(blob[:-10]) + c.finalize()
    p = padding.PKCS7(128).unpadder()
    try:
        raw = p.update(padded) + p.finalize()
    except ValueError as e:
        raise IntegrityError("Invalid padding") from e
    if len(plaintext_hash) != 32 or not hmac.compare_digest(sha(raw), plaintext_hash):
        raise IntegrityError("Plaintext hash mismatch")
    if length is not None and len(raw) != length:
        raise IntegrityError("Plaintext length mismatch")
    return raw


def decrypt_to_file(blob, media_key, kind, destination, **checks):
    # Publish only verified bytes. This full-file API buffers the complete input.
    raw = decrypt(blob, media_key, kind, **checks)
    destination = Path(destination)
    fd, tmp = tempfile.mkstemp(prefix=".wa-media-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def chunks(total, sizes=None):
    if type(total) is not int or total < 26 or (total - 10) % 16:
        raise ValueError("Invalid blob size")
    sizes = (
        list(sizes)
        if sizes is not None
        else [min(65536, total - i) for i in range(0, total, 65536)]
    )
    if (
        not sizes
        or any(type(n) is not int or n <= 0 for n in sizes)
        or sum(sizes) != total
        or any(n % 16 for n in sizes[:-1])
    ):
        raise ValueError("Invalid chunk layout")
    offsets = []
    offset = 0
    for n in sizes:
        offsets.append((offset, n))
        offset += n
    return offsets


def sidecar(blob, media_key, kind, *, sizes=None):
    iv, _, mac = derive(media_key, kind)
    return b"".join(
        tag(
            mac,
            (iv if start == 0 else blob[start - 16 : start]) + blob[start : start + n],
        )
        for start, n in chunks(len(blob), sizes)
    )


def decrypt_chunk(data, media_key, kind, *, total, index, sidecar_bytes, sizes=None):
    """data includes preceding16 for non-first chunks. Returns authenticated chunk plaintext.

    This is not complete-file success; callers must assemble and check full hashes.
    Explicit sizes are ciphertext-blob lengths, not raw JPEG scan lengths.
    """
    layout = chunks(total, sizes)
    if (
        type(index) is not int
        or not 0 <= index < len(layout)
        or len(sidecar_bytes) != 10 * len(layout)
    ):
        raise IntegrityError("Invalid sidecar/index")
    start, n = layout[index]
    if len(data) != n + (16 if start else 0):
        raise IntegrityError("Incomplete range")
    iv, aes, mac = derive(media_key, kind)
    if start:
        iv, data = data[:16], data[16:]
    if not hmac.compare_digest(tag(mac, iv + data), sidecar_bytes[index * 10 : index * 10 + 10]):
        raise IntegrityError("Chunk MAC mismatch")
    size = max(0, min(n, total - 10 - start))
    if not size:
        return b""
    c = Cipher(algorithms.AES(aes), modes.CBC(iv)).decryptor()
    raw = c.update(data[:size]) + c.finalize()
    if start + size == total - 10:
        p = padding.PKCS7(128).unpadder()
        try:
            raw = p.update(raw) + p.finalize()
        except ValueError as e:
            raise IntegrityError("Invalid final padding") from e
    return raw


class MediaStore:
    """Atomic local blob/metadata/key persistence, separate from message ratchets."""

    def __init__(self, store):
        self.store = store

    def save(self, id, value):
        import json

        decrypt(
            value.blob,
            value.media_key,
            value.kind,
            plaintext_hash=value.plaintext_hash,
            encrypted_hash=value.encrypted_hash,
            length=value.length,
        )
        meta = json.dumps(
            dict(
                kind=value.kind,
                length=value.length,
                plaintext_hash=value.plaintext_hash.hex(),
                encrypted_hash=value.encrypted_hash.hex(),
            ),
            sort_keys=True,
        ).encode()
        with self.store.db.atomic():
            old = self.store._get("media-meta", id)
            if old and (old[0] != meta or self.store._get("media-key", id)[0] != value.media_key):
                raise ValueError("Media ID already bound")
            self.store._put("media-meta", id, meta)
            self.store._put("media-key", id, value.media_key)
            self.store._put("media-blob", id, value.blob)

    def load(self, id):
        import json

        with self.store.db.atomic():
            meta = self.store._get("media-meta", id)
            if meta is None:
                raise KeyError(id)
            m = json.loads(meta[0])
            return Media(
                self.store._get("media-key", id)[0],
                m["kind"],
                m["length"],
                bytes.fromhex(m["plaintext_hash"]),
                bytes.fromhex(m["encrypted_hash"]),
                self.store._get("media-blob", id)[0],
            )


__all__ = [
    "INFO",
    "IntegrityError",
    "Media",
    "derive",
    "sha",
    "tag",
    "encrypt",
    "decrypt",
    "decrypt_to_file",
    "chunks",
    "sidecar",
    "decrypt_chunk",
    "MediaStore",
]
