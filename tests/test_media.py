import json
from pathlib import Path

import pytest

from whatsapp_e2ee import media

VECTORS = json.loads((Path(__file__).parent / "vectors/media.json").read_text())["vectors"]


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["type"] + "-" + str(v["plaintext_length"]))
def test_independent_node_vectors(v):
    p = bytes((i * 29 + 7) & 255 for i in range(v["plaintext_length"]))
    result = media.encrypt(p, v["type"].lower(), media_key=bytes(range(32)))
    iv, aes, mac = media.derive(result.media_key, result.kind)
    assert (iv.hex(), aes.hex(), mac.hex()) == (v["iv_hex"], v["cipher_key_hex"], v["mac_key_hex"])
    if "blob_hex" in v:
        assert result.blob.hex() == v["blob_hex"]
    assert result.encrypted_hash.hex() == v["encrypted_blob_sha256"]
    assert result.plaintext_hash.hex() == v["plaintext_sha256"]
    assert result.blob[-10:].hex() == v["mac10_hex"]
    assert (
        media.decrypt(
            result.blob,
            result.media_key,
            result.kind,
            plaintext_hash=result.plaintext_hash,
            encrypted_hash=result.encrypted_hash,
            length=len(p),
        )
        == p
    )
    sc = media.sidecar(result.blob, result.media_key, result.kind)
    recovered = []
    for i, (start, n) in enumerate(media.chunks(len(result.blob))):
        recovered.append(
            media.decrypt_chunk(
                result.blob[max(0, start - 16) : start + n],
                result.media_key,
                result.kind,
                total=len(result.blob),
                index=i,
                sidecar_bytes=sc,
            )
        )
    assert b"".join(recovered) == p


@pytest.mark.parametrize(
    "change",
    [
        "key",
        "kind",
        "cipher",
        "tag",
        "enc_hash",
        "plain_hash",
        "length",
        "truncated",
        "extra",
    ],
)
def test_corrupt_media_not_published(tmp_path, change):
    m = media.encrypt(b"private data", "image")
    b, k, kind, ph, eh, n = (
        m.blob,
        m.media_key,
        m.kind,
        m.plaintext_hash,
        m.encrypted_hash,
        m.length,
    )
    if change == "key":
        k = bytes(32)
    if change == "kind":
        kind = "video"
    if change == "cipher":
        b = bytes([b[0] ^ 1]) + b[1:]
    if change == "tag":
        b = b[:-1] + bytes([b[-1] ^ 1])
    if change == "enc_hash":
        eh = bytes(32)
    if change == "plain_hash":
        ph = bytes(32)
    if change == "length":
        n += 1
    if change == "truncated":
        b = b[:-1]
    if change == "extra":
        b += b"x"
    dst = tmp_path / "result"
    dst.write_bytes(b"previous")
    with pytest.raises(media.IntegrityError):
        media.decrypt_to_file(b, k, kind, dst, plaintext_hash=ph, encrypted_hash=eh, length=n)
    assert dst.read_bytes() == b"previous"
    assert list(tmp_path.iterdir()) == [dst]


def test_variable_sidecar_and_tamper():
    m = media.encrypt(bytes(100), "video")
    sizes = [16, 32, len(m.blob) - 48]
    tags = media.sidecar(m.blob, m.media_key, m.kind, sizes=sizes)
    parts = []
    for i, (start, n) in enumerate(media.chunks(len(m.blob), sizes)):
        raw = m.blob[max(0, start - 16) : start + n]
        parts.append(
            media.decrypt_chunk(
                raw,
                m.media_key,
                m.kind,
                total=len(m.blob),
                index=i,
                sidecar_bytes=tags,
                sizes=sizes,
            )
        )
        with pytest.raises(media.IntegrityError):
            media.decrypt_chunk(
                raw,
                m.media_key,
                m.kind,
                total=len(m.blob),
                index=i,
                sidecar_bytes=bytes(len(tags)),
                sizes=sizes,
            )
    assert b"".join(parts) == bytes(100)


def test_thumbnail_domain():
    key = bytes(range(32))
    assert media.derive(key, "image") != media.derive(key, "image-thumbnail")
    assert media.derive(key, "image") == media.derive(key, "sticker")
