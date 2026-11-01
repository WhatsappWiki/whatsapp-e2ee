import os
from dataclasses import replace

import pytest

from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media import IntegrityError, encrypt, sidecar
from whatsapp_e2ee.media_files import RangeDownload, decrypt_file, encrypt_file


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 65519, 65520, 65535, 65536, 65537, 200003])
@pytest.mark.parametrize("kind", ["image", "video", "audio", "document"])
def test_stream_files_match_memory(tmp_path, size, kind):
    raw = bytes(range(251)) * (size // 251) + bytes(range(size % 251))
    source, blob, output = [tmp_path / n for n in ("plain", "blob", "out")]
    source.write_bytes(raw)
    expected = encrypt(raw, kind, media_key=bytes(range(32)))
    result = encrypt_file(source, blob, kind, media_key=expected.media_key)
    assert blob.read_bytes() == expected.blob
    assert result.plaintext_hash == expected.plaintext_hash
    assert result.encrypted_hash == expected.encrypted_hash
    assert result.length == size
    assert (
        decrypt_file(
            blob,
            output,
            result.media_key,
            kind,
            plaintext_hash=result.plaintext_hash,
            encrypted_hash=result.encrypted_hash,
            length=size,
        )
        == size
    )
    assert output.read_bytes() == raw
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("damage", ["tag", "truncate", "append", "plainhash", "key", "length"])
def test_file_failure_keeps_destination(tmp_path, damage):
    m = encrypt(b"data" * 40000, "video")
    blob = m.blob
    if damage == "tag":
        blob = blob[:-1] + bytes([blob[-1] ^ 1])
    elif damage == "truncate":
        blob = blob[:-1]
    elif damage == "append":
        blob += b"x"
    elif damage == "plainhash":
        m = replace(m, plaintext_hash=b"x" * 32)
    elif damage == "key":
        m = replace(m, media_key=b"x" * 32)
    elif damage == "length":
        m = replace(m, length=m.length + 1)
    source, out = tmp_path / "blob", tmp_path / "out"
    source.write_bytes(blob)
    out.write_bytes(b"existing")
    with pytest.raises(IntegrityError):
        decrypt_file(
            source,
            out,
            m.media_key,
            m.kind,
            plaintext_hash=m.plaintext_hash,
            encrypted_hash=m.encrypted_hash,
            length=m.length,
        )
    assert out.read_bytes() == b"existing"
    assert not list(tmp_path.glob(".wa-*"))


@pytest.mark.parametrize("size,sizes", [(65520, None), (200000, None), (62, [16, 32, 26])])
def test_ranges_restart_reorder_and_final_validation(tmp_path, size, sizes):
    m = encrypt(os.urandom(size), "image")
    path = tmp_path / "state.db"
    db = Database(path)
    job = RangeDownload(SQLiteStore(db, "owner"), "download")
    args = dict(
        total=len(m.blob),
        sidecar=sidecar(m.blob, m.media_key, m.kind, sizes=sizes),
        plaintext_hash=m.plaintext_hash,
        encrypted_hash=m.encrypted_hash,
        length=m.length,
        sizes=sizes,
    )
    job.initialize(m.media_key, m.kind, **args)
    output = tmp_path / "out"
    with pytest.raises(IntegrityError):
        job.finalize(output)
    ranges = job.missing()
    index, start, end = ranges[-1]
    with pytest.raises(IntegrityError):
        job.accept(index, m.blob[start:end])  # short read
    job.accept(index, m.blob[start : end + 1])
    db.close()
    db = Database(path)
    job = RangeDownload(SQLiteStore(db, "owner"), "download")
    job.initialize(m.media_key, m.kind, **args)
    for index, start, end in reversed(job.missing()):
        job.accept(index, m.blob[start : end + 1])
        job.accept(index, m.blob[start : end + 1])
    assert job.missing() == []
    job.finalize(output)
    from whatsapp_e2ee.media import decrypt

    assert output.read_bytes() == decrypt(
        m.blob,
        m.media_key,
        m.kind,
        plaintext_hash=m.plaintext_hash,
        encrypted_hash=m.encrypted_hash,
    )
    job.finalize(output)
    with pytest.raises(ValueError):
        job.initialize(bytes(32), m.kind, **args)
    # Local cache corruption must fail whole-file checks even after all chunks
    # were accepted and persisted as individually authenticated.
    row = job.store._get("range-chunk", '["download",0]')[0]
    job.store._put("range-chunk", '["download",0]', bytes([row[0] ^ 1]) + row[1:])
    before = output.read_bytes()
    with pytest.raises(IntegrityError):
        job.finalize(output)
    assert output.read_bytes() == before
