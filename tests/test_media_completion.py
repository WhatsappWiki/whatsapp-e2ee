import base64
import hashlib
import json
from pathlib import Path

import pytest

from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media import IntegrityError, decrypt, encrypt, sidecar
from whatsapp_e2ee.media_files import RangeDownload, sidecar_file
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_layout import scan_chunk_sizes, scan_prefix_length
from whatsapp_e2ee.media_transfer import (
    Reconciliation,
    Response,
    TransferError,
    UploadReceipt,
    Uploads,
    UploadUncertain,
    download_all,
    download_range,
    json_upload_receipt,
)


def jobs(tmp_path):
    return MediaJobs(SQLiteStore(Database(tmp_path / "media.db"), "owner"), clock_ms=lambda: 123000)


@pytest.mark.parametrize(
    "scans,expected",
    [
        ([1, 1], (26,)),
        ([16, 16], (16, 42)),
        ([10, 10, 10, 10], (16, 16, 26)),
        ([15, 1, 1], (16, 26)),
        ([17, 1, 1], (42,)),
        ([31, 33, 5, 19], (32, 32, 16, 26)),
        ([32, 1], (32, 26)),
    ],
)
def test_native_scan_rounding_tail_merge(scans, expected):
    assert scan_chunk_sizes(scans) == expected
    assert scan_prefix_length(scans) == (sum(scans[:3]) if len(scans) == 4 else None)
    m = encrypt(bytes(sum(scans)), "image")
    tags = sidecar(m.blob, m.media_key, m.kind, sizes=expected)
    assert len(tags) == 10 * len(expected)


@pytest.mark.parametrize("scans", [[], [1], [0, 1], [-1, 2], [True, 2], [2**31, 1], [2**31 - 1, 1]])
def test_invalid_scan_lengths(scans):
    with pytest.raises(ValueError):
        scan_chunk_sizes(scans)


def test_file_job_restart_rebuild_and_source_mutation(tmp_path, monkeypatch):
    j = jobs(tmp_path)
    source = tmp_path / "source"
    raw = bytes(range(251)) * 3000
    source.write_bytes(raw)
    value = j.prepare_file("id", source, "image", tmp_path / "cache")
    assert not j.store._get("media-blob", "id")
    assert value.length == len(raw)
    root = value.media_key
    saved = value.path.read_bytes()
    tags = sidecar_file(value.path, root, "image")
    assert tags == sidecar(saved, root, "image")
    j.store.db.close()
    j = jobs(tmp_path)
    assert j.prepare_file("id", source, "image", tmp_path / "cache").media_key == root
    value.path.unlink()
    assert j.prepare_file("id", source, "image", tmp_path / "cache").path.read_bytes() == saved
    source.write_bytes(b"changed")
    with pytest.raises(ValueError):
        j.prepare_file("id", source, "image", tmp_path / "cache")
    assert value.path.read_bytes() == saved

    import whatsapp_e2ee.media_jobs as module

    original = module.encrypt_file

    def mutate(source, *args, **kwargs):
        Path(source).write_bytes(b"different after hashing")
        return original(source, *args, **kwargs)

    monkeypatch.setattr(module, "encrypt_file", mutate)
    with pytest.raises(ValueError):
        j.prepare_file("mutated", source, "image", tmp_path / "cache")
    assert j.store._get("media-file", "mutated") is None
    assert j.store._get("media-state", "mutated")[0] == b"preparing"
    assert not list((tmp_path / "cache").glob(".wa-job-*"))


def test_file_reservation_survives_encryption_failure(tmp_path, monkeypatch):
    j = jobs(tmp_path)
    source = tmp_path / "source"
    source.write_bytes(b"file")
    import whatsapp_e2ee.media_jobs as module

    original = module.encrypt_file

    def fail(*a, **kw):
        raise OSError("simulated interrupted encryption")

    monkeypatch.setattr(module, "encrypt_file", fail)
    with pytest.raises(OSError):
        j.prepare_file("job", source, "document", tmp_path / "cache")
    reserve = json.loads(j.store._get("media-file-reservation", "job")[0])
    monkeypatch.setattr(module, "encrypt_file", original)
    m = j.prepare_file("job", source, "document", tmp_path / "cache")
    assert m.media_key.hex() == reserve["media_key"]
    assert j.store._get("media-state", "job")[0] == b"prepared"


def ranged(tmp_path, size=150000):
    m = encrypt(b"x" * size, "video")
    j = jobs(tmp_path)
    r = RangeDownload(j.store, "download")
    r.initialize(
        m.media_key,
        m.kind,
        total=len(m.blob),
        sidecar=sidecar(m.blob, m.media_key, m.kind),
        plaintext_hash=m.plaintext_hash,
        encrypted_hash=m.encrypted_hash,
        length=m.length,
    )
    return m, r


def test_http_range_adapter_resume_and_transactions(tmp_path):
    m, r = ranged(tmp_path)
    calls, closed = [], []

    def transport(request):
        assert not r.store.db.connection.in_transaction
        h = dict(request.headers)
        start, end = map(int, h["range"][6:].split("-"))
        calls.append((start, end))
        assert request.method == "GET" and h["accept-encoding"] == "identity"
        raw = m.blob[start : end + 1]
        return Response(
            206,
            {
                "Content-Range": f"bytes {start}-{end}/{len(m.blob)}",
                "Content-Length": str(len(raw)),
            },
            (raw[:17], raw[17:]),
            lambda: closed.append(True),
        )

    download_range(r, 1, "https://media.invalid/blob", transport)
    assert not download_range(r, 1, "https://media.invalid/blob", transport)
    r.store.db.close()
    j = jobs(tmp_path)
    r = RangeDownload(j.store, "download")
    destination = tmp_path / "result"
    download_all(r, "https://media.invalid/blob", transport, destination)
    assert destination.read_bytes() == b"x" * m.length
    assert len(closed) == len(calls) == 3
    assert calls[0][0] == 65536 - 16


@pytest.mark.parametrize(
    "mode",
    [
        "status",
        "redirect",
        "range",
        "length",
        "encoding",
        "duplicate",
        "short",
        "long",
        "tamper",
        "exception",
    ],
)
def test_range_rejects_bad_response_without_accepting(tmp_path, mode):
    m, r = ranged(tmp_path)
    closed = []
    raw = m.blob[:65536]
    headers = [("Content-Range", f"bytes 0-65535/{len(m.blob)}"), ("Content-Length", "65536")]
    status = 206
    if mode == "status":
        status = 200
    if mode == "redirect":
        status = 302
    if mode == "range":
        headers[0] = ("Content-Range", f"bytes 1-65536/{len(m.blob)}")
    if mode == "length":
        headers[1] = ("Content-Length", "65535")
    if mode == "encoding":
        headers.append(("Content-Encoding", "gzip"))
    if mode == "duplicate":
        headers.append(("CONTENT-LENGTH", "65536"))
    if mode == "short":
        raw = raw[:-1]
    if mode == "long":
        raw += b"x"
    if mode == "tamper":
        raw = bytes([raw[0] ^ 1]) + raw[1:]
    if mode == "exception":

        def interrupted(data=raw):
            yield data[:30]
            raise OSError("connection interrupted")

        raw = interrupted()

    def transport(request):
        return Response(status, headers, raw, lambda: closed.append(True))

    with pytest.raises((TransferError, IntegrityError, OSError)):
        download_range(r, 0, "https://media.invalid/blob", transport)
    assert len(r.missing()) == 3
    assert closed == [True]


def test_single_full_range_may_be_200(tmp_path):
    m, r = ranged(tmp_path, 10)
    download_all(
        r,
        "https://media.invalid/blob",
        lambda q: Response(200, {"content-length": str(len(m.blob))}, m.blob),
        tmp_path / "out",
    )
    assert (tmp_path / "out").read_bytes() == b"x" * 10


def success_reply(m):
    return json.dumps(
        dict(
            direct_path="/blob",
            timestamp_ms=123000,
            file_enc_sha256=base64.b64encode(m.encrypted_hash).decode(),
        )
    ).encode()


@pytest.mark.parametrize("on_disk", [False, True])
def test_upload_adapter_multipart_checkpoint_and_no_resend(tmp_path, on_disk):
    j = jobs(tmp_path)
    source = tmp_path / "source"
    source.write_bytes(b"test" * 20000)
    m = (
        j.prepare_file("job", source, "document", tmp_path / "cache")
        if on_disk
        else j.prepare("job", source.read_bytes(), "document")
    )
    manager, calls = Uploads(j), []

    def transport(request):
        assert not j.store.db.connection.in_transaction
        assert manager.pending("job")["state"] == "in_flight"
        raw = b"".join(request.body)
        h = dict(request.headers)
        assert len(raw) == int(h["content-length"])
        assert b'name="file"' in raw
        blob = raw.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        assert hashlib.sha256(blob).digest() == m.encrypted_hash
        assert hashlib.sha256(raw).digest() != m.encrypted_hash
        calls.append(request)
        return Response(200, {}, success_reply(m))

    receipt = manager.send("job", "https://media.invalid/upload", transport, json_upload_receipt)
    assert receipt == UploadReceipt("/blob", 123000, m.encrypted_hash)
    assert (
        manager.send("job", "https://media.invalid/upload", transport, json_upload_receipt)
        == receipt
    )
    assert len(calls) == 1
    assert j.store._get("media-state", "job")[0] == b"uploaded"


@pytest.mark.parametrize("failure", ["timeout", "response", "undrained", "bad_hash", "checkpoint"])
def test_unknown_upload_does_not_automatically_retry(tmp_path, failure):
    j = jobs(tmp_path)
    m = j.prepare("job", b"file", "image")
    manager, calls = Uploads(j), []

    def transport(request):
        calls.append(request)
        if failure == "undrained":
            return Response(200, {}, success_reply(m))
        b"".join(request.body)
        if failure == "timeout":
            raise TimeoutError("result lost")
        if failure == "response":
            return Response(500, {}, b"oops")
        if failure == "bad_hash":
            return Response(200, {}, success_reply(encrypt(b"other", "image")))
        return Response(200, {}, success_reply(m))

    if failure == "checkpoint":
        with j.store.db.atomic() as c:
            c.execute(
                "CREATE TRIGGER fail_upload BEFORE INSERT ON records WHEN NEW.kind='media-upload' BEGIN SELECT RAISE(ABORT,'checkpoint failed'); END"
            )
    with pytest.raises(Exception):
        manager.send("job", "https://media.invalid/upload", transport, json_upload_receipt)
    assert manager.pending("job")["state"] == "unknown"
    if failure == "checkpoint":
        with j.store.db.atomic() as c:
            c.execute("DROP TRIGGER fail_upload")
    j.store.db.close()
    j = jobs(tmp_path)
    manager = Uploads(j)
    with pytest.raises(UploadUncertain):
        manager.send("job", "https://media.invalid/upload", transport, json_upload_receipt)
    assert len(calls) == 1
    assert manager.reconcile("job", lambda a: Reconciliation("unknown")) is None
    with pytest.raises(UploadUncertain):
        manager.send("job", "https://media.invalid/upload", transport, json_upload_receipt)
    receipt = UploadReceipt("/recovered", 123000, m.encrypted_hash)
    assert manager.reconcile("job", lambda a: Reconciliation("found", receipt)) == receipt
    assert j.store._get("media-state", "job")[0] == b"uploaded"


def test_upload_explicit_absence_allows_bounded_new_attempt(tmp_path):
    j = jobs(tmp_path)
    j.prepare("job", b"file", "document")
    manager = Uploads(j)

    def fail(request):
        b"".join(request.body)
        raise TimeoutError()

    for expected in (1, 2):
        with pytest.raises(TimeoutError):
            manager.send(
                "job", "https://media.invalid/upload", fail, json_upload_receipt, max_attempts=2
            )
        assert manager.pending("job")["count"] == expected
        manager.reconcile("job", lambda a: Reconciliation("absent"))
    with pytest.raises(TransferError):
        manager.send(
            "job", "https://media.invalid/upload", fail, json_upload_receipt, max_attempts=2
        )


@pytest.mark.parametrize("kind", ["image", "video", "document", "gif", "ptv"])
def test_thumbnail_binding_same_root_domains_and_metadata(tmp_path, kind):
    j = jobs(tmp_path)
    parent = j.prepare("parent", b"parent", kind)
    thumb = j.prepare_thumbnail("parent", "thumb", b"thumbnail")
    assert parent.media_key == thumb.media_key
    assert thumb.kind.endswith("-thumbnail")
    assert (
        thumb.encrypted_hash
        != encrypt(b"thumbnail", parent.kind, media_key=parent.media_key).encrypted_hash
    )
    j.mark_uploaded("parent", "/parent", 123000)
    j.mark_uploaded("thumb", "/thumb", 123000)
    meta = j.thumbnail_metadata("parent", "thumb")
    assert meta["thumbnail_sha256"] == thumb.plaintext_hash
    assert j.prepare_thumbnail("parent", "thumb", b"thumbnail") == thumb
    with pytest.raises(ValueError):
        j.prepare_thumbnail("parent", "thumb", b"changed")
    with pytest.raises(ValueError):
        j.thumbnail_metadata("wrong", "thumb")
    assert (
        decrypt(
            thumb.blob,
            parent.media_key,
            thumb.kind,
            plaintext_hash=thumb.plaintext_hash,
            encrypted_hash=thumb.encrypted_hash,
        )
        == b"thumbnail"
    )


def test_scan_metadata_on_large_file(tmp_path):
    j = jobs(tmp_path)
    source = tmp_path / "image"
    scans = [65535, 22, 45, 77]
    source.write_bytes(b"x" * sum(scans))
    m = j.prepare_file("image", source, "image", tmp_path / "cache")
    metadata = j.scan_metadata("image", scans)
    assert metadata["scan_lengths"] == tuple(scans)
    assert metadata["scans_sidecar"] == sidecar(
        m.path.read_bytes(), m.media_key, "image", sizes=scan_chunk_sizes(scans)
    )


@pytest.mark.parametrize(
    "mode", ["success", "short", "excess", "length", "wrong_hash", "encoded", "redirect"]
)
def test_complete_http_download_publication(tmp_path, mode):
    from dataclasses import replace

    from whatsapp_e2ee.media_transfer import download_file

    m = encrypt(b"media" * 17000, "document")
    raw = m.blob
    headers = {"Content-Length": str(len(raw))}
    status = 200
    if mode == "short":
        raw = raw[:-1]
    elif mode == "excess":
        raw += b"x"
    elif mode == "length":
        headers["Content-Length"] = "1"
    elif mode == "wrong_hash":
        m = replace(m, plaintext_hash=bytes(32))
    elif mode == "encoded":
        headers["Content-Encoding"] = "gzip"
    elif mode == "redirect":
        status = 302
    closed = []

    def transport(request):
        assert dict(request.headers)["accept-encoding"] == "identity"
        return Response(
            status,
            headers,
            (raw[i : i + 97] for i in range(0, len(raw), 97)),
            lambda: closed.append(True),
        )

    destination = tmp_path / "out"
    destination.write_bytes(b"old")
    if mode == "success":
        assert download_file("https://media.invalid/blob", transport, destination, m) == m.length
        assert destination.read_bytes() == b"media" * 17000
    else:
        with pytest.raises((TransferError, IntegrityError)):
            download_file("https://media.invalid/blob", transport, destination, m)
        assert destination.read_bytes() == b"old"
    assert closed == [True]
    assert not list(tmp_path.glob(".wa-*"))


def test_valid_mac_and_hash_but_bad_padding_not_published(tmp_path):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from whatsapp_e2ee.media import derive, tag
    from whatsapp_e2ee.media_files import decrypt_file

    root = bytes(range(32))
    iv, aes, mac = derive(root, "image")
    c = Cipher(algorithms.AES(aes), modes.CBC(iv)).encryptor()
    ciphertext = c.update(bytes(16)) + c.finalize()
    blob = ciphertext + tag(mac, iv + ciphertext)
    source, destination = tmp_path / "blob", tmp_path / "out"
    source.write_bytes(blob)
    destination.write_bytes(b"old")
    with pytest.raises(IntegrityError, match="padding"):
        decrypt_file(
            source,
            destination,
            root,
            "image",
            plaintext_hash=hashlib.sha256(b"").digest(),
            encrypted_hash=hashlib.sha256(blob).digest(),
        )
    assert destination.read_bytes() == b"old"


@pytest.mark.parametrize("scans", [[1, 1], [10, 10, 10, 10], [16] * 21])
def test_public_image_metadata_rejects_native_parser_incompatible_layout(tmp_path, scans):
    j = jobs(tmp_path)
    j.prepare("image", bytes(sum(scans)), "image")
    with pytest.raises(ValueError, match="receiver constraints"):
        j.scan_metadata("image", scans)


@pytest.mark.parametrize(
    "url",
    [
        "http://media.invalid/file",
        "https://name:secret@media.invalid/file",
        "https://media.invalid/a\r\nX: bad",
        "https://media.invalid/a#fragment",
    ],
)
def test_bad_endpoint_never_calls_transport(tmp_path, url):
    _, r = ranged(tmp_path)

    def forbidden(request):
        pytest.fail("transport must not be invoked")

    with pytest.raises(ValueError):
        download_range(r, 0, url, forbidden)


def test_thumbnail_timestamp_mismatch_rejected(tmp_path):
    j = jobs(tmp_path)
    j.prepare("parent", b"parent", "image")
    j.prepare_thumbnail("parent", "thumb", b"thumb")
    j.mark_uploaded("parent", "/parent")
    with pytest.raises(ValueError, match="timestamp"):
        j.mark_uploaded("thumb", "/thumb", 2000)


def test_media_key_time_created_once_not_upload_time(tmp_path):
    now = [1000]
    j = MediaJobs(SQLiteStore(Database(tmp_path / "time.db"), "owner"), clock_ms=lambda: now[0])
    first = j.prepare("id", b"first", "image")
    now[0] = 9000
    assert j.prepare("id", b"first", "image") == first
    assert j.key_timestamp_ms("id") == 1000
    with pytest.raises(ValueError, match="timestamp"):
        j.mark_uploaded("id", "/path", 9000)
    j.mark_uploaded("id", "/path")
    from whatsapp_e2ee.payload import parse

    assert parse(j.descriptor("id")).image_message.media_key_timestamp == 1
    j.prepare_thumbnail("id", "thumb", b"thumb")
    assert j.key_timestamp_ms("thumb") == 1000
    j.mark_uploaded("thumb", "/thumb")
    assert j.thumbnail_metadata("id", "thumb")["thumbnail_direct_path"] == "/thumb"
    with pytest.raises(ValueError, match="timestamp"):
        j.prepare("id", b"first", "image", media_key_timestamp_ms=5000)


def test_explicit_legacy_timestamp_mode(tmp_path):
    j = jobs(tmp_path)
    j.prepare("legacy", b"media", "image", media_key_timestamp_ms=None)
    assert j.key_timestamp_ms("legacy") is None
    with pytest.raises(ValueError, match="timestamp"):
        j.prepare_thumbnail("legacy", "thumb", b"thumb")
    with pytest.raises(ValueError, match="timestamp"):
        j.mark_uploaded("legacy", "/path")
    j.mark_uploaded("legacy", "/path", 123000)
    assert j.key_timestamp_ms("legacy") == 123000
    j.prepare_thumbnail("legacy", "thumb", b"thumb")
    assert j.key_timestamp_ms("thumb") == 123000


def test_memory_media_corruption_rejected_before_transport(tmp_path):
    j = jobs(tmp_path)
    j.prepare("job", b"media", "image")
    raw = j.store._get("media-blob", "job")[0]
    j.store._put("media-blob", "job", bytes([raw[0] ^ 1]) + raw[1:])

    def forbidden(q):
        pytest.fail("corrupt local content must fail before transport")

    with pytest.raises(IntegrityError):
        Uploads(j).send("job", "https://media.invalid/upload", forbidden, json_upload_receipt)
    assert Uploads(j).pending("job") is None


def test_sidecar_file_detects_truncated_input(tmp_path, monkeypatch):
    import io

    import whatsapp_e2ee.media_files as module

    m = encrypt(b"input" * 20000, "video")
    path = tmp_path / "blob"
    path.write_bytes(m.blob)
    monkeypatch.setattr(module, "open", lambda *a, **kw: io.BytesIO(m.blob[:-11]), raising=False)
    with pytest.raises(IntegrityError, match="truncated"):
        sidecar_file(path, m.media_key, m.kind)


def test_thumbnail_and_scan_metadata_payload(tmp_path):
    from whatsapp_e2ee.payload import parse

    j = jobs(tmp_path)
    scans = (32, 33, 64, 65)
    j.prepare("parent", b"image" * 38 + b"tail", "image")
    j.prepare_thumbnail("parent", "thumb", b"thumbnail")
    j.mark_uploaded("parent", "/parent")
    j.mark_uploaded("thumb", "/thumb")
    metadata = {**j.scan_metadata("parent", scans), **j.thumbnail_metadata("parent", "thumb")}
    message = parse(j.descriptor("parent", **metadata)).image_message
    assert list(message.scan_lengths) == list(scans)
    assert message.thumbnail_direct_path == "/thumb"
    assert message.scans_sidecar == metadata["scans_sidecar"]
    assert message.DESCRIPTOR.fields_by_name["thumbnail_direct_path"].number == 26
    assert message.DESCRIPTOR.fields_by_name["scan_lengths"].number == 22


def test_file_job_process_exit_after_blob_before_metadata(tmp_path):
    import subprocess
    import sys

    source = tmp_path / "source"
    source.write_bytes(b"restartable media" * 5000)
    script = """
import os, sys
from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media_jobs import MediaJobs
s = SQLiteStore(Database(sys.argv[1]), "owner")
j = MediaJobs(s, clock_ms=lambda: 123000)
put = s._put
def exit_before_metadata(kind, id, *a, **kw):
    if kind == "media-file":
        os._exit(29)
    return put(kind, id, *a, **kw)
s._put = exit_before_metadata
j.prepare_file("crashed", sys.argv[2], "video", sys.argv[3])
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(tmp_path / "media.db"),
            str(source),
            str(tmp_path / "cache"),
        ],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 29, result.stderr
    j = jobs(tmp_path)
    reservation = json.loads(j.store._get("media-file-reservation", "crashed")[0])
    assert j.store._get("media-file", "crashed") is None
    published = Path(reservation["path"]).read_bytes()
    recovered = j.prepare_file("crashed", source, "video", tmp_path / "cache")
    assert recovered.path.read_bytes() == published
    assert recovered.media_key.hex() == reservation["media_key"]
    assert j.key_timestamp_ms("crashed") == 123000
    assert j.store._get("media-state", "crashed")[0] == b"prepared"
