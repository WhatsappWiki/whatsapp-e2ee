"""Download cache repair, authenticated chunk boundaries and publication."""

from dataclasses import replace

import pytest

from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media import IntegrityError, chunks, decrypt_chunk, encrypt, sidecar
from whatsapp_e2ee.media_files import RangeDownload
from whatsapp_e2ee.media_transfer import (
    Response,
    TransferError,
    download_all,
    download_file,
    download_range,
)
from whatsapp_e2ee.store import key

URL = "https://media.invalid/blob"


@pytest.fixture
def jobs(tmp_path):
    opened = []

    def create(size=150000):
        media = encrypt(bytes((i % 251 for i in range(size))), "video", media_key=bytes(range(32)))
        db = Database(tmp_path / "state.db")
        opened.append(db)
        job = RangeDownload(SQLiteStore(db, "owner"), "download")
        job.initialize(
            media.media_key,
            media.kind,
            total=len(media.blob),
            sidecar=sidecar(media.blob, media.media_key, media.kind),
            plaintext_hash=media.plaintext_hash,
            encrypted_hash=media.encrypted_hash,
            length=media.length,
        )
        return media, job

    yield create
    for db in opened:
        db.close()


def accept_all(job, media):
    ranges = job.missing()
    for index, start, end in ranges:
        job.accept(index, media.blob[start : end + 1])
    return ranges


def responder(media, calls):
    def transport(request):
        fields = dict(request.headers)
        start, end = map(int, fields["range"][6:].split("-"))
        calls.append((start, end))
        return Response(
            206,
            {"Content-Range": f"bytes {start}-{end}/{len(media.blob)}"},
            media.blob[start : end + 1],
        )

    return transport


@pytest.mark.parametrize("index", [False, True, 0.0, 1.0, -1, None, "0", 3])
def test_invalid_index_rejected_before_cache_or_network(jobs, index):
    media, job = jobs()
    selected = int(index) if isinstance(index, (int, float)) and 0 <= index < 3 else 0
    _, start, end = job.missing()[selected]
    with pytest.raises(ValueError):
        job.accept(index, media.blob[start : end + 1])
    with pytest.raises(ValueError):
        decrypt_chunk(
            media.blob[start : end + 1],
            media.media_key,
            media.kind,
            total=len(media.blob),
            index=index,
            sidecar_bytes=sidecar(media.blob, media.media_key, media.kind),
        )
    with pytest.raises(ValueError):
        download_range(job, index, URL, lambda *_: pytest.fail("Invalid index caused a GET"))
    assert len(job.missing()) == 3


@pytest.mark.parametrize("total", [26.0, 42.0, True])
def test_chunk_total_must_be_integer(total):
    with pytest.raises(ValueError):
        chunks(total, [int(total)])


@pytest.mark.parametrize("id", [None, "", 1, True])
def test_range_job_requires_stable_string_id(tmp_path, id):
    db = Database(tmp_path / "state.db")
    try:
        with pytest.raises(ValueError):
            RangeDownload(SQLiteStore(db, "owner"), id)
    finally:
        db.close()


@pytest.mark.parametrize("damage", ["overlap", "ciphertext", "truncated"])
def test_corrupt_cached_chunk_is_refetched_after_restart(jobs, tmp_path, damage):
    media, job = jobs()
    ranges = accept_all(job, media)
    _, start, end = ranges[1]
    cached = job.store._get("range-chunk", key(job.id, 1))[0]
    position = 0 if damage == "overlap" else 20
    bad = (
        cached[:-1]
        if damage == "truncated"
        else cached[:position] + bytes([cached[position] ^ 1]) + cached[position + 1 :]
    )
    job.store._put("range-chunk", key(job.id, 1), bad)
    job.store.db.close()
    media, job = jobs()
    assert job.missing() == [(1, start, end)]
    calls = []
    download_all(job, URL, responder(media, calls), tmp_path / "out")
    assert calls == [(start, end)]
    assert (tmp_path / "out").read_bytes() == bytes((i % 251 for i in range(media.length)))


def test_valid_response_can_replace_corrupt_cached_range(jobs, tmp_path):
    media, job = jobs()
    index, start, end = job.missing()[1]
    valid = media.blob[start : end + 1]
    job.accept(index, valid)
    job.store._put("range-chunk", key(job.id, index), valid[:-1])
    job.accept(index, valid)
    assert job.store._get("range-chunk", key(job.id, index))[0] == valid


def test_corrupt_overlap_is_not_ignored_during_finalization(jobs, tmp_path):
    media, job = jobs()
    accept_all(job, media)
    cached = job.store._get("range-chunk", key(job.id, 1))[0]
    job.store._put("range-chunk", key(job.id, 1), bytes([cached[0] ^ 1]) + cached[1:])
    out = tmp_path / "out"
    out.write_bytes(b"previous")
    with pytest.raises(IntegrityError):
        job.finalize(out)
    assert out.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".wa-*"))


@pytest.mark.parametrize("operation", ["range", "all", "finalize"])
@pytest.mark.parametrize("outer", ["atomic", "raw"])
def test_download_callbacks_and_publication_reject_outer_transaction(
    jobs, tmp_path, operation, outer
):
    media, job = jobs(20)
    if operation == "finalize":
        accept_all(job, media)
    out = tmp_path / "out"
    out.write_bytes(b"previous")

    def attempt():
        with pytest.raises(RuntimeError, match="transaction"):
            if operation == "range":
                download_range(job, 0, URL, lambda *_: pytest.fail("GET under active transaction"))
            elif operation == "all":
                download_all(job, URL, lambda *_: pytest.fail("GET under active transaction"), out)
            else:
                job.finalize(out)

    if outer == "atomic":
        with job.store.db.atomic():
            attempt()
    else:
        job.store.db.connection.execute("BEGIN IMMEDIATE")
        try:
            attempt()
        finally:
            job.store.db.connection.rollback()
    assert out.read_bytes() == b"previous"


@pytest.mark.parametrize("ranged", [False, True])
def test_response_close_failure_does_not_publish_or_accept(jobs, tmp_path, ranged):
    media, job = jobs(20)
    out = tmp_path / "out"
    out.write_bytes(b"previous")
    closed = []

    def close():
        closed.append(True)
        raise OSError("close failed")

    response = Response(200, {}, media.blob, close)
    with pytest.raises(OSError, match="close failed"):
        if ranged:
            download_range(job, 0, URL, lambda _: response)
        else:
            download_file(URL, lambda _: response, out, media)
    assert closed == [True]
    assert out.read_bytes() == b"previous"
    assert len(job.missing()) == 1
    assert not list(tmp_path.glob(".wa-*"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("length", -1),
        ("length", False),
        ("length", 20.0),
        ("plaintext_hash", b"short"),
        ("encrypted_hash", b"short"),
        ("media_key", b"short"),
        ("kind", "unsupported"),
    ],
)
def test_invalid_complete_descriptor_never_fetches(jobs, tmp_path, field, value):
    media, _ = jobs(20)
    out = tmp_path / "out"
    out.write_bytes(b"previous")
    with pytest.raises((ValueError, KeyError)):
        download_file(
            URL,
            lambda *_: pytest.fail("Invalid descriptor caused a GET"),
            out,
            replace(media, **{field: value}),
        )
    assert out.read_bytes() == b"previous"


@pytest.mark.parametrize("header", ["range", "range_length", "full_length"])
def test_http_numeric_fields_require_ascii_digits(jobs, tmp_path, header):
    media, job = jobs(20)

    def to_fullwidth(value):
        return str(value).translate(str.maketrans("0123456789", "０１２３４５６７８９"))

    headers = {"Content-Length": str(len(media.blob))}
    if header == "range":
        headers["Content-Range"] = (
            f"bytes ０-{to_fullwidth(len(media.blob) - 1)}/{to_fullwidth(len(media.blob))}"
        )
    else:
        headers["Content-Length"] = to_fullwidth(len(media.blob))
        if header == "range_length":
            headers["Content-Range"] = f"bytes 0-{len(media.blob) - 1}/{len(media.blob)}"
    closed = []
    response = Response(
        200 if header == "full_length" else 206, headers, media.blob, lambda: closed.append(True)
    )
    with pytest.raises(TransferError):
        if header == "full_length":
            download_file(URL, lambda _: response, tmp_path / "out", media)
        else:
            download_range(job, 0, URL, lambda _: response)
    assert closed == [True]
    assert not (tmp_path / "out").exists()
    assert len(job.missing()) == 1


def test_header_generator_is_reused_for_every_range(jobs, tmp_path):
    media, job = jobs()
    observed = []
    reply = responder(media, [])

    def transport(request):
        observed.append(dict(request.headers).get("authorization"))
        return reply(request)

    download_all(
        job, URL, transport, tmp_path / "out", headers=iter([("Authorization", "synthetic")])
    )
    assert observed == ["synthetic"] * 3


@pytest.mark.parametrize("size", [0, 15, 16, 65520, 65521])
def test_authenticated_tail_boundaries_and_interruption_resume(jobs, tmp_path, size):
    media, job = jobs(size)
    ranges = job.missing()
    first = ranges[0]
    if len(ranges) > 1:
        job.accept(first[0], media.blob[first[1] : first[2] + 1])

        def interrupted(request):
            start, end = map(int, dict(request.headers)["range"][6:].split("-"))

            def body():
                yield media.blob[start : start + 3]
                raise OSError("interrupted")

            return Response(
                206, {"Content-Range": f"bytes {start}-{end}/{len(media.blob)}"}, body()
            )

        with pytest.raises(OSError, match="interrupted"):
            download_range(job, 1, URL, interrupted)
        assert len(job.missing()) == len(ranges) - 1
        job.store.db.close()
        media, job = jobs(size)
    calls = []
    download_all(job, URL, responder(media, calls), tmp_path / "out")
    assert len(calls) == (len(ranges) - 1 if len(ranges) > 1 else 1)
    assert (tmp_path / "out").read_bytes() == bytes((i % 251 for i in range(size)))
    assert (tmp_path / "out").stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".wa-*"))


def test_corrupt_cache_then_bad_response_keeps_valid_progress(jobs, tmp_path):
    media, job = jobs()
    ranges = accept_all(job, media)
    job.store._put("range-chunk", key(job.id, 1), b"corrupt")
    calls = []
    reply = responder(media, calls)

    def tampered(request):
        response = reply(request)
        response.body = bytes([response.body[0] ^ 1]) + response.body[1:]
        return response

    out = tmp_path / "out"
    out.write_bytes(b"previous")
    with pytest.raises(IntegrityError):
        download_all(job, URL, tampered, out)
    assert job.missing() == [ranges[1]]
    assert out.read_bytes() == b"previous"
    download_all(job, URL, reply, out)
    assert calls == [(ranges[1][1], ranges[1][2])] * 2
    assert out.stat().st_size == media.length


@pytest.mark.parametrize("check", ["main_mac", "encrypted_hash", "plaintext_hash", "length"])
def test_authenticated_chunks_still_require_complete_file_verification(jobs, tmp_path, check):
    from whatsapp_e2ee.media import sha

    media, original = jobs(70000)
    if check == "main_mac":
        blob = media.blob[:-1] + bytes([media.blob[-1] ^ 1])
        media = replace(media, blob=blob, encrypted_hash=sha(blob))
    elif check == "encrypted_hash":
        media = replace(media, encrypted_hash=bytes(32))
    elif check == "plaintext_hash":
        media = replace(media, plaintext_hash=bytes(32))
    else:
        media = replace(media, length=media.length + 1)
    job = RangeDownload(original.store, "invalid-global")
    job.initialize(
        media.media_key,
        media.kind,
        total=len(media.blob),
        sidecar=sidecar(media.blob, media.media_key, media.kind),
        plaintext_hash=media.plaintext_hash,
        encrypted_hash=media.encrypted_hash,
        length=media.length,
    )
    accept_all(job, media)
    out = tmp_path / "out"
    out.write_bytes(b"previous")
    with pytest.raises(IntegrityError):
        job.finalize(out)
    assert job.missing() == []  # Descriptor/main-file failure is not a cache MAC failure.
    assert out.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".wa-*"))


def test_output_sync_failure_keeps_old_file_and_can_retry(jobs, tmp_path, monkeypatch):
    from whatsapp_e2ee import media_files

    media, _ = jobs(20)
    out = tmp_path / "out"
    out.write_bytes(b"previous")
    closed = []

    def transport(_):
        return Response(200, {}, media.blob, lambda: closed.append(True))

    def fail_sync(_):
        raise OSError("sync failed")

    with monkeypatch.context() as patch:
        patch.setattr(media_files.os, "fsync", fail_sync)
        with pytest.raises(OSError, match="sync failed"):
            download_file(URL, transport, out, media)
    assert out.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".wa-*"))
    assert download_file(URL, transport, out, media) == media.length
    assert closed == [True, True]
