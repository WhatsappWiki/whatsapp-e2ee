"""Media HTTP framing and durable upload outcomes through an injected transport.

There is no socket client in this module. Endpoints/authentication and response
mapping are supplied explicitly. A transport must consume the request body and
return a bounded streaming response; range/cache crypto remains local.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from whatsapp_e2ee.media import IntegrityError
from whatsapp_e2ee.media_files import BLOCK, decrypt_file


class TransferError(ValueError):
    pass


class UploadUncertain(TransferError):
    pass


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    headers: tuple
    body: object = ()


@dataclass
class Response:
    status: int
    headers: tuple
    body: object
    close: object = lambda: None


@dataclass(frozen=True)
class UploadReceipt:
    """timestamp_ms is the original mediaKey creation time, never upload completion."""

    direct_path: str
    timestamp_ms: int
    encrypted_hash: bytes


@dataclass(frozen=True)
class Reconciliation:
    # absent means an authoritative lookup says the previous upload is absent.
    # unknown must not be converted into a fresh send.
    status: str
    receipt: UploadReceipt | None = None


def _url(url):
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("Invalid media URL")
    value = urlsplit(url)
    if (
        value.scheme != "https"
        or not value.hostname
        or value.username
        or value.password
        or value.fragment
    ):
        raise ValueError("An explicit HTTPS media endpoint is required")
    return url


def _headers(headers):
    entries = headers.items() if isinstance(headers, dict) else headers
    out = {}
    for name, value in entries:
        if not isinstance(name, str) or not isinstance(value, str):
            raise TransferError("Headers require text names and values")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise TransferError("Invalid HTTP header name")
        name = name.lower()
        if (
            not name
            or name in out
            or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value)
        ):
            raise TransferError("Duplicate or invalid header")
        out[name] = value
    return out


def _body_chunks(body):
    if isinstance(body, bytes):
        yield body
    else:
        yield from body


def read_response(response, limit):
    if type(limit) is not int or limit < 0:
        raise ValueError("Invalid response limit")
    output = bytearray()
    try:
        for chunk in _body_chunks(response.body):
            if not isinstance(chunk, bytes):
                raise TransferError("Transport must return byte chunks")
            if len(output) + len(chunk) > limit:
                raise TransferError("Response exceeds expected bound")
            output.extend(chunk)
        return bytes(output)
    finally:
        response.close()


def download_range(job, index, url, transport, *, headers=()):
    """Fetch one missing authenticated chunk. A failed request never marks it done."""
    s = job._spec()
    missing = {i: (start, end) for i, start, end in job.missing()}
    if index not in missing:
        return False
    start, end = missing[index]
    supplied = _headers(headers)
    if set(supplied) & {"range", "accept-encoding"}:
        raise ValueError("Range headers are controlled by the adapter")
    supplied.update({"range": f"bytes={start}-{end}", "accept-encoding": "identity"})
    response = transport(Request("GET", _url(url), tuple(supplied.items())))
    try:
        h = _headers(response.headers)
        if h.get("content-encoding", "identity").lower() != "identity":
            raise TransferError("Encoded media response is not byte-range stable")
        if response.status == 206:
            value = h.get("content-range", "")
            match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", value)
            if not match or tuple(map(int, match.groups())) != (start, end, s["total"]):
                raise TransferError("Content-Range does not match request and descriptor")
        elif response.status == 200 and start == 0 and end == s["total"] - 1:
            if "content-range" in h:
                raise TransferError("Unexpected Content-Range on full response")
        else:
            raise TransferError("Media server did not honor the required range")
        expected = end - start + 1
        if "content-length" in h and (
            not h["content-length"].isdigit() or int(h["content-length"]) != expected
        ):
            raise TransferError("Content-Length mismatch")
    except BaseException:
        response.close()
        raise
    data = read_response(response, expected)
    if len(data) != expected:
        raise TransferError("Truncated range response")
    job.accept(index, data)
    return True


def download_all(job, url, transport, destination, *, headers=(), max_requests=10000):
    missing = job.missing()
    if type(max_requests) is not int or max_requests < len(missing):
        raise ValueError("Range request budget is too small")
    for index, _, _ in missing:
        download_range(job, index, url, transport, headers=headers)
    job.finalize(destination)


def download_file(url, transport, destination, media, *, headers=()):
    """Complete media GET, bounded encrypted staging and verified publication."""
    supplied = _headers(headers)
    if set(supplied) & {"range", "accept-encoding"}:
        raise ValueError("Complete download controls range/encoding headers")
    supplied["accept-encoding"] = "identity"
    expected = (media.length // 16 + 1) * 16 + 10
    response = transport(Request("GET", _url(url), tuple(supplied.items())))
    temporary = None
    try:
        h = _headers(response.headers)
        if response.status != 200 or "content-range" in h:
            raise TransferError("Expected complete media response")
        if h.get("content-encoding", "identity").lower() != "identity":
            raise TransferError("Encoded media response is not byte stable")
        if "content-length" in h and (
            not h["content-length"].isdigit() or int(h["content-length"]) != expected
        ):
            raise TransferError("Content-Length mismatch")
        fd, temporary = tempfile.mkstemp(prefix=".wa-download-", dir=Path(destination).parent)
        size = 0
        with os.fdopen(fd, "wb") as out:
            for chunk in _body_chunks(response.body):
                if not isinstance(chunk, bytes) or size + len(chunk) > expected:
                    raise TransferError("Invalid or oversized media body")
                size += len(chunk)
                out.write(chunk)
        if size != expected:
            raise TransferError("Truncated complete media response")
        return decrypt_file(
            temporary,
            destination,
            media.media_key,
            media.kind,
            plaintext_hash=media.plaintext_hash,
            encrypted_hash=media.encrypted_hash,
            length=media.length,
        )
    finally:
        try:
            response.close()
        finally:
            if temporary is not None:
                os.unlink(temporary)


class _MultipartBody:
    def __init__(self, media, boundary):
        self.media = media
        self.prefix = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="blob"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        self.suffix = f"\r\n--{boundary}--\r\n".encode()
        self.size = (media.length // 16 + 1) * 16 + 10
        self.content_length = len(self.prefix) + self.size + len(self.suffix)
        self.started = self.finished = False

    def __iter__(self):
        if self.started:
            raise TransferError("Upload body is single-use")
        self.started = True
        digest, size = hashlib.sha256(), 0
        yield self.prefix
        if hasattr(self.media, "path"):
            with open(self.media.path, "rb") as source:
                while chunk := source.read(BLOCK):
                    size += len(chunk)
                    digest.update(chunk)
                    yield chunk
        else:
            for i in range(0, len(self.media.blob), BLOCK):
                chunk = self.media.blob[i : i + BLOCK]
                size += len(chunk)
                digest.update(chunk)
                yield chunk
        if size != self.size or not hmac.compare_digest(digest.digest(), self.media.encrypted_hash):
            raise IntegrityError("Prepared upload bytes changed during transfer")
        yield self.suffix
        self.finished = True


class Uploads:
    """Prepare → in_flight → uploaded, with explicit ambiguous-outcome recovery.

    A timeout or crash leaves an in_flight/unknown checkpoint. Retrying a POST is
    prohibited until reconciliation reports found or definitively absent.
    """

    def __init__(self, jobs):
        self.jobs, self.store = jobs, jobs.store

    def pending(self, id):
        row = self.store._get("media-upload-attempt", id)
        return json.loads(row[0]) if row else None

    def _write(self, id, state):
        self.store._put("media-upload-attempt", id, json.dumps(state, sort_keys=True).encode())

    def _receipt(self, id, receipt, attempt):
        if (
            not isinstance(receipt, UploadReceipt)
            or receipt.encrypted_hash.hex() != attempt["encrypted_hash"]
        ):
            raise TransferError("Upload receipt hash does not bind prepared media")
        self.jobs.mark_uploaded(id, receipt.direct_path, receipt.timestamp_ms)
        attempt.update(
            state="uploaded", direct_path=receipt.direct_path, timestamp_ms=receipt.timestamp_ms
        )
        self._write(id, attempt)
        return receipt

    def reconcile(self, id, lookup):
        self.store.db.require_no_transaction()
        attempt = self.pending(id)
        if attempt is None or attempt["state"] not in ("in_flight", "unknown"):
            raise ValueError("No ambiguous upload to reconcile")
        # lookup sees only a public content fingerprint and stable request ID.
        result = lookup(dict(attempt))
        if not isinstance(result, Reconciliation) or result.status not in (
            "found",
            "absent",
            "unknown",
        ):
            raise TransferError("Invalid upload reconciliation result")
        with self.store.db.atomic():
            current = self.pending(id)
            if current != attempt:
                raise TransferError("Upload state changed during reconciliation")
            if result.status == "found":
                return self._receipt(id, result.receipt, attempt)
            if result.receipt is not None:
                raise TransferError("Unexpected receipt for absent/unknown upload")
            if result.status == "absent":
                attempt["state"] = "absent"
                self._write(id, attempt)
            return None

    def send(self, id, url, transport, parse_receipt, *, headers=(), max_attempts=3):
        # No full-file validation or callback occurs under the write transaction.
        self.store.db.require_no_transaction()
        media = self.jobs.load(id, verify_file=True)
        supplied = _headers(headers)
        if set(supplied) & {"content-length", "content-type"}:
            raise ValueError("Multipart framing headers are controlled by the adapter")
        endpoint = _url(url)
        with self.store.db.atomic():
            previous = self.pending(id)
            checkpoint = self.store._get("media-upload", id)
            if checkpoint:
                path, stamp = json.loads(checkpoint[0])
                return UploadReceipt(path, stamp, media.encrypted_hash)
            if previous and previous["state"] == "uploaded":
                return UploadReceipt(
                    previous["direct_path"],
                    previous["timestamp_ms"],
                    bytes.fromhex(previous["encrypted_hash"]),
                )
            if previous and previous["state"] in ("in_flight", "unknown"):
                raise UploadUncertain("Previous upload outcome needs explicit reconciliation")
            count = (previous["count"] if previous else 0) + 1
            if type(max_attempts) is not int or max_attempts < 1 or count > max_attempts:
                raise TransferError("Upload attempt budget exhausted")
            attempt = dict(
                state="in_flight",
                count=count,
                request_id=secrets.token_hex(16),
                encrypted_hash=media.encrypted_hash.hex(),
                plaintext_hash=media.plaintext_hash.hex(),
                length=media.length,
            )
            self._write(id, attempt)
        boundary = "wa-e2ee-" + attempt["request_id"]
        body = _MultipartBody(media, boundary)
        supplied.update(
            {
                "content-type": "multipart/form-data; boundary=" + boundary,
                "content-length": str(body.content_length),
            }
        )
        try:
            response = transport(Request("POST", endpoint, tuple(supplied.items()), body))
            # Close a returned response even when the transport did not consume all bytes.
            if not body.finished:
                response.close()
                raise TransferError("Transport returned before draining the upload body")
            raw = read_response(response, 1024 * 1024)
            if not 200 <= response.status < 300:
                raise TransferError("Upload response is not successful")
            receipt = parse_receipt(response.status, _headers(response.headers), raw)
            with self.store.db.atomic():
                if self.pending(id) != attempt:
                    raise TransferError("Upload state changed before checkpoint")
                return self._receipt(id, receipt, attempt)
        except BaseException:
            with self.store.db.atomic():
                if self.pending(id) == attempt:
                    attempt["state"] = "unknown"
                    self._write(id, attempt)
            raise


def json_upload_receipt(status, headers, raw):
    """Explicit adapter profile for a normalized hash-bearing test/service reply.

    This does not claim WhatsApp always returns this JSON shape. A service
    adapter may provide a different parser; its result must bind the digest.
    """
    obj = json.loads(raw)
    return UploadReceipt(
        obj["direct_path"],
        obj["timestamp_ms"],
        base64.b64decode(obj["file_enc_sha256"], validate=True),
    )


__all__ = [
    "TransferError",
    "UploadUncertain",
    "Request",
    "Response",
    "UploadReceipt",
    "Reconciliation",
    "read_response",
    "download_range",
    "download_all",
    "download_file",
    "Uploads",
    "json_upload_receipt",
]
