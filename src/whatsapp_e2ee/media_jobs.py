"""Local media preparation/checkpoints; uploading belongs to a supplied adapter."""

import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path

from whatsapp_e2ee import payload
from whatsapp_e2ee.media import MediaStore, decrypt, encrypt, sha
from whatsapp_e2ee.media_files import MediaFile, encrypt_file, hash_file
from whatsapp_e2ee.store import key

_NOW = object()


class MediaJobs:
    def __init__(self, store, *, clock_ms=None):
        self.store = store
        self.media = MediaStore(store)
        self.clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def key_timestamp_ms(self, id):
        row = self.store._get("media-key-time", id)
        if row is not None:
            return int(row[0])
        old = self.store._get("media-upload", id)
        return json.loads(old[0])[1] if old else None

    def _bind_key_time(self, id, requested):
        if (
            requested is not _NOW
            and requested is not None
            and (type(requested) is not int or requested < 0)
        ):
            raise ValueError("Invalid media key creation timestamp")
        existing = self.key_timestamp_ms(id)
        if existing is not None:
            if requested is not _NOW and requested is not None and requested != existing:
                raise ValueError("Media key creation timestamp already bound")
            return existing
        if requested is None:
            # Explicit compatibility mode: caller will bind historical key time.
            return None
        value = self.clock_ms() if requested is _NOW else requested
        if type(value) is not int or value < 0:
            raise ValueError("Invalid media key creation timestamp")
        self.store._put("media-key-time", id, str(value).encode())
        return value

    def prepare(self, id, raw, kind, *, media_key_timestamp_ms=_NOW):
        fingerprint = key(kind, sha(raw).hex()).encode()
        with self.store.db.atomic():
            old = self.store._get("media-request", id)
            if old:
                if old[0] != fingerprint:
                    raise ValueError("Media job ID already bound")
                if self.store._get("media-file-reservation", id):
                    raise ValueError("Media job already uses file storage")
                if self.key_timestamp_ms(id) is None and media_key_timestamp_ms is _NOW:
                    raise ValueError("Existing media needs an explicit historical key timestamp")
                self._bind_key_time(id, media_key_timestamp_ms)
                return self.media.load(id)
            self._bind_key_time(id, media_key_timestamp_ms)
            value = encrypt(raw, kind)
            self.media.save(id, value)
            self.store._put("media-request", id, fingerprint)
            self.store._put("media-state", id, b"prepared")
            return value

    def mark_uploaded(self, id, direct_path, timestamp_ms=None):
        """Record an adapter's successful upload result. This sends nothing."""
        if not isinstance(direct_path, str) or not direct_path:
            raise ValueError("Invalid upload path")
        with self.store.db.atomic():
            self.load(id)
            creation = self.key_timestamp_ms(id)
            if timestamp_ms is None:
                timestamp_ms = creation
            if type(timestamp_ms) is not int or timestamp_ms < 0:
                raise ValueError("A valid media key creation timestamp is required")
            if creation is not None and creation != timestamp_ms:
                raise ValueError("Upload cannot change media key creation timestamp")
            self._bind_key_time(id, timestamp_ms)
            raw = json.dumps([direct_path, timestamp_ms]).encode()
            old = self.store._get("media-upload", id)
            if old and old[0] != raw:
                raise ValueError("Upload result already bound")
            if old is None:
                self.store._put("media-upload", id, raw)
                self.store._put("media-state", id, b"uploaded")

    def load(self, id, *, verify_file=False):
        row = self.store._get("media-file", id)
        if row is None:
            value = self.media.load(id)
            if verify_file:
                decrypt(
                    value.blob,
                    value.media_key,
                    value.kind,
                    plaintext_hash=value.plaintext_hash,
                    encrypted_hash=value.encrypted_hash,
                    length=value.length,
                )
            return value
        m = json.loads(row[0])
        value = MediaFile(
            bytes.fromhex(m["media_key"]),
            m["kind"],
            m["length"],
            bytes.fromhex(m["plaintext_hash"]),
            bytes.fromhex(m["encrypted_hash"]),
            Path(m["path"]),
        )
        if verify_file:
            size, digest = hash_file(value.path)
            if digest != value.encrypted_hash or size != (value.length // 16 + 1) * 16 + 10:
                raise ValueError("Prepared media file changed")
        return value

    def prepare_file(self, id, source, kind, cache_directory, *, media_key_timestamp_ms=_NOW):
        """Hash and encrypt with bounded memory. A reserved root key survives crashes.

        Encryption and fsync occur outside the database transaction. Concurrent
        preparations of identical input produce identical blob bytes. A changed
        source fails before publishing the final encrypted cache path.
        """
        size, digest = hash_file(source)
        fingerprint = key(kind, digest.hex()).encode()
        cache = Path(cache_directory).resolve()
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = cache / (hashlib.sha256(key(self.store.owner, id).encode()).hexdigest() + ".enc")
        with self.store.db.atomic():
            old = self.store._get("media-request", id)
            if old and old[0] != fingerprint:
                raise ValueError("Media job ID already bound")
            if self.store._get("media-meta", id):
                raise ValueError("Media job already uses in-database blob storage")
            if old and self.key_timestamp_ms(id) is None and media_key_timestamp_ms is _NOW:
                raise ValueError("Existing media needs an explicit historical key timestamp")
            self._bind_key_time(id, media_key_timestamp_ms)
            reservation = self.store._get("media-file-reservation", id)
            if reservation:
                reserve = json.loads(reservation[0])
                if reserve["path"] != str(path):
                    raise ValueError("Media job cache directory already bound")
            else:
                # Validate kind/key before creating persistent state.
                from whatsapp_e2ee.media import derive

                root = secrets.token_bytes(32)
                derive(root, kind)
                reserve = dict(
                    media_key=root.hex(),
                    kind=kind,
                    length=size,
                    plaintext_hash=digest.hex(),
                    path=str(path),
                )
                self.store._put("media-file-reservation", id, json.dumps(reserve).encode())
                self.store._put("media-request", id, fingerprint)
                self.store._put("media-state", id, b"preparing")
            ready = self.store._get("media-file", id)
        if ready and path.exists():
            return self.load(id, verify_file=True)
        fd, temporary = tempfile.mkstemp(prefix=".wa-job-", dir=cache)
        os.close(fd)
        try:
            value = encrypt_file(
                source, temporary, kind, media_key=bytes.fromhex(reserve["media_key"])
            )
            if value.length != size or value.plaintext_hash != digest:
                raise ValueError("Source changed while preparing media")
            os.replace(temporary, path)
            encoded = dict(reserve, encrypted_hash=value.encrypted_hash.hex())
            with self.store.db.atomic():
                previous = self.store._get("media-file", id)
                raw = json.dumps(encoded, sort_keys=True).encode()
                if previous and previous[0] != raw:
                    raise ValueError("Inconsistent prepared media result")
                self.store._put("media-file", id, raw)
                if self.store._get("media-state", id)[0] == b"preparing":
                    self.store._put("media-state", id, b"prepared")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return self.load(id)

    def prepare_thumbnail(self, parent_id, thumbnail_id, raw):
        """Ordinary image/video/document remote thumbnail, sharing parent root."""
        with self.store.db.atomic():
            parent = self.load(parent_id)
            kind = {"gif": "video", "ptv": "video"}.get(parent.kind, parent.kind)
            if kind not in ("image", "video", "document"):
                raise ValueError("Unsupported remote thumbnail parent")
            binding = key(parent_id, kind, sha(raw).hex()).encode()
            old = self.store._get("thumbnail-binding", thumbnail_id)
            if old and old[0] != binding:
                raise ValueError("Thumbnail ID already bound")
            if old:
                return self.media.load(thumbnail_id)
            if self.store._get("media-request", thumbnail_id) or self.store._get(
                "media-meta", thumbnail_id
            ):
                raise ValueError("Thumbnail ID already used by another media job")
            parent_time = self.key_timestamp_ms(parent_id)
            if parent_time is None:
                raise ValueError(
                    "Bind the parent's historical key timestamp before creating its thumbnail"
                )
            self._bind_key_time(thumbnail_id, parent_time)
            value = encrypt(raw, kind + "-thumbnail", media_key=parent.media_key)
            self.media.save(thumbnail_id, value)
            self.store._put("thumbnail-binding", thumbnail_id, binding)
            self.store._put("media-state", thumbnail_id, b"prepared")
            return value

    def thumbnail_metadata(self, parent_id, thumbnail_id):
        with self.store.db.atomic():
            row = self.store._get("thumbnail-binding", thumbnail_id)
            if row is None or json.loads(row[0])[0] != parent_id:
                raise ValueError("Thumbnail parent binding mismatch")
            parent, child = self.load(parent_id), self.media.load(thumbnail_id)
            parent_upload = self.store._get("media-upload", parent_id)
            upload = self.store._get("media-upload", thumbnail_id)
            if parent_upload is None or upload is None:
                raise ValueError("Both uploads must be checkpointed")
            _, parent_time = json.loads(parent_upload[0])
            path, child_time = json.loads(upload[0])
            if parent.media_key != child.media_key or parent_time != child_time:
                raise ValueError("Thumbnail root key/timestamp mismatch")
            return dict(
                thumbnail_direct_path=path,
                thumbnail_sha256=child.plaintext_hash,
                thumbnail_enc_sha256=child.encrypted_hash,
            )

    def descriptor(self, id, **metadata):
        with self.store.db.atomic():
            value = self.load(id)
            row = self.store._get("media-upload", id)
            if row is None:
                raise ValueError("Media upload has not been checkpointed")
            path, stamp = json.loads(row[0])
            return payload.media_message(value, path, stamp, **metadata)

    def prepare_message(
        self, id, message_id, client, recipients, *, group=None, bundles=None, metadata=None
    ):
        if client.store.db is not self.store.db or client.store.owner != self.store.owner:
            raise ValueError("Media and message must share one local transaction")
        with self.store.db.atomic():
            raw = self.descriptor(id, **(metadata or {}))
            if group is None:
                packets = client.prepare_direct(
                    message_id, {a: raw for a in recipients}, bundles=bundles
                )
            else:
                packets = client.prepare_group_delivery(
                    message_id, group, raw, recipients, bundles=bundles
                )
            self.store._put("media-message", key(id, message_id), raw)
            self.store._put("media-state", id, b"message_prepared")
            return packets

    def scan_metadata(self, id, scan_lengths):
        """Image encoder scan lengths plus their encrypted variable-block sidecar."""
        from whatsapp_e2ee.media import sidecar
        from whatsapp_e2ee.media_files import sidecar_file
        from whatsapp_e2ee.media_layout import scan_chunk_sizes

        value = self.load(id, verify_file=True)
        lengths = tuple(scan_lengths)
        if value.kind != "image" or sum(lengths) != value.length:
            raise ValueError("Scan layout must describe the complete image plaintext")
        sizes = scan_chunk_sizes(lengths)
        if not 2 <= len(lengths) <= 20 or sum(lengths) > 0x7FFFFFFF or len(sizes) != len(lengths):
            raise ValueError("Scan metadata does not satisfy ordinary image receiver constraints")
        if isinstance(value, MediaFile):
            tags = sidecar_file(value.path, value.media_key, value.kind, sizes=sizes)
        else:
            tags = sidecar(value.blob, value.media_key, value.kind, sizes=sizes)
        return dict(scan_lengths=lengths, scans_sidecar=tags)


__all__ = ["MediaJobs"]
