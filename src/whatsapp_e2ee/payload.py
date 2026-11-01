"""Minimal proto2 business schema. Unknown fields survive parsing/serialization."""

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

schema = descriptor_pb2.FileDescriptorProto(
    name="wa_e2ee_message.proto", package="wa_e2ee", syntax="proto2"
)


def define(name, fields):
    m = schema.message_type.add(name=name)
    for number, field, kind, target, repeated in fields:
        f = m.field.add(number=number, name=field, type=kind, label=3 if repeated else 1)
        if target:
            f.type_name = ".wa_e2ee." + target


# Field types follow google.protobuf.FieldDescriptorProto.Type.
def f(n, name, t=12, target=None, repeated=False):
    return n, name, t, target, repeated


define("Distribution", [f(1, "group_id", 9), f(2, "distribution")])
# Unsupported nested messages retain unknown fields without inventing policy.
define("DeviceListMetadata", [])
define(
    "ContextInfo",
    [
        f(1, "stanza_id", 9),
        f(2, "participant", 9),
        f(3, "quoted_message", 11, "Message"),
        f(4, "remote_jid", 9),
        f(15, "mentioned_jid", 9, repeated=True),
        f(21, "forwarding_score", 13),
        f(22, "is_forwarded", 8),
        f(25, "expiration", 13),
        f(26, "ephemeral_setting_timestamp", 3),
        f(27, "ephemeral_shared_secret"),
    ],
)
define(
    "MessageContextInfo",
    [
        f(1, "device_list_metadata", 11, "DeviceListMetadata"),
        f(2, "device_list_metadata_version", 5),
        f(3, "message_secret"),
        f(4, "padding_bytes"),
        f(5, "message_add_on_duration_in_secs", 13),
    ],
)
define(
    "ExtendedText",
    [
        f(1, "text", 9),
        f(2, "matched_text", 9),
        f(5, "description", 9),
        f(6, "title", 9),
        f(16, "jpeg_thumbnail"),
        f(17, "context_info", 11, "ContextInfo"),
        f(19, "thumbnail_direct_path", 9),
        f(20, "thumbnail_sha256"),
        f(21, "thumbnail_enc_sha256"),
        f(22, "media_key"),
        f(23, "media_key_timestamp", 3),
        f(24, "thumbnail_height", 13),
        f(25, "thumbnail_width", 13),
    ],
)
define(
    "DeviceSent",
    [f(1, "destination_jid", 9), f(2, "message", 11, "Message"), f(3, "phash", 9)],
)
MEDIA = {
    "image": (3, 8, 4, 9, 11, 5, 12),
    "video": (9, 6, 3, 11, 13, 4, 14),
    "audio": (8, 7, 3, 8, 9, 4, 10),
    "document": (7, 7, 4, 9, 10, 5, 11),
    "sticker": (26, 4, 2, 3, 8, 9, 10),
}
EXTRA = {
    "image": [
        f(1, "url", 9),
        f(2, "mimetype", 9),
        f(3, "caption", 9),
        f(6, "height", 13),
        f(7, "width", 13),
        f(16, "jpeg_thumbnail"),
        f(18, "first_scan_sidecar"),
        f(19, "first_scan_length", 13),
        f(21, "scans_sidecar"),
        f(22, "scan_lengths", 13, repeated=True),
        f(23, "mid_quality_file_sha256"),
        f(24, "mid_quality_file_enc_sha256"),
        f(26, "thumbnail_direct_path", 9),
        f(27, "thumbnail_sha256"),
        f(28, "thumbnail_enc_sha256"),
    ],
    "video": [
        f(1, "url", 9),
        f(2, "mimetype", 9),
        f(5, "seconds", 13),
        f(7, "caption", 9),
        f(8, "gif_playback", 8),
        f(9, "height", 13),
        f(10, "width", 13),
        f(16, "jpeg_thumbnail"),
        f(18, "streaming_sidecar"),
        f(21, "thumbnail_direct_path", 9),
        f(22, "thumbnail_sha256"),
        f(23, "thumbnail_enc_sha256"),
    ],
    "audio": [
        f(1, "url", 9),
        f(2, "mimetype", 9),
        f(5, "seconds", 13),
        f(6, "ptt", 8),
        f(18, "streaming_sidecar"),
        f(19, "waveform"),
    ],
    "document": [
        f(1, "url", 9),
        f(2, "mimetype", 9),
        f(3, "title", 9),
        f(6, "page_count", 13),
        f(8, "file_name", 9),
        f(13, "thumbnail_direct_path", 9),
        f(14, "thumbnail_sha256"),
        f(15, "thumbnail_enc_sha256"),
        f(16, "jpeg_thumbnail"),
        f(18, "thumbnail_height", 13),
        f(19, "thumbnail_width", 13),
        f(20, "caption", 9),
    ],
    "sticker": [
        f(1, "url", 9),
        f(5, "mimetype", 9),
        f(6, "height", 13),
        f(7, "width", 13),
        f(13, "is_animated", 8),
        f(16, "png_thumbnail"),
    ],
}
for kind, (_, k, ph, eh, path, size, ts) in MEDIA.items():
    define(
        kind.title(),
        [
            f(k, "media_key"),
            f(ph, "file_sha256"),
            f(eh, "file_enc_sha256"),
            f(path, "direct_path", 9),
            f(size, "file_length", 4),
            f(ts, "media_key_timestamp", 3),
            f(17, "context_info", 11, "ContextInfo"),
        ]
        + EXTRA[kind],
    )
define(
    "Message",
    [
        f(1, "conversation", 9),
        f(2, "sender_key_distribution_message", 11, "Distribution"),
        f(6, "extended_text_message", 11, "ExtendedText"),
        f(31, "device_sent_message", 11, "DeviceSent"),
        f(35, "message_context_info", 11, "MessageContextInfo"),
        f(66, "ptv_message", 11, "Video"),
    ]
    + [f(v[0], kind + "_message", 11, kind.title()) for kind, v in MEDIA.items()],
)
pool = descriptor_pool.DescriptorPool()
pool.Add(schema)
Message = message_factory.GetMessageClass(pool.FindMessageTypeByName("wa_e2ee.Message"))


def text(value):
    return Message(conversation=value).SerializeToString()


def parse(raw):
    m = Message()
    m.ParseFromString(raw)
    return m


def distribution(group, raw):
    m = Message()
    m.sender_key_distribution_message.group_id = group
    m.sender_key_distribution_message.distribution = raw
    return m.SerializeToString()


def device_sent(destination, raw, phash=None):
    m = Message()
    m.device_sent_message.destination_jid = destination
    inner = parse(raw)
    if inner.HasField("message_context_info"):
        m.message_context_info.CopyFrom(inner.message_context_info)
        inner.ClearField("message_context_info")
    m.device_sent_message.message.CopyFrom(inner)
    if phash is not None:
        m.device_sent_message.phash = phash
    return m.SerializeToString()


def media_message(media, direct_path, timestamp_ms, **metadata):
    kind = {"gif": "video", "ptv": "video", "ptt": "audio"}.get(media.kind, media.kind)
    if kind not in MEDIA:
        raise ValueError("Unsupported media descriptor")
    if not direct_path or timestamp_ms < 0:
        raise ValueError("Invalid media metadata")
    m = Message()
    d = getattr(m, "ptv_message" if media.kind == "ptv" else kind + "_message")
    d.media_key = media.media_key
    d.file_sha256 = media.plaintext_hash
    d.file_enc_sha256 = media.encrypted_hash
    d.direct_path = direct_path
    d.file_length = media.length
    d.media_key_timestamp = timestamp_ms // 1000
    allowed = {field[1] for field in EXTRA[kind]}
    for field, value in metadata.items():
        if field not in allowed:
            raise ValueError("Unsupported media metadata: " + field)
        if d.DESCRIPTOR.fields_by_name[field].is_repeated:
            getattr(d, field).extend(value)
        else:
            setattr(d, field, value)
    if media.kind == "ptt":
        d.ptt = True
    if media.kind == "gif":
        d.gif_playback = True
    return m.SerializeToString()


def classify(raw):
    """Keep unsupported legal messages intact; this is not an authenticity test."""
    m = parse(raw)
    if m.HasField("device_sent_message"):
        m = m.device_sent_message.message
    names = [f.name for f, _ in m.ListFields() if f.name != "message_context_info"]
    return tuple(names) if names else ("unsupported",)


def extended_text(value, *, context=None, **metadata):
    m = Message()
    d = m.extended_text_message
    d.text = value
    for field, val in metadata.items():
        if field not in d.DESCRIPTOR.fields_by_name or field in ("text", "context_info"):
            raise ValueError("Unsupported extended text metadata: " + field)
        setattr(d, field, val)
    if context is not None:
        if isinstance(context, bytes):
            d.context_info.ParseFromString(context)
        else:
            d.context_info.CopyFrom(context)
    return m.SerializeToString()


def context_info(
    *,
    stanza_id=None,
    participant=None,
    quoted=None,
    remote_jid=None,
    mentioned=(),
    forwarding_score=None,
    is_forwarded=None,
):
    cls = message_factory.GetMessageClass(pool.FindMessageTypeByName("wa_e2ee.ContextInfo"))
    context = cls()
    for field, value in (
        ("stanza_id", stanza_id),
        ("participant", participant),
        ("remote_jid", remote_jid),
        ("forwarding_score", forwarding_score),
        ("is_forwarded", is_forwarded),
    ):
        if value is not None:
            setattr(context, field, value)
    if quoted is not None:
        context.quoted_message.CopyFrom(parse(quoted))
    context.mentioned_jid.extend(mentioned)
    return context


__all__ = [
    "define",
    "f",
    "MEDIA",
    "EXTRA",
    "text",
    "parse",
    "distribution",
    "device_sent",
    "media_message",
    "classify",
    "extended_text",
    "context_info",
    "Message",
]
