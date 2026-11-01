"""Retry receipt wire fields and bounded, durable re-encryption attempts.

A transport retransmission uses the existing outbox. A protocol retry is a new
attempt, with its own advanced cryptographic state and an explicit link to the
original logical message. No identity trust is reset automatically.
"""

import base64
import hashlib
import json
from dataclasses import dataclass

from protocol_tree_node import Node
from signal_protocol import (
    ECPublicKey,
    IdentityKey,
    PreKeyBundle,
    SignalProtocolAddress,
    WhatsAppSessionBuilder,
)
from signal_protocol.kem import KemPublicKey

from whatsapp_e2ee.delivery import Delivery
from whatsapp_e2ee.packets import Conflict
from whatsapp_e2ee.stanza import address_from_jid, attributes, one, parse_jid
from whatsapp_e2ee.store import key


def number(value, name, *, minimum=0, maximum=0xFFFFFFFF):
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise ValueError("Invalid " + name)
    value = int(value)
    if not minimum <= value <= maximum:
        raise ValueError("Out-of-range " + name)
    return value


def data(node, size=None):
    if node is None or node.data is None or (size is not None and len(node.data) != size):
        raise ValueError("Invalid key node bytes")
    if node.attrs:
        raise ValueError("Unexpected key node attributes")
    return node.data


def key_parts(node, *, signed):
    allowed = {"id", "value", "signature"} if signed else {"id", "value"}
    if {c.tag for c in node.children or ()} != allowed:
        raise ValueError("Incomplete or unknown prekey fields")
    id = int.from_bytes(data(one(node, "id", required=True), 3), "big")
    value = data(one(node, "value", required=True))
    signature = data(one(node, "signature", required=True), 64) if signed else None
    return id, value, signature


def parse_bundle(keys, registration, device):
    allowed = {"identity", "type", "key", "skey", "pq", "device-identity"}
    if {c.tag for c in keys.children or ()} - allowed:
        raise ValueError("Unsupported key bundle field")
    if data(one(keys, "type", required=True), 1) != b"\x05":
        raise ValueError("Unsupported curve key type")
    identity = IdentityKey(ECPublicKey(data(one(keys, "identity", required=True), 32)))
    pre = key_parts(one(keys, "key", required=True), signed=False)
    signed = key_parts(one(keys, "skey", required=True), signed=True)
    if len(pre[1]) != 32 or len(signed[1]) != 32:
        raise ValueError("Curve public key must contain 32 bytes")
    kwargs = {}
    pq = one(keys, "pq")
    if pq is not None:
        kid, public, signature = key_parts(pq, signed=True)
        kwargs = dict(
            kyber_pre_key_id=kid,
            kyber_pre_key=KemPublicKey.from_bytes(public),
            kyber_pre_key_signature=signature,
        )
    one(keys, "device-identity")  # duplicate extension must not create ambiguity
    return PreKeyBundle(
        registration,
        device,
        pre[0],
        ECPublicKey(pre[1]),
        signed[0],
        ECPublicKey(signed[1]),
        signed[2],
        identity,
        **kwargs,
    )


@dataclass(frozen=True)
class RetryRequest:
    id: str
    chat: str
    sender: SignalProtocolAddress
    count: int
    registration_id: int
    timestamp: int
    error: int
    bundle: PreKeyBundle | None
    raw_node: Node


def parse_retry(node):
    attrs = attributes(node)
    if node.tag != "receipt" or attrs.get("type") != "retry" or not attrs.get("id"):
        raise ValueError("Not a retry receipt")
    source = parse_jid(attrs.get("from"))
    group = source.server == "g.us"
    sender = address_from_jid(attrs.get("participant") if group else source)
    if not group and "participant" in attrs:
        raise ValueError("Unexpected retry participant")
    retry = one(node, "retry", required=True)
    r = attributes(retry)
    if r.get("v") != "1" or r.get("id") != attrs["id"]:
        raise ValueError("Retry version/message ID mismatch")
    count = number(r.get("count"), "retry count", minimum=1)
    timestamp = number(r.get("t"), "retry time", maximum=0xFFFFFFFFFFFFFFFF)
    error = number(r.get("error", "0"), "retry error")
    registration = int.from_bytes(data(one(node, "registration", required=True), 4), "big")
    if not 0 < registration < 0x7FFFFFFF:
        raise ValueError("Invalid registration ID")
    keys = one(node, "keys")
    bundle = parse_bundle(keys, registration, sender.device_id) if keys is not None else None
    return RetryRequest(
        attrs["id"], str(source), sender, count, registration, timestamp, error, bundle, node
    )


def _public(raw):
    value = raw.serialize()
    if len(value) != 33 or value[0] != 5:
        raise ValueError("Invalid Curve public key encoding")
    return value[1:]


def bundle_node(bundle, *, device_identity=None):
    def record(tag, id, public, signature=None):
        if type(id) is not int or not 0 <= id < 1 << 24:
            raise ValueError("Wire prekey ID must fit 24 bits")
        nodes = [Node("id", data=id.to_bytes(3, "big")), Node("value", data=public)]
        if signature is not None:
            if len(signature) != 64:
                raise ValueError("Invalid prekey signature length")
            nodes.append(Node("signature", data=signature))
        return Node(tag, children=nodes)

    if bundle.pre_key is None:
        raise ValueError("This retry bundle format requires an ordinary prekey")
    nodes = [
        Node("identity", data=_public(bundle.identity_key)),
        Node("type", data=b"\x05"),
        record("key", bundle.pre_key_id, _public(bundle.pre_key)),
        record(
            "skey",
            bundle.signed_pre_key_id,
            _public(bundle.signed_pre_key),
            bundle.signed_pre_key_signature,
        ),
    ]
    kem_fields = (bundle.kyber_pre_key_id, bundle.kyber_pre_key, bundle.kyber_pre_key_signature)
    if any(v is not None for v in kem_fields):
        if not all(v is not None for v in kem_fields):
            raise ValueError("Incomplete KEM bundle")
        nodes.append(
            record(
                "pq",
                bundle.kyber_pre_key_id,
                bundle.kyber_pre_key.serialize(),
                bundle.kyber_pre_key_signature,
            )
        )
    if device_identity is not None:
        nodes.append(Node("device-identity", data=device_identity))
    return Node("keys", children=nodes)


def retry_receipt(
    id,
    destination,
    *,
    count,
    registration_id,
    timestamp,
    error=0,
    participant=None,
    recipient=None,
    bundle=None,
    device_identity=None,
):
    for value, name, maximum in [
        (count, "count", 0xFFFFFFFF),
        (timestamp, "timestamp", 0xFFFFFFFFFFFFFFFF),
        (error, "error", 0xFFFFFFFF),
        (registration_id, "registration", 0x7FFFFFFE),
    ]:
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError("Invalid retry " + name)
    if count == 0 or registration_id == 0 or not id:
        raise ValueError("Missing retry identity/count")
    attrs = {"to": parse_jid(destination), "id": id, "type": "retry"}
    if participant is not None:
        attrs["participant"] = parse_jid(participant)
    if recipient is not None:
        attrs["recipient"] = parse_jid(recipient)
    nodes = [
        Node(
            "retry",
            attrs={
                "v": "1",
                "count": str(count),
                "id": id,
                "t": str(timestamp),
                "error": str(error),
            },
        ),
        Node("registration", data=registration_id.to_bytes(4, "big")),
    ]
    if bundle is not None:
        if bundle.registration_id != registration_id:
            raise ValueError("Bundle registration mismatch")
        nodes.append(bundle_node(bundle, device_identity=device_identity))
    return Node("receipt", attrs=attrs, children=nodes)


@dataclass(frozen=True)
class RetryAttempt:
    logical_id: str
    attempt_id: str
    count: int
    packets: tuple


class RetryManager:
    def __init__(self, client, *, max_attempts=5):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 100:
            raise ValueError("Invalid local retry budget")
        self.client, self.store, self.max_attempts = client, client.store, max_attempts

    def prepare(self, request, *, authenticated_transport, bundle=None, current_group_devices=None):
        if authenticated_transport is not True:
            raise ValueError("Retry requires authenticated routing")
        request = parse_retry(request.raw_node)
        if request.count > self.max_attempts:
            raise ValueError("Retry budget exhausted")
        identity = key(request.id, request.chat, request.sender.name, request.sender.device_id)
        fingerprint = hashlib.sha256(
            json.dumps(request.raw_node.to_dict(), sort_keys=True).encode()
        ).hexdigest()
        marker = key(identity, request.count)
        attempt_id = key(
            "retry", request.id, request.sender.name, request.sender.device_id, request.count
        )
        with self.store.db.atomic():
            source = self.store._get("prepared-request", request.id)
            if source is None:
                raise ValueError("Original message input unavailable")
            original = json.loads(source[0])
            group = original[0] in ("group", "group-delivery")
            if group:
                if original[0] != "group-delivery":
                    raise ValueError("Original group recipient snapshot unavailable")
                if original[2] != self.store.space or original[4] != self.store.bucket:
                    raise ValueError("Original group namespace mismatch")
                if [request.sender.name, request.sender.device_id] not in original[5]:
                    raise ValueError("Retry requester was not an original group recipient")
                group_id = original[1] if original[0] == "group" else original[3]
                if (
                    request.chat != group_id
                    or current_group_devices is None
                    or request.sender not in current_group_devices
                ):
                    raise ValueError("Retry requester is not a current group recipient")
                snapshot = self.store._get("group-snapshot", key(group_id, self.store.bucket))
                if (
                    snapshot
                    and [request.sender.name, request.sender.device_id]
                    not in json.loads(snapshot[0])["members"]
                ):
                    raise ValueError("Retry requester is not in the current group snapshot")
                membership = self.store._get(
                    "group-accounts", key(group_id, self.store.bucket, self.store.space)
                )
                if membership and not json.loads(membership[0])["active"]:
                    raise ValueError("Local account is not a current group member")
                raw = base64.b64decode(
                    original[3] if original[0] == "group" else original[6], validate=True
                )
            elif original[0] == "direct":
                if original[1] != self.store.space:
                    raise ValueError("Original session namespace mismatch")
                targets = {
                    (name, device): base64.b64decode(raw, validate=True)
                    for name, device, raw in original[2]
                }
                raw = targets.get((request.sender.name, request.sender.device_id))
                if (
                    raw is None
                    or request.chat != str(parse_jid(request.sender.name))
                    and address_from_jid(request.chat) != request.sender
                ):
                    raise ValueError("Retry requester is not an original recipient")
            else:
                raise ValueError("Unsupported original preparation type")
            old = self.store._get("retry-attempt", marker)
            if old:
                saved = json.loads(old[0])
                if saved["fingerprint"] != fingerprint:
                    raise Conflict("Retry count reused with different request")
                return RetryAttempt(
                    request.id,
                    saved["attempt_id"],
                    request.count,
                    Delivery(self.store).prepared(saved["attempt_id"]),
                )
            last = self.store._get("retry-count", identity)
            if last and request.count <= int(last[0]):
                raise Conflict("Stale retry request")
            replacement = request.bundle if bundle is None else bundle
            if replacement is not None:
                if (
                    replacement.registration_id != request.registration_id
                    or replacement.device_id != request.sender.device_id
                ):
                    raise ValueError("Retry bundle does not match requester registration/device")
                # The core validates signatures and existing TOFU identity trust;
                # no identity/session purge is used to bypass those checks.
                WhatsAppSessionBuilder(self.store, request.sender).process(replacement)
            else:
                if not self.store.contains_session(request.sender):
                    raise ValueError("Retry requires a fresh prekey bundle")
                remote_registration = self.store.load_session(
                    request.sender
                ).session_state.remote_registration_id
                if remote_registration != request.registration_id:
                    raise ValueError("Changed registration requires a fresh bundle")
            if group:
                packets = self.client.prepare_group_delivery(
                    attempt_id,
                    group_id,
                    raw,
                    [request.sender],
                    force_distribution=(request.sender,),
                )
            else:
                packets = self.client.prepare_direct(attempt_id, {request.sender: raw})
            self.store._put(
                "retry-attempt",
                marker,
                json.dumps(
                    dict(
                        fingerprint=fingerprint,
                        attempt_id=attempt_id,
                        logical_id=request.id,
                        count=request.count,
                    )
                ).encode(),
            )
            self.store._put("retry-count", identity, str(request.count).encode())
            return RetryAttempt(request.id, attempt_id, request.count, packets)


__all__ = [
    "number",
    "data",
    "key_parts",
    "parse_bundle",
    "RetryRequest",
    "parse_retry",
    "bundle_node",
    "retry_receipt",
    "RetryAttempt",
    "RetryManager",
]
