"""Ordinary encrypted message nodes and explicit receive routing.

Inputs must come from the caller's authenticated transport. Parsing a Node does
not authenticate a server, group membership, a PN/LID alias, or an own device.
Unknown extension children are retained; unsupported encrypted forms fail closed.
"""

from dataclasses import dataclass

from protocol_tree_node import JID, Node
from signal_protocol import SignalProtocolAddress

from whatsapp_e2ee.packets import Packet

TYPES = frozenset(("msg", "pkmsg", "skmsg"))


def attributes(node):
    result = {}
    for a in node.attrs:
        if a.name in result:
            raise ValueError("Duplicate node attribute: " + a.name)
        result[a.name] = a.value
    return result


def children(node, tag):
    return tuple(c for c in node.children or () if c.tag == tag)


def one(node, tag, *, required=False):
    found = children(node, tag)
    if len(found) > 1 or (required and not found):
        raise ValueError("Missing or duplicate child: " + tag)
    return found[0] if found else None


def parse_jid(value):
    if isinstance(value, JID):
        return value
    if not isinstance(value, str) or value.count("@") != 1:
        raise ValueError("Expected a canonical JID")
    user, server = value.split("@")
    if not user or not server:
        raise ValueError("Empty JID component")
    if ":" in user:
        user, device = user.rsplit(":", 1)
        if not device.isascii() or not device.isdigit():
            raise ValueError("Invalid device JID")
        return JID(user, server, int(device))
    return JID(user, server)


def address_from_jid(value):
    jid = parse_jid(value)
    if jid.server not in ("s.whatsapp.net", "lid", "hosted", "hosted.lid") or not jid.user:
        raise ValueError("Expected an individual device JID")
    return SignalProtocolAddress(jid.user + "@" + jid.server, jid.device)


def jid_for_address(address):
    jid = parse_jid(address.name)
    if jid.device:
        raise ValueError("Signal account name must not include device suffix")
    return JID(jid.user, jid.server, address.device_id)


def enc_node(packet, **extras):
    if packet.kind not in TYPES or not packet.ciphertext:
        raise ValueError("Unsupported or empty encrypted message")
    if set(extras) & {"v", "type"}:
        raise ValueError("Cannot override enc version/type")
    allowed = {
        "count",
        "mediatype",
        "native_flow_name",
        "duration",
        "decrypt-fail",
        "state",
        "session_type",
        "bucket",
    }
    if set(extras) - allowed:
        raise ValueError("Unsupported enc attribute")
    return Node("enc", attrs={"v": "2", "type": packet.kind, **extras}, data=packet.ciphertext)


def parse_enc(node, *, recipient, device, group=""):
    attrs = attributes(node)
    if (
        node.tag != "enc"
        or attrs.get("v") != "2"
        or attrs.get("type") not in TYPES
        or not node.data
    ):
        raise ValueError("Invalid enc node")
    return Packet(recipient, device, attrs["type"], node.data, group)


def message_node(
    id,
    destination,
    packets,
    *,
    message_type="text",
    phash=None,
    addressing_mode=None,
    participant=None,
    recipient=None,
    enc_attributes=None,
    extensions=(),
    extra_attributes=None,
    direct=False,
):
    """Assemble already committed ciphertext. Never advances a Signal chain.

    For group fan-out, per-device packets contain SKDM and the one skmsg is a
    top-level child. Optional attributes/extension payloads must be supplied by
    the caller's resolved protocol context (not guessed by this function).
    """
    if not isinstance(id, str) or not id:
        raise ValueError("Missing message ID")
    dest = parse_jid(destination)
    packets = tuple(packets)
    if not packets:
        raise ValueError("No prepared packets")
    attrs = {"id": id, "to": dest, "type": message_type}
    options = {
        "phash": phash,
        "addressing_mode": addressing_mode,
        "participant": parse_jid(participant) if participant is not None else None,
        "recipient": parse_jid(recipient) if recipient is not None else None,
    }
    attrs.update({k: v for k, v in options.items() if v is not None})
    if extra_attributes:
        if set(extra_attributes) & set(attrs):
            raise ValueError("Duplicate message attribute")
        attrs.update(extra_attributes)
    enc_attrs = enc_attributes or {}
    group = dest.server == "g.us"
    nodes, to_nodes, seen = [], [], set()
    for p in packets:
        if p.kind == "skmsg":
            if (
                not group
                or p.recipient != str(dest)
                or p.group != str(dest)
                or any(n.tag == "enc" for n in nodes)
            ):
                raise ValueError("Group packet/destination mismatch")
            nodes.append(enc_node(p, **enc_attrs))
        else:
            if p.kind not in TYPES or p.group:
                raise ValueError("Invalid direct packet")
            identity = (p.recipient, p.device)
            if identity in seen:
                raise ValueError("Duplicate target device")
            seen.add(identity)
            to_nodes.append(
                Node(
                    "to",
                    attrs={"jid": jid_for_address(SignalProtocolAddress(*identity))},
                    children=(enc_node(p, **enc_attrs),),
                )
            )
    if group and not any(n.tag == "enc" for n in nodes):
        raise ValueError("Group message requires skmsg")
    if direct:
        if group or len(to_nodes) != 1 or str(parse_jid(to_nodes[0].attrs[0].value)) != str(dest):
            raise ValueError("Direct enc layout requires one exact destination device")
        nodes.extend(to_nodes[0].children)
    elif to_nodes:
        nodes.append(Node("participants", children=to_nodes))
    for extension in extensions:
        if extension.tag in ("enc", "participants"):
            raise ValueError("Reserved message extension")
        nodes.append(extension)
    return Node("message", attrs=attrs, children=nodes)


@dataclass(frozen=True)
class IncomingMessage:
    id: str
    chat: str
    sender: SignalProtocolAddress
    packets: tuple
    raw_node: Node
    recipient: str | None = None
    retry_counts: tuple = ()
    buckets: tuple = ()


def parse_message(node, local_address):
    """Interpret a server-delivered message. Ciphertext is never reserialized."""
    attrs = attributes(node)
    if (
        node.tag != "message"
        or node.data is not None
        or not isinstance(attrs.get("id"), str)
        or not attrs.get("id")
    ):
        raise ValueError("Invalid message node")
    source = parse_jid(attrs.get("from"))
    group = source.server == "g.us"
    if group:
        sender = address_from_jid(attrs.get("participant"))
    else:
        sender = address_from_jid(source)
        if attrs.get("participant") is not None:
            raise ValueError("Unexpected participant on direct message")
    if "to" in attrs:
        to = parse_jid(attrs["to"])
        local = jid_for_address(local_address)
        if (to.user, to.server) != (local.user, local.server) or (
            to.device and to.device != local.device
        ):
            raise ValueError("Message addressed to another local device")
    encs = list(children(node, "enc"))
    participants = one(node, "participants")
    if participants is not None:
        seen = set()
        for target in participants.children or ():
            if target.tag != "to":
                raise ValueError("Invalid participant child")
            address = address_from_jid(attributes(target).get("jid"))
            if address in seen:
                raise ValueError("Duplicate participant device")
            seen.add(address)
            if address == local_address:
                encs.extend(children(target, "enc"))
    if not encs:
        raise ValueError("No ciphertext for this device")
    packets, counts, buckets = [], [], []
    for enc in encs:
        count = attributes(enc).get("count", "0")
        if (
            not isinstance(count, str)
            or not count.isascii()
            or not count.isdigit()
            or not 0 <= int(count) <= 100
        ):
            raise ValueError("Invalid or excessive enc retry count")
        counts.append(int(count))
        bucket = attributes(enc).get("bucket", "")
        if not isinstance(bucket, str):
            raise ValueError("Invalid enc bucket")
        buckets.append(bucket)
        kind = attributes(enc).get("type")
        p = parse_enc(
            enc,
            recipient=str(source) if kind == "skmsg" else local_address.name,
            device=0 if kind == "skmsg" else local_address.device_id,
            group=str(source) if kind == "skmsg" else "",
        )
        if not group and p.kind == "skmsg":
            raise ValueError("Sender-key ciphertext outside a group")
        packets.append(p)
    if (
        len([p for p in packets if p.kind == "skmsg"]) > 1
        or len([p for p in packets if p.kind != "skmsg"]) > 1
    ):
        raise ValueError("Ambiguous ciphertext set")
    if not group and len(packets) != 1:
        raise ValueError("Ambiguous direct message")
    recipient = str(parse_jid(attrs["recipient"])) if "recipient" in attrs else None
    return IncomingMessage(
        str(attrs["id"]),
        str(source),
        sender,
        tuple(packets),
        node,
        recipient,
        tuple(counts),
        tuple(buckets),
    )


def receive_message(client, node, *, authenticated_transport, own_device_check=None):
    """Authenticate/decrypt all routed ciphertext under a single local transaction.

    authenticated_transport is a required assertion from the transport boundary,
    not something this parser can establish. Own-device classification must use
    the caller's authenticated device directory, including explicit PN/LID maps.
    The local-only check runs inside the receive transaction; database-backed
    checks must share the client's Database instance to preserve that snapshot.
    """
    if authenticated_transport is not True:
        raise ValueError("Unauthenticated transport routing")
    incoming = parse_message(node, client.address)
    group = incoming.chat if incoming.chat.endswith("@g.us") else None
    expected_bucket = client.store.bucket if group else ""
    if any(bucket != expected_bucket for bucket in incoming.buckets):
        raise ValueError("Encrypted bucket does not match selected store")
    output = []
    with client.store.db.atomic():
        own = bool(own_device_check and own_device_check(incoming.sender))
        for packet, count in sorted(
            zip(incoming.packets, incoming.retry_counts), key=lambda item: item[0].kind == "skmsg"
        ):
            slot = "distribution" if group and packet.kind != "skmsg" else "message"
            output.append(
                client.receive(
                    incoming.id,
                    incoming.sender,
                    packet,
                    expected_group=group,
                    own_device=own,
                    expected_destination=incoming.recipient or group,
                    content_slot=slot,
                    retry_count=count,
                )
            )
    return incoming, tuple(output)


__all__ = [
    "TYPES",
    "attributes",
    "children",
    "one",
    "parse_jid",
    "address_from_jid",
    "jid_for_address",
    "enc_node",
    "parse_enc",
    "message_node",
    "IncomingMessage",
    "parse_message",
    "receive_message",
]
