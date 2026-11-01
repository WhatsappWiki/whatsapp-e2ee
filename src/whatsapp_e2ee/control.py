"""Ordinary ACK/delivery/read receipt parsing and acknowledgments."""

from dataclasses import dataclass

from protocol_tree_node import Node

from whatsapp_e2ee.addressing import device_jid
from whatsapp_e2ee.stanza import address_from_jid, attributes, one, parse_jid


@dataclass(frozen=True)
class Control:
    kind: str
    ids: tuple
    source: str
    participant: str | None
    error: str | None
    raw_node: Node


def parse_control(node):
    a = attributes(node)
    if (
        node.tag not in ("ack", "receipt")
        or node.data is not None
        or not isinstance(a.get("id"), str)
        or not a["id"]
    ):
        raise ValueError("Invalid control node")
    source_jid = parse_jid(a.get("from"))
    group = source_jid.server == "g.us"
    if group:
        if not source_jid.user or ":" in source_jid.user or source_jid.device:
            raise ValueError("Invalid group control source")
    else:
        device_jid(address_from_jid(source_jid))
    source = str(source_jid)
    participant = None
    if "participant" in a:
        if not group:
            raise ValueError("Unexpected participant on direct control")
        participant_jid = parse_jid(a["participant"])
        device_jid(address_from_jid(participant_jid))
        participant = str(participant_jid)
    ids = [a["id"]]
    if node.tag == "ack":
        if a.get("class") != "message" or node.children:
            raise ValueError("Not a message ACK")
        if "error" in a and (not isinstance(a["error"], str) or not a["error"]):
            raise ValueError("Invalid message ACK error")
        kind = "error" if "error" in a else "server_ack"
    else:
        if "error" in a or (group and participant is None):
            raise ValueError("Invalid receipt routing")
        if any(child.tag != "list" for child in node.children or ()):
            raise ValueError("Unsupported receipt child")
        receipt_type = a.get("type", "delivery")
        if receipt_type not in ("delivery", "read"):
            raise ValueError("Unsupported receipt type; retry has its own parser")
        kind = "delivered" if receipt_type == "delivery" else "read"
        listed = one(node, "list")
        if listed:
            if listed.data is not None:
                raise ValueError("Invalid receipt list payload")
            for item in listed.children or ():
                if item.tag != "item" or item.data is not None or item.children:
                    raise ValueError("Invalid receipt item")
                id = attributes(item).get("id")
                if not isinstance(id, str) or not id or id in ids:
                    raise ValueError("Missing/duplicate receipt message ID")
                ids.append(id)
    return Control(kind, tuple(ids), source, participant, a.get("error"), node)


def acknowledge(node):
    a = attributes(node)
    if node.tag not in ("message", "receipt") or not isinstance(a.get("id"), str) or not a["id"]:
        raise ValueError("Unsupported acknowledged stanza")
    result = {"id": a["id"], "to": parse_jid(a.get("from")), "class": node.tag}
    type = a.get("type")
    if type is not None and not (node.tag == "receipt" and type == "delivery"):
        result["type"] = type
    for k in ("participant", "recipient"):
        if k in a:
            result[k] = parse_jid(a[k])
    if a.get("edit") not in (None, "", "0"):
        result["edit"] = a["edit"]
    return Node("ack", attrs=result)


def receipt_node(id, destination, *, kind="delivery", participant=None, additional_ids=()):
    if kind not in ("delivery", "read") or not isinstance(id, str) or not id:
        raise ValueError("Invalid receipt")
    ids = tuple(additional_ids)
    if any(not isinstance(x, str) or not x for x in ids) or len(set((id, *ids))) != 1 + len(ids):
        raise ValueError("Duplicate/empty receipt IDs")
    attrs = {"to": parse_jid(destination), "id": id}
    if kind != "delivery":
        attrs["type"] = kind
    if participant is not None:
        attrs["participant"] = parse_jid(participant)
    nodes = (Node("list", children=[Node("item", attrs={"id": x}) for x in ids]),) if ids else None
    return Node("receipt", attrs=attrs, children=nodes)


__all__ = ["Control", "parse_control", "acknowledge", "receipt_node"]
