"""Ordinary ACK/delivery/read receipt parsing and acknowledgments."""

from dataclasses import dataclass

from protocol_tree_node import Node

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
    if node.tag not in ("ack", "receipt") or not isinstance(a.get("id"), str) or not a["id"]:
        raise ValueError("Invalid control node")
    source = str(parse_jid(a.get("from")))
    participant = str(parse_jid(a["participant"])) if "participant" in a else None
    if participant is not None:
        address_from_jid(participant)
    ids = [a["id"]]
    if node.tag == "ack":
        if a.get("class") != "message":
            raise ValueError("Not a message ACK")
        kind = "error" if "error" in a else "server_ack"
    else:
        receipt_type = a.get("type", "delivery")
        if receipt_type not in ("delivery", "read"):
            raise ValueError("Unsupported receipt type; retry has its own parser")
        kind = "delivered" if receipt_type == "delivery" else "read"
        listed = one(node, "list")
        if listed:
            for item in listed.children or ():
                if item.tag != "item":
                    raise ValueError("Invalid receipt item")
                id = attributes(item).get("id")
                if not isinstance(id, str) or not id or id in ids:
                    raise ValueError("Missing/duplicate receipt message ID")
                ids.append(id)
    return Control(kind, tuple(ids), source, participant, a.get("error"), node)


def acknowledge(node):
    a = attributes(node)
    if node.tag not in ("message", "receipt") or not a.get("id"):
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
    if kind not in ("delivery", "read") or not id:
        raise ValueError("Invalid receipt")
    ids = tuple(additional_ids)
    if len(set((id, *ids))) != 1 + len(ids) or any(not isinstance(x, str) or not x for x in ids):
        raise ValueError("Duplicate/empty receipt IDs")
    attrs = {"to": parse_jid(destination), "id": id}
    if kind != "delivery":
        attrs["type"] = kind
    if participant is not None:
        attrs["participant"] = parse_jid(participant)
    nodes = (Node("list", children=[Node("item", attrs={"id": x}) for x in ids]),) if ids else None
    return Node("receipt", attrs=attrs, children=nodes)


__all__ = ["Control", "parse_control", "acknowledge", "receipt_node"]
