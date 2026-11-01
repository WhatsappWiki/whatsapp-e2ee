"""Pure usync request/response parsing and device snapshot values."""

from dataclasses import dataclass

from protocol_tree_node import JID, Node
from signal_protocol import SignalProtocolAddress

from whatsapp_e2ee.addressing import account_parts, device_address, device_jid


def _attrs(node):
    result = {}
    for attr in node.attrs:
        if attr.name in result:
            raise ValueError("Duplicate node attribute")
        result[attr.name] = attr.value
    return result


def _one(node, tag, *, required=True):
    found = [n for n in node.children or () if n.tag == tag]
    if len(found) > 1 or (required and not found):
        raise ValueError("Missing or duplicate " + tag)
    return found[0] if found else None


def _account(value):
    if isinstance(value, JID):
        if not value.user or value.device:
            raise ValueError("Expected user JID, not device JID")
        value = f"{value.user}@{value.server}"
    account_parts(value)
    return value


def _integer(value, default=None):
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError("Invalid nonnegative numeric attribute")
    return int(value)


@dataclass(frozen=True)
class Device:
    # Keep pickle references readable by releases predating the module split.
    __module__ = "whatsapp_e2ee.devices"

    address: SignalProtocolAddress
    key_index: int = 0
    hosted: bool = False

    def __post_init__(self):
        device_jid(self.address)
        if type(self.key_index) is not int or not 0 <= self.key_index < 2**63:
            raise ValueError("Invalid key-index")
        if type(self.hosted) is not bool:
            raise ValueError("Invalid hosted flag")


@dataclass(frozen=True)
class DeviceResult:
    # Keep pickle references readable by releases predating the module split.
    __module__ = "whatsapp_e2ee.devices"

    account: str
    devices: tuple[Device, ...]
    lid: str | None = None
    key_index_data: bytes | None = None
    key_index_timestamp: int | None = None
    key_index_expected_timestamp: int | None = None


def discovery_request(accounts, request_id, sid, *, mode, context):
    accounts = tuple(accounts)
    if not accounts or len(set(accounts)) != len(accounts):
        raise ValueError("Device query needs unique user accounts")
    if not all(isinstance(x, str) and x for x in (request_id, sid, mode, context)):
        raise ValueError("Missing request metadata")
    users = tuple(Node("user", {"jid": JID(*account_parts(a))}) for a in accounts)
    query = Node("query", children=(Node("devices", {"version": "2"}), Node("lid")))
    sync = Node(
        "usync",
        {"sid": sid, "index": "0", "last": "true", "mode": mode, "context": context},
        children=(query, Node("list", children=users)),
    )
    return Node("iq", {"xmlns": "usync", "id": request_id, "type": "get"}, children=(sync,))


def parse_discovery(node, *, expected_id, expected_sid, expected_accounts):
    attrs = _attrs(node)
    if node.tag != "iq" or attrs.get("type") != "result" or attrs.get("id") != expected_id:
        raise ValueError("Device response correlation/type mismatch")
    sync = _one(node, "usync")
    attrs = _attrs(sync)
    if (
        attrs.get("sid") != expected_sid
        or attrs.get("last") != "true"
        or attrs.get("index", "0") != "0"
    ):
        raise ValueError("Incomplete or mismatched device query page")
    expected = set(expected_accounts)
    users = _one(sync, "list")
    result = []
    seen = set()
    for user in users.children or ():
        if user.tag != "user":
            raise ValueError("Unexpected device-list entry")
        attrs = _attrs(user)
        account = _account(attrs.get("jid"))
        if account not in expected or account in seen:
            raise ValueError("Unexpected or duplicate account")
        seen.add(account)
        device_node = _one(user, "devices")
        if _one(device_node, "error", required=False):
            raise ValueError("Partial device-query error; cache is unchanged")
        device_list = _one(device_node, "device-list")
        devices, ids = [], set()
        for child in device_list.children or ():
            if child.tag != "device":
                raise ValueError("Unexpected device child")
            attrs = _attrs(child)
            id = _integer(attrs.get("id"))
            if id in ids:
                raise ValueError("Duplicate device ID")
            ids.add(id)
            hosted = attrs.get("is_hosted")
            if hosted not in (None, "true", "false"):
                raise ValueError("Invalid hosted flag")
            # Do not infer another account/domain from hosted flag alone.
            devices.append(
                Device(
                    device_address(account, id),
                    _integer(attrs.get("key-index"), 0),
                    hosted == "true",
                )
            )
        lid_node = _one(user, "lid", required=False)
        lid = _account(_attrs(lid_node).get("val")) if lid_node else None
        if lid is not None and account_parts(lid)[1] != "lid":
            raise ValueError("LID response has wrong domain")
        indexes = _one(device_node, "key-index-list", required=False)
        if indexes is not None and (not isinstance(indexes.data, bytes) or indexes.children):
            raise ValueError("Malformed key-index-list")
        metadata = _attrs(indexes) if indexes else {}
        result.append(
            DeviceResult(
                account,
                tuple(sorted(devices, key=lambda d: d.address.device_id)),
                lid,
                indexes.data if indexes else None,
                _integer(metadata.get("ts")) if indexes else None,
                _integer(metadata.get("expected_ts"), 0) if indexes else None,
            )
        )
    if seen != expected:
        raise ValueError("Incomplete requested account set")
    return tuple(result)


__all__ = ["Device", "DeviceResult", "discovery_request", "parse_discovery"]
