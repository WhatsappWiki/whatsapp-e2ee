"""Canonical device addresses and participant hashes; no persistence."""

import base64
import hashlib

from protocol_tree_node import JID
from signal_protocol import SignalProtocolAddress

DOMAINS = frozenset(("s.whatsapp.net", "lid", "hosted", "hosted.lid"))


def account_parts(account):
    if not isinstance(account, str) or account.count("@") != 1:
        raise ValueError("Canonical user account required")
    user, domain = account.split("@")
    if not user or ":" in user or domain not in DOMAINS:
        raise ValueError("Unsupported user account")
    return user, domain


def user_account(account):
    user, domain = account_parts(account)
    domain = {"hosted": "s.whatsapp.net", "hosted.lid": "lid"}.get(domain, domain)
    return user + "@" + domain


def device_jid(address):
    user, domain = account_parts(address.name)
    if type(address.device_id) is not int or not 0 <= address.device_id <= 255:
        raise ValueError("Invalid device ID")
    return JID(user, domain, address.device_id)


def device_address(account, device_id):
    """C0Dl.A01 maps device 99 to the hosted server before constructing a JID."""
    user, domain = account_parts(account)
    if device_id == 99:
        domain = "hosted.lid" if domain in ("lid", "hosted.lid") else "hosted"
    address = SignalProtocolAddress(user + "@" + domain, device_id)
    device_jid(address)
    return address


def participant_hash(addresses, *, version):
    """C1sn A04(v2)/A05(v3): duplicates are preserved by the native primitive.

    The caller supplies the actual set/snapshot and negotiated configuration.
    Java String ordering is reproduced by UTF-16BE sort keys, not Python's
    Unicode code-point order. Android's default charset is UTF-8.
    """
    if type(version) is not int or version not in (2, 3):
        raise ValueError("Unsupported participant hash version")
    strings = []
    for address in addresses:
        jid = device_jid(address)
        strings.append(f"{jid.user}{'.0' if version == 2 else ''}:{jid.device}@{jid.server}")
    strings.sort(key=lambda s: s.encode("utf-16-be", "surrogatepass"))
    digest = hashlib.sha256(b"".join(s.encode("utf-8") for s in strings)).digest()
    return str(version) + ":" + base64.b64encode(digest[:6]).decode("ascii")


__all__ = [
    "DOMAINS",
    "account_parts",
    "user_account",
    "device_jid",
    "device_address",
    "participant_hash",
]
