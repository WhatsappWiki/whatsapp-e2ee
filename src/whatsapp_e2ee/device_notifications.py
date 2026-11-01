"""Authenticated device deltas applied through an injected device directory."""

import base64
import json
from dataclasses import dataclass

from signal_protocol import SignalProtocolAddress

from whatsapp_e2ee.addressing import (
    account_parts,
    device_address,
    device_jid,
    participant_hash,
    user_account,
)
from whatsapp_e2ee.device_discovery import Device, _account, _attrs, _integer, _one


@dataclass(frozen=True)
class DeviceNotification:
    # Keep pickle references readable by releases predating the module split.
    __module__ = "whatsapp_e2ee.devices"

    event_id: str
    account: str
    lid: str | None
    additions: tuple[Device, ...]
    removals: tuple[Device, ...]
    lid_additions: tuple[Device, ...]
    lid_removals: tuple[Device, ...]
    device_hash: str
    lid_hash: str | None
    key_index_data: bytes | None
    timestamp: int
    offline: bool


def parse_device_notification(node, *, authenticated_transport):
    """C13w.A0A/C1sd.A01 ordinary device delta fields, without applying trust."""
    from whatsapp_e2ee.stanza import address_from_jid

    if authenticated_transport is not True:
        raise ValueError("Authenticated transport is required for device notifications")
    attrs = _attrs(node)
    if node.tag != "notification" or attrs.get("type") != "devices" or node.data is not None:
        raise ValueError("Expected devices notification")
    event_id = attrs.get("id")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("Missing device notification ID")
    account = _account(attrs.get("from"))
    if account_parts(account)[1] not in ("s.whatsapp.net", "lid"):
        raise ValueError("Unsupported device notification account")
    lid = _account(attrs["lid"]) if "lid" in attrs else None
    if lid and (account_parts(lid)[1] != "lid" or account_parts(account)[1] != "s.whatsapp.net"):
        raise ValueError("Invalid device notification alias")
    if any(c.tag not in ("add", "remove") for c in node.children or ()):
        raise ValueError("Unsupported device notification action")
    add, remove = _one(node, "add", required=False), _one(node, "remove", required=False)
    selected = add if add is not None else remove
    if selected is None:
        raise ValueError("Missing device notification action")
    fields = _attrs(selected)
    phash, lhash = fields.get("device_hash"), fields.get("device_lid_hash")
    if not isinstance(phash, str) or not phash or (lid is not None and not isinstance(lhash, str)):
        raise ValueError("Missing device notification hash")
    if lhash is not None and lid is None:
        raise ValueError("LID hash without alias")
    indexes = _one(selected, "key-index-list", required=False)
    meta = _attrs(indexes) if indexes is not None else {}
    timestamp = _integer(meta.get("ts"), 0)
    if indexes is not None and (not isinstance(indexes.data, bytes) or indexes.children):
        raise ValueError("Malformed key-index-list")

    def read(action):
        primary, aliases, seen, alias_seen = [], [], set(), set()
        if action is None:
            return (), ()
        if action.data is not None:
            raise ValueError("Malformed device action")
        for child in action.children or ():
            if child.tag == "key-index-list":
                continue
            if child.tag != "device" or child.data is not None or child.children:
                raise ValueError("Malformed device child")
            f = _attrs(child)
            address = address_from_jid(f.get("jid"))
            device_jid(address)
            if user_account(address.name) != account or address in seen:
                raise ValueError("Foreign or duplicate device")
            if address != device_address(account, address.device_id):
                raise ValueError("Noncanonical device namespace")
            index = _integer(f.get("key-index"), 0)
            primary.append(
                Device(address, index, account_parts(address.name)[1].startswith("hosted"))
            )
            seen.add(address)
            if "lid" in f:
                alias = address_from_jid(f["lid"])
                if (
                    lid is None
                    or user_account(alias.name) != lid
                    or alias.device_id != address.device_id
                    or alias in alias_seen
                ):
                    raise ValueError("Invalid device LID")
                aliases.append(
                    Device(alias, index, account_parts(alias.name)[1].startswith("hosted"))
                )
                alias_seen.add(alias)
            elif lid is not None:
                raise ValueError("Missing device LID in dual-namespace notification")
        return tuple(primary), tuple(aliases)

    additions, lid_additions = read(add)
    removals, lid_removals = read(remove)
    if not additions and not removals:
        raise ValueError("Empty device notification")
    return DeviceNotification(
        event_id,
        account,
        lid,
        additions,
        removals,
        lid_additions,
        lid_removals,
        phash,
        lhash,
        indexes.data if indexes else None,
        timestamp,
        "offline" in attrs,
    )


@dataclass(frozen=True)
class DeviceUpdate:
    # Keep pickle references readable by releases predating the module split.
    __module__ = "whatsapp_e2ee.devices"

    accounts: tuple[str, ...]
    added: tuple[SignalProtocolAddress, ...] = ()
    removed: tuple[SignalProtocolAddress, ...] = ()
    changed: tuple[SignalProtocolAddress, ...] = ()
    refresh_required: bool = False
    ignored: bool = False


class DeviceNotifications:
    """Authenticated node adapter using real ADV verification, no networking.

    Cached query identities are never inferred from ADV's embedded key. Identity
    changes/raw-ID reset need explicit account-lifecycle resolution, then refresh.
    Numerical key-index equality for remove is a deliberate local guard: the
    native KWX.A00 DEX uses reference equality on map values. We do not emulate
    Java boxed-object identity; final native participant-hash verification remains
    mandatory. TTL, revision, atomicity and duplicate behavior are local policy.
    """

    def __init__(self, directory, local_address, *, identity_lookup=None):
        self.directory, self.store = directory, directory.store
        self.local_address = local_address
        self.identity_lookup = identity_lookup or (
            lambda account: self.store.get_identity(device_address(account, 0))
        )

    def apply(
        self, node, *, revision, now, ttl, hash_version, authenticated_transport, max_age_days=35
    ):
        from whatsapp_e2ee.adv import filter_key_indexes, verify_key_index_list
        from whatsapp_e2ee.store import key

        event = parse_device_notification(node, authenticated_transport=authenticated_transport)
        if type(revision) is not int or revision < 0 or not 0 <= ttl <= 86400 or now < 0:
            raise ValueError("Invalid device notification revision/lifetime")
        if type(hash_version) is not int or hash_version not in (2, 3):
            raise ValueError("Unsupported participant hash version")
        accounts = (event.account,) + ((event.lid,) if event.lid else ())
        wire = json.dumps(node.to_dict(), sort_keys=True).encode()
        event_key = key(event.account, event.event_id)
        with self.store.db.atomic():
            previous = self.store._get("device-notification", event_key)
            if previous:
                if previous[0] != wire:
                    raise ValueError("Device notification ID already bound")
                return DeviceUpdate(accounts, ignored=True)
            if any(self.directory.same_user(a, self.local_address) for a in accounts):
                raise ValueError("Own-device notifications require a separate account lifecycle")
            if event.offline:
                for account in accounts:
                    self.directory.invalidate(account)
                self.store._put("device-notification", event_key, wire)
                return DeviceUpdate(accounts, refresh_required=True)
            rows = {}
            for account in accounts:
                row = self.store._get("device-cache", account)
                if row is None:
                    raise ValueError("Device notification requires a current queried snapshot")
                rows[account] = json.loads(row[0])
                self.directory.devices(account, now=now)  # expiry must not be extended by a delta
                if revision <= rows[account]["revision"]:
                    raise ValueError("Stale device notification revision")
                if (rows[account].get("key_index_timestamp") or 0) > event.timestamp:
                    return DeviceUpdate(accounts, ignored=True)
            additions = (event.additions, event.lid_additions)
            removals = (event.removals, event.lid_removals)
            hashes = (event.device_hash, event.lid_hash)
            verified = None
            if event.additions:
                if event.key_index_data is None:
                    raise ValueError("Device additions require authenticated ADV key-index-list")
                verified = verify_key_index_list(
                    event.key_index_data,
                    self.identity_lookup(event.account),
                    event.timestamp,
                    int(now * 1000),
                    max_age_days=max_age_days,
                    local_raw_id=rows[event.account].get("raw_id"),
                )
                if rows[event.account].get("raw_id") is not None and verified.raw_id_mismatch:
                    raise ValueError(
                        "ADV raw-ID changed; explicit account reset and refresh required"
                    )
            all_added, all_removed, all_changed = [], [], []
            updates = {}
            for account, add, remove, expected in zip(accounts, additions, removals, hashes):
                current = {d.address: d.key_index for d in self.directory.devices(account, now=now)}
                candidate = dict(current)
                candidate.update({d.address: d.key_index for d in add})
                if verified is not None:
                    candidate = filter_key_indexes(candidate, verified)
                for d in remove:
                    if candidate.get(d.address) == d.key_index:
                        candidate.pop(d.address, None)
                if participant_hash(set(candidate), version=hash_version) != expected:
                    raise ValueError("Device notification hash mismatch; explicit refresh required")
                all_added.extend(candidate.keys() - current.keys())
                all_removed.extend(current.keys() - candidate.keys())
                all_changed.extend(
                    a for a in current.keys() & candidate.keys() if current[a] != candidate[a]
                )
                value = rows[account]
                value.update(
                    revision=revision,
                    expires=now + ttl,
                    devices=[
                        [a.device_id, i, account_parts(a.name)[1].startswith("hosted")]
                        for a, i in sorted(candidate.items(), key=lambda p: p[0].device_id)
                    ],
                )
                if verified is not None:
                    value.update(
                        raw_id=verified.raw_id,
                        key_index_timestamp=event.timestamp,
                        key_index_data=base64.b64encode(event.key_index_data).decode(),
                    )
                updates[account] = value
            if event.lid:
                self.directory.bind_alias(event.account, event.lid, revision=revision)
            for account, value in updates.items():
                self.store._put("device-cache", account, json.dumps(value, sort_keys=True).encode())
            self.store._put("device-notification", event_key, wire)
            return DeviceUpdate(accounts, tuple(all_added), tuple(all_removed), tuple(all_changed))


__all__ = ["DeviceNotification", "parse_device_notification", "DeviceUpdate", "DeviceNotifications"]
