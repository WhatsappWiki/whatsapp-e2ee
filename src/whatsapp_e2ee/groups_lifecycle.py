"""Durable normalized group events and explicit SenderKey redistribution.

Events must be supplied after an application's authenticated metadata processing.
The policy is explicit: removals/identity changes rotate, additions distribute the
current generation, and resend requests invalidate only selected distribution
markers. These actions are statically observed primitives; this module does not
claim to reproduce every official event/configuration branch.
"""

import json
from dataclasses import dataclass

from protocol_tree_node import JID
from signal_protocol import SignalProtocolAddress

from whatsapp_e2ee.addressing import account_parts, device_jid
from whatsapp_e2ee.delivery import Delivery
from whatsapp_e2ee.device_discovery import _account, _attrs, _integer
from whatsapp_e2ee.routing import prepare_group_snapshot
from whatsapp_e2ee.store import key

REASONS = frozenset(("snapshot", "identity_changed", "redistribute", "force_rotate"))


class GroupLifecycle:
    def __init__(self, client):
        self.client, self.store = client, client.store

    def apply(self, event_id, group, recipients, *, revision, reason="snapshot", affected=()):
        if (
            not isinstance(event_id, str)
            or not event_id
            or not isinstance(group, str)
            or not group
            or reason not in REASONS
        ):
            raise ValueError("Invalid group event")
        if type(revision) is not int or revision < 0:
            raise ValueError("Invalid group revision")
        recipients = tuple(sorted(set(recipients), key=lambda a: (a.name, a.device_id)))
        affected = tuple(sorted(set(affected), key=lambda a: (a.name, a.device_id)))
        for address in (*recipients, *affected):
            device_jid(address)
        if self.client.address in recipients:
            raise ValueError("Recipient snapshot must exclude local sender device")
        if not set(affected) <= set(recipients):
            raise ValueError("Affected devices outside current snapshot")
        if reason in ("identity_changed", "redistribute") and not affected:
            raise ValueError("This event requires affected recipient devices")
        members = [[a.name, a.device_id] for a in recipients]
        value = dict(
            group=group,
            bucket=self.store.bucket,
            space=self.store.space,
            revision=revision,
            reason=reason,
            members=members,
            affected=[[a.name, a.device_id] for a in affected],
        )
        raw = json.dumps(value, sort_keys=True).encode()
        event_key = key(self.store.bucket, self.store.space, event_id)
        snapshot_key = key(group, self.store.bucket)
        with self.store.db.atomic():
            old_event = self.store._get("group-event", event_key)
            if old_event:
                if old_event[0] != raw:
                    raise ValueError("Group event ID already bound")
                return False
            old = self.store._get("group-snapshot", snapshot_key)
            removed = set()
            if old:
                prior = json.loads(old[0])
                if revision <= prior["revision"]:
                    raise ValueError("Stale group event revision")
                removed = set(map(tuple, prior["members"])) - set(map(tuple, members))
            if removed or reason in ("identity_changed", "force_rotate"):
                self.client.rotate_group(group)
                self.client.invalidate_distributions(group)
            elif reason == "redistribute":
                self.client.invalidate_distributions(group, affected)
            self.store._put(
                "group-snapshot",
                snapshot_key,
                json.dumps(dict(revision=revision, members=members)).encode(),
            )
            self.store._put("group-event", event_key, raw)
            return True

    def prepare(self, message_id, group, raw, *, bundles=None):
        with self.store.db.atomic():
            row = self.store._get("group-snapshot", key(group, self.store.bucket))
            if row is None:
                raise KeyError(group)
            snapshot = json.loads(row[0])
            recipients = [SignalProtocolAddress(*a) for a in snapshot["members"]]
            if not recipients:
                raise ValueError("Group has no authorized remote recipient devices")
            return prepare_group_snapshot(
                self.client,
                message_id,
                group,
                raw,
                recipients,
                revision=snapshot["revision"],
                bundles=bundles,
            )

    def retry_prepared(self, message_id):
        """Return frozen bytes without applying an older membership snapshot."""
        return Delivery(self.store).prepared(message_id)


@dataclass(frozen=True)
class GroupMember:
    account: str
    pn: str | None = None
    lid: str | None = None


@dataclass(frozen=True)
class GroupNotification:
    event_id: str
    group: str
    action: str
    members: tuple[GroupMember, ...]
    actor: str | None
    timestamp: int | None


def _group(value):
    if isinstance(value, JID):
        if not value.user or value.device or value.server != "g.us":
            raise ValueError("Expected ordinary group JID")
        value = f"{value.user}@{value.server}"
    if not isinstance(value, str) or value.count("@") != 1:
        raise ValueError("Expected ordinary group JID")
    user, server = value.split("@")
    if not user or ":" in user or server != "g.us":
        raise ValueError("Expected ordinary group JID")
    return value


def parse_group_notification(node, *, authenticated_transport):
    """Verified w:gp2 member shapes; no role/community/history interpretation.

    Caa.A00/C11W.A0A/HD6.A05 establish the raw fields. A modify's outer
    participant is the OLD account; its one child is the NEW account. Local
    replay/order rules and SenderKey rotation remain our explicit policy.
    """
    if authenticated_transport is not True:
        raise ValueError("Authenticated transport is required for group notifications")
    attrs = _attrs(node)
    if node.tag != "notification" or attrs.get("type") != "w:gp2":
        raise ValueError("Expected w:gp2 notification")
    event_id = attrs.get("id")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("Missing group notification ID")
    group = _group(attrs.get("from"))
    actor = _account(attrs["participant"]) if "participant" in attrs else None
    timestamp = _integer(attrs["t"]) if "t" in attrs else None
    if node.data is not None or len(node.children or ()) != 1:
        raise ValueError("Expected one group action")
    action = node.children[0]
    if action.tag not in ("add", "remove", "modify"):
        raise ValueError("Unsupported group action")
    if action.data is not None or not action.children:
        raise ValueError("Expected group participants")
    if set(_attrs(action)) - {"reason", "subject"}:
        raise ValueError("Unsupported group action metadata")
    members, seen = [], set()
    for child in action.children:
        if child.tag != "participant" or child.data is not None or child.children:
            raise ValueError("Unsupported group participant shape")
        fields = _attrs(child)
        if set(fields) - {
            "jid",
            "lid",
            "phone_number",
            "type",
            "display_name",
            "username",
            "join_time",
            "group_history_sent",
        }:
            raise ValueError("Unsupported group participant metadata")
        account = _account(fields.get("jid"))
        domain = account_parts(account)[1]
        if domain not in ("s.whatsapp.net", "lid") or account in seen:
            raise ValueError("Unsupported or duplicate group participant")
        pn = _account(fields["phone_number"]) if "phone_number" in fields else None
        lid = _account(fields["lid"]) if "lid" in fields else None
        if pn is not None and account_parts(pn)[1] != "s.whatsapp.net":
            raise ValueError("Invalid participant phone_number")
        if lid is not None and account_parts(lid)[1] != "lid":
            raise ValueError("Invalid participant lid")
        if (domain == "s.whatsapp.net" and pn not in (None, account)) or (
            domain == "lid" and lid not in (None, account)
        ):
            raise ValueError("Conflicting participant aliases")
        members.append(
            GroupMember(
                account,
                account if domain == "s.whatsapp.net" else pn,
                account if domain == "lid" else lid,
            )
        )
        seen.add(account)
    if action.tag == "modify" and (actor is None or len(members) != 1):
        raise ValueError("Modify requires one new member and the old participant")
    return GroupNotification(event_id, group, action.tag, tuple(members), actor, timestamp)


class GroupNotifications:
    """Explicitly registered ordinary groups, fed authenticated nodes offline.

    The caller assigns increasing local revisions after ordering transport events;
    server seconds are metadata, never a unique monotonic revision. Accounts are
    retained even with no cached devices. Missing/stale discovery fails atomically.
    Community/interop role changes and unregistered groups fail closed.
    """

    def __init__(self, lifecycle, directory):
        self.lifecycle, self.directory = lifecycle, directory
        self.store, self.client = lifecycle.store, lifecycle.client
        if directory.store is not self.store:
            raise ValueError("Group lifecycle and directory must share the same store")

    def _key(self, group):
        return key(group, self.store.bucket, self.store.space)

    def _recipients(self, accounts, *, now):
        result = set()
        for account in accounts:
            for device in self.directory.devices(account, now=now):
                a = device.address
                if (
                    self.directory.same_user(a, self.client.address)
                    and a.device_id == self.client.address.device_id
                ):
                    continue
                result.add(a)
        return result

    def _apply_snapshot(self, event_id, group, accounts, *, revision, now, active=True):
        recipients = self._recipients(accounts, now=now) if active else set()
        indexes = {
            key(d.address.name, d.address.device_id): d.key_index
            for account in accounts
            if active
            for d in self.directory.devices(account, now=now)
            if d.address in recipients
        }
        event_key = key(group, self.store.bucket, self.store.space, event_id)
        event = json.dumps(
            dict(accounts=sorted(accounts), revision=revision, indexes=indexes, active=active),
            sort_keys=True,
        ).encode()
        prior_event = self.store._get("group-device-event", event_key)
        if prior_event:
            if prior_event[0] != event:
                raise ValueError("Group device event ID already bound")
            return False
        row = self.store._get("group-device-indexes", self._key(group))
        old = json.loads(row[0]) if row else {}
        changed = [
            a
            for a in recipients
            if key(a.name, a.device_id) in old
            and old[key(a.name, a.device_id)] != indexes[key(a.name, a.device_id)]
        ]
        result = self.lifecycle.apply(
            event_id,
            group,
            recipients,
            revision=revision,
            reason="redistribute" if changed else "snapshot",
            affected=changed,
        )
        self.store._put("group-device-indexes", self._key(group), json.dumps(indexes).encode())
        self.store._put("group-device-event", event_key, event)
        return result

    def initialize(self, group, accounts, *, revision, now, ordinary_group):
        if ordinary_group is not True:
            raise ValueError("Explicit ordinary-group metadata required")
        group = _group(group)
        accounts = tuple(sorted(set(_account(a) for a in accounts)))
        with self.store.db.atomic():
            if not any(self.directory.same_user(a, self.client.address) for a in accounts):
                raise ValueError("Local account must be a member at initialization")
            if self.store._get("group-accounts", self._key(group)):
                raise ValueError("Group already initialized")
            self._apply_snapshot("initialize:" + group, group, accounts, revision=revision, now=now)
            self.store._put(
                "group-accounts",
                self._key(group),
                json.dumps(dict(accounts=accounts, active=True, revision=revision)).encode(),
            )

    def apply(self, node, *, revision, now, authenticated_transport):
        event = parse_group_notification(node, authenticated_transport=authenticated_transport)
        wire = json.dumps(node.to_dict(), sort_keys=True).encode()
        event_key = key(event.group, self.store.bucket, self.store.space, event.event_id)
        with self.store.db.atomic():
            prior = self.store._get("group-notification", event_key)
            if prior:
                if prior[0] != wire:
                    raise ValueError("Group notification ID already bound")
                return False
            row = self.store._get("group-accounts", self._key(event.group))
            if row is None:
                raise ValueError("Ordinary group must be explicitly initialized")
            state = json.loads(row[0])
            if not state["active"]:
                raise ValueError("Local account no longer belongs to this group")
            for member in event.members:
                if member.pn and member.lid:
                    self.directory.bind_alias(member.pn, member.lid, revision=revision)
            accounts = set(state["accounts"])

            def matching(account):
                return {a for a in accounts if self.directory.same_user(a, account)}

            if event.action == "add":
                for member in event.members:
                    if not matching(member.account):
                        accounts.add(member.account)
            else:
                removed = (
                    (event.actor,)
                    if event.action == "modify"
                    else tuple(m.account for m in event.members)
                )
                for account in removed:
                    matches = matching(account)
                    if not matches:
                        raise ValueError("Removed participant absent from current group")
                    accounts -= matches
                if event.action == "modify":
                    accounts.add(event.members[0].account)
            active = any(self.directory.same_user(a, self.client.address) for a in accounts)
            self._apply_snapshot(
                "notification:" + event.group + ":" + event.event_id,
                event.group,
                accounts,
                revision=revision,
                now=now,
                active=active,
            )
            self.store._put(
                "group-accounts",
                self._key(event.group),
                json.dumps(
                    dict(accounts=sorted(accounts), active=active, revision=revision)
                ).encode(),
            )
            self.store._put("group-notification", event_key, wire)
            return True

    def refresh_devices(self, group, *, event_id, revision, now):
        """Explicitly propagate a newly accepted discovery snapshot to the group."""
        group = _group(group)
        with self.store.db.atomic():
            row = self.store._get("group-accounts", self._key(group))
            if row is None:
                raise KeyError(group)
            state = json.loads(row[0])
            if not state["active"]:
                raise ValueError("Local account no longer belongs to this group")
            return self._apply_snapshot(
                event_id, group, state["accounts"], revision=revision, now=now
            )


__all__ = [
    "REASONS",
    "GroupLifecycle",
    "GroupMember",
    "GroupNotification",
    "parse_group_notification",
    "GroupNotifications",
]
