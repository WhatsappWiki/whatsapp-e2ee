"""Explicit device snapshots. No device discovery or PN/LID inference.

The removal-rotation rule here is a conservative local policy, not a claim about
all official client event handlers. Provider revisions must be monotonic.
"""

import json

from whatsapp_e2ee import payload
from whatsapp_e2ee.store import key


def prepare_chat(
    client,
    id,
    destination,
    raw,
    recipients,
    *,
    own_devices=(),
    phash=None,
    bundles=None,
    directory=None,
):
    targets = {a: raw for a in recipients}
    if not targets:
        raise ValueError("No destination devices")
    if client.address in targets:
        raise ValueError("Local device cannot be a remote recipient")
    wrapped = payload.device_sent(destination, raw, phash)
    for address in own_devices:
        if address.name != client.address.name and not (
            directory is not None and directory.same_user(address, client.address)
        ):
            raise ValueError(
                "Own-device account must match the bound local account or explicit alias"
            )
        if address == client.address or (
            directory is not None
            and address.device_id == client.address.device_id
            and directory.same_user(address, client.address)
        ):
            continue
        if address in targets:
            raise ValueError("Own and recipient device sets overlap")
        targets[address] = wrapped
    return client.prepare_direct(id, targets, bundles=bundles)


def prepare_group_snapshot(client, id, group, raw, recipients, *, revision, bundles=None):
    if type(revision) is not int or revision < 0:
        raise ValueError("Revision must be a nonnegative integer")
    recipients = tuple(sorted(set(recipients), key=lambda a: (a.name, a.device_id)))
    if not recipients or client.address in recipients:
        raise ValueError("Snapshot must contain remote devices only")
    members = [[a.name, a.device_id] for a in recipients]
    store = client.store
    snapshot_id = key(group, store.bucket)
    with store.db.atomic():
        old = store._get("group-snapshot", snapshot_id)
        if old:
            prior = json.loads(old[0])
            if revision < prior["revision"] or (
                revision == prior["revision"] and members != prior["members"]
            ):
                raise ValueError("Stale or conflicting group snapshot")
            if set(map(tuple, prior["members"])) - set(map(tuple, members)):
                client.rotate_group(group)
        packets = client.prepare_group_delivery(
            id, group, raw, recipients, bundles=bundles, snapshot_revision=revision
        )
        store._put(
            "group-snapshot",
            snapshot_id,
            json.dumps(dict(revision=revision, members=members)).encode(),
        )
        return packets


def prepare_chat_from_directory(
    client, id, destination, raw, directory, *, now, own_account=None, hash_version, bundles=None
):
    """Freeze cached devices and the native hash before per-device encryption.

    A directory belongs to the same database/owner. An alias is selected only by
    an explicit account parameter; crypto sessions are never implicitly migrated.
    """
    from whatsapp_e2ee.addressing import participant_hash

    if directory.store.db is not client.store.db or directory.store.owner != client.store.owner:
        raise ValueError("Directory and client must share a local owner/transaction")
    own_account = own_account or client.address.name
    if not directory.same_user(own_account, client.address.name):
        raise ValueError("Unbound own account")
    with client.store.db.atomic():
        recipients = tuple(d.address for d in directory.devices(destination, now=now))
        own_devices = tuple(d.address for d in directory.devices(own_account, now=now))
        if directory.same_user(destination, own_account):
            raise ValueError("Self-chat needs an explicit separate routing policy")
        local = directory.resolve_address(client.address, domain=own_account.split("@", 1)[1])
        if local not in own_devices:
            raise ValueError("Own device snapshot is missing the sending device")
        phash = participant_hash((*recipients, *own_devices), version=hash_version)
        linked = tuple(a for a in own_devices if a != local)
        packets = prepare_chat(
            client,
            id,
            destination,
            raw,
            recipients,
            own_devices=linked,
            phash=phash,
            bundles=bundles,
            directory=directory,
        )
        return packets, phash


__all__ = ["prepare_chat", "prepare_group_snapshot", "prepare_chat_from_directory"]
