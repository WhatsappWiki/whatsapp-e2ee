"""Persistent PN/LID aliases and authenticated device query snapshots."""

import base64
import hashlib
import json
from dataclasses import replace

from signal_protocol import SignalProtocolAddress

from whatsapp_e2ee.addressing import account_parts, device_address, device_jid, user_account
from whatsapp_e2ee.device_discovery import Device, discovery_request, parse_discovery


class DeviceDirectory:
    def __init__(self, store, *, identity_lookup=None):
        self.store = store
        self.identity_lookup = identity_lookup or (
            lambda account: store.get_identity(device_address(account, 0))
        )

    def bind_alias(self, pn, lid, *, revision):
        if account_parts(pn)[1] != "s.whatsapp.net" or account_parts(lid)[1] != "lid":
            raise ValueError("Expected explicit PN and LID pair")
        if type(revision) is not int or revision < 0:
            raise ValueError("Invalid alias revision")
        with self.store.db.atomic():
            for account, other in ((pn, lid), (lid, pn)):
                old = self.store._get("device-alias", account)
                if old:
                    value = json.loads(old[0])
                    if value["other"] != other or revision < value["revision"]:
                        raise ValueError("Conflicting or stale alias; explicit unlink required")
            self.store._put(
                "device-alias", pn, json.dumps(dict(other=lid, revision=revision)).encode()
            )
            self.store._put(
                "device-alias", lid, json.dumps(dict(other=pn, revision=revision)).encode()
            )

    def unlink_alias(self, account):
        account_parts(account)
        with self.store.db.atomic():
            old = self.store._get("device-alias", account)
            if old:
                other = json.loads(old[0])["other"]
                self.store._remove("device-alias", other)
                self.store._remove("device-alias", account)

    def same_user(self, first, second):
        first = first.name if isinstance(first, SignalProtocolAddress) else first
        second = second.name if isinstance(second, SignalProtocolAddress) else second
        first, second = user_account(first), user_account(second)
        if first == second:
            return True
        row = self.store._get("device-alias", first)
        return row is not None and json.loads(row[0])["other"] == second

    def resolve_address(self, address, *, domain):
        device_jid(address)
        account = user_account(address.name)
        domain = {"hosted": "s.whatsapp.net", "hosted.lid": "lid"}.get(domain, domain)
        if account_parts(account)[1] == domain:
            return device_address(account, address.device_id)
        row = self.store._get("device-alias", account)
        if row is None:
            raise KeyError(account)
        other = json.loads(row[0])["other"]
        if account_parts(other)[1] != domain:
            raise ValueError("No mapping for requested domain")
        # Scope/type and all stored sessions remain untouched.
        return device_address(other, address.device_id)

    def prepare_query(self, accounts, request_id, sid, *, mode, context):
        accounts = tuple(accounts)
        node = discovery_request(accounts, request_id, sid, mode=mode, context=context)
        raw = json.dumps(
            dict(accounts=accounts, sid=sid, mode=mode, context=context), sort_keys=True
        ).encode()
        with self.store.db.atomic():
            old = self.store._get("device-query", request_id)
            if old and old[0] != raw:
                raise ValueError("Query ID already bound")
            self.store._put("device-query", request_id, raw)
        return node

    def apply_query(
        self,
        node,
        request_id,
        *,
        revision,
        now,
        ttl,
        authenticated_transport,
        verification="adv",
        max_age_days=35,
    ):
        """Strict ADV by default; trusted_snapshot is an explicit external policy.

        The compatibility profile allows absent ADV only for snapshots already
        validated elsewhere (or synthetic tests). Present ADV is ALWAYS checked;
        authenticated_transport alone does not establish device-key validity.
        """
        from whatsapp_e2ee.adv import filter_key_indexes, verify_key_index_list

        if authenticated_transport is not True:
            raise ValueError("Authenticated transport is required for device responses")
        if verification not in ("adv", "trusted_snapshot"):
            raise ValueError("Unknown device verification profile")
        if type(revision) is not int or revision < 0 or not 0 <= ttl <= 86400 or now < 0:
            raise ValueError("Invalid cache revision/lifetime")
        with self.store.db.atomic():
            query = self.store._get("device-query", request_id)
            if query is None:
                raise KeyError(request_id)
            q = json.loads(query[0])
            results = parse_discovery(
                node, expected_id=request_id, expected_sid=q["sid"], expected_accounts=q["accounts"]
            )
            verified, checked = {}, []
            for result in results:
                if result.key_index_data is None:
                    if verification == "adv":
                        raise ValueError("Device snapshot requires ADV key-index-list")
                else:
                    prior = self.store._get("device-cache", result.account)
                    local_raw_id = json.loads(prior[0]).get("raw_id") if prior else None
                    proof = verify_key_index_list(
                        result.key_index_data,
                        self.identity_lookup(result.account),
                        result.key_index_timestamp,
                        int(now * 1000),
                        max_age_days=max_age_days,
                        local_raw_id=local_raw_id,
                    )
                    if local_raw_id is not None and proof.raw_id_mismatch:
                        raise ValueError("ADV raw-ID changed; explicit account reset required")
                    accepted = filter_key_indexes(
                        {d.address: d.key_index for d in result.devices}, proof
                    )
                    result = replace(
                        result, devices=tuple(d for d in result.devices if d.address in accepted)
                    )
                    verified[result.account] = proof
                checked.append(result)
            results = tuple(checked)
            digest = hashlib.sha256(json.dumps(node.to_dict(), sort_keys=True).encode()).hexdigest()
            old = self.store._get("device-query-result", request_id)
            if old:
                if old[0].decode() != digest:
                    raise ValueError("Conflicting response for query ID")
                return results
            for r in results:
                row = self.store._get("device-cache", r.account)
                raw = dict(
                    revision=revision,
                    expires=now + ttl,
                    devices=[[d.address.device_id, d.key_index, d.hosted] for d in r.devices],
                    key_index_data=base64.b64encode(r.key_index_data).decode()
                    if r.key_index_data is not None
                    else None,
                    key_index_timestamp=r.key_index_timestamp,
                    key_index_expected_timestamp=r.key_index_expected_timestamp,
                )
                if row:
                    prior = json.loads(row[0])
                    if revision <= prior["revision"]:
                        raise ValueError("Stale device snapshot")
                    if (prior.get("key_index_timestamp") or 0) > (r.key_index_timestamp or 0):
                        raise ValueError("Stale device snapshot timestamp")
                if r.account in verified:
                    raw["raw_id"] = verified[r.account].raw_id
                raw["verification"] = "adv" if r.account in verified else "trusted_snapshot"
                self.store._put("device-cache", r.account, json.dumps(raw, sort_keys=True).encode())
                if r.lid and account_parts(r.account)[1] == "s.whatsapp.net":
                    self.bind_alias(r.account, r.lid, revision=revision)
            self.store._put("device-query-result", request_id, digest.encode())
            return results

    def devices(self, account, *, now):
        account_parts(account)
        row = self.store._get("device-cache", account)
        if row is None:
            raise KeyError(account)
        cached = json.loads(row[0])
        if now >= cached["expires"]:
            raise ValueError("Expired device snapshot; explicit refresh required")
        return tuple(
            Device(device_address(account, id), index, hosted)
            for id, index, hosted in cached["devices"]
        )

    def invalidate(self, account):
        account_parts(account)
        self.store._remove("device-cache", account)


__all__ = ["DeviceDirectory"]
