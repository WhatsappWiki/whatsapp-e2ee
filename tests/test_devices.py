import json
from pathlib import Path

import pytest
from protocol_tree_node import JID, Node
from signal_protocol import SignalProtocolAddress
from test_client import bundle, endpoint

from whatsapp_e2ee import Client, Database, SQLiteStore, payload
from whatsapp_e2ee.devices import (
    DeviceDirectory,
    discovery_request,
    parse_discovery,
    participant_hash,
)
from whatsapp_e2ee.routing import prepare_chat_from_directory

CASES = json.loads((Path(__file__).parent / "vectors/participant-hash.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES)
def test_jdk_participant_hash_vectors(case):
    addresses = [SignalProtocolAddress(*a) for a in case["addresses"]]
    assert participant_hash(addresses, version=case["version"]) == case["expected"]
    assert participant_hash(list(reversed(addresses)), version=case["version"]) == case["expected"]


def response(accounts, *, id="query", sid="sid", missing=False):
    users = []
    for account, devices in accounts.items():
        children = [
            Node(
                "devices",
                children=(
                    Node(
                        "device-list",
                        children=tuple(
                            Node("device", {"id": str(d), "key-index": str(index)})
                            for d, index in devices
                        ),
                    ),
                ),
            )
        ]
        if account == "1@s.whatsapp.net":
            children.append(Node("lid", {"val": JID("101", "lid")}))
        users.append(Node("user", {"jid": account}, children=children))
    return Node(
        "iq",
        {"type": "result", "id": id},
        children=(
            Node(
                "usync",
                {"sid": sid, "index": "0", "last": "false" if missing else "true"},
                children=(Node("list", children=users),),
            ),
        ),
    )


def directory(path):
    return DeviceDirectory(SQLiteStore(Database(path), "local"))


def test_discovery_wire_shape_and_parse():
    node = discovery_request(["1@s.whatsapp.net"], "query", "sid", mode="query", context="message")
    assert dict((a.name, a.value) for a in node.attrs) == {
        "xmlns": "usync",
        "id": "query",
        "type": "get",
    }
    query = node.children[0].children[0]
    assert query.tag == "query"
    assert query.children[0] == Node("devices", {"version": "2"})
    result = parse_discovery(
        response({"1@s.whatsapp.net": [(0, 0), (3, 77)]}),
        expected_id="query",
        expected_sid="sid",
        expected_accounts=["1@s.whatsapp.net"],
    )
    assert result[0].lid == "101@lid"
    assert [(d.address.device_id, d.key_index) for d in result[0].devices] == [(0, 0), (3, 77)]


@pytest.mark.parametrize("case", ["id", "sid", "missing", "extra", "duplicate"])
def test_query_correlation_and_partial_results(tmp_path, case):
    d = directory(tmp_path / "db")
    d.prepare_query(["1@s.whatsapp.net"], "query", "sid", mode="query", context="message")
    kwargs = {}
    accounts = {"1@s.whatsapp.net": [(0, 0)]}
    if case in ("id", "sid"):
        kwargs[case] = "wrong"
    elif case == "missing":
        kwargs["missing"] = True
    elif case == "extra":
        accounts["2@s.whatsapp.net"] = [(0, 0)]
    else:
        accounts["1@s.whatsapp.net"] = [(0, 0), (0, 1)]
    with pytest.raises(ValueError):
        d.apply_query(
            response(accounts, **kwargs),
            "query",
            revision=1,
            now=10,
            ttl=60,
            authenticated_transport=True,
            verification="trusted_snapshot",
        )
    with pytest.raises(KeyError):
        d.devices("1@s.whatsapp.net", now=11)


def test_directory_restart_expiry_alias_isolation_and_refresh(tmp_path):
    path = tmp_path / "db"
    d = directory(path)
    d.prepare_query(["1@s.whatsapp.net"], "query", "sid", mode="query", context="message")
    r = response({"1@s.whatsapp.net": [(0, 0), (3, 77)]})
    d.apply_query(
        r,
        "query",
        revision=1,
        now=10,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    assert d.apply_query(
        r,
        "query",
        revision=1,
        now=11,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    d.store.db.close()
    d = directory(path)
    assert [x.address.device_id for x in d.devices("1@s.whatsapp.net", now=12)] == [0, 3]
    assert d.same_user("1@s.whatsapp.net", "101@lid")
    original = SignalProtocolAddress("1@s.whatsapp.net", 3)
    assert d.resolve_address(original, domain="lid") == SignalProtocolAddress("101@lid", 3)
    assert not d.store.contains_session(original)
    with pytest.raises(KeyError):
        d.devices("101@lid", now=12)  # no invented device snapshot
    with pytest.raises(ValueError):
        d.devices("1@s.whatsapp.net", now=70)
    with pytest.raises(ValueError):
        d.bind_alias("1@s.whatsapp.net", "102@lid", revision=2)
    d.prepare_query(["1@s.whatsapp.net"], "new", "sid2", mode="query", context="message")
    r2 = response({"1@s.whatsapp.net": [(4, 88)]}, id="new", sid="sid2")
    with pytest.raises(ValueError):
        d.apply_query(
            r2,
            "new",
            revision=0,
            now=70,
            ttl=60,
            authenticated_transport=True,
            verification="trusted_snapshot",
        )
    d.apply_query(
        r2,
        "new",
        revision=2,
        now=70,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    assert [x.address.device_id for x in d.devices("1@s.whatsapp.net", now=71)] == [4]
    d.unlink_alias("1@s.whatsapp.net")
    assert not d.same_user("1@s.whatsapp.net", "101@lid")


def test_cached_multi_device_fanout_and_hash(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    store = SQLiteStore(Database(tmp_path / "a2.db"), "a2")
    store.initialize()
    a2 = Client(store, SignalProtocolAddress(a.address.name, 2))
    d = DeviceDirectory(a.store)
    d.prepare_query(
        [a.address.name, b.address.name], "query", "sid", mode="query", context="message"
    )
    d.apply_query(
        response({a.address.name: [(1, 0), (2, 1)], b.address.name: [(1, 0)]}),
        "query",
        revision=1,
        now=0,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    packets, phash = prepare_chat_from_directory(
        a,
        "chat",
        b.address.name,
        payload.text("text"),
        d,
        now=1,
        hash_version=3,
        bundles={b.address: bundle(b), a2.address: bundle(a2)},
    )
    assert len(packets) == 2
    assert phash == participant_hash([a.address, a2.address, b.address], version=3)
    own = next(p for p in packets if p.recipient == a.address.name)
    decoded = payload.parse(
        a2.receive("chat", a.address, own, own_device=True, expected_destination=b.address.name)
    )
    assert decoded.device_sent_message.phash == phash
    assert decoded.device_sent_message.message.conversation == "text"
    target = next(p for p in packets if p.recipient == b.address.name)
    assert b.receive("chat", a.address, target) == payload.text("text")


def test_device_99_domain_mapping(tmp_path):
    from whatsapp_e2ee.devices import device_address

    assert device_address("1@s.whatsapp.net", 99) == SignalProtocolAddress("1@hosted", 99)
    assert device_address("101@lid", 99) == SignalProtocolAddress("101@hosted.lid", 99)
    d = directory(tmp_path / "db")
    d.prepare_query(["1@s.whatsapp.net"], "query", "sid", mode="query", context="message")
    result = d.apply_query(
        response({"1@s.whatsapp.net": [(0, 0), (99, 6)]}),
        "query",
        revision=1,
        now=0,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    assert result[0].devices[1].address == SignalProtocolAddress("1@hosted", 99)
    assert d.devices("1@s.whatsapp.net", now=1)[1].address == SignalProtocolAddress("1@hosted", 99)


def test_directory_multi_account_error_is_atomic(tmp_path):
    d = directory(tmp_path / "db")
    d.prepare_query(
        ["1@s.whatsapp.net", "2@s.whatsapp.net"], "query", "sid", mode="query", context="message"
    )
    # Existing mapping conflict occurs after the first account has been parsed;
    # no cache row may escape the enclosing transaction.
    d.bind_alias("3@s.whatsapp.net", "101@lid", revision=1)
    with pytest.raises(ValueError):
        d.apply_query(
            response({"1@s.whatsapp.net": [(0, 0)], "2@s.whatsapp.net": [(0, 0)]}),
            "query",
            revision=2,
            now=10,
            ttl=60,
            authenticated_transport=True,
            verification="trusted_snapshot",
        )
    with pytest.raises(KeyError):
        d.devices("1@s.whatsapp.net", now=11)
    with pytest.raises(KeyError):
        d.devices("2@s.whatsapp.net", now=11)
    assert d.same_user("3@s.whatsapp.net", "101@lid")


def test_alias_binding_does_not_merge_sessions(tmp_path):
    from signal_protocol import WHATSAPP, SessionRecord

    d = directory(tmp_path / "db")
    pn = SignalProtocolAddress("1@s.whatsapp.net", 2)
    lid = SignalProtocolAddress("101@lid", 2)
    d.store.store_session(pn, SessionRecord(profile=WHATSAPP))
    d.bind_alias(pn.name, lid.name, revision=1)
    assert d.store.contains_session(pn)
    assert not d.store.contains_session(lid)
    assert d.resolve_address(pn, domain="lid") == lid


def test_hosted_alias_resolution_preserves_device_namespace(tmp_path):
    d = directory(tmp_path / "db")
    d.bind_alias("1@s.whatsapp.net", "101@lid", revision=1)
    pn = SignalProtocolAddress("1@hosted", 99)
    lid = SignalProtocolAddress("101@hosted.lid", 99)
    assert d.same_user(pn, "1@s.whatsapp.net")
    assert d.same_user(pn, lid)
    assert d.resolve_address(pn, domain="lid") == lid
    assert d.resolve_address(lid, domain="s.whatsapp.net") == pn


def device_notification(
    id,
    account,
    *,
    add=(),
    remove=(),
    final=(),
    proof=None,
    ts=100,
    offline=False,
    lid=None,
    lid_final=(),
):
    from whatsapp_e2ee.devices import device_jid

    attrs = {"id": id, "from": account, "type": "devices"}
    if offline:
        attrs["offline"] = "0"  # native tests presence, not truthiness
    if lid:
        attrs["lid"] = lid
    actions = []
    for name, entries in (("add", add), ("remove", remove)):
        if not entries:
            continue
        a = {"device_hash": participant_hash(final, version=3)}
        if lid:
            a["device_lid_hash"] = participant_hash(lid_final, version=3)
        children = []
        for address, index in entries:
            fields = {"jid": device_jid(address), "key-index": str(index)}
            if lid:
                from whatsapp_e2ee.devices import device_address

                fields["lid"] = device_jid(device_address(lid, address.device_id))
            children.append(Node("device", fields))
        children.append(Node("key-index-list", {"ts": str(ts)}, data=proof or b""))
        actions.append(Node(name, a, children=children))
    return Node("notification", attrs, children=actions)


def notification_setup(tmp_path):
    from signal_protocol import Curve, IdentityKey

    from whatsapp_e2ee.devices import DeviceNotifications, device_address

    d = directory(tmp_path / "devices.db")
    account = "1@s.whatsapp.net"
    d.prepare_query([account], "query", "sid", mode="query", context="message")
    d.apply_query(
        response({account: [(0, 0), (1, 1)]}),
        "query",
        revision=1,
        now=100,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    identity = Curve.generate_key_pair()
    d.store.save_identity(device_address(account, 0), IdentityKey(identity.public_key))
    adapter = DeviceNotifications(d, SignalProtocolAddress("local@s.whatsapp.net", 0))
    return d, adapter, identity, account


def signed_indexes(identity, *, indexes=(1, 2), ts=100, raw_id=7):
    from whatsapp_e2ee.adv import KeyIndexList, sign_key_index_list

    return sign_key_index_list(
        KeyIndexList(
            raw_id=raw_id, timestamp=ts, current_index=max(indexes), valid_indexes=indexes
        ),
        identity.private_key,
    )


def apply_delta(adapter, node, revision=2):
    return adapter.apply(
        node, revision=revision, now=100, ttl=60, hash_version=3, authenticated_transport=True
    )


def test_device_notification_real_adv_add_remove_replay(tmp_path):
    from whatsapp_e2ee.devices import device_address

    d, adapter, identity, account = notification_setup(tmp_path)
    a0, a1, a2 = [device_address(account, i) for i in range(3)]
    add = device_notification(
        "add", account, add=[(a2, 2)], final=[a0, a1, a2], proof=signed_indexes(identity)
    )
    outcome = apply_delta(adapter, add)
    assert outcome.added == (a2,) and not outcome.refresh_required
    assert apply_delta(adapter, add).ignored
    assert len(d.devices(account, now=100)) == 3
    remove = device_notification("remove", account, remove=[(a1, 1)], final=[a0, a2])
    assert apply_delta(adapter, remove, revision=3).removed == (a1,)
    assert [x.address for x in d.devices(account, now=100)] == [a0, a2]
    wrong_index = device_notification("wrong", account, remove=[(a2, 999)], final=[a0])
    with pytest.raises(ValueError, match="hash mismatch"):
        apply_delta(adapter, wrong_index, revision=4)
    assert len(d.devices(account, now=100)) == 2


def test_device_notification_adv_tamper_identity_raw_id_and_offline(tmp_path):
    from signal_protocol import Curve

    from whatsapp_e2ee.adv import ADVIdentityChange, KeyIndexList, sign_key_index_list
    from whatsapp_e2ee.devices import device_address

    d, adapter, identity, account = notification_setup(tmp_path)
    a0, a1, a2 = [device_address(account, i) for i in range(3)]
    good = signed_indexes(identity)
    bad = good[:-1] + bytes([good[-1] ^ 1])
    for proof in (None, bad):
        with pytest.raises(ValueError):
            apply_delta(
                adapter,
                device_notification("bad", account, add=[(a2, 2)], final=[a0, a1, a2], proof=proof),
            )
    assert len(d.devices(account, now=100)) == 2
    foreign = Curve.generate_key_pair()
    proof = sign_key_index_list(
        KeyIndexList(raw_id=8, timestamp=100, current_index=2, valid_indexes=[1, 2]),
        foreign.private_key,
        account_signature_key=foreign.public_key,
    )
    with pytest.raises(ADVIdentityChange):
        apply_delta(
            adapter,
            device_notification("foreign", account, add=[(a2, 2)], final=[a0, a1, a2], proof=proof),
        )
    apply_delta(
        adapter, device_notification("good", account, add=[(a2, 2)], final=[a0, a1, a2], proof=good)
    )
    with pytest.raises(ValueError, match="raw-ID changed"):
        apply_delta(
            adapter,
            device_notification(
                "reset",
                account,
                add=[(a2, 2)],
                final=[a0, a1, a2],
                proof=signed_indexes(identity, raw_id=8),
            ),
            revision=3,
        )
    outcome = apply_delta(
        adapter,
        device_notification("offline", account, remove=[(a1, 1)], final=[a0, a2], offline=True),
        revision=3,
    )
    assert outcome.refresh_required
    with pytest.raises(KeyError):
        d.devices(account, now=100)


def test_device_notification_dual_namespace_atomic_hashes(tmp_path):
    from whatsapp_e2ee.devices import device_address

    d, adapter, identity, account = notification_setup(tmp_path)
    lid = "101@lid"
    d.prepare_query([lid], "lid-query", "lid-sid", mode="query", context="message")
    d.apply_query(
        response({lid: [(0, 0), (1, 1)]}, id="lid-query", sid="lid-sid"),
        "lid-query",
        revision=1,
        now=100,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    pn = [device_address(account, i) for i in range(3)]
    li = [device_address(lid, i) for i in range(3)]
    bad = device_notification(
        "dual",
        account,
        add=[(pn[2], 2)],
        final=pn,
        proof=signed_indexes(identity),
        lid=lid,
        lid_final=li[:2],
    )
    with pytest.raises(ValueError, match="hash mismatch"):
        apply_delta(adapter, bad)
    assert len(d.devices(account, now=100)) == len(d.devices(lid, now=100)) == 2
    good = device_notification(
        "dual",
        account,
        add=[(pn[2], 2)],
        final=pn,
        proof=signed_indexes(identity),
        lid=lid,
        lid_final=li,
    )
    outcome = apply_delta(adapter, good)
    assert set(outcome.added) == {pn[2], li[2]}


def test_discovery_and_notifications_require_explicit_authentication(tmp_path):
    from whatsapp_e2ee.devices import parse_device_notification

    d = directory(tmp_path / "db")
    d.prepare_query(["1@s.whatsapp.net"], "query", "sid", mode="query", context="message")
    with pytest.raises(TypeError):
        d.apply_query(response({"1@s.whatsapp.net": [(0, 0)]}), "query", revision=1, now=0, ttl=60)
    with pytest.raises(ValueError, match="Authenticated"):
        d.apply_query(
            response({"1@s.whatsapp.net": [(0, 0)]}),
            "query",
            revision=1,
            now=0,
            ttl=60,
            authenticated_transport=False,
            verification="trusted_snapshot",
        )
    with pytest.raises(ValueError, match="Authenticated"):
        parse_device_notification(Node("notification"), authenticated_transport=False)


def with_query_proofs(node, proofs, *, ts=100):
    sync = node.children[0]
    users = []
    for user in sync.children[0].children:
        account = next(a.value for a in user.attrs if a.name == "jid")
        dev = user.children[0]
        proof = Node(
            "key-index-list", {"ts": str(ts), "expected_ts": str(ts)}, data=proofs[account]
        )
        devices = Node("devices", children=(*dev.children, proof))
        users.append(Node("user", attrs=user.attrs, children=(devices, *user.children[1:])))
    return Node(
        "iq",
        attrs=node.attrs,
        children=(Node("usync", attrs=sync.attrs, children=(Node("list", children=users),)),),
    )


def test_discovery_default_adv_and_invalid_signature_atomic(tmp_path):
    from signal_protocol import Curve

    identity = Curve.generate_key_pair()
    d = DeviceDirectory(
        SQLiteStore(Database(tmp_path / "db"), "local"),
        identity_lookup=lambda a: identity.public_key,
    )
    account = "1@s.whatsapp.net"
    d.prepare_query([account], "query", "sid", mode="query", context="message")
    plain = response({account: [(0, 0), (1, 1), (2, 99)]})
    with pytest.raises(ValueError, match="requires ADV"):
        d.apply_query(plain, "query", revision=1, now=100, ttl=60, authenticated_transport=True)
    signed = with_query_proofs(plain, {account: signed_indexes(identity)})
    accepted = d.apply_query(
        signed, "query", revision=1, now=100, ttl=60, authenticated_transport=True
    )
    # The authenticated valid-index list excludes unlisted index99 even if the
    # server's unsigned device-list includes it.
    assert [x.address.device_id for x in accepted[0].devices] == [0, 1]
    assert [x.address.device_id for x in d.devices(account, now=100)] == [0, 1]
    d.prepare_query([account], "new", "sid2", mode="query", context="message")
    original = signed_indexes(identity)
    tampered = original[:-1] + bytes([original[-1] ^ 1])
    bad = with_query_proofs(
        response({account: [(0, 0), (1, 1), (2, 2)]}, id="new", sid="sid2"), {account: tampered}
    )
    # Compatibility mode never turns a present invalid signature into acceptance.
    for mode in ("adv", "trusted_snapshot"):
        with pytest.raises(ValueError, match="signature"):
            d.apply_query(
                bad,
                "new",
                revision=2,
                now=100,
                ttl=60,
                authenticated_transport=True,
                verification=mode,
            )
    assert [x.address.device_id for x in d.devices(account, now=100)] == [0, 1]
    good = with_query_proofs(
        response({account: [(0, 0), (1, 1), (2, 2)]}, id="new", sid="sid2"), {account: original}
    )
    d.apply_query(good, "new", revision=2, now=100, ttl=60, authenticated_transport=True)
    assert [x.address.device_id for x in d.devices(account, now=100)] == [0, 1, 2]


def test_persisted_signed_device_node_fixture(tmp_path):
    from signal_protocol import ECPublicKey, IdentityKey

    from whatsapp_e2ee.devices import device_address

    fixture = json.loads(
        (Path(__file__).parent / "vectors/device-notification-adv.json").read_text()
    )
    d, adapter, _, account = notification_setup(tmp_path)
    d.store.save_identity(
        device_address(account, 0), IdentityKey(ECPublicKey(bytes.fromhex(fixture["public_key"])))
    )
    result = apply_delta(adapter, Node.from_dict(fixture["node"]))
    assert not result.refresh_required
    assert [x.address.device_id for x in d.devices(account, now=100)] == fixture["expected_devices"]


def test_device_notification_changed_index_and_stale_self_guard(tmp_path):
    from whatsapp_e2ee.devices import DeviceNotifications, device_address

    d, adapter, identity, account = notification_setup(tmp_path)
    a0, a1 = [device_address(account, i) for i in range(2)]
    node = device_notification(
        "changed", account, add=[(a1, 2)], final=[a0, a1], proof=signed_indexes(identity)
    )
    outcome = apply_delta(adapter, node)
    assert outcome.changed == (a1,) and not outcome.added and not outcome.removed
    old = device_notification("old", account, remove=[(a1, 2)], final=[a0], ts=99)
    assert apply_delta(adapter, old, revision=3).ignored
    assert len(d.devices(account, now=100)) == 2
    own = DeviceNotifications(d, a0)
    with pytest.raises(ValueError, match="Own-device"):
        apply_delta(
            own, device_notification("own", account, remove=[(a1, 2)], final=[a0]), revision=3
        )


@pytest.mark.parametrize("version", [2.0, 3.0, True])
def test_participant_hash_rejects_non_integer_version(version):
    with pytest.raises(ValueError, match="version"):
        participant_hash([], version=version)
