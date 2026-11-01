import pytest
from signal_protocol.exceptions import InvalidMessageException
from signal_protocol.groups import SenderKeyName
from test_client import bundle, endpoint

from whatsapp_e2ee import payload
from whatsapp_e2ee.groups_lifecycle import GroupLifecycle


def receive(receiver, sender, packets, id):
    for p in packets[:-1]:
        if p.recipient == receiver.address.name and p.device == receiver.address.device_id:
            receiver.receive(id + "-d", sender.address, p, expected_group="G")
    return receiver.receive(id, sender.address, packets[-1], expected_group="G")


def test_lifecycle_remove_readd_rotate_redistribute_and_old_retry(tmp_path):
    a, b, c = [endpoint(tmp_path / (n + ".db"), n) for n in "abc"]
    life = GroupLifecycle(a)
    life.apply("initial", "G", [b.address, c.address], revision=1)
    first = life.prepare(
        "first", "G", payload.text("one"), bundles={b.address: bundle(b), c.address: bundle(c)}
    )
    for r in (b, c):
        assert receive(r, a, first, "first") == payload.text("one")
    life.apply("remove", "G", [b.address], revision=2)
    second = life.prepare("second", "G", payload.text("two"))
    assert receive(b, a, second, "second") == payload.text("two")
    with pytest.raises(InvalidMessageException):
        c.receive("second", a.address, second[-1], expected_group="G")
    assert life.retry_prepared("first") == first
    assert life.apply("remove", "G", [b.address], revision=2) is False
    with pytest.raises(ValueError):
        life.apply("stale", "G", [b.address, c.address], revision=1)
    life.apply("add", "G", [b.address, c.address], revision=3)
    third = life.prepare("third", "G", payload.text("three"))
    assert len(third) == 2  # only C needs new generation
    for r in (b, c):
        assert receive(r, a, third, "third") == payload.text("three")
    key_id = a.store.load_sender_key(SenderKeyName("G", a.address)).get_sender_key_state().key_id
    life.apply(
        "resend",
        "G",
        [b.address, c.address],
        revision=4,
        reason="redistribute",
        affected=[b.address],
    )
    fourth = life.prepare("fourth", "G", payload.text("four"))
    assert len(fourth) == 2 and fourth[0].recipient == b.address.name
    assert (
        a.store.load_sender_key(SenderKeyName("G", a.address)).get_sender_key_state().key_id
        == key_id
    )
    for r in (b, c):
        assert receive(r, a, fourth, "fourth") == payload.text("four")
    life.apply(
        "identity",
        "G",
        [b.address, c.address],
        revision=5,
        reason="identity_changed",
        affected=[b.address],
    )
    fifth = life.prepare("fifth", "G", payload.text("five"))
    assert len(fifth) == 3
    for r in (b, c):
        assert receive(r, a, fifth, "fifth") == payload.text("five")


def test_no_remote_members_and_conflicting_events(tmp_path):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    life = GroupLifecycle(a)
    life.apply("initial", "G", [b.address], revision=1)
    with pytest.raises(ValueError):
        life.apply("initial", "G", [], revision=1)
    with pytest.raises(ValueError):
        life.apply(
            "foreign", "G", [b.address], revision=2, reason="redistribute", affected=[a.address]
        )
    life.apply("empty", "G", [], revision=2)
    with pytest.raises(ValueError):
        life.prepare("nothing", "G", payload.text("x"))


def test_group_event_failure_rolls_back_key_and_snapshot(tmp_path):
    import sqlite3

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    life = GroupLifecycle(a)
    life.apply("initial", "G", [b.address], revision=1)
    life.prepare("first", "G", payload.text("one"), bundles={b.address: bundle(b)})
    name = SenderKeyName("G", a.address)
    prior = a.store.load_sender_key(name).serialize()
    with a.store.db.atomic() as c:
        c.execute(
            "CREATE TRIGGER fail_group_event BEFORE INSERT ON records WHEN NEW.kind='group-event' BEGIN SELECT RAISE(ABORT,'failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        life.apply("rotate", "G", [b.address], revision=2, reason="force_rotate")
    assert a.store.load_sender_key(name).serialize() == prior
    with a.store.db.atomic() as c:
        c.execute("DROP TRIGGER fail_group_event")
    assert life.apply("rotate", "G", [b.address], revision=2, reason="force_rotate")


def notification(id, action, members, *, actor=None, group="G@g.us"):
    from protocol_tree_node import Node

    attrs = {"id": id, "type": "w:gp2", "from": group, "t": "12345"}
    if actor:
        attrs["participant"] = actor
    return Node(
        "notification",
        attrs,
        children=(
            Node(
                action,
                children=tuple(
                    Node("participant", m if isinstance(m, dict) else {"jid": m}) for m in members
                ),
            ),
        ),
    )


def setup_group(tmp_path):
    from test_devices import response

    from whatsapp_e2ee.devices import DeviceDirectory
    from whatsapp_e2ee.groups_lifecycle import GroupNotifications

    a, b, c = [endpoint(tmp_path / (n + ".db"), n) for n in "abc"]
    d = DeviceDirectory(a.store)
    accounts = {x.address.name: [(1, 1)] for x in (a, b, c)}
    d.prepare_query(accounts, "query", "sid", mode="query", context="message")
    d.apply_query(
        response(accounts),
        "query",
        revision=1,
        now=0,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    life = GroupLifecycle(a)
    raw = GroupNotifications(life, d)
    raw.initialize(
        "G@g.us", [a.address.name, b.address.name], revision=1, now=1, ordinary_group=True
    )
    return a, b, c, d, life, raw


def test_raw_group_add_remove_modify_and_removed_self(tmp_path):
    a, b, c, d, life, raw = setup_group(tmp_path)
    add = notification("add", "add", [c.address.name])
    assert raw.apply(add, revision=2, now=1, authenticated_transport=True)
    packets = life.prepare(
        "before",
        "G@g.us",
        payload.text("one"),
        bundles={b.address: bundle(b), c.address: bundle(c)},
    )
    assert len(packets) == 3
    remove = notification("remove", "remove", [c.address.name])
    assert raw.apply(remove, revision=3, now=1, authenticated_transport=True)
    assert raw.apply(remove, revision=3, now=1, authenticated_transport=True) is False
    assert life.retry_prepared("before") == packets
    after = life.prepare("after", "G@g.us", payload.text("two"))
    assert len(after) == 2 and after[0].recipient == b.address.name
    change = notification("modify", "modify", [c.address.name], actor=b.address.name)
    raw.apply(change, revision=4, now=1, authenticated_transport=True)
    changed = life.prepare("changed", "G@g.us", payload.text("three"))
    assert len(changed) == 2 and changed[0].recipient == c.address.name
    raw.apply(
        notification("self", "remove", [a.address.name]),
        revision=5,
        now=1,
        authenticated_transport=True,
    )
    with pytest.raises(ValueError, match="no authorized"):
        life.prepare("left", "G@g.us", payload.text("four"))
    with pytest.raises(ValueError, match="no longer"):
        raw.apply(
            notification("late", "add", [b.address.name]),
            revision=6,
            now=1,
            authenticated_transport=True,
        )


def test_group_raw_failure_alias_conflict_and_retry_atomic(tmp_path):
    a, b, c, d, life, raw = setup_group(tmp_path)
    n = notification("new", "add", [{"jid": "missing@s.whatsapp.net", "lid": "100@lid"}])
    with pytest.raises(KeyError):
        raw.apply(n, revision=2, now=1, authenticated_transport=True)
    assert not d.same_user("missing@s.whatsapp.net", "100@lid")
    with pytest.raises(ValueError, match="Authenticated"):
        raw.apply(
            notification("x", "add", [c.address.name]),
            revision=2,
            now=1,
            authenticated_transport=False,
        )
    raw.apply(
        notification("new", "add", [c.address.name]),
        revision=2,
        now=1,
        authenticated_transport=True,
    )
    with pytest.raises(ValueError, match="already bound"):
        raw.apply(
            notification("new", "remove", [c.address.name]),
            revision=3,
            now=1,
            authenticated_transport=True,
        )
    with pytest.raises(ValueError, match="Stale"):
        raw.apply(
            notification("old", "remove", [c.address.name]),
            revision=1,
            now=1,
            authenticated_transport=True,
        )


def test_group_device_change_and_expired_snapshot(tmp_path):
    from signal_protocol import SignalProtocolAddress
    from test_devices import response

    a, b, c, d, life, raw = setup_group(tmp_path)
    life.prepare("one", "G@g.us", payload.text("one"), bundles={b.address: bundle(b)})
    from whatsapp_e2ee import Client, Database, SQLiteStore

    b2_store = SQLiteStore(Database(tmp_path / "b2.db"), "b2")
    b2_store.initialize()
    b2 = Client(b2_store, SignalProtocolAddress(b.address.name, 2))
    d.prepare_query([b.address.name], "refresh", "sid2", mode="query", context="message")
    d.apply_query(
        response({b.address.name: [(1, 1), (2, 2)]}, id="refresh", sid="sid2"),
        "refresh",
        revision=2,
        now=1,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    raw.refresh_devices("G@g.us", event_id="device-add", revision=2, now=2)
    packets = life.prepare("two", "G@g.us", payload.text("two"), bundles={b2.address: bundle(b2)})
    assert (
        len(packets) == 2
        and SignalProtocolAddress(packets[0].recipient, packets[0].device) == b2.address
    )
    with pytest.raises(ValueError, match="Expired"):
        raw.refresh_devices("G@g.us", event_id="stale-cache", revision=3, now=100)


@pytest.mark.parametrize(
    "action,members,actor",
    [
        ("promote", ["b@s.whatsapp.net"], None),
        ("modify", ["b@s.whatsapp.net"], None),
        ("modify", ["b@s.whatsapp.net", "c@s.whatsapp.net"], "a@s.whatsapp.net"),
        ("add", ["b@s.whatsapp.net", "b@s.whatsapp.net"], None),
        ("add", [{"jid": "b@s.whatsapp.net", "phone_number": "c@s.whatsapp.net"}], None),
        ("add", ["b@hosted"], None),
    ],
)
def test_raw_group_rejects_unsupported_and_ambiguous(action, members, actor):
    from whatsapp_e2ee.groups_lifecycle import parse_group_notification

    with pytest.raises(ValueError):
        parse_group_notification(
            notification("bad", action, members, actor=actor), authenticated_transport=True
        )


def test_persisted_raw_group_node_fixtures():
    import json
    from pathlib import Path

    from protocol_tree_node import Node

    from whatsapp_e2ee.groups_lifecycle import parse_group_notification

    cases = json.loads((Path(__file__).parent / "vectors/group-notifications.json").read_text())[
        "cases"
    ]
    for case in cases:
        node = Node.from_dict(case["node"])
        if case["accepted"]:
            assert (
                parse_group_notification(node, authenticated_transport=True).action
                == case["action"]
            )
        else:
            with pytest.raises(ValueError):
                parse_group_notification(node, authenticated_transport=True)


def test_group_same_device_new_index_redistributes_once(tmp_path):
    from test_devices import response

    a, b, c, d, life, raw = setup_group(tmp_path)
    life.prepare("first-index", "G@g.us", payload.text("one"), bundles={b.address: bundle(b)})
    d.prepare_query([b.address.name], "changed-index", "sid2", mode="query", context="message")
    d.apply_query(
        response({b.address.name: [(1, 2)]}, id="changed-index", sid="sid2"),
        "changed-index",
        revision=2,
        now=1,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    assert raw.refresh_devices("G@g.us", event_id="re-index", revision=2, now=2)
    assert raw.refresh_devices("G@g.us", event_id="re-index", revision=2, now=2) is False
    assert len(life.prepare("second-index", "G@g.us", payload.text("two"))) == 2
    assert len(life.prepare("third-index", "G@g.us", payload.text("three"))) == 1
