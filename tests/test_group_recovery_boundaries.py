"""Tracked membership, SenderKey redistributions and late-message recovery."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event

import pytest
from signal_protocol import KeyHelper
from signal_protocol.exceptions import InvalidMessageException
from signal_protocol.groups import GroupSessionBuilder, SenderKeyName
from signal_protocol.protocol import SenderKeyDistributionMessage
from test_group_lifecycle import notification, setup_group
from test_retry import advertised, incoming_retry
from wire_helpers import endpoint

from whatsapp_e2ee import payload
from whatsapp_e2ee.groups_lifecycle import GroupLifecycle
from whatsapp_e2ee.retry import RetryManager
from whatsapp_e2ee.store import key

GROUP = "1000001@g.us"


@pytest.fixture
def clients(tmp_path):
    opened = []

    def create(name):
        client = endpoint(tmp_path / (name + ".db"), name)
        opened.append(client)
        return client

    yield create
    for client in opened:
        client.store.db.close()


def receive(receiver, sender, packets, id, *, retry_count=0):
    for packet in packets[:-1]:
        if (packet.recipient, packet.device) == (receiver.address.name, receiver.address.device_id):
            receiver.receive(
                id,
                sender.address,
                packet,
                expected_group=GROUP,
                content_slot="distribution",
                retry_count=retry_count,
            )
    return receiver.receive(
        id, sender.address, packets[-1], expected_group=GROUP, retry_count=retry_count
    )


@pytest.mark.parametrize("cached", [False, True])
def test_tracked_removal_overrides_stale_external_retry_list(clients, cached):
    a, b, c = [clients(name) for name in "abc"]
    life = GroupLifecycle(a)
    life.apply("initial", GROUP, [b.address, c.address], revision=1)
    original = life.prepare(
        "original",
        GROUP,
        payload.text("body"),
        bundles={b.address: advertised(b), c.address: advertised(c)},
    )
    request = incoming_retry(b, bundle=advertised(b), group=GROUP)
    manager = RetryManager(a)
    if cached:
        manager.prepare(
            request, authenticated_transport=True, current_group_devices=[b.address, c.address]
        )
    life.apply("remove", GROUP, [c.address], revision=2)
    state = a.store.load_sender_key(SenderKeyName(GROUP, a.address)).serialize()
    pairwise = a.store.load_session(b.address).serialize()
    with pytest.raises(ValueError, match="current|snapshot"):
        manager.prepare(
            request, authenticated_transport=True, current_group_devices=[b.address, c.address]
        )
    assert a.store.load_sender_key(SenderKeyName(GROUP, a.address)).serialize() == state
    assert a.store.load_session(b.address).serialize() == pairwise
    assert life.retry_prepared("original") == original


@pytest.mark.parametrize("cached", [False, True])
def test_local_leave_blocks_new_and_cached_protocol_retry(tmp_path, cached):
    a, b, c, directory, life, notifications = setup_group(tmp_path)
    try:
        life.prepare("original", "G@g.us", payload.text("body"), bundles={b.address: advertised(b)})
        request = incoming_retry(b, bundle=advertised(b), group="G@g.us")
        manager = RetryManager(a)
        if cached:
            manager.prepare(
                request, authenticated_transport=True, current_group_devices=[b.address]
            )
        notifications.apply(
            notification("left", "remove", [a.address.name]),
            revision=2,
            now=1,
            authenticated_transport=True,
        )
        with pytest.raises(ValueError, match="current|snapshot|member"):
            manager.prepare(
                request, authenticated_transport=True, current_group_devices=[b.address]
            )
    finally:
        for client in (a, b, c):
            client.store.db.close()


@pytest.mark.parametrize("redistribution", ["same", "ahead", "behind"])
def test_same_generation_distribution_preserves_unread_skipped_key(clients, redistribution):
    a, b = [clients(name) for name in "ab"]
    original = a.prepare_group_delivery(
        "zero", GROUP, payload.text("zero"), [b.address], bundles={b.address: advertised(b)}
    )
    original_dist = a.distribution_payload(GROUP)
    b.receive("initial", a.address, original[0], expected_group=GROUP, content_slot="distribution")
    one = a.prepare_group("one", GROUP, payload.text("one"))[0]
    assert b.receive("one", a.address, one, expected_group=GROUP) == payload.text("one")
    if redistribution == "ahead":
        a.prepare_group("unseen", GROUP, payload.text("unseen"))
    distribution = original_dist if redistribution == "behind" else a.distribution_payload(GROUP)
    fresh = a.prepare_direct("fresh-distribution", {b.address: distribution})[0]
    b.receive(
        "fresh-distribution", a.address, fresh, expected_group=GROUP, content_slot="distribution"
    )
    b.store.db.close()
    b = clients("b")
    assert b.receive("zero", a.address, original[-1], expected_group=GROUP) == payload.text("zero")
    assert b.receive("zero", a.address, original[-1], expected_group=GROUP) == payload.text("zero")


def test_redistribution_preserves_unseen_message_from_forward_gap(clients):
    a, b = [clients(name) for name in "ab"]
    zero = a.prepare_group_delivery(
        "zero", GROUP, payload.text("zero"), [b.address], bundles={b.address: advertised(b)}
    )
    assert receive(b, a, zero, "zero") == payload.text("zero")
    late = a.prepare_group("late", GROUP, payload.text("late"))[0]
    fresh = a.prepare_direct("checkpoint", {b.address: a.distribution_payload(GROUP)})[0]
    b.receive("checkpoint", a.address, fresh, expected_group=GROUP, content_slot="distribution")
    assert b.receive("late", a.address, late, expected_group=GROUP) == payload.text("late")


def test_repeated_redistribution_does_not_evict_older_generation(clients):
    a, b = [clients(name) for name in "ab"]
    old = a.prepare_group_delivery(
        "old", GROUP, payload.text("old"), [b.address], bundles={b.address: advertised(b)}
    )
    b.receive("old-dist", a.address, old[0], expected_group=GROUP, content_slot="distribution")
    a.rotate_group(GROUP)
    current = a.prepare_group_delivery("new", GROUP, payload.text("new"), [b.address])
    assert receive(b, a, current, "new") == payload.text("new")
    for i in range(7):
        packet = a.prepare_direct(f"redistribute-{i}", {b.address: a.distribution_payload(GROUP)})[
            0
        ]
        b.receive(
            f"redistribute-{i}",
            a.address,
            packet,
            expected_group=GROUP,
            content_slot="distribution",
        )
    assert b.receive("old", a.address, old[-1], expected_group=GROUP) == payload.text("old")
    assert len(b.store.load_sender_key(SenderKeyName(GROUP, a.address)).states) == 2


def test_rotated_key_id_collision_supports_both_generations(clients, monkeypatch):
    monkeypatch.setattr(KeyHelper, "generate_sender_key_id", staticmethod(lambda: 12345))
    a, b = [clients(name) for name in "ab"]
    old = a.prepare_group_delivery(
        "old", GROUP, payload.text("old"), [b.address], bundles={b.address: advertised(b)}
    )
    b.receive("old-dist", a.address, old[0], expected_group=GROUP, content_slot="distribution")
    a.rotate_group(GROUP)
    new = a.prepare_group_delivery("new", GROUP, payload.text("new"), [b.address])
    assert receive(b, a, new, "new") == payload.text("new")
    assert b.receive("old", a.address, old[-1], expected_group=GROUP) == payload.text("old")
    latest = a.prepare_group("latest", GROUP, payload.text("latest"))[0]
    assert b.receive("latest", a.address, latest, expected_group=GROUP) == payload.text("latest")


@pytest.mark.parametrize("stage", ["sender", "generation", "snapshot", "event"])
def test_rotation_failure_preserves_whole_generation_and_retry(clients, stage):
    a, b, c = [clients(name) for name in "abc"]
    life = GroupLifecycle(a)
    life.apply("initial", GROUP, [b.address, c.address], revision=1)
    packets = life.prepare(
        "original",
        GROUP,
        payload.text("body"),
        bundles={b.address: advertised(b), c.address: advertised(c)},
    )
    before = a.store.db.connection.execute(
        "SELECT * FROM records ORDER BY kind,space,id"
    ).fetchall()
    kinds = {
        "sender": "sender",
        "generation": "group-generation",
        "snapshot": "group-snapshot",
        "event": "group-event",
    }
    a.store.db.connection.execute(
        "CREATE TRIGGER fail_rotate BEFORE INSERT ON records WHEN NEW.kind='"
        + kinds[stage]
        + "' BEGIN SELECT RAISE(ABORT,'rotation'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="rotation"):
        life.apply("remove", GROUP, [b.address], revision=2)
    assert (
        a.store.db.connection.execute("SELECT * FROM records ORDER BY kind,space,id").fetchall()
        == before
    )
    a.store.db.connection.execute("DROP TRIGGER fail_rotate")
    assert life.apply("remove", GROUP, [b.address], revision=2)
    assert life.retry_prepared("original") == packets


@pytest.mark.parametrize("event_id", [None, "", 1, True])
def test_normalized_group_events_require_nonempty_string_id(clients, event_id):
    a, b = [clients(name) for name in "ab"]
    with pytest.raises(ValueError):
        GroupLifecycle(a).apply(event_id, GROUP, [b.address], revision=1)
    assert a.store._get("group-snapshot", key(GROUP, a.store.bucket)) is None


def test_empty_user_jid_is_not_a_valid_group_notification():
    from protocol_tree_node import JID

    from whatsapp_e2ee.groups_lifecycle import parse_group_notification

    with pytest.raises(ValueError):
        parse_group_notification(
            notification("bad", "add", ["15550002@s.whatsapp.net"], group=JID(None, "g.us")),
            authenticated_transport=True,
        )


@pytest.mark.parametrize("field", ["jid", "lid", "phone_number", "actor"])
def test_group_notification_rejects_jid_without_user(field):
    from protocol_tree_node import JID

    from whatsapp_e2ee.groups_lifecycle import parse_group_notification

    member = {"jid": "15550002@s.whatsapp.net"}
    actor = None
    if field == "actor":
        actor = JID(None, "s.whatsapp.net")
    else:
        member[field] = JID(None, "lid" if field == "lid" else "s.whatsapp.net")
    with pytest.raises(ValueError):
        parse_group_notification(
            notification("bad-account", "add", [member], actor=actor),
            authenticated_transport=True,
        )


def distribute(a, b, raw, id):
    packet = a.prepare_direct(id, {b.address: raw}, bundles={b.address: advertised(b)})[0]
    return b.receive(id, a.address, packet, expected_group=GROUP, content_slot="distribution")


def checkpoint(a):
    return SenderKeyDistributionMessage.from_bytes(
        payload.parse(a.distribution_payload(GROUP)).sender_key_distribution_message.distribution
    )


def database_state(client):
    return {
        table: client.store.db.connection.execute(
            f"SELECT * FROM {table} ORDER BY rowid"
        ).fetchall()
        for table in ("records", "inbox", "events")
    }


@pytest.mark.parametrize("position", ["same", "ahead", "behind", "short-key"])
def test_conflicting_checkpoint_rejects_atomically_and_valid_retry_recovers(clients, position):
    a, b = [clients(name) for name in "ab"]
    original = a.prepare_group_delivery(
        "zero", GROUP, payload.text("zero"), [b.address], bundles={b.address: advertised(b)}
    )
    old = checkpoint(a)
    assert receive(b, a, original, "zero") == payload.text("zero")
    if position == "behind":
        a.prepare_group("one", GROUP, payload.text("one"))
        distribute(a, b, a.distribution_payload(GROUP), "advanced")
        d = old
    else:
        if position == "ahead":
            a.prepare_group("one", GROUP, payload.text("one"))
        d = checkpoint(a)
    bad = SenderKeyDistributionMessage(
        d.id, d.iteration, bytes(31 if position == "short-key" else 32), d.signature_key
    )
    packet = a.prepare_direct("bad", {b.address: payload.distribution(GROUP, bad.serialize())})[0]
    before = database_state(b)
    with pytest.raises(InvalidMessageException, match="chain|checkpoint"):
        b.receive("bad", a.address, packet, expected_group=GROUP, content_slot="distribution")
    assert database_state(b) == before
    distribute(a, b, a.distribution_payload(GROUP), "valid")
    current = a.prepare_group("current", GROUP, payload.text("current"))[0]
    assert b.receive("current", a.address, current, expected_group=GROUP) == payload.text("current")


def test_new_generation_invalid_chain_key_does_not_create_state(clients):
    a, b = [clients(name) for name in "ab"]
    d = checkpoint(a)
    bad = SenderKeyDistributionMessage(d.id, d.iteration, b"", d.signature_key)
    packet = a.prepare_direct(
        "invalid",
        {b.address: payload.distribution(GROUP, bad.serialize())},
        bundles={b.address: advertised(b)},
    )[0]
    before = database_state(b)
    with pytest.raises(InvalidMessageException):
        b.receive("invalid", a.address, packet, expected_group=GROUP, content_slot="distribution")
    assert database_state(b) == before
    assert b.store.load_sender_key(SenderKeyName(GROUP, a.address)).is_empty()


@pytest.mark.parametrize("distance", [2000, 2001])
def test_checkpoint_gap_is_bounded_and_preserves_existing_skipped_keys(clients, distance):
    a, b = [clients(name) for name in "ab"]
    zero = a.prepare_group_delivery(
        "zero", GROUP, payload.text("zero"), [b.address], bundles={b.address: advertised(b)}
    )
    b.receive("dist", a.address, zero[0], expected_group=GROUP, content_slot="distribution")
    one = a.prepare_group("one", GROUP, payload.text("one"))[0]
    assert b.receive("one", a.address, one, expected_group=GROUP) == payload.text("one")
    late = a.prepare_group("late", GROUP, payload.text("late"))[0]
    name = SenderKeyName(GROUP, a.address)
    record = a.store.load_sender_key(name)
    state = record.get_sender_key_state()
    chain = state.sender_chain_key
    for _ in range(distance - 1):
        chain = chain.next()
    state.sender_chain_key = chain
    a.store.store_sender_key(name, record)
    distribute(a, b, a.distribution_payload(GROUP), "gap")
    state = b.store.load_sender_key(name).get_sender_key_state()
    assert len(state.structure.senderMessageKeys) <= 2000
    assert state.sender_chain_key.iteration == distance + 2
    if distance == 2000:
        assert b.receive("late", a.address, late, expected_group=GROUP) == payload.text("late")
    else:
        assert b.receive("zero", a.address, zero[-1], expected_group=GROUP) == payload.text("zero")
    current = a.prepare_group("current", GROUP, payload.text("current"))[0]
    assert b.receive("current", a.address, current, expected_group=GROUP) == payload.text("current")


@pytest.mark.parametrize("legacy_order", ["newest-first", "oldest-first"])
def test_legacy_duplicate_generations_merge_on_receive(clients, legacy_order):
    from signal_protocol import WHATSAPP

    a, b = [clients(name) for name in "ab"]
    zero = a.prepare_group_delivery(
        "zero", GROUP, payload.text("zero"), [b.address], bundles={b.address: advertised(b)}
    )
    b.receive("dist", a.address, zero[0], expected_group=GROUP, content_slot="distribution")
    old = checkpoint(a)
    one = a.prepare_group("one", GROUP, payload.text("one"))[0]
    assert b.receive("one", a.address, one, expected_group=GROUP) == payload.text("one")
    name = SenderKeyName(GROUP, a.address)
    GroupSessionBuilder(b.store, profile=WHATSAPP).process(name, old)
    if legacy_order == "newest-first":
        record = b.store.load_sender_key(name)
        record.states.reverse()
        b.store.store_sender_key(name, record)
    assert len(b.store.load_sender_key(name).states) == 2
    assert b.receive("zero", a.address, zero[-1], expected_group=GROUP) == payload.text("zero")
    assert len(b.store.load_sender_key(name).states) == 1
    current = a.prepare_group("current", GROUP, payload.text("current"))[0]
    assert b.receive("current", a.address, current, expected_group=GROUP) == payload.text("current")


@pytest.mark.parametrize("legacy_order", ["newest-first", "oldest-first"])
def test_legacy_checkpoint_holes_recover_independent_of_state_order(clients, legacy_order):
    from signal_protocol import WHATSAPP

    a, b = [clients(name) for name in "ab"]
    zero = a.prepare_group_delivery(
        "zero", GROUP, payload.text("zero"), [b.address], bundles={b.address: advertised(b)}
    )
    assert receive(b, a, zero, "zero") == payload.text("zero")
    late = a.prepare_group("late", GROUP, payload.text("late"))[0]
    name = SenderKeyName(GROUP, a.address)
    # A database written by the older receiver has independent entries, rather
    # than one merged chain with skipped keys. Both orderings must retain the
    # earlier authenticated checkpoint as a source for the unread gap.
    GroupSessionBuilder(b.store, profile=WHATSAPP).process(name, checkpoint(a))
    if legacy_order == "oldest-first":
        record = b.store.load_sender_key(name)
        record.states.reverse()
        b.store.store_sender_key(name, record)
    assert b.receive("late", a.address, late, expected_group=GROUP) == payload.text("late")
    assert len(b.store.load_sender_key(name).states) == 1


@pytest.mark.parametrize("stage", ["inbox", "events", "sender", "authenticated-ciphertext"])
def test_colliding_generation_receive_failure_rolls_back_and_recovers(clients, monkeypatch, stage):
    monkeypatch.setattr(KeyHelper, "generate_sender_key_id", staticmethod(lambda: 67890))
    a, b = [clients(name) for name in "ab"]
    old = a.prepare_group_delivery(
        "old", GROUP, payload.text("old"), [b.address], bundles={b.address: advertised(b)}
    )
    b.receive("old-dist", a.address, old[0], expected_group=GROUP, content_slot="distribution")
    a.rotate_group(GROUP)
    distribute(a, b, a.distribution_payload(GROUP), "new-dist")
    before = database_state(b)
    table = stage if stage in ("inbox", "events") else "records"
    where = "" if table != "records" else f" WHEN NEW.kind='{stage}'"
    b.store.db.connection.execute(
        f"CREATE TRIGGER fail_receive BEFORE INSERT ON {table}{where} "
        "BEGIN SELECT RAISE(ABORT,'receive-failed'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="receive-failed"):
        b.receive("old", a.address, old[-1], expected_group=GROUP)
    assert database_state(b) == before
    b.store.db.connection.execute("DROP TRIGGER fail_receive")
    assert b.receive("old", a.address, old[-1], expected_group=GROUP) == payload.text("old")
    current = a.prepare_group("current", GROUP, payload.text("current"))[0]
    assert b.receive("current", a.address, current, expected_group=GROUP) == payload.text("current")


def test_group_ciphertext_cannot_carry_embedded_distribution(clients):
    a, b = [clients(name) for name in "ab"]
    original = a.prepare_group_delivery(
        "zero", GROUP, payload.text("zero"), [b.address], bundles={b.address: advertised(b)}
    )
    assert receive(b, a, original, "zero") == payload.text("zero")
    nested = a.prepare_group("nested", GROUP, a.distribution_payload(GROUP))[0]
    before = database_state(b)
    with pytest.raises(ValueError, match="pairwise"):
        b.receive("nested", a.address, nested, expected_group=GROUP)
    assert database_state(b) == before
    current = a.prepare_group("current", GROUP, payload.text("current"))[0]
    assert b.receive("current", a.address, current, expected_group=GROUP) == payload.text("current")


@pytest.mark.parametrize("cached", [False, True])
def test_retry_waits_for_concurrent_membership_removal(clients, cached):
    a, b, c = [clients(name) for name in "abc"]
    life = GroupLifecycle(a)
    life.apply("initial", GROUP, [b.address, c.address], revision=1)
    life.prepare(
        "original",
        GROUP,
        payload.text("body"),
        bundles={b.address: advertised(b), c.address: advertised(c)},
    )
    other = clients("a")
    manager = RetryManager(other)
    request = incoming_retry(b, bundle=advertised(b), group=GROUP)
    if cached:
        manager.prepare(
            request, authenticated_transport=True, current_group_devices=[b.address, c.address]
        )
    started = Event()
    other.store.db.connection.set_trace_callback(
        lambda sql: started.set() if sql == "BEGIN IMMEDIATE" else None
    )
    with ThreadPoolExecutor(1) as executor:
        with a.store.db.atomic():
            life.apply("remove", GROUP, [c.address], revision=2)
            before = database_state(a)
            future = executor.submit(
                manager.prepare,
                request,
                authenticated_transport=True,
                current_group_devices=[b.address, c.address],
            )
            assert started.wait(5)
            assert not future.done()
        with pytest.raises(ValueError, match="snapshot"):
            future.result(timeout=5)
    other.store.db.connection.set_trace_callback(None)
    assert database_state(a) == before


@pytest.mark.parametrize("target", ["old", "new"])
def test_collision_signature_failure_preserves_generation_order(clients, monkeypatch, target):
    monkeypatch.setattr(KeyHelper, "generate_sender_key_id", staticmethod(lambda: 24680))
    a, b = [clients(name) for name in "ab"]
    old = a.prepare_group_delivery(
        "old", GROUP, payload.text("old"), [b.address], bundles={b.address: advertised(b)}
    )
    b.receive("old-dist", a.address, old[0], expected_group=GROUP, content_slot="distribution")
    a.rotate_group(GROUP)
    new = a.prepare_group_delivery("new", GROUP, payload.text("new"), [b.address])
    b.receive("new-dist", a.address, new[0], expected_group=GROUP, content_slot="distribution")
    packet = old[-1] if target == "old" else new[-1]
    corrupt = replace(
        packet, ciphertext=packet.ciphertext[:-1] + bytes([packet.ciphertext[-1] ^ 1])
    )
    before = database_state(b)
    with pytest.raises(InvalidMessageException):
        b.receive(target, a.address, corrupt, expected_group=GROUP)
    assert database_state(b) == before
    assert b.receive("old", a.address, old[-1], expected_group=GROUP) == payload.text("old")
    assert b.receive("new", a.address, new[-1], expected_group=GROUP) == payload.text("new")


def test_distinct_generation_history_stays_bounded_after_redistributions(clients):
    a, b = [clients(name) for name in "ab"]
    original = a.prepare_group_delivery(
        "old", GROUP, payload.text("old"), [b.address], bundles={b.address: advertised(b)}
    )
    b.receive("old-dist", a.address, original[0], expected_group=GROUP, content_slot="distribution")
    for i in range(5):
        a.rotate_group(GROUP)
        distribute(a, b, a.distribution_payload(GROUP), f"rotation-{i}")
        distribute(a, b, a.distribution_payload(GROUP), f"repeat-{i}")
    record = b.store.load_sender_key(SenderKeyName(GROUP, a.address))
    assert len(record.states) == 5
    with pytest.raises(InvalidMessageException):
        b.receive("old", a.address, original[-1], expected_group=GROUP)
    current = a.prepare_group("current", GROUP, payload.text("current"))[0]
    assert b.receive("current", a.address, current, expected_group=GROUP) == payload.text("current")
