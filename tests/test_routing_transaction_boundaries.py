"""Device routing, session restart and real SQLite transaction boundaries."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from protocol_tree_node import Codec, TokenDictionary
from signal_protocol import KemKeyType
from test_client import bundle
from test_devices import response
from test_stanza_delivery import deliver
from wire_helpers import endpoint

from whatsapp_e2ee import Client, Conflict, Database, SQLiteStore, payload
from whatsapp_e2ee.devices import DeviceDirectory, device_address, participant_hash
from whatsapp_e2ee.routing import prepare_chat, prepare_chat_from_directory
from whatsapp_e2ee.stanza import message_node, receive_message


def device(path, account, number):
    store = SQLiteStore(Database(path), "local")
    store.initialize()
    return Client(store, device_address(account, number))


@pytest.mark.parametrize("domain", ["s.whatsapp.net", "lid"])
def test_hosted_sender_uses_account_snapshot_and_excludes_itself(tmp_path, domain):
    account = "15550001@" + domain
    a = device(tmp_path / "a.db", account, 99)
    linked = device(tmp_path / "linked.db", account, 1)
    b = endpoint(tmp_path / "b.db", "b")
    directory = DeviceDirectory(a.store)
    accounts = {account: [(1, 1), (99, 2)], b.address.name: [(1, 0)]}
    directory.prepare_query(accounts, "query", "sid", mode="query", context="message")
    directory.apply_query(
        response(accounts),
        "query",
        revision=1,
        now=0,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    raw = payload.text("hosted fanout")
    packets, phash = prepare_chat_from_directory(
        a,
        "chat",
        b.address.name,
        raw,
        directory,
        now=1,
        hash_version=3,
        bundles={linked.address: bundle(linked), b.address: bundle(b)},
    )
    assert {(p.recipient, p.device) for p in packets} == {
        (linked.address.name, 1),
        (b.address.name, 1),
    }
    assert phash == participant_hash([a.address, linked.address, b.address], version=3)
    assert not a.store.contains_session(a.address)
    codec = Codec(TokenDictionary.bundled())
    wire = codec.read(codec.write(message_node("chat", b.address.name, packets, phash=phash)))
    assert receive_message(b, deliver(wire, a.address), authenticated_transport=True)[1] == (raw,)
    copied = receive_message(
        linked,
        deliver(wire, a.address, recipient=b.address.name),
        authenticated_transport=True,
        own_device_check=lambda sender: directory.same_user(sender, linked.address),
    )[1][0]
    wrapper = payload.parse(copied).device_sent_message
    assert wrapper.message.conversation == "hosted fanout"
    assert wrapper.destination_jid == b.address.name and wrapper.phash == phash
    for client in (a, linked, b):
        client.store.db.close()


def test_full_sqlite_rollback_preserves_original_exception(tmp_path):
    db = Database(tmp_path / "rollback.db")
    store = SQLiteStore(db, "local")
    db.connection.execute(
        "CREATE TRIGGER fail_record BEFORE INSERT ON records "
        "BEGIN SELECT RAISE(ROLLBACK,'engine rollback'); END"
    )
    try:
        with pytest.raises(sqlite3.IntegrityError, match="engine rollback"):
            with db.atomic():
                store._put("test", "x", b"x")
        assert db.depth == 0 and not db.connection.in_transaction
    finally:
        db.close()


def test_caught_full_rollback_cannot_commit_later_ratchet_or_outbox(tmp_path):
    a, b = [endpoint(tmp_path / (name + ".db"), name) for name in "ab"]
    advertised = bundle(b)
    c = a.store.db.connection
    c.execute(
        "CREATE TRIGGER fail_record BEFORE INSERT ON records WHEN NEW.kind='fail' "
        "BEGIN SELECT RAISE(ROLLBACK,'engine rollback'); END"
    )
    try:
        with pytest.raises((RuntimeError, sqlite3.Error)):
            with a.store.db.atomic():
                a.store._put("before", "x", b"before")
                try:
                    a.store._put("fail", "x", b"x")
                except sqlite3.Error:
                    pass  # An application catches the database error and tries to continue.
                a.prepare_direct(
                    "leaked", {b.address: payload.text("x")}, bundles={b.address: advertised}
                )
        assert not a.store.contains_session(b.address)
        assert a.store._get("before", "x") is None
        assert a.store._get("prepared-request", "leaked") is None
        assert c.execute("SELECT count(*) FROM outbox").fetchone()[0] == 0
        assert a.store.db.depth == 0 and not c.in_transaction
        c.execute("DROP TRIGGER fail_record")
        a.store.db.close()
        a = endpoint(tmp_path / "a.db", "a")
        packet = a.prepare_direct(
            "leaked", {b.address: payload.text("x")}, bundles={b.address: advertised}
        )[0]
        assert b.receive("leaked", a.address, packet) == payload.text("x")
    finally:
        a.store.db.close()
        b.store.db.close()


def test_caught_savepoint_abort_keeps_outer_transaction_usable(tmp_path):
    db = Database(tmp_path / "abort.db")
    store = SQLiteStore(db, "local")
    db.connection.execute(
        "CREATE TRIGGER fail_record BEFORE INSERT ON records WHEN NEW.kind='fail' "
        "BEGIN SELECT RAISE(ABORT,'statement abort'); END"
    )
    try:
        with db.atomic():
            store._put("before", "x", b"before")
            with pytest.raises(sqlite3.IntegrityError, match="statement abort"):
                with db.atomic():
                    store._put("nested", "x", b"rolled back")
                    store._put("fail", "x", b"x")
            store._put("after", "x", b"after")
        assert store._get("before", "x")[0] == b"before"
        assert store._get("after", "x")[0] == b"after"
        assert store._get("nested", "x") is None
    finally:
        db.close()


def test_caught_engine_rollback_invalidates_all_enclosing_scopes(tmp_path):
    db = Database(tmp_path / "rollback.db")
    store = SQLiteStore(db, "local")
    db.connection.execute(
        "CREATE TRIGGER fail_record BEFORE INSERT ON records "
        "BEGIN SELECT RAISE(ROLLBACK,'engine rollback'); END"
    )
    try:
        with pytest.raises(RuntimeError, match="rolled back"):
            with db.atomic():
                with pytest.raises(RuntimeError, match="rolled back"):
                    with db.atomic():
                        with pytest.raises(sqlite3.IntegrityError, match="engine rollback"):
                            store._put("fail", "x", b"x")
                with pytest.raises(RuntimeError, match="rolled back"):
                    with db.atomic():
                        pytest.fail("Aborted transaction allowed another savepoint")
        assert db.depth == 0 and not db.connection.in_transaction
        db.connection.execute("DROP TRIGGER fail_record")
        store._put("new", "x", b"fresh transaction")
        assert store._get("new", "x")[0] == b"fresh transaction"
    finally:
        db.close()


@pytest.mark.parametrize("foreign", ["connection", "owner"])
def test_chat_rejects_directory_outside_local_transaction(tmp_path, foreign):
    a, b = [endpoint(tmp_path / (name + ".db"), name) for name in "ab"]
    db = Database(tmp_path / "a.db") if foreign == "connection" else a.store.db
    directory = DeviceDirectory(SQLiteStore(db, "foreign" if foreign == "owner" else a.store.owner))
    try:
        with pytest.raises(ValueError, match="owner/transaction"):
            prepare_chat(
                a,
                "chat",
                b.address.name,
                payload.text("body"),
                [b.address],
                directory=directory,
                bundles={b.address: bundle(b)},
            )
        assert not a.store.contains_session(b.address)
        assert a.store.db.connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == 0
    finally:
        if db is not a.store.db:
            db.close()
        a.store.db.close()
        b.store.db.close()


def test_own_device_authorization_and_acceptance_share_transaction(tmp_path):
    pn, lid = "15550001@s.whatsapp.net", "15551001@lid"
    a = device(tmp_path / "a.db", pn, 1)
    b = device(tmp_path / "b.db", lid, 2)
    directory = DeviceDirectory(b.store)
    directory.bind_alias(pn, lid, revision=1)
    updater_db = Database(tmp_path / "b.db")
    updater_db.connection.execute("PRAGMA busy_timeout=0")
    updater = DeviceDirectory(SQLiteStore(updater_db, b.store.owner))
    destination = "15550003@s.whatsapp.net"
    raw = payload.device_sent(destination, payload.text("linked copy"))
    packets = a.prepare_direct("copy", {b.address: raw}, bundles={b.address: bundle(b)})
    incoming = deliver(message_node("copy", destination, packets), a.address, recipient=destination)
    revocations = []

    def revoke():
        try:
            updater.unlink_alias(pn)
        except sqlite3.OperationalError as error:
            assert "locked" in str(error)
            return False
        return True

    try:
        with ThreadPoolExecutor(1) as executor:

            def own_device(sender):
                trusted = directory.same_user(sender, b.address)
                revocations.append(executor.submit(revoke).result(timeout=5))
                return trusted

            assert receive_message(
                b,
                incoming,
                authenticated_transport=True,
                own_device_check=own_device,
            )[1] == (raw,)
        assert revocations == [False], "Revocation committed between authorization and acceptance"
        updater.unlink_alias(pn)  # A new transaction can revoke after acceptance completes.
        state = b.store.load_session(a.address).serialize()
        with pytest.raises(ValueError, match="own-device"):
            receive_message(
                b,
                incoming,
                authenticated_transport=True,
                own_device_check=lambda sender: directory.same_user(sender, b.address),
            )
        assert b.store.load_session(a.address).serialize() == state
        assert len(b.pending_events()) == 1
    finally:
        updater_db.close()
        a.store.db.close()
        b.store.db.close()


@pytest.mark.parametrize("operation", ["chat", "directory_chat", "group_initialize"])
def test_routing_alias_authorization_cannot_race_revocation(tmp_path, operation):
    from whatsapp_e2ee.groups_lifecycle import GroupLifecycle, GroupNotifications

    pn, lid = "15550001@s.whatsapp.net", "15551001@lid"
    a = device(tmp_path / "a.db", pn, 1)
    linked = device(tmp_path / "linked.db", lid, 2)
    b = endpoint(tmp_path / "b.db", "b")
    directory = DeviceDirectory(a.store)
    directory.bind_alias(pn, lid, revision=1)
    accounts = {lid: [(1, 1), (2, 2)], b.address.name: [(1, 0)]}
    directory.prepare_query(accounts, "query", "sid", mode="query", context="message")
    directory.apply_query(
        response(accounts),
        "query",
        revision=1,
        now=0,
        ttl=60,
        authenticated_transport=True,
        verification="trusted_snapshot",
    )
    updater_db = Database(tmp_path / "a.db")
    updater_db.connection.execute("PRAGMA busy_timeout=0")
    updater = DeviceDirectory(SQLiteStore(updater_db, a.store.owner))
    same_user = directory.same_user
    attempts = []

    def revoke():
        try:
            updater.unlink_alias(pn)
        except sqlite3.OperationalError as error:
            assert "locked" in str(error)
            return False
        return True

    try:
        with ThreadPoolExecutor(1) as executor:

            def check(first, second):
                trusted = same_user(first, second)
                if trusted and not attempts:
                    attempts.append(executor.submit(revoke).result(timeout=5))
                return trusted

            directory.same_user = check
            raw = payload.text("frozen route")
            bundles = {linked.address: bundle(linked), b.address: bundle(b)}
            if operation == "chat":
                packets = prepare_chat(
                    a,
                    "chat",
                    b.address.name,
                    raw,
                    [b.address],
                    own_devices=[linked.address],
                    directory=directory,
                    bundles=bundles,
                )
                assert len(packets) == 2
            elif operation == "directory_chat":
                packets, _ = prepare_chat_from_directory(
                    a,
                    "chat",
                    b.address.name,
                    raw,
                    directory,
                    now=1,
                    own_account=lid,
                    hash_version=3,
                    bundles=bundles,
                )
                assert len(packets) == 2
            else:
                GroupNotifications(GroupLifecycle(a), directory).initialize(
                    "1000001@g.us",
                    [lid, b.address.name],
                    revision=1,
                    now=1,
                    ordinary_group=True,
                )
        assert attempts == [False], "Alias revocation committed inside a routing decision"
        updater.unlink_alias(pn)
        assert not same_user(pn, lid)
    finally:
        updater_db.close()
        for client in (a, linked, b):
            client.store.db.close()


@pytest.mark.parametrize("conflicting", [False, True])
def test_concurrent_connections_prepare_one_durable_attempt(tmp_path, conflicting):
    a, b = [endpoint(tmp_path / (name + ".db"), name) for name in "ab"]
    other = endpoint(tmp_path / "a.db", "a")
    advertised = bundle(b)
    barrier = Barrier(2)

    def prepare(client, body):
        barrier.wait(timeout=5)
        try:
            return client.prepare_direct(
                "same", {b.address: payload.text(body)}, bundles={b.address: advertised}
            )[0], body
        except Conflict:
            return None

    try:
        with ThreadPoolExecutor(2) as executor:
            futures = [
                executor.submit(prepare, client, body)
                for client, body in ((a, "one"), (other, "two" if conflicting else "one"))
            ]
            outcomes = [f.result(timeout=10) for f in futures]
        accepted = [result for result in outcomes if result is not None]
        assert len(accepted) == (1 if conflicting else 2)
        assert len({packet.ciphertext for packet, _ in accepted}) == 1
        packet, body = accepted[0]
        assert b.receive("same", a.address, packet) == payload.text(body)
        state = a.store.load_session(b.address).serialize()
        assert other.store.load_session(b.address).serialize() == state
        assert a.store.db.connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == 1
        # Reopen and reuse exactly the winning packet without advancing the chain.
        other.store.db.close()
        other = endpoint(tmp_path / "a.db", "a")
        assert other.prepare_direct("same", {b.address: payload.text(body)}) == (packet,)
        assert other.store.load_session(b.address).serialize() == state
    finally:
        for client in (a, other, b):
            client.store.db.close()


@pytest.mark.parametrize("kem", [None, KemKeyType.ML_KEM_1024])
def test_concurrent_receive_after_restart_consumes_prekey_once(tmp_path, kem):
    a, b = [endpoint(tmp_path / (name + ".db"), name) for name in "ab"]
    advertised = bundle(b, kem)
    packets = [
        a.prepare_direct(
            str(i), {b.address: payload.text(str(i))}, bundles={b.address: advertised}
        )[0]
        for i in range(3)
    ]
    b.store.db.close()
    receivers = [endpoint(tmp_path / "b.db", "b") for _ in range(2)]
    barrier = Barrier(2)

    def receive(client):
        barrier.wait(timeout=5)
        return client.receive("2", a.address, packets[2])

    try:
        with ThreadPoolExecutor(2) as executor:
            futures = [executor.submit(receive, client) for client in receivers]
            assert [f.result(timeout=10) for f in futures] == [payload.text("2")] * 2
        b = receivers[0]
        assert not b.store.contains_pre_key(7)
        if kem:
            assert not b.store.contains_kyber_pre_key(9)
        assert len(b.pending_events()) == 1
        # Skipped message keys must survive another restart and be consumed once.
        for client in receivers:
            client.store.db.close()
        receivers = [endpoint(tmp_path / "b.db", "b")]
        b = receivers[0]
        for i in (0, 1):
            assert b.receive(str(i), a.address, packets[i]) == payload.text(str(i))
        assert len(b.pending_events()) == 3
        reply = b.prepare_direct("reply", {a.address: payload.text("reply")})[0]
        assert a.receive("reply", b.address, reply) == payload.text("reply")
    finally:
        a.store.db.close()
        for client in receivers:
            client.store.db.close()


@pytest.mark.parametrize("kem", [None, KemKeyType.ML_KEM_1024])
def test_archived_session_recovers_delayed_message_after_retry_and_restart(tmp_path, kem):
    from test_retry import incoming_retry

    from whatsapp_e2ee.retry import RetryManager

    a, b = [endpoint(tmp_path / (name + ".db"), name) for name in "ab"]
    try:
        first = a.prepare_direct(
            "original",
            {b.address: payload.text("body")},
            bundles={b.address: bundle(b, kem)},
        )[0]
        assert b.receive("original", a.address, first) == payload.text("body")
        reply = b.prepare_direct("reply", {a.address: payload.text("reply")})[0]
        assert a.receive("reply", b.address, reply) == payload.text("reply")
        late = a.prepare_direct("late", {b.address: payload.text("late")})[0]
        assert late.kind == "msg"
        retry = RetryManager(a).prepare(
            incoming_retry(b, bundle=bundle(b, kem)),
            authenticated_transport=True,
        )
        assert b.receive("original", a.address, retry.packets[0], retry_count=1) == payload.text(
            "body"
        )
        for client in (a, b):
            client.store.db.close()
        a, b = [endpoint(tmp_path / (name + ".db"), name) for name in "ab"]
        assert b.store.load_session(a.address).previous_states
        assert b.receive("late", a.address, late) == payload.text("late")
        state = b.store.load_session(a.address).serialize()
        assert b.receive("late", a.address, late) == payload.text("late")
        with pytest.raises(Conflict, match="replayed"):
            b.receive("relabelled", a.address, late)
        assert b.store.load_session(a.address).serialize() == state
        assert len(b.pending_events()) == 2
        recovered = b.prepare_direct("recovered", {a.address: payload.text("recovered")})[0]
        assert a.receive("recovered", b.address, recovered) == payload.text("recovered")
    finally:
        a.store.db.close()
        b.store.db.close()
