import os
import subprocess
import sys

import pytest
from signal_protocol.exceptions import InvalidKeyIdException
from test_client import bundle, endpoint

from whatsapp_e2ee import Database, SQLiteStore, payload
from whatsapp_e2ee.delivery import Delivery


@pytest.mark.parametrize("committed", [False, True])
def test_process_kill_atomicity(tmp_path, committed):
    path = tmp_path / "crash.db"
    script = """
import os,sys
from whatsapp_e2ee import Database,SQLiteStore
db=Database(sys.argv[1]); s=SQLiteStore(db,'a'); s.initialize()
with db.atomic() as c:
 s._put('session','test',b'new state')
 c.execute("INSERT INTO outbox(owner,id,fingerprint,value) VALUES('a','x','f',X'5b5d')")
 if sys.argv[2]=='no': os._exit(27)
os._exit(28)
"""
    p = subprocess.run([sys.executable, "-c", script, str(path), "yes" if committed else "no"])
    assert p.returncode == (28 if committed else 27)
    db = Database(path)
    s = SQLiteStore(db, "a")
    assert (s._get("session", "test") is not None) == committed
    with db.atomic() as c:
        assert c.execute("SELECT count(*) FROM outbox").fetchone()[0] == int(committed)
    db.close()


def test_delivery_timeout_replays_identical_packet_and_monotonic_receipts(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    b = endpoint(tmp_path / "b.db", "b")
    p = a.prepare_direct("x", {b.address: payload.text("x")}, bundles={b.address: bundle(b)})[0]
    state = a.store.load_session(b.address).serialize()
    delivery = Delivery(a.store)
    seen = []

    def uncertain(id, packet):
        assert not a.store.db.connection.in_transaction
        seen.append(packet)
        raise TimeoutError()

    with pytest.raises(TimeoutError):
        delivery.dispatch("x", uncertain)
    delivery.dispatch("x", lambda id, packet: seen.append(packet))
    assert seen == [p, p] and a.store.load_session(b.address).serialize() == state
    delivery.receipt("x", p, "delivered")
    delivery.receipt("x", p, "server_ack")
    delivery.dispatch("x", lambda *args: pytest.fail("already acknowledged"))


def test_new_files_private_and_incomplete_identity_not_regenerated(tmp_path):
    s = SQLiteStore(Database(tmp_path / "state.db"), "a")
    s.initialize()
    assert (os.stat(tmp_path / "state.db").st_mode & 0o777) == 0o600
    s._remove("local", "registration")
    identity = s.get_identity_key_pair().serialize()
    with pytest.raises(InvalidKeyIdException):
        s.initialize()
    assert s.get_identity_key_pair().serialize() == identity


@pytest.mark.parametrize("stage", ["session", "prekey", "kem", "event"])
def test_receive_late_failure_restores_all_state(tmp_path, stage):
    import sqlite3

    from signal_protocol import KemKeyType
    from test_client import bundle, endpoint

    from whatsapp_e2ee import payload

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    p = a.prepare_direct(
        "x", {b.address: payload.text("x")}, bundles={b.address: bundle(b, KemKeyType.ML_KEM_1024)}
    )[0]
    sql = {
        "session": "BEFORE INSERT ON records WHEN NEW.kind='session'",
        "prekey": "BEFORE DELETE ON records WHEN OLD.kind='pre'",
        "kem": "BEFORE DELETE ON records WHEN OLD.kind='kem'",
        "event": "BEFORE INSERT ON events",
    }[stage]
    with b.store.db.atomic() as c:
        c.execute(
            "CREATE TRIGGER fail_late " + sql + " BEGIN SELECT RAISE(ABORT,'test failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        b.receive("x", a.address, p)
    assert b.store.contains_pre_key(7)
    assert b.store.contains_kyber_pre_key(9)
    assert not b.store.contains_session(a.address)
    assert not b.pending_events()
    with b.store.db.atomic() as c:
        assert c.execute("SELECT COUNT(*) FROM inbox").fetchone()[0] == 0
        c.execute("DROP TRIGGER fail_late")
    assert b.receive("x", a.address, p) == payload.text("x")
    assert not b.store.contains_pre_key(7)
    assert not b.store.contains_kyber_pre_key(9)
