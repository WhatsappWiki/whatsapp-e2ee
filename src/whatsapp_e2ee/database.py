"""SQLite schema and nested transaction ownership."""

import os
import sqlite3
import threading
from contextlib import contextmanager


class Database:
    def __init__(self, path):
        if str(path) != ":memory:":
            try:
                fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        self.connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False, timeout=30
        )
        self.lock = threading.RLock()
        self.depth = 0
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            self.connection.close()
            raise ValueError("Unsupported database schema")
        with self.atomic():
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS records(owner TEXT, kind TEXT, space TEXT, id TEXT, value BLOB NOT NULL, flag INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(owner,kind,space,id))"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS outbox(owner TEXT, id TEXT, fingerprint TEXT NOT NULL, value BLOB NOT NULL, state TEXT NOT NULL DEFAULT 'prepared', PRIMARY KEY(owner,id))"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS inbox(owner TEXT, id TEXT, fingerprint TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY(owner,id))"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS events(owner TEXT, id TEXT, value BLOB NOT NULL, done INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(owner,id))"
            )
            self.connection.execute("PRAGMA user_version=1")

    @contextmanager
    def atomic(self):
        with self.lock:
            level = self.depth
            self.connection.execute("BEGIN IMMEDIATE" if level == 0 else f"SAVEPOINT uow_{level}")
            self.depth += 1
            try:
                yield self.connection
                self.connection.execute("COMMIT" if level == 0 else f"RELEASE uow_{level}")
            except BaseException:
                if level == 0:
                    if self.connection.in_transaction:
                        self.connection.execute("ROLLBACK")
                else:
                    self.connection.execute(f"ROLLBACK TO uow_{level}")
                    self.connection.execute(f"RELEASE uow_{level}")
                raise
            finally:
                self.depth -= 1

    def require_no_transaction(self):
        """Reject callbacks whose durable checkpoints could still be rolled back.

        Acquire the connection lock so another thread's transaction can finish;
        a transaction held by this caller is an error, including raw SQL BEGIN.
        """
        with self.lock:
            if self.depth or self.connection.in_transaction:
                raise RuntimeError("Transport callbacks require no active transaction")

    def close(self):
        with self.lock:
            if self.depth:
                raise RuntimeError("Cannot close an active transaction")
            self.connection.close()


__all__ = ["Database"]
