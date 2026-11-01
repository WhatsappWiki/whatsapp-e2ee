"""SQLite records, isolation and a shared unit of work for protocol callbacks."""

import json

from signal_protocol import (
    WHATSAPP,
    IdentityKey,
    IdentityKeyPair,
    KeyHelper,
    KyberPreKeyRecord,
    PreKeyRecord,
    SessionRecord,
    SignedPreKeyRecord,
)
from signal_protocol.exceptions import InvalidKeyIdException
from signal_protocol.groups import SenderKeyRecord

from whatsapp_e2ee.database import Database


def key(*parts):
    return json.dumps(parts, ensure_ascii=False, separators=(",", ":"))


class SQLiteStore:
    def __init__(self, db, owner, *, scope=0, session_type=0, bucket=""):
        self.db, self.owner = db, owner
        self.space = key(scope, session_type)
        self.bucket = bucket

    def _space(self, kind):
        return self.space if kind == "session" else (key(self.bucket) if kind == "sender" else "")

    def _get(self, kind, id):
        with self.db.atomic() as c:
            return c.execute(
                "SELECT value,flag FROM records WHERE owner=? AND kind=? AND space=? AND id=?",
                (self.owner, kind, self._space(kind), id),
            ).fetchone()

    def _put(self, kind, id, value, flag=0):
        with self.db.atomic() as c:
            c.execute(
                "INSERT INTO records VALUES(?,?,?,?,?,?) ON CONFLICT(owner,kind,space,id) DO UPDATE SET value=excluded.value,flag=excluded.flag",
                (self.owner, kind, self._space(kind), id, value, flag),
            )

    def _remove(self, kind, id):
        with self.db.atomic() as c:
            c.execute(
                "DELETE FROM records WHERE owner=? AND kind=? AND space=? AND id=?",
                (self.owner, kind, self._space(kind), id),
            )

    def initialize(self):
        """Explicit creation only. Ordinary getters never generate identities."""
        with self.db.atomic():
            identity_row = self._get("local", "identity")
            registration_row = self._get("local", "registration")
            if (identity_row is None) != (registration_row is None):
                raise InvalidKeyIdException("Incomplete local identity; explicit recovery required")
            if identity_row is None:
                identity = KeyHelper.generate_identity_key_pair()
                self._put("local", "identity", identity.serialize())
                self._put(
                    "local",
                    "registration",
                    str(KeyHelper.generate_registration_id(True)).encode(),
                )
            self.get_local_registration_id()

    def get_identity_key_pair(self):
        row = self._get("local", "identity")
        if row is None:
            raise InvalidKeyIdException("Local account is not initialized")
        return IdentityKeyPair.from_bytes(row[0], profile=WHATSAPP)

    def get_local_registration_id(self):
        row = self._get("local", "registration")
        if row is None:
            raise InvalidKeyIdException("Missing registration ID")
        return int(row[0])

    @staticmethod
    def address(address):
        # name contains the canonical account domain; device remains independent.
        return key(address.name, address.device_id)

    def get_identity(self, address):
        row = self._get("identity", self.address(address))
        return IdentityKey.from_bytes(row[0]) if row else None

    def save_identity(self, address, identity):
        with self.db.atomic():
            old = self.get_identity(address)
            self._put("identity", self.address(address), identity.serialize())
            return old != identity

    def is_trusted_identity(self, address, identity, direction):
        old = self.get_identity(address)
        return old is None or old == identity

    def load_session(self, address):
        row = self._get("session", self.address(address))
        return SessionRecord(row[0] if row else None, profile=WHATSAPP)

    def store_session(self, address, record):
        self._put("session", self.address(address), record.serialize())

    def contains_session(self, address):
        return self._get("session", self.address(address)) is not None

    def delete_session(self, address):
        self._remove("session", self.address(address))

    def delete_all_sessions(self, name):
        with self.db.atomic() as c:
            for (id,) in c.execute(
                "SELECT id FROM records WHERE owner=? AND kind='session' AND space=?",
                (self.owner, self.space),
            ).fetchall():
                if json.loads(id)[0] == name:
                    self._remove("session", id)

    def get_sub_device_sessions(self, name):
        with self.db.atomic() as c:
            rows = c.execute(
                "SELECT id FROM records WHERE owner=? AND kind='session' AND space=?",
                (self.owner, self.space),
            ).fetchall()
        return sorted(
            {
                json.loads(r[0])[1]
                for r in rows
                if json.loads(r[0])[0] == name and json.loads(r[0])[1] != 1
            }
        )

    def _load_key(self, kind, id, cls):
        row = self._get(kind, str(id & 0xFFFFFFFF))
        if row is None:
            raise InvalidKeyIdException(f"Missing {kind} {id}")
        kwargs = {"last_resort": bool(row[1])} if kind == "kem" else {}
        return cls.from_bytes(row[0], profile=WHATSAPP, **kwargs)

    def load_pre_key(self, id):
        return self._load_key("pre", id, PreKeyRecord)

    def store_pre_key(self, id, record):
        self._put("pre", str(id & 0xFFFFFFFF), record.serialize())

    def contains_pre_key(self, id):
        return self._get("pre", str(id & 0xFFFFFFFF)) is not None

    def remove_pre_key(self, id):
        self._remove("pre", str(id & 0xFFFFFFFF))

    def load_signed_pre_key(self, id):
        return self._load_key("signed", id, SignedPreKeyRecord)

    def store_signed_pre_key(self, id, record):
        self._put("signed", str(id & 0xFFFFFFFF), record.serialize())

    def contains_signed_pre_key(self, id):
        return self._get("signed", str(id & 0xFFFFFFFF)) is not None

    def remove_signed_pre_key(self, id):
        self._remove("signed", str(id & 0xFFFFFFFF))

    def load_signed_pre_keys(self):
        with self.db.atomic() as c:
            rows = c.execute(
                "SELECT value FROM records WHERE owner=? AND kind='signed'",
                (self.owner,),
            ).fetchall()
        return [SignedPreKeyRecord.from_bytes(r[0], profile=WHATSAPP) for r in rows]

    def load_kyber_pre_key(self, id):
        return self._load_key("kem", id, KyberPreKeyRecord)

    def store_kyber_pre_key(self, id, record):
        self._put("kem", str(id & 0xFFFFFFFF), record.serialize(), int(record.last_resort))

    def contains_kyber_pre_key(self, id):
        return self._get("kem", str(id & 0xFFFFFFFF)) is not None

    def mark_kyber_pre_key_used(self, id):
        with self.db.atomic():
            row = self._get("kem", str(id & 0xFFFFFFFF))
            if row and not row[1]:
                self._remove("kem", str(id & 0xFFFFFFFF))

    def load_sender_key(self, name):
        row = self._get("sender", key(name.group_id, name.sender.name, name.sender.device_id))
        return SenderKeyRecord(row[0] if row else None, profile=WHATSAPP)

    def store_sender_key(self, name, record):
        self._put(
            "sender",
            key(name.group_id, name.sender.name, name.sender.device_id),
            record.serialize(),
        )


__all__ = ["key", "SQLiteStore", "Database"]
