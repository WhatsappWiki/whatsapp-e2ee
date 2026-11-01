"""Synthetic wire endpoints using canonical numeric protocol addresses."""

from signal_protocol import SignalProtocolAddress

from whatsapp_e2ee import Client, Database, SQLiteStore


def endpoint(path, name):
    store = SQLiteStore(Database(path), name)
    store.initialize()
    account = {"a": "15550001", "b": "15550002", "c": "15550003"}.get(name, name)
    return Client(store, SignalProtocolAddress(account + "@s.whatsapp.net", 1))
