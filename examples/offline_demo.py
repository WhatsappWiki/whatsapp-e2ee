"""Three synthetic endpoints, no phone/network/credentials required."""

import json
import tempfile
from pathlib import Path

from signal_protocol import SignalProtocolAddress

from whatsapp_e2ee import Client, Database, SQLiteStore, payload
from whatsapp_e2ee.media import decrypt
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.prekeys import PreKeys
from whatsapp_e2ee.routing import prepare_group_snapshot


def main():
    with tempfile.TemporaryDirectory(prefix="wa-e2ee-demo-") as folder:
        clients, bundles = [], {}
        for name in ("alice", "bob", "carol"):
            store = SQLiteStore(Database(Path(folder) / (name + ".db")), name)
            store.initialize()
            client = Client(store, SignalProtocolAddress(name + "@s.whatsapp.net", 1))
            inventory = PreKeys(client)
            inventory.rotate_signed()
            opk = inventory.generate(1)[0]
            bundles[client.address] = inventory.bundle(pre_key_id=opk)
            clients.append(client)
        a, b, c = clients
        direct = a.prepare_direct("direct", {b.address: payload.text("你好，Bob")}, bundles=bundles)
        assert payload.parse(b.receive("direct", a.address, direct[0])).conversation == "你好，Bob"
        group = prepare_group_snapshot(
            a,
            "group-text",
            "synthetic@g.us",
            payload.text("群聊文本"),
            [b.address, c.address],
            revision=1,
            bundles=bundles,
        )
        for receiver in (b, c):
            distribution = next(p for p in group if p.recipient == receiver.address.name)
            receiver.receive("group-skdm", a.address, distribution, expected_group="synthetic@g.us")
            assert (
                payload.parse(
                    receiver.receive(
                        "group-text", a.address, group[-1], expected_group="synthetic@g.us"
                    )
                ).conversation
                == "群聊文本"
            )
        jobs = MediaJobs(a.store)
        media = jobs.prepare(
            "document", b"synthetic attachment", "document", media_key_timestamp_ms=1000
        )
        # This is an offline adapter checkpoint, not an upload.
        jobs.mark_uploaded("document", "/offline-fixture", 1000)
        packets = jobs.prepare_message(
            "document",
            "attachment",
            a,
            [b.address],
            metadata={"mimetype": "application/octet-stream", "file_name": "example.bin"},
        )
        d = payload.parse(b.receive("attachment", a.address, packets[0])).document_message
        assert (
            decrypt(
                media.blob,
                d.media_key,
                "document",
                plaintext_hash=d.file_sha256,
                encrypted_hash=d.file_enc_sha256,
                length=d.file_length,
            )
            == b"synthetic attachment"
        )
        print(json.dumps(dict(direct=True, group_receivers=2, media=True, network_calls=0)))
        for client in clients:
            client.store.db.close()


if __name__ == "__main__":
    main()
