"""An in-process broker: exercises adapters without sockets or live accounts."""

import pytest
from protocol_tree_node import JID, Codec, Node, TokenDictionary
from signal_protocol import SignalProtocolAddress

from whatsapp_e2ee import Client, Database, SQLiteStore, payload
from whatsapp_e2ee.adv import KeyIndexList, sign_key_index_list
from whatsapp_e2ee.devices import DeviceDirectory
from whatsapp_e2ee.groups_lifecycle import GroupLifecycle
from whatsapp_e2ee.media_files import RangeDownload, sidecar_file
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import Response, UploadReceipt, Uploads, download_all
from whatsapp_e2ee.prekeys import PreKeys
from whatsapp_e2ee.routing import prepare_chat_from_directory
from whatsapp_e2ee.stanza import attributes, jid_for_address, receive_message
from whatsapp_e2ee.transport import StanzaDelivery

CODEC = Codec(TokenDictionary.bundled())


def create_endpoint(tmp_path, account, device):
    name = account.split("@")[0] + str(device)
    store = SQLiteStore(Database(tmp_path / (name + ".db")), name)
    store.initialize()
    client = Client(store, SignalProtocolAddress(account, device))
    keys = PreKeys(client)
    keys.rotate_signed()
    return client, keys.bundle(pre_key_id=keys.generate(1)[0])


def discovery_response(request, endpoints):
    a = attributes(request)
    sync = request.children[0]
    sa = attributes(sync)
    users = []
    for user in sync.children[1].children:
        jid = attributes(user)["jid"]
        account = str(jid)
        devices = tuple(
            Node("device", {"id": str(c.address.device_id), "key-index": "7"})
            for c in endpoints
            if c.address.name == account
        )
        primary = next(
            c for c in endpoints if c.address.name == account and c.address.device_id == 0
        )
        details = KeyIndexList(raw_id=123, timestamp=10, current_index=7, valid_indexes=[7])
        proof = sign_key_index_list(details, primary.store.get_identity_key_pair().private_key)
        users.append(
            Node(
                "user",
                {"jid": jid},
                children=(
                    Node(
                        "devices",
                        children=(
                            Node("device-list", children=devices),
                            Node("key-index-list", {"ts": "10", "expected_ts": "0"}, data=proof),
                        ),
                    ),
                ),
            )
        )
    return Node(
        "iq",
        {"id": a["id"], "type": "result"},
        children=(
            Node(
                "usync",
                {"sid": sa["sid"], "last": "true", "index": "0"},
                children=(Node("list", children=users),),
            ),
        ),
    )


def delivered(wire, sender, receiver):
    outgoing = CODEC.read(wire)
    a = attributes(outgoing)
    group = a["to"].server == "g.us"
    attrs = {
        "id": a["id"],
        "type": a["type"],
        "to": jid_for_address(receiver.address),
        "from": a["to"] if group else jid_for_address(sender.address),
    }
    if group:
        attrs["participant"] = jid_for_address(sender.address)
    elif sender.address.name == receiver.address.name:
        attrs["recipient"] = a["to"]
    # The fake broker changes routing only, never encrypted bytes.
    return CODEC.read(CODEC.write(Node("message", attrs, children=outgoing.children)))


def test_directory_fanout_wire_receipts_and_restart(tmp_path):
    pairs = [
        create_endpoint(tmp_path, a, d)
        for a, d in (
            ("15550001@s.whatsapp.net", 0),
            ("15550001@s.whatsapp.net", 2),
            ("15550002@s.whatsapp.net", 0),
            ("15550002@s.whatsapp.net", 2),
        )
    ]
    a, a2, b, b2 = (p[0] for p in pairs)
    bundles = {c.address: bundle for c, bundle in pairs}
    primary_identities = {
        c.address.name: c.store.get_identity_key_pair().public_key
        for c, _ in pairs
        if c.address.device_id == 0
    }
    directory = DeviceDirectory(
        a.store, identity_lookup=lambda account: primary_identities[account]
    )
    request = directory.prepare_query(
        [a.address.name, b.address.name], "discovery", "sid", mode="query", context="message"
    )
    response = CODEC.read(CODEC.write(discovery_response(request, [a, a2, b, b2])))
    directory.apply_query(
        response, "discovery", revision=1, now=10, ttl=100, authenticated_transport=True
    )
    context = payload.context_info(
        stanza_id="quoted",
        participant=b.address.name,
        quoted=payload.text("old"),
        mentioned=[b.address.name],
    )
    raw = payload.extended_text("你好🙂\ne\u0301", context=context)
    packets, phash = prepare_chat_from_directory(
        a, "one", b.address.name, raw, directory, now=11, hash_version=3, bundles=bundles
    )
    assert len(packets) == 3
    delivery = StanzaDelivery(a.store)
    wire = delivery.prepare("one", b.address.name, phash=phash)
    for receiver in (a2, b, b2):
        incoming, outputs = receive_message(
            receiver,
            delivered(wire, a, receiver),
            authenticated_transport=True,
            own_device_check=lambda address: directory.same_user(address, a.address),
        )
        m = payload.parse(outputs[0])
        if receiver is a2:
            m = m.device_sent_message.message
        assert m.extended_text_message.text == "你好🙂\ne\u0301"
        assert m.extended_text_message.context_info.quoted_message.conversation == "old"
    delivery.apply_control(
        "one",
        Node("ack", {"id": "one", "class": "message", "from": JID("15550002", "s.whatsapp.net")}),
        authenticated_transport=True,
    )
    for receiver in (b, b2):
        delivery.apply_control(
            "one",
            Node("receipt", {"id": "one", "from": jid_for_address(receiver.address)}),
            authenticated_transport=True,
        )
    before = a.store.load_session(b.address).serialize()
    path = tmp_path / "155500010.db"
    a.store.db.close()
    restored = SQLiteStore(Database(path), "155500010")
    assert StanzaDelivery(restored).prepare("one", b.address.name, phash=phash) == wire
    StanzaDelivery(restored).dispatch("one", lambda *args: pytest.fail("Already acknowledged"))
    assert restored.load_session(b.address).serialize() == before


def test_streamed_media_to_group_wire_and_authenticated_ranges(tmp_path):
    pairs = [create_endpoint(tmp_path, name + "@s.whatsapp.net", 0) for name in ("15550001", "15550002", "15550003")]
    a, b, c = (p[0] for p in pairs)
    bundles = {client.address: bb for client, bb in pairs}
    raw_media = bytes(range(256)) * 1400
    source = tmp_path / "document.bin"
    source.write_bytes(raw_media)
    jobs = MediaJobs(a.store, clock_ms=lambda: 123000)
    encrypted = jobs.prepare_file("attachment", source, "document", tmp_path / "cache")
    observed = []

    def upload(request):
        assert not a.store.db.connection.in_transaction
        observed.append(b"".join(request.body))
        return Response(200, (), b"success")

    receipt = Uploads(jobs).send(
        "attachment",
        "https://offline.invalid/upload",
        upload,
        lambda status, headers, body: UploadReceipt(
            "/synthetic/file", 123000, encrypted.encrypted_hash
        ),
    )
    assert observed and receipt.direct_path == "/synthetic/file"
    group = GroupLifecycle(a)
    group.apply("snapshot", "1000003@g.us", [b.address, c.address], revision=1)
    desc = jobs.descriptor(
        "attachment", mimetype="application/octet-stream", file_name="document.bin"
    )
    group.prepare("document", "1000003@g.us", desc, bundles=bundles)
    wire = StanzaDelivery(a.store).prepare(
        "document", "1000003@g.us", message_type="media", enc_attributes={"mediatype": "document"}
    )
    for receiver in (b, c):
        _, result = receive_message(
            receiver, delivered(wire, a, receiver), authenticated_transport=True
        )
        d = payload.parse(result[-1]).document_message
        assert d.media_key_timestamp == 123 and d.file_name == "document.bin"
        job = RangeDownload(receiver.store, "document")
        blob = encrypted.path.read_bytes()
        job.initialize(
            d.media_key,
            "document",
            total=len(blob),
            sidecar=sidecar_file(encrypted.path, d.media_key, "document"),
            plaintext_hash=d.file_sha256,
            encrypted_hash=d.file_enc_sha256,
            length=d.file_length,
        )

        def download(request):
            assert not receiver.store.db.connection.in_transaction
            start, end = map(int, dict(request.headers)["range"].removeprefix("bytes=").split("-"))
            return Response(
                206,
                (("content-range", f"bytes {start}-{end}/{len(blob)}"),),
                (blob[start : start + 5], blob[start + 5 : end + 1]),
            )

        destination = tmp_path / (receiver.store.owner + ".out")
        download_all(job, "https://offline.invalid/file", download, destination)
        assert destination.read_bytes() == raw_media
