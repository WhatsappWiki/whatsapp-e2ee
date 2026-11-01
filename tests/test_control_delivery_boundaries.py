"""Receipt routing, durable delivery state and malformed control inputs."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest
from protocol_tree_node import JID, Attribute, Node
from test_client import bundle
from wire_helpers import endpoint

from whatsapp_e2ee import payload
from whatsapp_e2ee.control import acknowledge, parse_control, receipt_node
from whatsapp_e2ee.delivery import Delivery
from whatsapp_e2ee.stanza import jid_for_address
from whatsapp_e2ee.store import key
from whatsapp_e2ee.transport import StanzaDelivery


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


def prepare(a, b, *, id="m", destination=None):
    packets = a.prepare_direct(id, {b.address: payload.text(id)}, bundles={b.address: bundle(b)})
    wire = StanzaDelivery(a.store)
    wire.prepare(id, destination or b.address.name)
    return wire, packets


def control(b, *, id="m", kind="read"):
    return Node("receipt", {"id": id, "from": jid_for_address(b.address), "type": kind})


def outbox_state(a, id="m"):
    return a.store.db.connection.execute(
        "SELECT state FROM outbox WHERE owner=? AND id=?", (a.store.owner, id)
    ).fetchone()[0]


@pytest.mark.parametrize("kind", ["delivery", "read"])
def test_recipient_receipt_before_server_ack_stops_stanza_retransmission(clients, kind):
    a, b = clients("a"), clients("b")
    wire, packets = prepare(a, b)
    wire.apply_control("m", control(b, kind=kind), authenticated_transport=True)
    assert outbox_state(a) == "submitted"
    a.store.db.close()
    a = clients("a")
    wire = StanzaDelivery(a.store)
    wire.dispatch("m", lambda *_: pytest.fail("Already confirmed payload was sent again"))
    assert a.store._get("stanza-state", "m")[0] != b"server_ack"
    assert Delivery(a.store).prepared("m") == packets


def test_partial_fanout_receipt_does_not_suppress_unconfirmed_devices(clients):
    a, b, c = [clients(name) for name in "abc"]
    packets = a.prepare_direct(
        "m",
        {b.address: payload.text("b"), c.address: payload.text("c")},
        bundles={b.address: bundle(b), c.address: bundle(c)},
    )
    wire = StanzaDelivery(a.store)
    encoded = wire.prepare("m", b.address.name)
    wire.apply_control("m", control(b), authenticated_transport=True)
    assert outbox_state(a) == "prepared"
    sent = []
    wire.dispatch("m", lambda _, body: sent.append(body))
    assert sent == [encoded]  # Whole stanza retries preserve the frozen bytes.
    wire.apply_control("m", control(c), authenticated_transport=True)
    wire.dispatch("m", lambda *_: pytest.fail("All fanout targets are confirmed"))
    assert outbox_state(a) == "submitted"
    assert Delivery(a.store).prepared("m") == packets


@pytest.mark.parametrize("error", [False, True])
def test_device_specific_ack_rejects_other_device_of_same_account(clients, error):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b, destination=jid_for_address(b.address))
    fields = {"id": "m", "from": JID("15550002", "s.whatsapp.net", 2), "class": "message"}
    if error:
        fields["error"] = "421"
    with pytest.raises(ValueError, match="device"):
        wire.apply_control("m", Node("ack", fields), authenticated_transport=True)
    assert a.store._get("stanza-state", "m")[0] == b"prepared"
    assert a.store._get("stanza-error", "m") is None
    assert (
        a.store.db.connection.execute(
            "SELECT count(*) FROM records WHERE kind='receipt'"
        ).fetchone()[0]
        == 0
    )


@pytest.mark.parametrize("qualified", [False, True])
def test_device_specific_ack_accepts_account_or_matching_device(clients, qualified):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b, destination=jid_for_address(b.address))
    source = jid_for_address(b.address) if qualified else b.address.name
    wire.apply_control(
        "m",
        Node("ack", {"id": "m", "class": "message", "from": source}),
        authenticated_transport=True,
    )
    assert outbox_state(a) == "submitted"
    wire.dispatch("m", lambda *_: pytest.fail("ACK was lost"))


MALFORMED = [
    "ack_payload",
    "ack_list",
    "receipt_payload",
    "unknown_child",
    "list_payload",
    "item_payload",
    "nested_item",
    "duplicate_list",
    "duplicate_item_id",
    "direct_participant",
    "group_device",
    "negative_device",
    "large_device",
    "colon_user",
    "empty_error",
    "null_error",
    "jid_error",
    "receipt_error",
    "group_missing_participant",
    "group_empty_user",
    "participant_large_device",
]


def malformed(case, b):
    ack = Node("ack", {"id": "m", "class": "message", "from": b.address.name})
    receipt = control(b)
    item = Node("item", {"id": "other"})
    if case == "ack_payload":
        return replace(ack, data=b"unexpected")
    if case == "ack_list":
        return replace(ack, children=[Node("list", children=[item])])
    if case == "receipt_payload":
        return replace(receipt, data=b"unexpected")
    if case == "unknown_child":
        return replace(receipt, children=[Node("retry", {"count": "1"})])
    if case == "list_payload":
        return replace(receipt, children=[Node("list", data=b"unexpected")])
    if case in ("item_payload", "nested_item"):
        item = (
            replace(item, data=b"unexpected")
            if case == "item_payload"
            else replace(item, children=[Node("item", {"id": "hidden"})])
        )
    if case == "duplicate_list":
        return replace(receipt, children=[Node("list", children=[item])] * 2)
    if case == "duplicate_item_id":
        item = Node("item", attrs=[Attribute("id", "other"), Attribute("id", "hidden")])
    if case == "direct_participant":
        return replace(
            receipt,
            attrs={
                **dict((a.name, a.value) for a in receipt.attrs),
                "participant": jid_for_address(b.address),
            },
        )
    sources = {
        "group_device": JID("1000001", "g.us", 1),
        "negative_device": JID("15550002", "s.whatsapp.net", -1),
        "large_device": JID("15550002", "s.whatsapp.net", 256),
        "colon_user": JID("15550002:0", "s.whatsapp.net", 1),
        "group_empty_user": JID(None, "g.us"),
    }
    if case in sources:
        return replace(ack, attrs={"id": "m", "class": "message", "from": sources[case]})
    if case in ("empty_error", "null_error", "jid_error"):
        return replace(
            ack,
            attrs={
                "id": "m",
                "class": "message",
                "from": b.address.name,
                "error": {"empty_error": "", "null_error": None, "jid_error": JID("1", "lid")}[
                    case
                ],
            },
        )
    if case == "receipt_error":
        return replace(
            receipt, attrs={"id": "m", "from": jid_for_address(b.address), "error": "421"}
        )
    if case == "group_missing_participant":
        return Node("receipt", {"id": "m", "from": "1000001@g.us"})
    if case == "participant_large_device":
        return Node(
            "receipt",
            {
                "id": "m",
                "from": "1000001@g.us",
                "participant": JID("15550002", "s.whatsapp.net", 256),
            },
        )
    return replace(receipt, children=[Node("list", children=[item])])


@pytest.mark.parametrize("case", MALFORMED)
def test_malformed_control_rejected_without_state_changes(clients, case):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b)
    before = a.store.db.connection.execute(
        "SELECT * FROM records ORDER BY kind,space,id"
    ).fetchall()
    with pytest.raises(ValueError):
        parse_control(malformed(case, b))
    with pytest.raises(ValueError):
        wire.apply_control("m", malformed(case, b), authenticated_transport=True)
    assert (
        a.store.db.connection.execute("SELECT * FROM records ORDER BY kind,space,id").fetchall()
        == before
    )
    assert outbox_state(a) == "prepared"


@pytest.mark.parametrize("id", [None, "", JID("15550002", "s.whatsapp.net")])
def test_receipt_and_ack_helpers_require_string_ids(id):
    with pytest.raises(ValueError):
        receipt_node(id, "15550002@s.whatsapp.net")
    with pytest.raises(ValueError):
        acknowledge(Node("message", {"id": id, "from": "15550002@s.whatsapp.net"}))


@pytest.mark.parametrize("id", [None, ["nested"], JID("1", "lid")])
def test_invalid_additional_id_is_rejected_before_duplicate_check(id):
    with pytest.raises(ValueError):
        receipt_node("m", "15550002@s.whatsapp.net", additional_ids=[id])


@pytest.mark.parametrize("targeted", [False, True])
@pytest.mark.parametrize("error", [False, True])
def test_group_ack_participant_must_match_prepared_envelope(clients, targeted, error):
    a, b, c = [clients(name) for name in "abc"]
    group = "1000001@g.us"
    a.prepare_group_delivery(
        "g", group, payload.text("g"), [b.address], bundles={b.address: bundle(b)}
    )
    wire = StanzaDelivery(a.store)
    options = {"participant": jid_for_address(b.address)} if targeted else {}
    wire.prepare("g", group, **options)
    fields = {
        "id": "g",
        "class": "message",
        "from": group,
        "participant": jid_for_address(c.address),
    }
    if error:
        fields["error"] = "421"
    with pytest.raises(ValueError, match="participant"):
        wire.apply_control("g", Node("ack", fields), authenticated_transport=True)
    assert a.store._get("stanza-state", "g")[0] == b"prepared"
    assert a.store._get("stanza-error", "g") is None
    if targeted:
        fields["participant"] = jid_for_address(b.address)
    else:
        fields.pop("participant")
    wire.apply_control("g", Node("ack", fields), authenticated_transport=True)
    assert a.store._get("stanza-state", "g")[0] == (b"prepared" if error else b"server_ack")


def test_successful_stanza_send_updates_both_delivery_checkpoints(clients):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b)
    sent = []
    wire.dispatch("m", lambda *args: sent.append(args))
    assert len(sent) == 1
    assert a.store._get("stanza-state", "m")[0] == b"submitted"
    assert outbox_state(a) == "submitted"


def test_post_send_checkpoint_failure_retries_identical_bytes(clients):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b)
    a.store.db.connection.execute(
        "CREATE TRIGGER fail_submitted BEFORE UPDATE ON outbox "
        "BEGIN SELECT RAISE(ABORT,'checkpoint failure'); END"
    )
    sent = []
    with pytest.raises(sqlite3.IntegrityError, match="checkpoint failure"):
        wire.dispatch("m", lambda _, body: sent.append(body))
    assert len(sent) == 1
    assert outbox_state(a) == "prepared"
    assert a.store._get("stanza-state", "m")[0] == b"prepared"
    a.store.db.connection.execute("DROP TRIGGER fail_submitted")
    wire.dispatch("m", lambda _, body: sent.append(body))
    assert sent[0] == sent[1]
    assert outbox_state(a) == "submitted"


def test_group_receipts_remain_member_scoped_and_do_not_ack_entire_stanza(clients):
    a, b, c = [clients(name) for name in "abc"]
    group = "1000001@g.us"
    a.prepare_group_delivery(
        "g",
        group,
        payload.text("g"),
        [b.address, c.address],
        bundles={b.address: bundle(b), c.address: bundle(c)},
    )
    wire = StanzaDelivery(a.store)
    wire.prepare("g", group)
    for kind in ("read", "delivery"):
        wire.apply_control(
            "g",
            Node(
                "receipt",
                {"id": "g", "from": group, "participant": jid_for_address(b.address), "type": kind},
            ),
            authenticated_transport=True,
        )
    assert a.store._get("group-receipt", key("g", b.address.name, b.address.device_id))[0] == b"3"
    assert a.store._get("group-receipt", key("g", c.address.name, c.address.device_id)) is None
    sent = []
    wire.dispatch("g", lambda *args: sent.append(args))
    assert len(sent) == 1


def test_ack_failure_rolls_back_whole_fanout_state(clients):
    a, b, c = [clients(name) for name in "abc"]
    a.prepare_direct(
        "m",
        {b.address: payload.text("b"), c.address: payload.text("c")},
        bundles={b.address: bundle(b), c.address: bundle(c)},
    )
    wire = StanzaDelivery(a.store)
    wire.prepare("m", b.address.name)
    a.store.db.connection.execute(
        "CREATE TRIGGER fail_receipt BEFORE INSERT ON records WHEN NEW.kind='receipt' "
        "AND NEW.id LIKE '%15550003%' BEGIN SELECT RAISE(ABORT,'second receipt'); END"
    )
    ack = Node("ack", {"id": "m", "class": "message", "from": b.address.name})
    with pytest.raises(sqlite3.IntegrityError, match="second receipt"):
        wire.apply_control("m", ack, authenticated_transport=True)
    assert a.store._get("stanza-state", "m")[0] == b"prepared"
    assert outbox_state(a) == "prepared"
    assert (
        a.store.db.connection.execute(
            "SELECT count(*) FROM records WHERE kind='receipt'"
        ).fetchone()[0]
        == 0
    )
    a.store.db.connection.execute("DROP TRIGGER fail_receipt")
    wire.apply_control("m", ack, authenticated_transport=True)
    assert outbox_state(a) == "submitted"


def test_ack_inside_timed_out_send_survives_restart(clients):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b)

    def send(*_):
        wire.apply_control(
            "m",
            Node("ack", {"id": "m", "class": "message", "from": b.address.name}),
            authenticated_transport=True,
        )
        raise TimeoutError("callback lost completion")

    with pytest.raises(TimeoutError):
        wire.dispatch("m", send)
    assert outbox_state(a) == "submitted"
    a.store.db.close()
    a = clients("a")
    StanzaDelivery(a.store).dispatch("m", lambda *_: pytest.fail("ACKed ciphertext resent"))


def test_batch_receipt_only_updates_explicitly_selected_message(clients):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b, id="one")
    prepare(a, b, id="two")
    batch = replace(
        receipt_node("one", b.address.name, kind="read", additional_ids=["two"]),
        attrs={"id": "one", "from": jid_for_address(b.address), "type": "read"},
    )
    assert parse_control(batch).ids == ("one", "two")
    wire.apply_control("two", batch, authenticated_transport=True)
    assert outbox_state(a, "one") == "prepared"
    assert outbox_state(a, "two") == "submitted"
    wire.apply_control("one", batch, authenticated_transport=True)
    assert outbox_state(a, "one") == "submitted"


def test_concurrent_controls_keep_highest_receipt_and_ack_state(clients):
    a, b = clients("a"), clients("b")
    wire, packets = prepare(a, b)
    other = clients("a")
    barrier = Barrier(3)
    nodes = [
        control(b),
        control(b, kind="delivery"),
        Node("ack", {"id": "m", "class": "message", "from": b.address.name}),
    ]

    def apply(index):
        barrier.wait(timeout=5)
        StanzaDelivery((a, other, a)[index].store).apply_control(
            "m", nodes[index], authenticated_transport=True
        )

    with ThreadPoolExecutor(3) as executor:
        futures = [executor.submit(apply, i) for i in range(3)]
        for future in futures:
            future.result(timeout=10)
    packet = packets[0]
    assert (
        a.store._get("receipt", key("m", packet.recipient, packet.device, packet.kind))[0] == b"3"
    )
    assert a.store._get("stanza-state", "m")[0] == b"server_ack"
    assert outbox_state(a) == "submitted"


@pytest.mark.parametrize("authenticated", [False, None, 1])
def test_controls_require_explicit_authenticated_transport(clients, authenticated):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b)
    ack = Node("ack", {"id": "m", "class": "message", "from": b.address.name})
    with pytest.raises(ValueError, match="Untrusted"):
        wire.apply_control("m", ack, authenticated_transport=authenticated)
    assert a.store._get("stanza-state", "m")[0] == b"prepared"
    assert outbox_state(a) == "prepared"


def test_late_error_after_read_and_ack_does_not_downgrade_delivery(clients):
    a, b = clients("a"), clients("b")
    wire, packets = prepare(a, b)
    nodes = [
        control(b),
        Node("ack", {"id": "m", "class": "message", "from": b.address.name}),
        Node("ack", {"id": "m", "class": "message", "from": b.address.name, "error": "421"}),
    ]
    for node in nodes:
        decoded = wire.codec.read(wire.codec.write(node))
        wire.apply_control("m", decoded, authenticated_transport=True)
    packet = packets[0]
    assert (
        a.store._get("receipt", key("m", packet.recipient, packet.device, packet.kind))[0] == b"3"
    )
    assert a.store._get("stanza-state", "m")[0] == b"server_ack"
    assert a.store._get("stanza-error", "m") is not None
    wire.dispatch("m", lambda *_: pytest.fail("Late error regressed acknowledged delivery"))


@pytest.mark.parametrize("proof", ["server_ack", "read"])
def test_dispatch_repairs_legacy_prepared_outbox_from_durable_confirmation(clients, proof):
    a, b = clients("a"), clients("b")
    wire, _ = prepare(a, b)
    node = (
        control(b)
        if proof == "read"
        else Node(
            "ack",
            {
                "id": "m",
                "class": "message",
                "from": b.address.name,
            },
        )
    )
    wire.apply_control("m", node, authenticated_transport=True)
    # Older checkpoints retained prepared even after storing positive proof.
    a.store.db.connection.execute("UPDATE outbox SET state='prepared'")
    a.store.db.close()
    a = clients("a")
    StanzaDelivery(a.store).dispatch("m", lambda *_: pytest.fail("Durable confirmation ignored"))
    assert outbox_state(a) == "submitted"
