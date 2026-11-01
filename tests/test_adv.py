import json
from pathlib import Path

import pytest
from signal_protocol import Curve, ECPrivateKey, ECPublicKey, IdentityKey, SignalProtocolAddress

from whatsapp_e2ee.adv import (
    DOMAIN,
    ADVIdentityChange,
    InvalidADV,
    KeyIndexList,
    SignedKeyIndexList,
    filter_key_indexes,
    sign_key_index_list,
    verify_key_index_list,
)

VECTORS = json.loads((Path(__file__).parent / "vectors/adv-java.json").read_text())["vectors"]
PUB = bytes.fromhex(VECTORS[0]["public_key"])
PRIVATE = ECPrivateKey(bytes.fromhex(VECTORS[0]["private_key"]))
TS = 1700000000
DAY = 86400000


def signed(*, timestamp=TS, valid=(1, 7), raw_id=7, current=7, embedded=None):
    details = KeyIndexList(
        raw_id=raw_id,
        timestamp=timestamp,
        current_index=current,
        valid_indexes=valid,
    )
    return sign_key_index_list(details, PRIVATE, account_signature_key=embedded)


def verify(data=None, **kwargs):
    opts = dict(identity_key=PUB, expected_timestamp=TS, now_ms=TS * 1000, local_raw_id=7)
    opts.update(kwargs)
    return verify_key_index_list(signed() if data is None else data, **opts)


@pytest.mark.parametrize("vector", VECTORS)
def test_independent_jvm_signature_and_wire_vectors(vector):
    pub = bytes.fromhex(vector["public_key"])
    raw = bytes.fromhex(vector["serialized"])
    result = verify(raw, identity_key=pub)
    assert result.raw_id == vector["raw_id"]
    assert result.current_index == vector["current_index"]
    assert result.account_type == vector["account_type"]
    assert result.signing_key == pub
    assert result.replacement_key is None
    assert result.details.hex() == vector["details"]
    rebuilt = sign_key_index_list(
        result.details,
        ECPrivateKey(bytes.fromhex(vector["private_key"])),
        account_signature_key=pub if vector["embedded"] else None,
        random=bytes.fromhex(vector["random"]),
    )
    assert rebuilt == raw
    assert vector["java_verified"]


def test_original_details_are_signed_not_reserialized():
    vector = VECTORS[2]
    original = bytes.fromhex(vector["details"])
    parsed = KeyIndexList.FromString(original)
    assert parsed.raw_id == 7  # Last duplicate wins; unknown field is preserved.
    assert parsed.SerializeToString() != original
    outer = SignedKeyIndexList.FromString(bytes.fromhex(vector["serialized"]))
    outer.details = parsed.SerializeToString()
    with pytest.raises(InvalidADV, match="signature"):
        verify(outer.SerializeToString(), identity_key=bytes.fromhex(vector["public_key"]))


@pytest.mark.parametrize(
    "identity", [PUB, b"\x05" + PUB, ECPublicKey(PUB), IdentityKey(ECPublicKey(PUB))]
)
def test_trusted_public_key_input_forms(identity):
    assert verify(signed(embedded=PUB), identity_key=identity).replacement_key is None


@pytest.mark.parametrize("identity", [None, bytes.fromhex(VECTORS[1]["public_key"])])
def test_embedded_key_change_is_explicit(identity):
    data = signed(embedded=PUB)
    with pytest.raises(ADVIdentityChange) as caught:
        verify(data, identity_key=identity)
    assert caught.value.result.replacement_key == PUB
    allowed = verify(data, identity_key=identity, allow_identity_change=True)
    assert allowed == caught.value.result


def test_no_identity_binding_is_not_implicitly_accepted():
    with pytest.raises(InvalidADV, match="No primary identity"):
        verify(identity_key=None)
    with pytest.raises(InvalidADV, match="signature"):
        verify(identity_key=bytes.fromhex(VECTORS[1]["public_key"]))


@pytest.mark.parametrize("mutation", ["signature", "details", "domain", "empty_sig"])
def test_invalid_authentication(mutation):
    outer = SignedKeyIndexList.FromString(signed(embedded=PUB))
    if mutation == "signature":
        outer.account_signature = (
            bytes([outer.account_signature[0] ^ 1]) + outer.account_signature[1:]
        )
    elif mutation == "details":
        outer.details += b"\x28\x01"
    elif mutation == "domain":
        outer.account_signature = Curve.calculate_signature(PRIVATE, b"\x06\x01" + outer.details)
    else:
        outer.ClearField("account_signature")
    with pytest.raises(InvalidADV, match="signature"):
        verify(outer.SerializeToString(), identity_key=None, allow_identity_change=True)


@pytest.mark.parametrize("key", [b"", bytes(31), bytes(33), b"\x05" + PUB])
def test_embedded_wire_key_must_be_raw32(key):
    outer = SignedKeyIndexList.FromString(signed())
    outer.account_signature_key = key
    with pytest.raises(InvalidADV, match="raw32"):
        verify(outer.SerializeToString())


@pytest.mark.parametrize("key", [b"", bytes(31), bytes(34), b"\x04" + PUB, "not bytes"])
def test_invalid_trusted_key(key):
    with pytest.raises(InvalidADV):
        verify(identity_key=key)


def test_malformed_outer_and_authenticated_inner():
    with pytest.raises(InvalidADV, match="Malformed ADVSigned"):
        verify(b"\x0a\xff")
    with pytest.raises(InvalidADV, match="Malformed authenticated"):
        verify(sign_key_index_list(b"\x08\xff", PRIVATE))


def test_timestamp_must_match_outer_even_for_valid_signature():
    with pytest.raises(InvalidADV, match="outer timestamp"):
        verify(expected_timestamp=TS + 1)


@pytest.mark.parametrize("config,days", [(0, 1), (-10, 1), (1, 1), (12, 12), (35, 35), (99, 35)])
def test_age_clamping_and_exact_boundary(config, days):
    now = TS * 1000 + days * DAY
    verify(now_ms=now + 999, max_age_days=config)
    with pytest.raises(InvalidADV, match="Expired"):
        verify(now_ms=now + 1000, max_age_days=config)


@pytest.mark.parametrize("valid", [(), (7,)])
def test_zero_or_one_index_is_not_age_rejected(valid):
    assert verify(signed(valid=valid), now_ms=(TS + 100000000) * 1000).valid_indexes == valid


def test_future_timestamp_and_missing_fields_follow_native_defaults():
    verify(now_ms=0)
    empty = sign_key_index_list(b"", PRIVATE)
    result = verify(empty, expected_timestamp=0)
    assert (result.raw_id, result.current_index, result.account_type, result.valid_indexes) == (
        0,
        0,
        0,
        (),
    )


def test_java_negative_division_and_long_overflow():
    negative = signed(timestamp=2**64 - 1)
    verify(negative, expected_timestamp=-1, now_ms=DAY - 1000, max_age_days=1)
    with pytest.raises(InvalidADV, match="Expired"):
        verify(negative, expected_timestamp=-1, now_ms=DAY - 999, max_age_days=1)
    # Java signed long subtraction wraps below MIN_VALUE.
    with pytest.raises(InvalidADV, match="Expired"):
        verify(now_ms=-(2**63), max_age_days=1)


@pytest.mark.parametrize("local,expected", [(7, False), (8, True), (None, True)])
def test_raw_id_reset_suggestion(local, expected):
    assert verify(local_raw_id=local).raw_id_mismatch is expected


def test_filter_uses_positive_long_low32_and_primary_exception():
    result = verify(signed(valid=(7, 0xFFFFFFFF), current=1))
    values = [0, 7, -1, 8, 2**32 + 7, 0xFFFFFFFF, 2**32 - 1, 2**32, 0]
    incoming = {
        SignalProtocolAddress("123@s.whatsapp.net", i): value for i, value in enumerate(values)
    }
    output = filter_key_indexes(incoming, result)
    assert {a.device_id for a in output} == {0, 1, 4, 5, 6}
    assert incoming[SignalProtocolAddress("123@s.whatsapp.net", 3)] == 8
    primary = SignalProtocolAddress("123@s.whatsapp.net", 0)
    assert filter_key_indexes({primary: -100}, result) == {primary: -100}


@pytest.mark.parametrize("bad", [True, "7", 2**63, -(2**63) - 1])
def test_filter_rejects_non_java_long(bad):
    with pytest.raises(InvalidADV, match="signed int64"):
        filter_key_indexes({SignalProtocolAddress("123@s.whatsapp.net", 1): bad}, verify())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_bytes": 0},
        {"max_bytes": True},
        {"max_bytes": -1},
        {"expected_timestamp": 2**63},
        {"expected_timestamp": True},
        {"now_ms": 2**63},
        {"now_ms": True},
        {"max_age_days": 1.5},
        {"local_raw_id": -1},
        {"local_raw_id": 2**32},
        {"local_raw_id": True},
    ],
)
def test_resource_and_source_type_guards(kwargs):
    with pytest.raises(InvalidADV):
        verify(**kwargs)


def test_schema_field_numbers_and_packed_uint32():
    assert DOMAIN == b"\x06\x02"
    assert [(f.name, f.number) for f in SignedKeyIndexList.DESCRIPTOR.fields] == [
        ("details", 1),
        ("account_signature", 2),
        ("account_signature_key", 3),
    ]
    assert [(f.name, f.number) for f in KeyIndexList.DESCRIPTOR.fields] == [
        ("raw_id", 1),
        ("timestamp", 2),
        ("current_index", 3),
        ("valid_indexes", 4),
        ("account_type", 5),
    ]
    assert KeyIndexList(valid_indexes=[1, 7]).SerializeToString() == b"\x22\x02\x01\x07"
    # Unknown proto2 enum has default 0, and is retained as an unknown field.
    assert verify(sign_key_index_list(b"\x28\x63", PRIVATE), expected_timestamp=0).account_type == 0
