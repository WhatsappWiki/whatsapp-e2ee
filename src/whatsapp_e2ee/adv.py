"""Authenticated ordinary ADV key-index lists and native device-index filtering.

The signature covers 06 02 || the original details bytes. Account/JID binding
comes from the caller's trusted primary identity lookup, not from a JID inside
this protobuf. Native embedded-key replacement is returned explicitly; it is
never silently written into the Signal identity store by this module.
"""

from dataclasses import dataclass

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError
from signal_protocol import Curve, ECPublicKey, IdentityKey

DOMAIN = bytes.fromhex("0602")


class InvalidADV(ValueError):
    pass


class ADVIdentityChange(InvalidADV):
    def __init__(self, result):
        super().__init__("ADV signature uses an unbound or changed account identity")
        self.result = result


_schema = descriptor_pb2.FileDescriptorProto(name="wa_adv.proto", package="wa_adv", syntax="proto2")
_enum = _schema.enum_type.add(name="AccountType")
for _i in range(3):
    _enum.value.add(name="TYPE_" + str(_i), number=_i)
for _name, _fields in (
    (
        "SignedKeyIndexList",
        [
            (1, "details", 12, False),
            (2, "account_signature", 12, False),
            (3, "account_signature_key", 12, False),
        ],
    ),
    (
        "KeyIndexList",
        [
            (1, "raw_id", 13, False),
            (2, "timestamp", 4, False),
            (3, "current_index", 13, False),
            (4, "valid_indexes", 13, True),
            (5, "account_type", 14, False),
        ],
    ),
):
    _message = _schema.message_type.add(name=_name)
    for _number, _field, _type, _repeated in _fields:
        _f = _message.field.add(
            number=_number, name=_field, type=_type, label=3 if _repeated else 1
        )
        if _repeated:
            _f.options.packed = True
        if _type == 14:
            _f.type_name = ".wa_adv.AccountType"
_pool = descriptor_pool.DescriptorPool()
_pool.Add(_schema)
SignedKeyIndexList = message_factory.GetMessageClass(
    _pool.FindMessageTypeByName("wa_adv.SignedKeyIndexList")
)
KeyIndexList = message_factory.GetMessageClass(_pool.FindMessageTypeByName("wa_adv.KeyIndexList"))


@dataclass(frozen=True)
class VerifiedKeyIndexList:
    raw_id: int
    timestamp: int
    current_index: int
    valid_indexes: tuple[int, ...]
    account_type: int
    signing_key: bytes
    replacement_key: bytes | None
    raw_id_mismatch: bool
    details: bytes


def _public(value):
    if value is None:
        return None
    if isinstance(value, IdentityKey):
        return value.public_key
    if isinstance(value, ECPublicKey):
        return value
    if not isinstance(value, bytes):
        raise InvalidADV("Identity must be raw32, typed33, or a protocol public key")
    if len(value) == 33 and value[0] == 5:
        value = value[1:]
    if len(value) != 32:
        raise InvalidADV("Invalid account public key")
    return ECPublicKey(value)


def _signed64(value):
    return value if value < 2**63 else value - 2**64


def verify_key_index_list(
    data,
    identity_key,
    expected_timestamp,
    now_ms,
    *,
    max_age_days=35,
    local_raw_id=None,
    allow_identity_change=False,
    max_bytes=1024 * 1024,
):
    """Verify A07 signature and A04 timestamp policy, preserving original bytes.

    ``max_age_days`` supplies the config-730 value; native clamps it to 1..35.
    A stale list with zero/one valid index is allowed by the observed predicate.
    Future timestamps are not independently rejected. ``raw_id_mismatch`` is a
    reset suggestion to the account lifecycle owner, not an identity mutation.
    ``allow_identity_change=True`` reproduces the native embedded-key choice;
    the caller must deliberately handle its returned replacement key.
    """
    if (
        not isinstance(data, bytes)
        or type(max_bytes) is not int
        or max_bytes < 0
        or len(data) > max_bytes
    ):
        raise InvalidADV("Invalid or oversized signed key-index list")
    if type(expected_timestamp) is not int or not -(2**63) <= expected_timestamp < 2**63:
        raise InvalidADV("Expected timestamp must be a signed int64 in seconds")
    if type(now_ms) is not int or not -(2**63) <= now_ms < 2**63 or type(max_age_days) is not int:
        raise InvalidADV("Invalid clock/config value")
    if local_raw_id is not None and (
        type(local_raw_id) is not int or not 0 <= local_raw_id < 2**32
    ):
        raise InvalidADV("Invalid local ADV raw ID")
    trusted = _public(identity_key)
    signed = SignedKeyIndexList()
    try:
        signed.ParseFromString(data)
    except DecodeError as exc:
        raise InvalidADV("Malformed ADVSignedKeyIndexList") from exc
    embedded = None
    if signed.HasField("account_signature_key"):
        # This field is raw32, not Signal's 05-prefixed public-key encoding.
        if len(signed.account_signature_key) != 32:
            raise InvalidADV("Embedded account signature key must be raw32")
        embedded = ECPublicKey(signed.account_signature_key)
    replacement = embedded is not None and embedded != trusted
    selected = embedded if replacement else trusted
    if selected is None:
        raise InvalidADV("No primary identity or embedded account key")
    if not Curve.verify_signature(selected, DOMAIN + signed.details, signed.account_signature):
        raise InvalidADV("Invalid account signature")
    details = KeyIndexList()
    try:
        details.ParseFromString(signed.details)
    except DecodeError as exc:
        raise InvalidADV("Malformed authenticated ADVKeyIndexList") from exc
    timestamp = _signed64(details.timestamp)
    if timestamp != expected_timestamp:
        raise InvalidADV("ADV timestamp does not match outer timestamp")
    days = max(1, min(35, max_age_days))
    cutoff_ms = _signed64((now_ms - days * 86400000) & (2**64 - 1))
    # Java integer division truncates toward zero, unlike Python // for negatives.
    cutoff = cutoff_ms // 1000 if cutoff_ms >= 0 else -((-cutoff_ms) // 1000)
    if timestamp < cutoff and len(details.valid_indexes) > 1:
        raise InvalidADV("Expired multi-index ADV list")
    result = VerifiedKeyIndexList(
        details.raw_id,
        timestamp,
        details.current_index,
        tuple(details.valid_indexes),
        details.account_type,
        selected.key,
        selected.key if replacement else None,
        local_raw_id is None or local_raw_id != details.raw_id,
        signed.details,
    )
    if replacement and not allow_identity_change:
        raise ADVIdentityChange(result)
    return result


def filter_key_indexes(incoming, verified):
    """C13z.A08 effective filter; primary device ID is zero.

    The caller merges current + incoming additions *after* any raw-ID reset.
    Java Number.intValue compares the low 32 bits to protobuf validIndexes.
    currentIndex and the previous map affect diagnostics only in this method;
    they do not cap an otherwise valid incoming key index or restore an old one.
    """
    valid = set(verified.valid_indexes)
    output = {}
    for address, index in incoming.items():
        if type(index) is not int or not -(2**63) <= index < 2**63:
            raise InvalidADV("Device key-index must be a signed int64")
        if type(address.device_id) is not int or not 0 <= address.device_id <= 255:
            raise InvalidADV("Invalid device address")
        if address.device_id == 0 or (index > 0 and index & 0xFFFFFFFF in valid):
            output[address] = index
    return output


def sign_key_index_list(details, private_key, *, account_signature_key=None, random=None):
    """Protocol serializer/signer; useful for explicit local provisioning/tests."""
    if not isinstance(details, bytes):
        details = details.SerializeToString()
    key = _public(account_signature_key)
    signed = SignedKeyIndexList(
        details=details,
        account_signature=Curve.calculate_signature(private_key, DOMAIN + details, random=random),
    )
    if key is not None:
        signed.account_signature_key = key.key
    return signed.SerializeToString()


__all__ = [
    "DOMAIN",
    "InvalidADV",
    "ADVIdentityChange",
    "VerifiedKeyIndexList",
    "verify_key_index_list",
    "filter_key_indexes",
    "sign_key_index_list",
    "SignedKeyIndexList",
    "KeyIndexList",
]
