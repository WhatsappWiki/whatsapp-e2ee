import pytest
from signal_protocol import KemKeyType
from test_client import endpoint

from whatsapp_e2ee import payload
from whatsapp_e2ee.prekeys import PreKeys


@pytest.mark.parametrize(
    "kem", [None, KemKeyType.ML_KEM_512, KemKeyType.ML_KEM_768, KemKeyType.ML_KEM_1024]
)
@pytest.mark.parametrize("opk", [False, True])
@pytest.mark.parametrize("last_resort", [False, True])
def test_public_bundle_inventory_and_consumption(tmp_path, kem, opk, last_resort):
    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    keys = PreKeys(b)
    signed_id = keys.rotate_signed()
    pre = keys.generate(1)[0] if opk else None
    k = keys.generate_kem(kem, last_resort=last_resort) if kem else None
    bb = keys.bundle(pre_key_id=pre, kem_id=k)
    # A later active SPK must not delete the old record needed by an in-flight bundle.
    new_signed_id = keys.rotate_signed()
    assert signed_id != new_signed_id
    p = a.prepare_direct("first", {b.address: payload.text("hello")}, bundles={b.address: bb})[0]
    assert b.receive("first", a.address, p) == payload.text("hello")
    assert b.store.contains_signed_pre_key(signed_id)
    if opk:
        assert not b.store.contains_pre_key(pre)
    if kem:
        assert b.store.contains_kyber_pre_key(k) == last_resort
    b.store.db.close()
    b = endpoint(tmp_path / "b.db", "b")
    keys = PreKeys(b)
    assert keys.bundle().signed_pre_key_id == new_signed_id
    next_id = keys.generate(1)[0]
    if pre is not None:
        assert next_id > pre


def test_allocation_failure_and_existing_id(tmp_path):
    a = endpoint(tmp_path / "a.db", "a")
    keys = PreKeys(a)
    with pytest.raises(ValueError):
        keys.bundle()
    ids = keys.generate(2)
    a.store._put("key-next", "pre", b"1")
    assert keys.generate(1) == (ids[-1] + 1,)
    a.store._put("key-next", "pre", b"16777214")
    with pytest.raises(ValueError):
        keys.generate(2)
    assert not a.store.contains_pre_key(16777214)
    assert keys.generate(1) == (16777214,)


def test_curve_last_resort_not_consumed(tmp_path):
    from signal_protocol import Curve, PreKeyRecord

    a, b = [endpoint(tmp_path / (n + ".db"), n) for n in "ab"]
    keys = PreKeys(b)
    keys.rotate_signed()
    id = 0xFFFFFF
    b.store.store_pre_key(id, PreKeyRecord(id, Curve.generate_key_pair()))
    bb = keys.bundle(pre_key_id=id)
    p = a.prepare_direct("x", {b.address: payload.text("x")}, bundles={b.address: bb})[0]
    assert b.receive("x", a.address, p) == payload.text("x")
    assert b.store.contains_pre_key(id)
