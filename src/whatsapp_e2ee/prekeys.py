"""Explicit local prekey inventory; no automatic publication or key rotation.

The allocator never wraps or reuses consumed IDs. Active signed-key selection is
an explicit persistent pointer, not a guess based on ID or insertion order.
"""

from signal_protocol import Curve, KeyHelper, PreKeyBundle, PreKeyRecord

from whatsapp_e2ee.store import key


class PreKeys:
    def __init__(self, client):
        self.client, self.store = client, client.store

    def _allocate(self, kind):
        row = self.store._get("key-next", kind)
        candidate = int(row[0]) if row else 1
        if candidate < 1:
            raise ValueError("Invalid local prekey allocation cursor; explicit recovery required")
        while candidate < 0xFFFFFF and (
            self.store._get(kind, str(candidate)) is not None
            or self.store._get("key-retired", key(kind, candidate)) is not None
        ):
            candidate += 1
        if candidate >= 0xFFFFFF:
            raise ValueError("Local prekey ID space exhausted; explicit migration required")
        self.store._put("key-next", kind, str(candidate + 1).encode())
        return candidate

    def generate(self, count):
        if type(count) is not int or not 1 <= count <= 1000:
            raise ValueError("Prekey batch must contain 1..1000 keys")
        with self.store.db.atomic():
            ids = []
            for _ in range(count):
                id = self._allocate("pre")
                self.store.store_pre_key(id, PreKeyRecord(id, Curve.generate_key_pair()))
                ids.append(id)
            return tuple(ids)

    def rotate_signed(self):
        with self.store.db.atomic():
            id = self._allocate("signed")
            record = KeyHelper.generate_signed_pre_key(self.store.get_identity_key_pair(), id)
            self.store.store_signed_pre_key(id, record)
            self.store._put("key-active", "signed", str(id).encode())
            return id

    def generate_kem(self, key_type, *, last_resort=False):
        with self.store.db.atomic():
            id = self._allocate("kem")
            record = KeyHelper.generate_kyber_pre_key(
                self.store.get_identity_key_pair(), id, key_type=key_type, last_resort=last_resort
            )
            self.store.store_kyber_pre_key(id, record)
            return id

    def bundle(self, *, pre_key_id=None, kem_id=None):
        """Public material only. Exporting does not consume a one-time key."""
        with self.store.db.atomic():
            row = self.store._get("key-active", "signed")
            if row is None:
                raise ValueError("No active signed prekey; explicitly create one")
            signed_id = int(row[0])
            signed = self.store.load_signed_pre_key(signed_id)
            pre = self.store.load_pre_key(pre_key_id) if pre_key_id is not None else None
            if signed.id != (signed_id & 0xFFFFFFFF) or (
                pre is not None and pre.id != (pre_key_id & 0xFFFFFFFF)
            ):
                raise ValueError("Prekey record ID does not match its storage slot")
            identity = self.store.get_identity_key_pair().public_key
            if not Curve.verify_signature(
                identity.public_key, signed.key_pair.public_key.serialize(), signed.signature
            ):
                raise ValueError("Signed prekey signature does not match the local identity")
            kwargs = {}
            if kem_id is not None:
                kem = self.store.load_kyber_pre_key(kem_id)
                if kem.id != (kem_id & 0xFFFFFFFF):
                    raise ValueError("KEM prekey record ID does not match its storage slot")
                if not Curve.verify_signature(
                    identity.public_key, kem.key_pair.public_key.serialize(), kem.signature
                ):
                    raise ValueError("KEM prekey signature does not match the local identity")
                kwargs = dict(
                    kyber_pre_key_id=kem.id,
                    kyber_pre_key=kem.key_pair.public_key,
                    kyber_pre_key_signature=kem.signature,
                )
            return PreKeyBundle(
                self.store.get_local_registration_id(),
                self.client.address.device_id,
                pre.id if pre else None,
                pre.key_pair.public_key if pre else None,
                signed.id,
                signed.key_pair.public_key,
                signed.signature,
                identity,
                **kwargs,
            )


__all__ = ["PreKeys"]
