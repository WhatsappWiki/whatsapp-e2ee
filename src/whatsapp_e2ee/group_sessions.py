"""Preserve authenticated SenderKey generations and bounded skipped keys."""

import hmac

from signal_protocol import WHATSAPP, WhatsAppGroupCipher
from signal_protocol.exceptions import InvalidMessageException
from signal_protocol.groups import (
    GroupSessionBuilder,
    SenderChainKey,
    SenderMessageKey,
)
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage

_MAX_SKIP = 2000
_HALF = 1 << 31
_MASK = (1 << 32) - 1


def _generation(state):
    return state.key_id, state.signing_key_public.serialize()


def _distance(new, old):
    return (new - old) & _MASK


def _cache(state, keys):
    current = state.sender_chain_key.iteration
    del state.structure.senderMessageKeys[:]
    for iteration in sorted(keys, key=lambda i: _distance(current, i), reverse=True):
        state.add_sender_message_key(SenderMessageKey(iteration, keys[iteration]))


def _merge_checkpoint(state, iteration, seed):
    chain = state.sender_chain_key
    distance = _distance(iteration, chain.iteration)
    if distance == 0:
        if not hmac.compare_digest(chain.seed, seed):
            raise InvalidMessageException("Conflicting SenderKey checkpoint")
    elif distance < _HALF:
        if distance <= _MAX_SKIP:
            for _ in range(distance):
                state.add_sender_message_key(chain.sender_message_key())
                chain = chain.next()
            if not hmac.compare_digest(chain.seed, seed):
                raise InvalidMessageException("Conflicting SenderKey checkpoint")
        state.sender_chain_key = SenderChainKey(iteration, seed)
    elif _distance(chain.iteration, iteration) <= _MAX_SKIP:
        # A retry may arrive before the original distribution. Fill bounded
        # historical holes from that older checkpoint without rewinding.
        earlier = SenderChainKey(iteration, seed)
        recovered = {}
        for _ in range(_distance(chain.iteration, iteration)):
            recovered[earlier.iteration] = earlier.sender_message_key().seed
            earlier = earlier.next()
        if not hmac.compare_digest(earlier.seed, chain.seed):
            raise InvalidMessageException("Conflicting SenderKey checkpoint")
        for item in state.structure.senderMessageKeys:
            cached = bytes(item.seed)
            if item.iteration in recovered and recovered[item.iteration] != cached:
                raise InvalidMessageException("Conflicting cached SenderKey material")
            recovered[item.iteration] = cached
        _cache(state, recovered)


def install_distribution(store, name, message):
    """Merge a same-generation checkpoint without discarding unread keys.

    A large authenticated checkpoint skips unbounded derivation while retaining
    already cached keys. Older checkpoints never rewind the receiving ratchet.
    """
    if len(message.chain_key) != 32:
        raise InvalidMessageException("SenderKey chain key must contain 32 bytes")
    with store.db.atomic():
        record = store.load_sender_key(name)
        generation = message.id, message.signature_key.serialize()
        matches = [state for state in record.states if _generation(state) == generation]
        if not matches:
            GroupSessionBuilder(store, profile=WHATSAPP).process(name, message)
            return
        selected = matches[0]
        for state in matches[1:]:
            if (
                0
                < _distance(state.sender_chain_key.iteration, selected.sender_chain_key.iteration)
                < _HALF
            ):
                selected = state
        # Recover skipped keys from legacy duplicate entries, retaining at most
        # the protocol's bounded cache. Do not promote an old generation.
        cached = {}
        current = selected.sender_chain_key.iteration
        for state in matches:
            for item in state.structure.senderMessageKeys:
                if 0 < _distance(current, item.iteration) < _HALF:
                    seed = bytes(item.seed)
                    if item.iteration in cached and cached[item.iteration] != seed:
                        raise InvalidMessageException("Conflicting cached SenderKey material")
                    cached[item.iteration] = seed
        _cache(selected, cached)
        for state in matches:
            if state is not selected:
                chain = state.sender_chain_key
                _merge_checkpoint(selected, chain.iteration, chain.seed)
        _merge_checkpoint(selected, message.iteration, message.chain_key)
        position = next(
            i for i, state in enumerate(record.states) if _generation(state) == generation
        )
        record.states = [state for state in record.states if _generation(state) != generation]
        record.states.insert(position, selected)
        store.store_sender_key(name, record)


def decrypt_group(store, name, ciphertext, callback):
    """Resolve rare key-ID collisions by signature, preserving generation order."""
    message = SenderKeyMessage.from_bytes(ciphertext, profile=WHATSAPP)
    with store.db.atomic():
        record = store.load_sender_key(name)
        # Compact legacy redistributions before selecting an unread message key.
        seen = set()
        for state in record.states:
            generation = _generation(state)
            if generation in seen:
                install_distribution(
                    store,
                    name,
                    SenderKeyDistributionMessage(
                        state.key_id,
                        state.sender_chain_key.iteration,
                        state.sender_chain_key.seed,
                        state.signing_key_public,
                    ),
                )
            seen.add(generation)
        record = store.load_sender_key(name)
        matches = [state for state in record.states if state.key_id == message.key_id]
        order = [_generation(state) for state in record.states]
        if len(matches) > 1:
            for state in matches:
                try:
                    message.verify_signature(state.signing_key_public)
                except InvalidMessageException:
                    continue
                record.states.remove(state)
                record.states.insert(0, state)
                store.store_sender_key(name, record)
                break
        raw = WhatsAppGroupCipher(store, name).decrypt(ciphertext, callback)
        if len(matches) > 1:
            record = store.load_sender_key(name)
            record.states.sort(key=lambda state: order.index(_generation(state)))
            store.store_sender_key(name, record)
        return raw


__all__ = ["install_distribution", "decrypt_group"]
