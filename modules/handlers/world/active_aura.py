"""Small reusable active-aura registry and 5.4.8 wire serializer.

Only mount effects are executed today.  Keeping the registry and packet code
effect-agnostic prevents mount UI state becoming a second spell system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Any, Callable

from DSL.modules.bitsHandler import BitWriter


AFLAG_CASTER = 0x01
AFLAG_POSITIVE = 0x02
AFLAG_DURATION = 0x04
AURA_EFFECT_MOUNT = "mount"


@dataclass(slots=True)
class ActiveAura:
    spell_id: int
    slot: int
    caster_guid: int
    duration_ms: int = -1
    remaining_ms: int = -1
    stack_count: int = 1
    positive: bool = True
    cancelable: bool = True
    applied_effects: tuple[str, ...] = field(default_factory=tuple)
    effect_mask: int = 1
    caster_level: int = 1


def registry(owner: Any) -> dict[int, ActiveAura]:
    value = getattr(owner, "active_auras", None)
    if not isinstance(value, dict):
        value = {}
        owner.active_auras = value
    return value


def find_by_spell(owner: Any, spell_id: int) -> ActiveAura | None:
    for aura in registry(owner).values():
        if int(aura.spell_id) == int(spell_id):
            return aura
    return None


def find_by_effect(owner: Any, effect: str) -> ActiveAura | None:
    for aura in registry(owner).values():
        if str(effect) in aura.applied_effects:
            return aura
    return None


def register(owner: Any, aura: ActiveAura) -> ActiveAura:
    aura.slot &= 0xFF
    registry(owner)[aura.slot] = aura
    return aura


def unregister(owner: Any, slot: int, *, spell_id: int | None = None) -> ActiveAura | None:
    current = registry(owner).get(int(slot) & 0xFF)
    if current is None or (spell_id is not None and int(current.spell_id) != int(spell_id)):
        return None
    return registry(owner).pop(int(slot) & 0xFF)


def expire(owner: Any, elapsed_ms: int, remover: Callable[[ActiveAura], object]) -> None:
    for aura in list(registry(owner).values()):
        if aura.remaining_ms < 0:
            continue
        aura.remaining_ms = max(0, int(aura.remaining_ms) - max(0, int(elapsed_ms)))
        if aura.remaining_ms == 0:
            remover(aura)


def aura_owner_guid(owner: Any) -> int:
    """Return the exact Unit GUID used by PPE's player CREATE_OBJECT."""
    player = getattr(owner, "player", None)
    if player is not None:
        character_guid = int(getattr(player, "character_guid", 0) or 0)
        if character_guid > 0:
            return character_guid & 0xFF
    return int(
        getattr(owner, "char_guid", 0)
        or getattr(owner, "player_guid", 0)
        or getattr(owner, "world_guid", 0)
        or 0
    ) & 0xFF


def _guid_bytes(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def _byte_seq(payload: bytearray, raw: bytes, index: int) -> None:
    if raw[index]:
        payload.append(raw[index] ^ 1)


def build_aura_update(owner: Any, auras: list[ActiveAura], *, full_replay: bool = False) -> bytes:
    """Serialize SMSG_AURA_UPDATE exactly in SkyFire 5.4.8 field order."""
    owner_guid = aura_owner_guid(owner)
    target = _guid_bytes(owner_guid)
    bits = BitWriter()
    bits.write_bits(bool(target[7]), 1)
    bits.write_bits(bool(full_replay), 1)
    bits.write_bits(len(auras), 24)
    for index in (6, 1, 3, 0, 4, 2, 5):
        bits.write_bits(bool(target[index]), 1)
    for aura in auras:
        bits.write_bits(1, 1)  # not remove
        bits.write_bits(0, 22)  # effect amounts are not sent in initial scope
        self_cast = int(aura.caster_guid) == owner_guid
        flags = (AFLAG_POSITIVE if aura.positive else 0) | (AFLAG_CASTER if self_cast else 0)
        has_duration = int(aura.duration_ms) >= 0
        if has_duration:
            flags |= AFLAG_DURATION
        bits.write_bits(not self_cast, 1)
        caster = _guid_bytes(aura.caster_guid)
        if not self_cast:
            for index in (3, 4, 6, 1, 5, 2, 0, 7):
                bits.write_bits(bool(caster[index]), 1)
        bits.write_bits(0, 22)
        bits.write_bits(has_duration, 1)
        bits.write_bits(has_duration, 1)
    payload = bytearray(bits.getvalue())
    for aura in auras:
        caster = _guid_bytes(aura.caster_guid)
        self_cast = int(aura.caster_guid) == owner_guid
        if not self_cast:
            for index in (3, 2, 1, 6, 4, 0, 5, 7):
                _byte_seq(payload, caster, index)
        flags = (AFLAG_POSITIVE if aura.positive else 0) | (AFLAG_CASTER if self_cast else 0)
        if int(aura.duration_ms) >= 0:
            flags |= AFLAG_DURATION
        payload.extend(struct.pack("<BHI", flags, int(aura.caster_level) & 0xFFFF, int(aura.spell_id)))
        if int(aura.duration_ms) >= 0:
            payload.extend(struct.pack("<II", int(aura.duration_ms), max(0, int(aura.remaining_ms))))
        # SkyFire writes charges for non-stackable spells; ordinary buffs and
        # mounts therefore use zero on the wire while the registry still owns
        # the logical stack count of one.
        wire_stack_or_charges = int(aura.stack_count) if int(aura.stack_count) > 1 else 0
        payload.extend(struct.pack("<BI", wire_stack_or_charges & 0xFF, int(aura.effect_mask)))
        payload.append(int(aura.slot) & 0xFF)
    for index in (2, 6, 7, 1, 3, 4, 0, 5):
        _byte_seq(payload, target, index)
    return bytes(payload)


def build_aura_remove(owner: Any, slot: int) -> bytes:
    target = _guid_bytes(aura_owner_guid(owner))
    bits = BitWriter()
    bits.write_bits(bool(target[7]), 1)
    bits.write_bits(0, 1)
    bits.write_bits(1, 24)
    for index in (6, 1, 3, 0, 4, 2, 5):
        bits.write_bits(bool(target[index]), 1)
    bits.write_bits(0, 1)  # remove
    payload = bytearray(bits.getvalue())
    payload.append(int(slot) & 0xFF)
    for index in (2, 6, 7, 1, 3, 4, 0, 5):
        _byte_seq(payload, target, index)
    return bytes(payload)


def replay_response(owner: Any) -> tuple[str, bytes]:
    return "SMSG_AURA_UPDATE", build_aura_update(owner, list(registry(owner).values()), full_replay=True)
