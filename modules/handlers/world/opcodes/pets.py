#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import struct

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitInterPreter
from shared.Logger import Logger
from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.pet.pet_service import (
    battle_pet_by_spell,
    battle_pet_by_guid,
    build_battle_pet_journal_payload,
    build_battle_pet_update_payload,
)
from server.modules.protocol.PacketContext import PacketContext

_COMPANION_CREATE_FLAGS = bytes.fromhex("200000000029CC00000800004F")
_COMPANION_UPDATE_COUNT = 1
_COMPANION_UPDATE_TYPE_CREATE = 2
_COMPANION_OBJECT_TYPE_UNIT = 3
_COMPANION_OBJECT_TYPE_MASK = 0x09
_COMPANION_FIELD_MASK_BLOCKS = 5
_COMPANION_DYNAMIC_MASK_BLOCKS = 0
_COMPANION_VISIBILITY_RADIUS = 120.0
_COMPANION_FEEDBACK_EMOTE_ID = 16

_OBJECT_FIELD_GUID = 0
_OBJECT_FIELD_TYPE = 4
_OBJECT_FIELD_ENTRY = 5
_OBJECT_FIELD_DYNAMIC_FLAGS = 6
_OBJECT_FIELD_SCALE = 7
_UNIT_FIELD_SUMMONED_BY = 16
_UNIT_FIELD_CREATED_BY = 18
_UNIT_FIELD_DEMON_CREATOR = 20
_UNIT_FIELD_BATTLE_PET_COMPANION_GUID = 24
_UNIT_FIELD_HEALTH = 33
_UNIT_FIELD_MAX_HEALTH = 39
_UNIT_FIELD_POWER_ENERGY = 40
_UNIT_FIELD_LEVEL = 55
_UNIT_FIELD_FACTION_TEMPLATE = 57
_UNIT_FIELD_FLAGS = 61
_UNIT_FIELD_FLAGS2 = 62
_UNIT_FIELD_ATTACK_ROUND_BASE_TIME = 64
_UNIT_FIELD_BOUNDING_RADIUS = 67
_UNIT_FIELD_COMBAT_REACH = 68
_UNIT_FIELD_DISPLAY_ID = 69
_UNIT_FIELD_NATIVE_DISPLAY_ID = 70
_UNIT_FIELD_MOUNT_DISPLAY_ID = 71
_UNIT_FIELD_PET_NUMBER = 77
_UNIT_FIELD_PET_NAME_TIMESTAMP = 78
_UNIT_FIELD_MOD_CASTING_SPEED = 81
_UNIT_FIELD_MOD_SPELL_HASTE = 82
_UNIT_FIELD_CREATED_BY_SPELL = 86
_UNIT_FIELD_MOD_DAMAGE_DONE_PCT = 154
_UNIT_FIELD_MOD_HEALING_DONE_PCT = 157

_FIELD_LOG_NAMES = {
    _OBJECT_FIELD_GUID: "OBJECT_FIELD_GUID_LOW",
    _OBJECT_FIELD_GUID + 1: "OBJECT_FIELD_GUID_HIGH",
    _OBJECT_FIELD_TYPE: "OBJECT_FIELD_TYPE",
    _OBJECT_FIELD_ENTRY: "OBJECT_FIELD_ENTRY",
    _OBJECT_FIELD_DYNAMIC_FLAGS: "OBJECT_FIELD_DYNAMIC_FLAGS",
    _OBJECT_FIELD_SCALE: "OBJECT_FIELD_SCALE",
    _UNIT_FIELD_SUMMONED_BY: "UNIT_FIELD_SUMMONED_BY_LOW",
    _UNIT_FIELD_SUMMONED_BY + 1: "UNIT_FIELD_SUMMONED_BY_HIGH",
    _UNIT_FIELD_CREATED_BY: "UNIT_FIELD_CREATED_BY_LOW",
    _UNIT_FIELD_CREATED_BY + 1: "UNIT_FIELD_CREATED_BY_HIGH",
    _UNIT_FIELD_DEMON_CREATOR: "UNIT_FIELD_DEMON_CREATOR_LOW",
    _UNIT_FIELD_DEMON_CREATOR + 1: "UNIT_FIELD_DEMON_CREATOR_HIGH",
    _UNIT_FIELD_BATTLE_PET_COMPANION_GUID: "UNIT_FIELD_BATTLE_PET_COMPANION_GUID_LOW",
    _UNIT_FIELD_BATTLE_PET_COMPANION_GUID + 1: "UNIT_FIELD_BATTLE_PET_COMPANION_GUID_HIGH",
    _UNIT_FIELD_HEALTH: "UNIT_FIELD_HEALTH",
    _UNIT_FIELD_MAX_HEALTH: "UNIT_FIELD_MAX_HEALTH",
    _UNIT_FIELD_LEVEL: "UNIT_FIELD_LEVEL",
    _UNIT_FIELD_FACTION_TEMPLATE: "UNIT_FIELD_FACTIONTEMPLATE",
    _UNIT_FIELD_FLAGS: "UNIT_FIELD_FLAGS",
    _UNIT_FIELD_FLAGS2: "UNIT_FIELD_FLAGS2",
    _UNIT_FIELD_DISPLAY_ID: "UNIT_FIELD_DISPLAYID",
    _UNIT_FIELD_NATIVE_DISPLAY_ID: "UNIT_FIELD_NATIVEDISPLAYID",
    _UNIT_FIELD_MOUNT_DISPLAY_ID: "UNIT_FIELD_MOUNTDISPLAYID",
}


def _decode_battle_pet_guid(payload: bytes) -> int:
    data = bytes(payload or b"")
    if len(data) < 1:
        return 0

    byte_pos = 0
    bit_pos = 0
    mask: dict[int, int] = {}
    for index in (3, 2, 5, 0, 7, 1, 6, 4):
        mask[index], byte_pos, bit_pos = BitInterPreter.read_bit(data, byte_pos, bit_pos)

    if bit_pos:
        byte_pos += 1
        bit_pos = 0

    guid_bytes = [0] * 8
    for index in (6, 7, 3, 5, 0, 4, 1, 2):
        if not mask.get(index):
            continue
        if byte_pos >= len(data):
            return 0
        guid_bytes[index] = int(data[byte_pos]) & 0xFF
        byte_pos += 1

    guid = 0
    for index, value in enumerate(guid_bytes):
        guid |= int(value) << (index * 8)
    return int(guid)


def _summoned_companion_world_guid(session) -> int:
    return int(getattr(session, "summoned_companion_world_guid", 0) or 0)


def _session_world_guid(session) -> int:
    return int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or getattr(session, "char_guid", 0)
        or 0
    )


def _build_companion_feedback_response(session) -> tuple[str, bytes] | None:
    player_guid = _session_world_guid(session)
    if player_guid <= 0:
        return None

    payload = EncoderHandler.encode_packet(
        "SMSG_EMOTE",
        {
            "emote_id": _COMPANION_FEEDBACK_EMOTE_ID,
            "guid": player_guid,
        },
    )
    Logger.info(
        "[BattlePet][Feedback] emote_id=%s player_guid=0x%016X",
        _COMPANION_FEEDBACK_EMOTE_ID,
        player_guid & 0xFFFFFFFFFFFFFFFF,
    )
    return "SMSG_EMOTE", payload


def _build_unsummon_response(session, world_guid: int) -> tuple[str, bytes] | None:
    if int(world_guid) <= 0:
        return None
    from server.modules.handlers.world.opcodes.movement import _build_out_of_range_update_object_payload

    map_id = int(getattr(session, "map_id", 0) or 0)
    payload = _build_out_of_range_update_object_payload(map_id=map_id, guid=int(world_guid))
    return "SMSG_UPDATE_OBJECT", payload


def _u32_from_float(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def _guid_words(guid: int) -> tuple[int, int]:
    value = int(guid) & 0xFFFFFFFFFFFFFFFF
    return value & 0xFFFFFFFF, (value >> 32) & 0xFFFFFFFF


def _build_fixed_u32_field_block(fields: dict[int, int], *, mask_blocks: int) -> tuple[bytes, bytes]:
    mask = bytearray(int(mask_blocks) * 4)
    field_bytes = bytearray()

    for field_index in sorted(int(index) for index in fields):
        word_index = field_index // 32
        if word_index >= int(mask_blocks):
            raise ValueError(f"companion field {field_index} exceeds mask_blocks={mask_blocks}")
        bit_index = field_index % 32
        current_word = struct.unpack_from("<I", mask, word_index * 4)[0]
        struct.pack_into("<I", mask, word_index * 4, current_word | (1 << bit_index))

    for field_index in range(int(mask_blocks) * 32):
        word_index = field_index // 32
        bit_index = field_index % 32
        word_value = struct.unpack_from("<I", mask, word_index * 4)[0]
        if word_value & (1 << bit_index):
            field_bytes += struct.pack("<I", int(fields.get(field_index, 0)) & 0xFFFFFFFF)
    return bytes(mask), bytes(field_bytes)


def _companion_faction_template(session) -> int:
    faction = int(getattr(session, "faction_template", 0) or getattr(session, "faction", 0) or 0)
    if faction > 0:
        return faction
    race = int(getattr(session, "race", 0) or 0)
    if race in {2, 5, 6, 8, 9, 10, 24, 26}:
        return 85
    return 35


def _build_companion_field_values(session, pet, *, world_guid: int, owner_guid: int) -> dict[int, int]:
    display_id = int(getattr(pet, "display_id", 0) or 0)
    companion_guid = int(getattr(pet, "species_id", 0) or 0) & 0xFFFFFFFF
    world_low, world_high = _guid_words(world_guid)
    owner_low, owner_high = _guid_words(owner_guid)

    return {
        _OBJECT_FIELD_GUID: world_low,
        _OBJECT_FIELD_GUID + 1: world_high,
        _OBJECT_FIELD_TYPE: _COMPANION_OBJECT_TYPE_MASK,
        _OBJECT_FIELD_ENTRY: int(getattr(pet, "creature_id", 0) or 0),
        _OBJECT_FIELD_DYNAMIC_FLAGS: 0,
        _OBJECT_FIELD_SCALE: _u32_from_float(1.0),
        _UNIT_FIELD_SUMMONED_BY: owner_low,
        _UNIT_FIELD_SUMMONED_BY + 1: owner_high,
        _UNIT_FIELD_CREATED_BY: owner_low,
        _UNIT_FIELD_CREATED_BY + 1: owner_high,
        _UNIT_FIELD_DEMON_CREATOR: owner_low,
        _UNIT_FIELD_DEMON_CREATOR + 1: owner_high,
        _UNIT_FIELD_BATTLE_PET_COMPANION_GUID: companion_guid,
        _UNIT_FIELD_BATTLE_PET_COMPANION_GUID + 1: 0,
        _UNIT_FIELD_HEALTH: 260,
        _UNIT_FIELD_MAX_HEALTH: 260,
        _UNIT_FIELD_POWER_ENERGY: 1000,
        _UNIT_FIELD_LEVEL: 1,
        _UNIT_FIELD_FACTION_TEMPLATE: _companion_faction_template(session),
        _UNIT_FIELD_FLAGS: 0,
        _UNIT_FIELD_FLAGS2: 0,
        _UNIT_FIELD_ATTACK_ROUND_BASE_TIME: 2000,
        _UNIT_FIELD_ATTACK_ROUND_BASE_TIME + 1: 2000,
        _UNIT_FIELD_BOUNDING_RADIUS: _u32_from_float(0.05),
        _UNIT_FIELD_COMBAT_REACH: _u32_from_float(0.15),
        _UNIT_FIELD_DISPLAY_ID: display_id,
        _UNIT_FIELD_NATIVE_DISPLAY_ID: display_id,
        _UNIT_FIELD_MOUNT_DISPLAY_ID: 0,
        _UNIT_FIELD_PET_NUMBER: companion_guid,
        _UNIT_FIELD_PET_NAME_TIMESTAMP: 1,
        _UNIT_FIELD_MOD_CASTING_SPEED: _u32_from_float(1.0),
        _UNIT_FIELD_MOD_SPELL_HASTE: _u32_from_float(1.0),
        _UNIT_FIELD_CREATED_BY_SPELL: int(getattr(pet, "spell_id", 0) or 0),
        _UNIT_FIELD_MOD_DAMAGE_DONE_PCT: _u32_from_float(1.0),
        _UNIT_FIELD_MOD_HEALING_DONE_PCT: 1,
    }


def _append_companion_living_block(body: bytearray, *, world_guid: int, x: float, y: float, z: float, orientation: float) -> None:
    raw_guid = GuidHelper.to_le_bytes(world_guid)
    body += struct.pack("<B", raw_guid[4])
    body += struct.pack("<f", 7.0)
    body += struct.pack("<B", raw_guid[2])
    body += struct.pack("<B", raw_guid[1])
    body += struct.pack("<f", 3.1415939331054688)
    body += struct.pack("<f", 4.7)
    body += struct.pack("<B", raw_guid[7])
    body += struct.pack("<f", 3.140000104904175)
    body += struct.pack("<f", float(x))
    body += struct.pack("<f", float(orientation))
    body += struct.pack("<f", 2.5)
    body += struct.pack("<f", float(y))
    body += struct.pack("<f", 4.5)
    body += struct.pack("<B", raw_guid[5])
    body += struct.pack("<B", raw_guid[6])
    body += struct.pack("<B", raw_guid[0])
    body += struct.pack("<f", 2.5)
    body += struct.pack("<f", 8.000020027160645)
    body += struct.pack("<f", 4.722221851348877)
    body += struct.pack("<f", float(z))


def _build_companion_update_payload(session, pet, entry: dict) -> bytes:
    world_guid = int(entry["world_guid"])
    owner_guid = _session_world_guid(session)
    field_values = _build_companion_field_values(session, pet, world_guid=world_guid, owner_guid=owner_guid)
    mask_bytes, field_bytes = _build_fixed_u32_field_block(
        field_values,
        mask_blocks=_COMPANION_FIELD_MASK_BLOCKS,
    )

    body = bytearray()
    _append_companion_living_block(
        body,
        world_guid=world_guid,
        x=float(entry["x"]),
        y=float(entry["y"]),
        z=float(entry["z"]),
        orientation=float(entry["orientation"]),
    )
    body += struct.pack("<B", len(mask_bytes) // 4)
    body += mask_bytes
    body += field_bytes
    body += struct.pack("<B", _COMPANION_DYNAMIC_MASK_BLOCKS)

    payload = bytearray()
    payload += struct.pack("<HI", int(getattr(session, "map_id", 0) or 0) & 0xFFFF, _COMPANION_UPDATE_COUNT)
    payload += struct.pack("<B", _COMPANION_UPDATE_TYPE_CREATE)
    payload += GuidHelper.pack(world_guid)
    payload += struct.pack("<B", _COMPANION_OBJECT_TYPE_UNIT)
    payload += _COMPANION_CREATE_FLAGS
    payload += body
    _log_companion_update_packet(session, pet, entry, field_values, payload)
    return bytes(payload)


def _log_companion_update_packet(session, pet, entry: dict, field_values: dict[int, int], payload: bytearray) -> None:
    set_fields = sorted(int(index) for index in field_values)
    named_fields = [
        _FIELD_LOG_NAMES[index]
        for index in set_fields
        if index in _FIELD_LOG_NAMES
    ]
    Logger.info(
        "[BattlePet][CreateObject] guid=0x%016X owner=0x%016X map=%s "
        "type=%s type_mask=0x%X update_type=%s flags=%s pos=(%.3f, %.3f, %.3f, %.3f) "
        "fields=%s mask_blocks=%s size=%s",
        int(entry["world_guid"]) & 0xFFFFFFFFFFFFFFFF,
        int(
            getattr(session, "world_guid", 0)
            or getattr(session, "player_guid", 0)
            or getattr(session, "char_guid", 0)
            or 0
        ) & 0xFFFFFFFFFFFFFFFF,
        int(getattr(session, "map_id", 0) or 0),
        _COMPANION_OBJECT_TYPE_UNIT,
        _COMPANION_OBJECT_TYPE_MASK,
        _COMPANION_UPDATE_TYPE_CREATE,
        _COMPANION_CREATE_FLAGS.hex(),
        float(entry["x"]),
        float(entry["y"]),
        float(entry["z"]),
        float(entry["orientation"]),
        ",".join(named_fields),
        _COMPANION_FIELD_MASK_BLOCKS,
        len(payload),
    )
    Logger.debug(
        "[BattlePet][Fields] species=%s creature=%s display=%s values=%s",
        int(getattr(pet, "species_id", 0) or 0),
        int(getattr(pet, "creature_id", 0) or 0),
        int(getattr(pet, "display_id", 0) or 0),
        {int(index): int(field_values[index]) for index in set_fields},
    )


def _region_companions(session) -> dict[int, dict]:
    region = getattr(session, "region", None)
    if region is None:
        return {}
    companions = getattr(region, "battle_pet_companions", None)
    if not isinstance(companions, dict):
        companions = {}
        region.battle_pet_companions = companions
    return companions


def _remember_companion_spawn(session, entry: dict) -> None:
    companions = _region_companions(session)
    if getattr(session, "region", None) is None:
        return
    companions[int(entry["world_guid"])] = dict(entry)
    Logger.info(
        "[BattlePet][MapInsert] guid=0x%016X region_map=%s companions=%s alive=1",
        int(entry["world_guid"]) & 0xFFFFFFFFFFFFFFFF,
        int(getattr(getattr(session, "region", None), "map_id", getattr(session, "map_id", 0)) or 0),
        len(companions),
    )


def _forget_companion_spawn(session, world_guid: int) -> None:
    companions = _region_companions(session)
    removed = companions.pop(int(world_guid), None) if companions else None
    Logger.info(
        "[BattlePet][Despawn] guid=0x%016X removed=%s companions=%s",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(removed is not None),
        len(companions),
    )


def _nearby_observers(session, *, x: float, y: float) -> list:
    region = getattr(session, "region", None)
    players = list(getattr(region, "players", ()) or ())
    observers = []
    source_map = int(getattr(session, "map_id", 0) or 0)
    for player in players:
        if player is session:
            continue
        if int(getattr(player, "map_id", 0) or 0) != source_map:
            continue
        dx = float(getattr(player, "x", 0.0) or 0.0) - float(x)
        dy = float(getattr(player, "y", 0.0) or 0.0) - float(y)
        if math.hypot(dx, dy) <= _COMPANION_VISIBILITY_RADIUS:
            observers.append(player)
    return observers


def _broadcast_companion_create(session, create_response: tuple[str, bytes], entry: dict) -> None:
    observers = _nearby_observers(session, x=float(entry["x"]), y=float(entry["y"]))
    if not observers:
        Logger.info(
            "[BattlePet][Visibility] guid=0x%016X nearby_players=0",
            int(entry["world_guid"]) & 0xFFFFFFFFFFFFFFFF,
        )
        return
    from server.modules.handlers.world.state.runtime import dispatch_responses_to_sessions

    dispatch_responses_to_sessions(observers, [create_response])
    Logger.info(
        "[BattlePet][Visibility] guid=0x%016X create_sent_to=%s",
        int(entry["world_guid"]) & 0xFFFFFFFFFFFFFFFF,
        len(observers),
    )


def _broadcast_companion_remove(session, remove_response: tuple[str, bytes] | None, world_guid: int) -> None:
    if remove_response is None:
        return
    region = getattr(session, "region", None)
    observers = [player for player in list(getattr(region, "players", ()) or ()) if player is not session]
    if not observers:
        return
    from server.modules.handlers.world.state.runtime import dispatch_responses_to_sessions

    dispatch_responses_to_sessions(observers, [remove_response])
    Logger.info(
        "[BattlePet][Visibility] guid=0x%016X destroy_sent_to=%s",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        len(observers),
    )


def _build_companion_create_response(session, pet) -> tuple[str, bytes]:
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    species_id = int(getattr(pet, "species_id", 0) or 0)
    creature_id = int(getattr(pet, "creature_id", 0) or 0)
    display_id = int(getattr(pet, "display_id", 0) or 0)
    world_guid = 0xF130000000000000 | ((char_guid & 0xFFFFFF) << 16) | (species_id & 0xFFFF)

    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)
    orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    pet_x = x
    pet_y = y

    entry = {
        "world_guid": int(world_guid),
        "entry": creature_id,
        "modelid": display_id,
        "x": pet_x,
        "y": pet_y,
        "z": z,
        "orientation": orientation,
    }
    Logger.info(
        "[BattlePet] summon species=%s creature=%s spell=%s display=%s world_guid=0x%016X owner=0x%016X",
        species_id,
        creature_id,
        int(getattr(pet, "spell_id", 0) or 0),
        display_id,
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        char_guid & 0xFFFFFFFFFFFFFFFF,
    )
    payload = _build_companion_update_payload(session, pet, entry)
    session.summoned_companion_world_guid = int(world_guid)
    session.summoned_companion_pet_guid = int(getattr(pet, "species_id", 0) or 0)
    _remember_companion_spawn(session, entry)
    response = ("SMSG_UPDATE_OBJECT", payload)
    _broadcast_companion_create(session, response, entry)
    return response


def summon_companion_pet(session, pet) -> list[tuple[str, bytes]] | None:
    responses: list[tuple[str, bytes]] = []
    feedback = _build_companion_feedback_response(session)
    if feedback:
        responses.append(feedback)

    current_world_guid = _summoned_companion_world_guid(session)
    current_pet_guid = int(getattr(session, "summoned_companion_pet_guid", 0) or 0)
    species_id = int(getattr(pet, "species_id", 0) or 0)

    if current_world_guid:
        unsummon = _build_unsummon_response(session, current_world_guid)
        if unsummon:
            responses.append(unsummon)
            _broadcast_companion_remove(session, unsummon, current_world_guid)
        _forget_companion_spawn(session, current_world_guid)

    if current_pet_guid == species_id:
        session.summoned_companion_world_guid = 0
        session.summoned_companion_pet_guid = 0
        Logger.info(
            "[BattlePet] unsummon species=%s world_guid=0x%016X",
            species_id,
            int(current_world_guid) & 0xFFFFFFFFFFFFFFFF,
        )
        return responses or None

    responses.append((
        "SMSG_BATTLE_PET_UPDATE",
        build_battle_pet_update_payload(pet, notification=True),
    ))
    responses.append(_build_companion_create_response(session, pet))
    return responses


def summon_companion_pet_by_spell(session, spell_id: int) -> list[tuple[str, bytes]] | None:
    pet = battle_pet_by_spell(int(spell_id))
    if pet is None:
        return None
    return summon_companion_pet(session, pet)


@register("CMSG_BATTLE_PET_REQUEST_JOURNAL")
def handle_battle_pet_request_journal(_session, _ctx: PacketContext):
    return 0, [("SMSG_BATTLE_PET_JOURNAL", build_battle_pet_journal_payload())]


@register("CMSG_BATTLE_PET_SUMMON_COMPANION")
def handle_battle_pet_summon_companion(session, ctx: PacketContext):
    pet_guid = _decode_battle_pet_guid(ctx.payload)
    pet = battle_pet_by_guid(pet_guid)
    if pet is None:
        Logger.warning("[BattlePet] summon unknown pet_guid=0x%016X", int(pet_guid))
        return 0, None

    return 0, summon_companion_pet(session, pet)
