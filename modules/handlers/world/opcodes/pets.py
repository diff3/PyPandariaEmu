#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math

from DSL.modules.bitsHandler import BitInterPreter
from shared.Logger import Logger
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.pet.pet_service import (
    battle_pet_by_spell,
    battle_pet_by_guid,
    build_battle_pet_journal_payload,
    build_battle_pet_update_payload,
)
from server.modules.protocol.PacketContext import PacketContext


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


def _build_unsummon_response(session, world_guid: int) -> tuple[str, bytes] | None:
    if int(world_guid) <= 0:
        return None
    from server.modules.handlers.world.opcodes.movement import _build_out_of_range_update_object_payload

    map_id = int(getattr(session, "map_id", 0) or 0)
    payload = _build_out_of_range_update_object_payload(map_id=map_id, guid=int(world_guid))
    return "SMSG_UPDATE_OBJECT", payload


def _build_companion_create_response(session, pet) -> tuple[str, bytes]:
    from server.modules.handlers.world.bootstrap.replay import _build_creature_update_payload

    char_guid = int(getattr(session, "char_guid", 0) or 0)
    species_id = int(getattr(pet, "species_id", 0) or 0)
    creature_id = int(getattr(pet, "creature_id", 0) or 0)
    display_id = int(getattr(pet, "display_id", 0) or 0)
    world_guid = 0xF130000000000000 | ((char_guid & 0xFFFFFF) << 16) | (species_id & 0xFFFF)

    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)
    orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    offset = 1.5
    pet_x = x + math.cos(orientation + 1.8) * offset
    pet_y = y + math.sin(orientation + 1.8) * offset

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
        "[BattlePet] summon species=%s creature=%s spell=%s display=%s world_guid=0x%016X",
        species_id,
        creature_id,
        int(getattr(pet, "spell_id", 0) or 0),
        display_id,
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
    )
    payload = _build_creature_update_payload(
        map_id=int(getattr(session, "map_id", 0) or 0),
        entry=entry,
        realm_id=int(getattr(session, "realm_id", 1) or 1),
    )
    session.summoned_companion_world_guid = int(world_guid)
    session.summoned_companion_pet_guid = int(getattr(pet, "species_id", 0) or 0)
    return "SMSG_UPDATE_OBJECT", payload


def summon_companion_pet(session, pet) -> list[tuple[str, bytes]] | None:
    responses: list[tuple[str, bytes]] = []
    current_world_guid = _summoned_companion_world_guid(session)
    current_pet_guid = int(getattr(session, "summoned_companion_pet_guid", 0) or 0)
    species_id = int(getattr(pet, "species_id", 0) or 0)

    if current_world_guid:
        unsummon = _build_unsummon_response(session, current_world_guid)
        if unsummon:
            responses.append(unsummon)

    if current_pet_guid == species_id:
        session.summoned_companion_world_guid = 0
        session.summoned_companion_pet_guid = 0
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
