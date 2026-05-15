#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import struct
from types import SimpleNamespace

from server.modules.handlers.world.opcodes.pets import (
    _build_companion_create_response,
    summon_companion_pet,
)
from server.modules.handlers.world.pet.pet_service import BattlePetJournalEntry


def _parse_first_create_fields(payload: bytes) -> tuple[int, int, dict[int, int]]:
    offset = 0
    _map_id, update_count = struct.unpack_from("<HI", payload, offset)
    offset += 6
    assert update_count == 1

    update_type = payload[offset]
    offset += 1

    guid_mask = payload[offset]
    offset += 1 + int(guid_mask).bit_count()

    object_type = payload[offset]
    offset += 1
    offset += 13

    # Fixed living-unit body emitted by the companion create builder.
    offset += 59

    mask_blocks = payload[offset]
    offset += 1
    mask_bytes = payload[offset:offset + (mask_blocks * 4)]
    offset += mask_blocks * 4

    field_indices: list[int] = []
    for index in range(mask_blocks * 32):
        word = struct.unpack_from("<I", mask_bytes, (index // 32) * 4)[0]
        if word & (1 << (index % 32)):
            field_indices.append(index)

    fields = {}
    for field_index in field_indices:
        fields[field_index] = struct.unpack_from("<I", payload, offset)[0]
        offset += 4

    assert payload[offset] == 0
    return update_type, object_type, fields


def test_battle_pet_create_contains_owner_linkage_and_render_fields():
    session = SimpleNamespace(
        char_guid=0x10,
        world_guid=0x3000100000010,
        realm_id=1,
        map_id=1,
        x=2030.434,
        y=-6710.1,
        z=5.594,
        orientation=1.052741,
        race=1,
        faction_template=35,
        region=None,
    )
    pet = BattlePetJournalEntry(
        species_id=83,
        creature_id=8376,
        spell_id=12243,
        display_id=7920,
    )

    opcode, payload = _build_companion_create_response(session, pet)

    update_type, object_type, fields = _parse_first_create_fields(payload)

    assert opcode == "SMSG_UPDATE_OBJECT"
    assert update_type == 2
    assert object_type == 3
    assert fields[4] == 0x09
    assert fields[5] == 8376
    assert fields[16] == 0x10
    assert fields[17] == 0x30001
    assert fields[18] == 0x10
    assert fields[19] == 0x30001
    assert fields[20] == 0x10
    assert fields[21] == 0x30001
    assert fields[24] == 83
    assert fields[57] == 35
    assert fields[61] == 0
    assert fields[69] == 7920
    assert fields[70] == 7920
    assert fields[86] == 12243


def test_battle_pet_summon_sends_player_feedback_before_pet_packets():
    session = SimpleNamespace(
        char_guid=0x10,
        world_guid=0x3000100000010,
        realm_id=1,
        map_id=1,
        x=2030.434,
        y=-6710.1,
        z=5.594,
        orientation=1.052741,
        race=1,
        faction_template=35,
        region=None,
    )
    pet = BattlePetJournalEntry(
        species_id=83,
        creature_id=8376,
        spell_id=12243,
        display_id=7920,
    )

    responses = summon_companion_pet(session, pet)

    assert responses is not None
    assert [opcode for opcode, _payload in responses] == [
        "SMSG_EMOTE",
        "SMSG_BATTLE_PET_UPDATE",
        "SMSG_UPDATE_OBJECT",
    ]
    assert all(payload for _opcode, payload in responses)
