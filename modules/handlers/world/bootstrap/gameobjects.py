#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import struct

from server.modules.game.guid import GameObjectGuid, GuidHelper

_GAMEOBJECT_CREATE_FLAGS = bytes.fromhex("000000030040")


def _u32_from_float(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def _build_create_update_object_entry(*, guid: int, object_type: int, create_flags: bytes, body: bytes) -> bytes:
    payload = bytearray()
    payload += struct.pack("<B", 1)
    payload += GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)
    payload += struct.pack("<B", int(object_type) & 0xFF)
    payload += bytes(create_flags)
    payload += bytes(body)
    return bytes(payload)


def _build_fixed_u32_field_block(fields: dict[int, int], *, mask_blocks: int = 1) -> tuple[bytes, bytes]:
    if not fields:
        return (b"\x00" * (int(mask_blocks) * 4), b"")

    mask = bytearray(int(mask_blocks) * 4)
    field_bytes = bytearray()
    for field_index in sorted(int(index) for index in fields):
        word_index = field_index // 32
        bit_index = field_index % 32
        current_word = struct.unpack_from("<I", mask, word_index * 4)[0]
        struct.pack_into("<I", mask, word_index * 4, current_word | (1 << bit_index))
        field_bytes += struct.pack("<I", int(fields[field_index]) & 0xFFFFFFFF)
    return bytes(mask), bytes(field_bytes)


def _build_gameobject_field_values(entry: dict, *, world_guid: int) -> dict[int, int]:
    state = int(entry.get("state", 0) or 0) & 0xFF
    object_bytes_1 = state | ((int(entry.get("type", 0) or 0) & 0xFF) << 8)
    field_values: dict[int, int] = {
        0: int(world_guid) & 0xFFFFFFFF,
        1: (int(world_guid) >> 32) & 0xFFFFFFFF,
        4: 33,
        5: int(entry.get("entry", 0) or 0),
        7: _u32_from_float(float(entry.get("size", 1.0) or 1.0)),
        10: int(entry.get("display_id", 0) or 0),
        11: int(entry.get("flags", 0) or 0),
        18: object_bytes_1,
        19: (int(entry.get("animprogress", 0) or 0) & 0xFF) << 24,
    }
    if int(entry.get("faction", 0) or 0) != 0:
        field_values[16] = int(entry.get("faction", 0) or 0)
    for offset, key in enumerate(("rotation0", "rotation1", "rotation2", "rotation3")):
        value = float(entry.get(key, 0.0) or 0.0)
        if value != 0.0:
            field_values[12 + offset] = _u32_from_float(value)
    if 15 not in field_values:
        field_values[15] = _u32_from_float(1.0)
    return field_values


def _build_gameobject_update_payload(*, map_id: int, entry: dict, realm_id: int) -> bytes:
    world_guid = int(
        entry.get("world_guid")
        or GameObjectGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), int(realm_id) or 1)
    )
    mask_bytes, field_bytes = _build_fixed_u32_field_block(
        _build_gameobject_field_values(entry, world_guid=world_guid),
        mask_blocks=1,
    )

    stationary_y = float(entry.get("y", 0.0) or 0.0)
    stationary_z = float(entry.get("z", 0.0) or 0.0)
    stationary_orientation = float(entry.get("orientation", 0.0) or 0.0)
    stationary_x = float(entry.get("x", 0.0) or 0.0)
    gameobject_rotation_packed = 0
    movement_block_uint32 = 0

    body = bytearray()
    body += struct.pack(
        "<ffff",
        stationary_y,
        stationary_z,
        stationary_orientation,
        stationary_x,
    )
    body += struct.pack("<I", movement_block_uint32)
    body += struct.pack("<Q", gameobject_rotation_packed)
    body += struct.pack("<B", len(mask_bytes) // 4)
    body += bytes(mask_bytes)
    body += bytes(field_bytes)
    body += struct.pack("<B", 0)

    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
    payload += _build_create_update_object_entry(
        guid=world_guid,
        object_type=5,
        create_flags=_GAMEOBJECT_CREATE_FLAGS,
        body=bytes(body),
    )
    return bytes(payload)
