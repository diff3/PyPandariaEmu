#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import struct
from typing import Any, Mapping

from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.game.guid import GameObjectGuid

_GAMEOBJECT_CREATE_FLAGS = bytes.fromhex("000000030040")
_GAMEOBJECT_UPDATE_COUNT = 1
_GAMEOBJECT_UPDATE_TYPE = 1
_GAMEOBJECT_OBJECT_TYPE = 5
_GAMEOBJECT_MASK_BLOCKS = 1
_GAMEOBJECT_DYNAMIC_MASK_BLOCKS = 0
_GAMEOBJECT_MOVEMENT_BLOCK_UINT32 = 0
_GAMEOBJECT_ROTATION_PACKED = 0

_OBJECT_FIELD_GUID_LOW = 0
_OBJECT_FIELD_GUID_HIGH = 1
_OBJECT_FIELD_TYPE = 4
_OBJECT_FIELD_ENTRY = 5
_OBJECT_FIELD_SCALE = 7
_GAMEOBJECT_FIELD_DISPLAY_ID = 10
_GAMEOBJECT_FIELD_FLAGS = 11
_GAMEOBJECT_FIELD_ROTATION_START = 12
_GAMEOBJECT_FIELD_FACTION = 16
_GAMEOBJECT_FIELD_BYTES_1 = 18
_GAMEOBJECT_FIELD_BYTES_2 = 19
_GAMEOBJECT_ROTATION_COMPONENT_KEYS = ("rotation0", "rotation1", "rotation2", "rotation3")


def _entry_int(entry: Mapping[str, Any], key: str, default: int = 0) -> int:
    """Return an integer field from a GameObject entry."""
    return int(entry.get(key, default) or default)


def _entry_float(entry: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    """Return a float field from a GameObject entry."""
    return float(entry.get(key, default) or default)


def _u32_from_float(value: float) -> int:
    """Pack a float into a little-endian uint32 value."""
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def _build_fixed_u32_field_block(fields: dict[int, int], *, mask_blocks: int = 1) -> tuple[bytes, bytes]:
    """Build a fixed-size update mask and packed uint32 field payload."""
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


def _resolve_world_guid(entry: Mapping[str, Any], realm_id: int) -> int:
    """Resolve the full 64-bit world guid for a GameObject spawn."""
    return int(
        entry.get("world_guid")
        or GameObjectGuid.from_spawn_guid(_entry_int(entry, "guid"), int(realm_id) or 1)
    )


def _build_gameobject_field_values(entry: Mapping[str, Any], *, world_guid: int) -> dict[int, int]:
    """Build update-field values for a single GameObject create packet."""
    state = _entry_int(entry, "state") & 0xFF
    gameobject_type = _entry_int(entry, "type") & 0xFF
    object_bytes_1 = state | (gameobject_type << 8)
    field_values: dict[int, int] = {
        _OBJECT_FIELD_GUID_LOW: int(world_guid) & 0xFFFFFFFF,
        _OBJECT_FIELD_GUID_HIGH: (int(world_guid) >> 32) & 0xFFFFFFFF,
        _OBJECT_FIELD_TYPE: 33,
        _OBJECT_FIELD_ENTRY: _entry_int(entry, "entry"),
        _OBJECT_FIELD_SCALE: _u32_from_float(_entry_float(entry, "size", 1.0)),
        _GAMEOBJECT_FIELD_DISPLAY_ID: _entry_int(entry, "display_id"),
        _GAMEOBJECT_FIELD_FLAGS: _entry_int(entry, "flags"),
        _GAMEOBJECT_FIELD_BYTES_1: object_bytes_1,
        _GAMEOBJECT_FIELD_BYTES_2: (_entry_int(entry, "animprogress") & 0xFF) << 24,
    }
    faction = _entry_int(entry, "faction")
    if faction != 0:
        field_values[_GAMEOBJECT_FIELD_FACTION] = faction
    for offset, key in enumerate(_GAMEOBJECT_ROTATION_COMPONENT_KEYS):
        value = _entry_float(entry, key)
        if value != 0.0:
            field_values[_GAMEOBJECT_FIELD_ROTATION_START + offset] = _u32_from_float(value)
    if _GAMEOBJECT_FIELD_ROTATION_START + 3 not in field_values:
        field_values[_GAMEOBJECT_FIELD_ROTATION_START + 3] = _u32_from_float(1.0)
    return field_values


def _build_gameobject_update_payload(*, map_id: int, entry: Mapping[str, Any], realm_id: int) -> bytes:
    """Encode a GameObject CREATE_OBJECT payload through the DSL definition."""
    world_guid = _resolve_world_guid(entry, realm_id)
    mask_bytes, field_bytes = _build_fixed_u32_field_block(
        _build_gameobject_field_values(entry, world_guid=world_guid),
        mask_blocks=_GAMEOBJECT_MASK_BLOCKS,
    )

    stationary_y = _entry_float(entry, "y")
    stationary_z = _entry_float(entry, "z")
    stationary_orientation = _entry_float(entry, "orientation")
    stationary_x = _entry_float(entry, "x")

    return EncoderHandler.encode_packet(
        "GAMEOBJECT_CREATE",
        {
            "map_id": int(map_id) & 0xFFFF,
            "update_count": _GAMEOBJECT_UPDATE_COUNT,
            "update_type": _GAMEOBJECT_UPDATE_TYPE,
            "guid": {"guid": world_guid},
            "object_type": _GAMEOBJECT_OBJECT_TYPE,
            "create_flag_0": _GAMEOBJECT_CREATE_FLAGS[0],
            "create_flag_1": _GAMEOBJECT_CREATE_FLAGS[1],
            "create_flag_2": _GAMEOBJECT_CREATE_FLAGS[2],
            "create_flag_3": _GAMEOBJECT_CREATE_FLAGS[3],
            "create_flag_4": _GAMEOBJECT_CREATE_FLAGS[4],
            "create_flag_5": _GAMEOBJECT_CREATE_FLAGS[5],
            "stationary_y": stationary_y,
            "stationary_z": stationary_z,
            "stationary_orientation": stationary_orientation,
            "stationary_x": stationary_x,
            # The current create flags expect these two fields explicitly.
            "movement_block_uint32": _GAMEOBJECT_MOVEMENT_BLOCK_UINT32,
            "gameobject_rotation_packed": _GAMEOBJECT_ROTATION_PACKED,
            "mask_blocks": len(mask_bytes) // 4,
            "mask": mask_bytes,
            "fields": field_bytes,
            "dynamic_mask_blocks": _GAMEOBJECT_DYNAMIC_MASK_BLOCKS,
        },
    )
