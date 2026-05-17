#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import struct
import time
from typing import Any, Mapping

from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.game.guid import GameObjectGuid, MoTransportGuid

_GAMEOBJECT_CREATE_FLAGS = bytes.fromhex("000000030040")
_GAMEOBJECT_UPDATE_COUNT = 1
_GAMEOBJECT_UPDATE_TYPE = 1
_GAMEOBJECT_OBJECT_TYPE = 5
_GAMEOBJECT_MASK_BLOCKS = 1
_GAMEOBJECT_DYNAMIC_MASK_BLOCKS = 0
_GAMEOBJECT_MOVEMENT_BLOCK_UINT32 = 0

_OBJECT_FIELD_GUID_LOW = 0
_OBJECT_FIELD_GUID_HIGH = 1
_OBJECT_FIELD_TYPE = 4
_OBJECT_FIELD_ENTRY = 5
_OBJECT_FIELD_DYNAMIC_FLAGS = 6
_OBJECT_FIELD_SCALE = 7
_GAMEOBJECT_FIELD_DISPLAY_ID = 10
_GAMEOBJECT_FIELD_FLAGS = 11
_GAMEOBJECT_FIELD_ROTATION_START = 12
_GAMEOBJECT_FIELD_FACTION = 16
_GAMEOBJECT_FIELD_LEVEL = 17
_GAMEOBJECT_FIELD_PERCENT_HEALTH = 18
_GAMEOBJECT_FIELD_STATE_SPELL_VISUAL_ID = 19
_GAMEOBJECT_ROTATION_COMPONENT_KEYS = ("rotation0", "rotation1", "rotation2", "rotation3")
_PACKED_QUATERNION_X_SCALE = 2_097_152
_PACKED_QUATERNION_YZ_SCALE = 1_048_576

_GAMEOBJECT_TYPE_TRANSPORT = 11
_GAMEOBJECT_TYPE_MO_TRANSPORT = 15
_GO_FLAG_TRANSPORT = 0x00000008
_GO_STATE_ACTIVE = 0
_GO_STATE_READY = 1
_GO_HEALTH_FULL = 0xFF


def _entry_int(entry: Mapping[str, Any], key: str, default: int = 0) -> int:
    """Return an integer field from a GameObject entry."""
    return int(entry.get(key, default) or default)


def _entry_float(entry: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    """Return a float field from a GameObject entry."""
    return float(entry.get(key, default) or default)


def _u32_from_float(value: float) -> int:
    """Pack a float into a little-endian uint32 value."""
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def _rotation_has_quaternion(entry: Mapping[str, Any]) -> bool:
    return any(
        abs(_entry_float(entry, key)) > 0.000001
        for key in ("rotation0", "rotation1", "rotation2")
    ) or abs(abs(_entry_float(entry, "rotation3")) - 1.0) > 0.000001


def _rotation_has_yaw_only(entry: Mapping[str, Any]) -> bool:
    return (
        abs(_entry_float(entry, "rotation0")) <= 0.000001
        and abs(_entry_float(entry, "rotation1")) <= 0.000001
        and _rotation_has_quaternion(entry)
    )


def _normalize_quaternion(
    x: float,
    y: float,
    z: float,
    w: float,
) -> tuple[float, float, float, float]:
    length = math.sqrt((x * x) + (y * y) + (z * z) + (w * w))
    if length <= 0.000001:
        return 0.0, 0.0, 0.0, 1.0

    x /= length
    y /= length
    z /= length
    w /= length
    if w < 0.0:
        x = -x
        y = -y
        z = -z
        w = -w
    return float(x), float(y), float(z), float(w)


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(int(minimum), min(int(maximum), int(value)))


def _pack_signed(value: int, bits: int) -> int:
    return int(value) & ((1 << int(bits)) - 1)


def _pack_gameobject_rotation(x: float, y: float, z: float, w: float) -> int:
    """Pack a normalized GameObject quaternion into the 5.4.x create block."""
    x, y, z, _w = _normalize_quaternion(x, y, z, w)
    packed_x = _clamp(
        round(x * _PACKED_QUATERNION_X_SCALE),
        -_PACKED_QUATERNION_X_SCALE,
        _PACKED_QUATERNION_X_SCALE - 1,
    )
    packed_y = _clamp(
        round(y * _PACKED_QUATERNION_YZ_SCALE),
        -_PACKED_QUATERNION_YZ_SCALE,
        _PACKED_QUATERNION_YZ_SCALE - 1,
    )
    packed_z = _clamp(
        round(z * _PACKED_QUATERNION_YZ_SCALE),
        -_PACKED_QUATERNION_YZ_SCALE,
        _PACKED_QUATERNION_YZ_SCALE - 1,
    )

    return (
        (_pack_signed(packed_x, 22) << 42)
        | (_pack_signed(packed_y, 21) << 21)
        | _pack_signed(packed_z, 21)
    )


def _stationary_orientation(entry: Mapping[str, Any]) -> float:
    """Use DB quaternion yaw when available so facing and rotation fields agree."""
    if _rotation_has_yaw_only(entry):
        orientation = 2.0 * math.atan2(
            _entry_float(entry, "rotation2"),
            _entry_float(entry, "rotation3"),
        )
    else:
        orientation = _entry_float(entry, "orientation")
    orientation = math.fmod(float(orientation), math.tau)
    if orientation < 0.0:
        orientation += math.tau
    return float(orientation)


def _rotation_components(entry: Mapping[str, Any]) -> tuple[float, float, float, float]:
    if _rotation_has_quaternion(entry):
        return _normalize_quaternion(
            *(_entry_float(entry, key) for key in _GAMEOBJECT_ROTATION_COMPONENT_KEYS)
        )

    orientation = _stationary_orientation(entry)
    if abs(orientation) > 0.000001:
        return _normalize_quaternion(
            0.0,
            0.0,
            math.sin(orientation * 0.5),
            math.cos(orientation * 0.5),
        )
    return 0.0, 0.0, 0.0, 1.0


def _gameobject_rotation_packed(entry: Mapping[str, Any]) -> int:
    return _pack_gameobject_rotation(*_rotation_components(entry))


def _gameobject_movement_block_uint32(entry: Mapping[str, Any]) -> int:
    """Return the extra movement block value required by the create flags."""
    gameobject_type = _entry_int(entry, "type") & 0xFF
    if gameobject_type == _GAMEOBJECT_TYPE_TRANSPORT:
        return _entry_int(entry, "transport_path_progress", int(time.time() * 1000.0)) & 0xFFFFFFFF
    return _GAMEOBJECT_MOVEMENT_BLOCK_UINT32


def _gameobject_dynamic_flags(entry: Mapping[str, Any]) -> int:
    """Pack GO dynamic flags; transport path progress lives in the high half."""
    gameobject_type = _entry_int(entry, "type") & 0xFF
    if gameobject_type not in (_GAMEOBJECT_TYPE_TRANSPORT, _GAMEOBJECT_TYPE_MO_TRANSPORT):
        return 0

    period = _entry_int(entry, "transport_period", _entry_int(entry, "data0"))
    if period <= 0:
        return 0xFFFF0000

    timer = _entry_int(entry, "transport_path_progress") % int(period)
    path_progress = int((float(timer) / float(period)) * 65535.0) & 0xFFFF
    return path_progress << 16


def _effective_gameobject_state(entry: Mapping[str, Any]) -> int:
    """Return the client-visible GO state after type-specific initialization."""
    gameobject_type = _entry_int(entry, "type") & 0xFF
    if gameobject_type == _GAMEOBJECT_TYPE_TRANSPORT:
        start_open = _entry_int(entry, "data1") != 0
        return _GO_STATE_ACTIVE if start_open else _GO_STATE_READY
    return _entry_int(entry, "state") & 0xFF


def _pack_gameobject_percent_health(entry: Mapping[str, Any]) -> int:
    state = _effective_gameobject_state(entry)
    gameobject_type = _entry_int(entry, "type") & 0xFF
    return state | (gameobject_type << 8) | (_GO_HEALTH_FULL << 24)


def _pack_gameobject_state_spell_visual_id(entry: Mapping[str, Any]) -> int:
    artkit = _entry_int(entry, "artkit") & 0xFF
    animprogress = _entry_int(entry, "animprogress") & 0xFF
    return (artkit << 8) | (animprogress << 24)


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
    if _entry_int(entry, "type") == _GAMEOBJECT_TYPE_MO_TRANSPORT:
        return int(
            entry.get("world_guid")
            or MoTransportGuid.from_spawn_guid(_entry_int(entry, "guid"))
        )
    return int(
        entry.get("world_guid")
        or GameObjectGuid.from_spawn_guid(_entry_int(entry, "guid"), int(realm_id) or 1)
    )


def _build_gameobject_field_values(entry: Mapping[str, Any], *, world_guid: int) -> dict[int, int]:
    """Build update-field values for a single GameObject create packet."""
    gameobject_type = _entry_int(entry, "type") & 0xFF
    gameobject_flags = _entry_int(entry, "flags")
    if gameobject_type in (_GAMEOBJECT_TYPE_TRANSPORT, _GAMEOBJECT_TYPE_MO_TRANSPORT):
        gameobject_flags |= _GO_FLAG_TRANSPORT
    field_values: dict[int, int] = {
        _OBJECT_FIELD_GUID_LOW: int(world_guid) & 0xFFFFFFFF,
        _OBJECT_FIELD_GUID_HIGH: (int(world_guid) >> 32) & 0xFFFFFFFF,
        _OBJECT_FIELD_TYPE: 33,
        _OBJECT_FIELD_ENTRY: _entry_int(entry, "entry"),
        _OBJECT_FIELD_DYNAMIC_FLAGS: _gameobject_dynamic_flags(entry),
        _OBJECT_FIELD_SCALE: _u32_from_float(_entry_float(entry, "size", 1.0)),
        _GAMEOBJECT_FIELD_DISPLAY_ID: _entry_int(entry, "display_id"),
        _GAMEOBJECT_FIELD_FLAGS: gameobject_flags,
        _GAMEOBJECT_FIELD_PERCENT_HEALTH: _pack_gameobject_percent_health(entry),
        _GAMEOBJECT_FIELD_STATE_SPELL_VISUAL_ID: _pack_gameobject_state_spell_visual_id(entry),
    }
    if gameobject_type in (_GAMEOBJECT_TYPE_TRANSPORT, _GAMEOBJECT_TYPE_MO_TRANSPORT):
        field_values[_GAMEOBJECT_FIELD_LEVEL] = _entry_int(
            entry,
            "transport_period",
            _entry_int(entry, "data0"),
        )
    faction = _entry_int(entry, "faction")
    if faction != 0:
        field_values[_GAMEOBJECT_FIELD_FACTION] = faction
    for offset, value in enumerate(_rotation_components(entry)):
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
    stationary_orientation = _stationary_orientation(entry)
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
            "movement_block_uint32": _gameobject_movement_block_uint32(entry),
            "gameobject_rotation_packed": _gameobject_rotation_packed(entry),
            "mask_blocks": len(mask_bytes) // 4,
            "mask": mask_bytes,
            "fields": field_bytes,
            "dynamic_mask_blocks": _GAMEOBJECT_DYNAMIC_MASK_BLOCKS,
        },
    )
