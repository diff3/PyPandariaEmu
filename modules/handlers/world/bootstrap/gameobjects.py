#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import struct
import time
from typing import Any, Mapping

from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.game.guid import GameObjectGuid, GuidHelper, MoTransportGuid
from server.modules.handlers.world.bootstrap.playerobjects import make_update_object_response
from server.modules.handlers.world.protocol.update_object import gameobject as gameobject_defs
from server.modules.handlers.world.protocol.update_object.serializers import (
    build_fixed_u32_field_block,
    u32_from_float,
)
from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger

for _definition_name in gameobject_defs.__all__:
    globals()[f"_{_definition_name}"] = getattr(gameobject_defs, _definition_name)

_OBJECT_FIELD_SCALE = gameobject_defs.OBJECT_FIELD_SCALE_X


def _entry_int(entry: Mapping[str, Any], key: str, default: int = 0) -> int:
    """Return an integer field from a GameObject entry."""
    return int(entry.get(key, default) or default)


def _entry_float(entry: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    """Return a float field from a GameObject entry."""
    return float(entry.get(key, default) or default)


def _u32_from_float(value: float) -> int:
    """Pack a float into a little-endian uint32 value."""
    return u32_from_float(value)


def _normalize_orientation(orientation: float) -> float:
    orientation = math.fmod(float(orientation), math.tau)
    if orientation < 0.0:
        orientation += math.tau
    return float(orientation)


def _rotation_has_quaternion(entry: Mapping[str, Any]) -> bool:
    return any(
        abs(_entry_float(entry, key)) > _QUATERNION_EPSILON
        for key in ("rotation0", "rotation1", "rotation2")
    ) or abs(abs(_entry_float(entry, "rotation3")) - 1.0) > _QUATERNION_EPSILON


def _rotation_has_yaw_only(entry: Mapping[str, Any]) -> bool:
    return (
        abs(_entry_float(entry, "rotation0")) <= _QUATERNION_EPSILON
        and abs(_entry_float(entry, "rotation1")) <= _QUATERNION_EPSILON
        and _rotation_has_quaternion(entry)
    )


def _raw_rotation_components(entry: Mapping[str, Any]) -> tuple[float, float, float, float]:
    return tuple(
        _entry_float(entry, key)
        for key in _GAMEOBJECT_ROTATION_COMPONENT_KEYS
    )


def _quaternion_is_unit(x: float, y: float, z: float, w: float) -> bool:
    length_squared = (x * x) + (y * y) + (z * z) + (w * w)
    return abs(length_squared - 1.0) <= _QUATERNION_UNIT_EPSILON


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
    """Return DB spawn yaw in radians, normalized to the client-friendly range."""
    return _normalize_orientation(_entry_float(entry, "orientation"))


def _rotation_components(entry: Mapping[str, Any]) -> tuple[float, float, float, float]:
    raw_rotation = _raw_rotation_components(entry)
    has_real_quaternion = (
        _rotation_has_quaternion(entry)
        and not _rotation_has_yaw_only(entry)
        and _quaternion_is_unit(*raw_rotation)
    )
    if has_real_quaternion:
        return _normalize_quaternion(*raw_rotation)

    orientation = _stationary_orientation(entry)
    # TODO: Add display/model-level validation before supporting authored
    # model offsets. Global yaw offsets are intentionally kept out of this path.
    if abs(orientation) > _QUATERNION_EPSILON:
        return _normalize_quaternion(
            0.0,
            0.0,
            math.sin(orientation * 0.5),
            math.cos(orientation * 0.5),
        )
    return 0.0, 0.0, 0.0, 1.0


def _gameobject_rotation_packed(entry: Mapping[str, Any]) -> int:
    return _pack_gameobject_rotation(*_rotation_components(entry))


def _gameobject_orientation_debug_enabled() -> bool:
    config = ConfigLoader.get_config() or {}
    world_config = config.get("World", {}) or {}
    return bool(world_config.get("DebugGameObjectOrientation", False))


def _quaternion_yaw(x: float, y: float, z: float, w: float) -> float:
    return _normalize_orientation(
        math.atan2(
            2.0 * ((w * z) + (x * y)),
            1.0 - (2.0 * ((y * y) + (z * z))),
        )
    )


def _log_gameobject_orientation_debug(
    entry: Mapping[str, Any],
    *,
    stationary_orientation: float,
    packet_rotation: tuple[float, float, float, float],
    packed_rotation: int,
) -> None:
    if not _gameobject_orientation_debug_enabled():
        return

    raw_rotation = _raw_rotation_components(entry)
    Logger.info(
        "GO_DEBUG entry=%s display=%s type=%s pos=(%.3f %.3f %.3f) "
        "yaw=%.6f db_quat=(%.6f %.6f %.6f %.6f) "
        "packet_quat=(%.6f %.6f %.6f %.6f) converted_yaw=%.6f "
        "packet_yaw=%.6f packed=%s",
        _entry_int(entry, "entry"),
        _entry_int(entry, "display_id"),
        _entry_int(entry, "type"),
        _entry_float(entry, "x"),
        _entry_float(entry, "y"),
        _entry_float(entry, "z"),
        _normalize_orientation(_entry_float(entry, "orientation")),
        raw_rotation[0],
        raw_rotation[1],
        raw_rotation[2],
        raw_rotation[3],
        packet_rotation[0],
        packet_rotation[1],
        packet_rotation[2],
        packet_rotation[3],
        _quaternion_yaw(*_normalize_quaternion(*raw_rotation)),
        stationary_orientation,
        hex(int(packed_rotation) & 0xFFFFFFFFFFFFFFFF),
        scope="worldserver",
    )


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
    return build_fixed_u32_field_block(fields, mask_blocks=mask_blocks)


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
    packet_rotation = _rotation_components(entry)
    packed_rotation = _pack_gameobject_rotation(*packet_rotation)
    _log_gameobject_orientation_debug(
        entry,
        stationary_orientation=stationary_orientation,
        packet_rotation=packet_rotation,
        packed_rotation=packed_rotation,
    )
    _log_mo_transport_create_debug(
        entry,
        world_guid=world_guid,
        packet_map_id=int(map_id),
        packet_x=stationary_x,
        packet_y=stationary_y,
        packet_z=stationary_z,
        packet_orientation=stationary_orientation,
    )

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
            "gameobject_rotation_packed": packed_rotation,
            "mask_blocks": len(mask_bytes) // 4,
            "mask": mask_bytes,
            "fields": field_bytes,
            "dynamic_mask_blocks": _GAMEOBJECT_DYNAMIC_MASK_BLOCKS,
        },
    )


def _build_gameobject_values_update_payload(*, map_id: int, entry: Mapping[str, Any], realm_id: int) -> bytes:
    """Encode a minimal GameObject VALUES update for an already-created object."""
    world_guid = _resolve_world_guid(entry, realm_id)
    all_fields = _build_gameobject_field_values(entry, world_guid=world_guid)
    changed_fields: dict[int, int] = {}

    for field_index in (
        _OBJECT_FIELD_DYNAMIC_FLAGS,
        _GAMEOBJECT_FIELD_FLAGS,
        _GAMEOBJECT_FIELD_LEVEL,
        _GAMEOBJECT_FIELD_PERCENT_HEALTH,
        _GAMEOBJECT_FIELD_STATE_SPELL_VISUAL_ID,
    ):
        if field_index in all_fields:
            changed_fields[field_index] = all_fields[field_index]

    for field_index in range(
        _GAMEOBJECT_FIELD_ROTATION_START,
        _GAMEOBJECT_FIELD_ROTATION_START + len(_GAMEOBJECT_ROTATION_COMPONENT_KEYS),
    ):
        if field_index in all_fields:
            changed_fields[field_index] = all_fields[field_index]

    mask_blocks = max(1, (max(changed_fields, default=0) // 32) + 1)
    mask_bytes, field_bytes = _build_fixed_u32_field_block(changed_fields, mask_blocks=mask_blocks)

    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, _GAMEOBJECT_UPDATE_COUNT)
    payload += struct.pack("<B", _GAMEOBJECT_VALUES_UPDATE_TYPE)
    payload += GuidHelper.pack(int(world_guid) & 0xFFFFFFFFFFFFFFFF)
    payload += struct.pack("<B", len(mask_bytes) // 4)
    payload += mask_bytes
    payload += field_bytes
    payload += struct.pack("<B", _GAMEOBJECT_DYNAMIC_MASK_BLOCKS)
    return bytes(payload)


def _log_mo_transport_create_debug(
    entry: Mapping[str, Any],
    *,
    world_guid: int,
    packet_map_id: int,
    packet_x: float,
    packet_y: float,
    packet_z: float,
    packet_orientation: float,
) -> None:
    if _entry_int(entry, "type") != _GAMEOBJECT_TYPE_MO_TRANSPORT:
        return

    runtime_state = None
    runtime_transform = None
    try:
        from server.modules.handlers.world.transport_runtime import runtime_transport_state_for_guid
        from server.modules.handlers.world.movements.manager import get_movement_manager

        runtime_state = runtime_transport_state_for_guid(int(world_guid))
        runtime_transform = get_movement_manager().get_transform(int(world_guid))
    except Exception as exc:
        Logger.warning(
            "[MO_TRANSPORT_CREATE] runtime lookup failed world_guid=0x%016X entry=%s err=%s",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            _entry_int(entry, "entry"),
            exc,
        )

    source_path = str(
        entry.get("_transport_create_source_path")
        or entry.get("transport_create_source_path")
        or "template"
    )
    runtime_found = runtime_state is not None
    runtime_map = int(
        getattr(runtime_transform, "map_id", getattr(runtime_state, "map_id", packet_map_id))
        if runtime_found
        else packet_map_id
    )
    runtime_x = float(
        getattr(runtime_transform, "x", getattr(runtime_state, "x", packet_x))
        if runtime_found
        else packet_x
    )
    runtime_y = float(
        getattr(runtime_transform, "y", getattr(runtime_state, "y", packet_y))
        if runtime_found
        else packet_y
    )
    runtime_z = float(
        getattr(runtime_transform, "z", getattr(runtime_state, "z", packet_z))
        if runtime_found
        else packet_z
    )
    phase_ms = int(
        getattr(runtime_transform, "phase_ms", getattr(runtime_state, "path_progress_ms", 0))
        if runtime_found
        else 0
    ) & 0xFFFFFFFF
    packet_progress = _entry_int(entry, "transport_path_progress") & 0xFFFFFFFF

    Logger.info(
        "[MO_TRANSPORT_CREATE] world_guid=0x%016X entry=%s transport_type=%s "
        "source_path=%s runtime_state_found=%s runtime_map=%s "
        "runtime_pos=(%.3f %.3f %.3f) packet_map=%s "
        "packet_pos=(%.3f %.3f %.3f %.3f) phase_ms=%s "
        "transport_path_progress=%s",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        _entry_int(entry, "entry"),
        _entry_int(entry, "type"),
        source_path,
        "yes" if runtime_found else "no",
        int(runtime_map),
        runtime_x,
        runtime_y,
        runtime_z,
        int(packet_map_id),
        float(packet_x),
        float(packet_y),
        float(packet_z),
        float(packet_orientation),
        int(phase_ms),
        int(packet_progress),
    )


def build_database_gameobject_responses(
    session,
    *,
    loaded_guids: set[int] | None = None,
    discovery_context: str = "bootstrap",
) -> list[tuple[str, bytes]]:
    from server.modules.database.DatabaseConnection import DatabaseConnection
    from server.modules.handlers.world.transport_runtime import (
        cached_transport_runtime_entry,
        prepare_runtime_transport_entry,
        register_loaded_transport_entry,
        synthetic_transport_entries_near,
    )

    if not bool(getattr(session, "gameobjects_visible", True)):
        return []

    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    if map_id < 0:
        return []

    entries = DatabaseConnection.get_gameobjects_near(
        map_id,
        x,
        y,
        radius=_GAMEOBJECT_VISIBILITY_RADIUS,
        limit=_GAMEOBJECT_PACKET_LIMIT,
    )
    if not entries:
        Logger.info("[WorldLoginReplay] no DB gameobjects near map=%s x=%.1f y=%.1f", map_id, x, y)
        entries = []

    seen = loaded_guids if isinstance(loaded_guids, set) else None
    session_loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    if not isinstance(session_loaded_gameobjects, set):
        session_loaded_gameobjects = set()
        session.loaded_gameobjects = session_loaded_gameobjects
    filtered_entries: list[dict] = []
    for entry in entries:
        entry = prepare_runtime_transport_entry(entry)
        if int(entry.get("type", 0) or 0) == 15:
            entry["_transport_create_source_path"] = "database"
        if int(entry.get("type", 0) or 0) == 15 or bool(entry.get("use_transport_guid")):
            world_guid = int(
                entry.get("world_guid")
                or MoTransportGuid.from_spawn_guid(int(entry.get("guid", 0) or 0))
            )
        else:
            world_guid = int(
                entry.get("world_guid")
                or GameObjectGuid.from_spawn_guid(
                    int(entry.get("guid", 0) or 0),
                    int(realm_id) or 1,
                )
            )
        if seen is not None and world_guid in seen:
            continue
        entry["world_guid"] = world_guid
        if not register_loaded_transport_entry(
            session,
            entry,
            world_guid=world_guid,
            map_id=map_id,
        ):
            continue
        original_world_guid = int(world_guid)
        entry = cached_transport_runtime_entry(session, entry)
        world_guid = int(entry.get("world_guid", original_world_guid) or original_world_guid)
        if world_guid != original_world_guid:
            loaded_transports = getattr(session, "loaded_transport_entries", None)
            if isinstance(loaded_transports, dict):
                loaded_transports.pop(original_world_guid, None)
                loaded_transports[world_guid] = dict(entry)
        filtered_entries.append(entry)
        if seen is not None:
            seen.add(world_guid)
        else:
            session_loaded_gameobjects.add(world_guid)

    for entry in synthetic_transport_entries_near(
        session,
        loaded_guids=seen,
        context=discovery_context,
    ):
        world_guid = int(entry.get("world_guid", 0) or 0)
        if world_guid <= 0:
            continue
        if int(entry.get("type", 0) or 0) == 15:
            entry.setdefault("_transport_create_source_path", "startup")
        filtered_entries.append(entry)
        register_loaded_transport_entry(
            session,
            entry,
            world_guid=world_guid,
            map_id=int(entry.get("map", map_id) or map_id),
        )
        if seen is not None:
            seen.add(world_guid)
        else:
            session_loaded_gameobjects.add(world_guid)

    if not filtered_entries:
        Logger.info("[WorldLoginReplay] DB gameobjects already loaded near map=%s x=%.1f y=%.1f", map_id, x, y)
        return []

    Logger.info(
        "[WorldLoginReplay] loaded %s DB gameobjects near map=%s x=%.1f y=%.1f",
        len(filtered_entries),
        map_id,
        x,
        y,
    )
    responses: list[tuple[str, bytes]] = []
    for entry in filtered_entries:
        entry = cached_transport_runtime_entry(session, entry)
        payload = _build_gameobject_update_payload(
            map_id=map_id,
            entry=entry,
            realm_id=realm_id,
        )
        if bool(entry.get("synthetic_transport")):
            Logger.info(
                "[WorldTransport] synthetic create guid=%s entry=%s type=%s "
                "payload=%s pos=(%.2f %.2f %.2f) o=%.3f",
                int(entry.get("guid", 0) or 0),
                int(entry.get("entry", 0) or 0),
                int(entry.get("type", 0) or 0),
                len(payload),
                float(entry.get("x", 0.0) or 0.0),
                float(entry.get("y", 0.0) or 0.0),
                float(entry.get("z", 0.0) or 0.0),
                float(entry.get("orientation", 0.0) or 0.0),
            )
        if int(entry.get("type", 0) or 0) == 11:
            Logger.info(
                "[TransportElevator] stream create guid=%s entry=%s payload=%s "
                "pos=(%.2f %.2f %.2f)",
                int(entry.get("guid", 0) or 0),
                int(entry.get("entry", 0) or 0),
                len(payload),
                float(entry.get("x", 0.0) or 0.0),
                float(entry.get("y", 0.0) or 0.0),
                float(entry.get("z", 0.0) or 0.0),
            )
        if int(entry.get("type", 0) or 0) == 15:
            Logger.info(
                "[WorldTransport] stream create guid=%s entry=%s payload=%s "
                "pos=(%.2f %.2f %.2f) o=%.3f",
                int(entry.get("guid", 0) or 0),
                int(entry.get("entry", 0) or 0),
                len(payload),
                float(entry.get("x", 0.0) or 0.0),
                float(entry.get("y", 0.0) or 0.0),
                float(entry.get("z", 0.0) or 0.0),
                float(entry.get("orientation", 0.0) or 0.0),
            )
        responses.append(make_update_object_response(payload))
    return responses
