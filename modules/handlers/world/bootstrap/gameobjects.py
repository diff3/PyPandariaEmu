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
from server.modules.handlers.world.protocol.orientation import normalize_orientation
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_store import (
    gameobject_identity_matches_mapping,
    gameobject_matches_mapping,
    resolve_gameobject_runtime,
)
from server.modules.handlers.world.runtime.runtime_object import RuntimeObject
from server.modules.handlers.world.runtime.world_object import WorldObject
from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.handlers.world.feature_config import transport_movement_debug_enabled
from server.modules.handlers.world.transport_debug import (
    log_transport_packet_snapshot,
)

for _definition_name in gameobject_defs.__all__:
    globals()[f"_{_definition_name}"] = getattr(gameobject_defs, _definition_name)

_OBJECT_FIELD_SCALE = gameobject_defs.OBJECT_FIELD_SCALE_X


def _entry_int(entry: Mapping[str, Any], key: str, default: int = 0) -> int:
    """Return an integer field from a GameObject entry."""
    return int(entry.get(key, default) or default)


def _entry_float(entry: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    """Return a float field from a GameObject entry."""
    return float(entry.get(key, default) or default)


def _entry_map_id(entry: Mapping[str, Any], default: int = 0) -> int:
    """Return a map id; map 0 is valid and must not fall back."""
    value = entry.get("map", entry.get("map_id", default))
    if value is None:
        value = default
    return int(value)


def _transport_debug_log(message: str, *args) -> None:
    if not transport_movement_debug_enabled():
        return
    Logger.info(message, *args)


def _transport_packet_context_matches_map(
    entry: Mapping[str, Any],
    map_id: int,
) -> bool:
    """Return whether a moving transport belongs to the packet map snapshot."""
    is_moving_transport = bool(
        _entry_int(entry, "type") == 15
        or entry.get("use_transport_guid")
        or entry.get("synthetic_transport")
        or entry.get("world_db_transport")
    )
    if not is_moving_transport:
        return True
    return _entry_map_id(entry, int(map_id)) == int(map_id)


def _discard_transport_packet_snapshot(
    session,
    *,
    world_guids: tuple[int, ...],
) -> None:
    """Remove a rejected transport snapshot from session-known containers."""
    loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    loaded_gameobject_entries = getattr(
        session,
        "loaded_gameobject_entries",
        None,
    )
    loaded_transport_entries = getattr(
        session,
        "loaded_transport_entries",
        None,
    )
    for world_guid in world_guids:
        if isinstance(loaded_gameobjects, set):
            loaded_gameobjects.discard(int(world_guid))
        if isinstance(loaded_gameobject_entries, dict):
            loaded_gameobject_entries.pop(int(world_guid), None)
        if isinstance(loaded_transport_entries, dict):
            loaded_transport_entries.pop(int(world_guid), None)


def _manager_transport_for_guid(
    world_guid: int,
    entry: Mapping[str, Any] | None = None,
) -> WorldObject | None:
    """Resolve the existing moving WorldObject or elevator fallback."""
    try:
        from server.modules.handlers.world.transport_runtime import (
            get_world_transport_manager,
        )

        if isinstance(entry, Mapping):
            return get_world_transport_manager().resolve_world_object(
                int(world_guid),
                dict(entry),
            )
        return get_world_transport_manager().world_object_for_guid(int(world_guid))
    except Exception:
        return None


def _u32_from_float(value: float) -> int:
    """Pack a float into a little-endian uint32 value."""
    return u32_from_float(value)


_normalize_orientation = normalize_orientation


def _rotation_has_quaternion(
    entry: Mapping[str, Any],
    gameobject: RuntimeObject | None = None,
) -> bool:
    if gameobject is not None:
        return any(
            abs(float(value)) > _QUATERNION_EPSILON
            for value in gameobject.rotation[:3]
        ) or abs(abs(float(gameobject.rotation[3])) - 1.0) > _QUATERNION_EPSILON
    return any(
        abs(_entry_float(entry, key)) > _QUATERNION_EPSILON
        for key in ("rotation0", "rotation1", "rotation2")
    ) or abs(abs(_entry_float(entry, "rotation3")) - 1.0) > _QUATERNION_EPSILON


def _raw_rotation_components(
    entry: Mapping[str, Any],
    gameobject: RuntimeObject | None = None,
) -> tuple[float, float, float, float]:
    if gameobject is not None:
        return tuple(float(value) for value in gameobject.rotation)
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


def _stationary_orientation(
    entry: Mapping[str, Any],
    gameobject: RuntimeObject | None = None,
) -> float:
    """Return DB spawn yaw in radians, normalized to the client-friendly range."""
    if gameobject is not None:
        return _normalize_orientation(gameobject.orientation)
    return _normalize_orientation(_entry_float(entry, "orientation"))


def _rotation_components(
    entry: Mapping[str, Any],
    gameobject: RuntimeObject | None = None,
) -> tuple[float, float, float, float]:
    runtime_gameobject_type = (
        None
        if gameobject is None
        else getattr(gameobject, "gameobject_type", None)
    )
    gameobject_type = (
        int(runtime_gameobject_type)
        if runtime_gameobject_type is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    if gameobject_type in (
        _GAMEOBJECT_TYPE_TRANSPORT,
        _GAMEOBJECT_TYPE_MO_TRANSPORT,
    ) and bool(entry.get("_runtime_transport_orientation_authoritative")):
        orientation = _stationary_orientation(entry, gameobject)
        return _normalize_quaternion(
            0.0,
            0.0,
            math.sin(orientation * 0.5),
            math.cos(orientation * 0.5),
        )

    raw_rotation = _raw_rotation_components(entry, gameobject)
    # SkyFire preserves an authored unit parent quaternion, including the
    # identity quaternion (0, 0, 0, 1).  Parent rotation is a separate update
    # field from the stationary world yaw and packed world rotation; replacing
    # identity with a yaw quaternion changes the client model transform.
    if _quaternion_is_unit(*raw_rotation):
        return _normalize_quaternion(*raw_rotation)

    orientation = _stationary_orientation(entry, gameobject)
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


def _gameobject_rotation_packed(
    entry: Mapping[str, Any],
    gameobject: RuntimeObject | None = None,
) -> int:
    orientation = _stationary_orientation(entry, gameobject)
    atan_pow = math.atan(math.pow(2.0, -20.0))
    rotation_sin = math.sin(orientation * 0.5)
    rotation_cos = math.cos(orientation * 0.5)
    packed = int(
        rotation_sin / atan_pow * (1.0 if rotation_cos >= 0.0 else -1.0)
    )
    return int(packed) & 0x1FFFFF


def _gameobject_update_flags(
    entry: Mapping[str, Any],
    gameobject: GameObject | None = None,
) -> int:
    """Return SkyFire-style update flags for the create movement blocks."""
    flags = _UPDATEFLAG_STATIONARY_POSITION | _UPDATEFLAG_ROTATION
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    if gameobject_type in (_GAMEOBJECT_TYPE_TRANSPORT, _GAMEOBJECT_TYPE_MO_TRANSPORT):
        flags |= _UPDATEFLAG_TRANSPORT
    return int(flags)


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
    gameobject: GameObject,
    stationary_orientation: float,
    packet_rotation: tuple[float, float, float, float],
    packed_rotation: int,
) -> None:
    if not _gameobject_orientation_debug_enabled():
        return

    raw_rotation = _raw_rotation_components(entry, gameobject)
    Logger.info(
        "GO_DEBUG entry=%s display=%s type=%s pos=(%.3f %.3f %.3f) "
        "yaw=%.6f db_quat=(%.6f %.6f %.6f %.6f) "
        "packet_quat=(%.6f %.6f %.6f %.6f) converted_yaw=%.6f "
        "packet_yaw=%.6f packed=%s",
        int(gameobject.entry),
        int(gameobject.display_id),
        int(gameobject.gameobject_type),
        float(gameobject.x),
        float(gameobject.y),
        float(gameobject.z),
        _normalize_orientation(gameobject.orientation),
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


def _gameobject_movement_block_uint32(
    entry: Mapping[str, Any],
    gameobject: GameObject | None = None,
) -> int:
    """Return the extra movement block value required by the create flags."""
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    if gameobject_type in (_GAMEOBJECT_TYPE_TRANSPORT, _GAMEOBJECT_TYPE_MO_TRANSPORT):
        return _effective_transport_path_progress(entry)
    return _GAMEOBJECT_MOVEMENT_BLOCK_UINT32


def _client_transport_period(
    entry: Mapping[str, Any],
    gameobject: GameObject | None = None,
) -> int:
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    if gameobject_type == _GAMEOBJECT_TYPE_TRANSPORT:
        return _entry_int(entry, "data0")
    return _entry_int(entry, "transport_period", _entry_int(entry, "data0"))


def _effective_transport_path_progress(entry: Mapping[str, Any]) -> int:
    path_progress = entry.get("transport_path_progress")
    if path_progress is None:
        path_progress = int(time.time() * 1000.0)
    return int(path_progress) & 0xFFFFFFFF


def _gameobject_dynamic_flags(
    entry: Mapping[str, Any],
    gameobject: GameObject | None = None,
) -> int:
    """Pack GO dynamic flags; transport path progress lives in the high half."""
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    if gameobject_type != _GAMEOBJECT_TYPE_MO_TRANSPORT:
        return 0

    period = _client_transport_period(entry, gameobject)
    if period <= 0:
        return 0xFFFF0000

    timer = _effective_transport_path_progress(entry) % int(period)
    path_progress = int((float(timer) / float(period)) * 65535.0) & 0xFFFF
    return path_progress << 16


def _effective_gameobject_state(
    entry: Mapping[str, Any],
    gameobject: GameObject | None = None,
) -> int:
    """Return the client-visible GO state after type-specific initialization."""
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    if gameobject_type == _GAMEOBJECT_TYPE_TRANSPORT:
        start_open = _entry_int(entry, "data1") != 0
        return _GO_STATE_ACTIVE if start_open else _GO_STATE_READY
    if gameobject_type == _GAMEOBJECT_TYPE_MO_TRANSPORT:
        # MoP 5.4.8 transport creates use GO_STATE_READY even when the
        # synthetic runtime entry has not supplied a client-visible state.
        return _GO_STATE_READY
    if gameobject is not None:
        return int(gameobject.state) & 0xFF
    return _entry_int(entry, "state") & 0xFF


def _pack_gameobject_percent_health(
    entry: Mapping[str, Any],
    gameobject: GameObject | None = None,
) -> int:
    state = _effective_gameobject_state(entry, gameobject)
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    return state | (gameobject_type << 8)


def _pack_gameobject_state_spell_visual_id(
    entry: Mapping[str, Any],
    gameobject: GameObject | None = None,
) -> int:
    artkit = (
        int(gameobject.art_kit)
        if gameobject is not None
        else _entry_int(entry, "artkit")
    ) & 0xFF
    animprogress = (
        int(gameobject.animation_progress)
        if gameobject is not None
        else _entry_int(entry, "animprogress")
    ) & 0xFF
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    if gameobject_type == _GAMEOBJECT_TYPE_MO_TRANSPORT:
        # Both available 5.4.8 transport captures carry full animation
        # progress, including for runtime-created cross-map transports.
        animprogress = _GO_HEALTH_FULL
    return (artkit << 8) | (animprogress << 24)


def _build_fixed_u32_field_block(fields: dict[int, int], *, mask_blocks: int = 1) -> tuple[bytes, bytes]:
    """Build a fixed-size update mask and packed uint32 field payload."""
    return build_fixed_u32_field_block(fields, mask_blocks=mask_blocks)


def _resolve_world_guid(entry: Mapping[str, Any], realm_id: int) -> int:
    """Resolve the full 64-bit world guid for a GameObject spawn."""
    if (
        _entry_int(entry, "type") == _GAMEOBJECT_TYPE_MO_TRANSPORT
        or bool(entry.get("use_transport_guid"))
    ):
        return int(
            entry.get("world_guid")
            or MoTransportGuid.from_spawn_guid(_entry_int(entry, "guid"))
        )
    return int(
        entry.get("world_guid")
        or GameObjectGuid.from_spawn_guid(_entry_int(entry, "guid"), int(realm_id) or 1)
    )


def _transport_runtime_packet_entry(
    entry: Mapping[str, Any],
    gameobject: GameObject | None = None,
    transport: WorldObject | None = None,
) -> Mapping[str, Any]:
    """Overlay transport packet fields from RuntimeTransportState when available."""
    if bool(entry.get("_bootstrap_runtime_transform_pinned")):
        return entry
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    )
    if gameobject_type not in (_GAMEOBJECT_TYPE_TRANSPORT, _GAMEOBJECT_TYPE_MO_TRANSPORT):
        return entry

    world_guid = int(
        transport.runtime_guid
        if transport is not None
        else (
            gameobject.runtime_guid
            if gameobject is not None
            else _resolve_world_guid(entry, _entry_int(entry, "realm_id", 1))
        )
    )
    if world_guid <= 0:
        return entry

    state = getattr(transport, "runtime_state", None)
    if state is None:
        try:
            from server.modules.handlers.world.transport_runtime import runtime_transport_state_for_guid

            state = runtime_transport_state_for_guid(world_guid)
        except Exception as exc:
            Logger.warning(
                "[TRANSPORT_CREATE] runtime state lookup failed world_guid=0x%016X type=%s err=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(gameobject_type),
                exc,
            )
            return entry

    if state is None:
        return entry

    packet_entry = dict(entry)
    # MO_TRANSPORT routes publish a live server yaw. Local type-11 transports
    # instead use their authored parent quaternion to transform the client DBC
    # animation; replacing it with stationary yaw rotates that path in-world.
    packet_entry["_runtime_transport_orientation_authoritative"] = not (
        gameobject_type == _GAMEOBJECT_TYPE_TRANSPORT
        and bool(packet_entry.get("client_driven_transport_animation"))
    )
    packet_entry["world_guid"] = int(state.guid)
    if (
        gameobject_type == _GAMEOBJECT_TYPE_TRANSPORT
        and bool(packet_entry.get("client_driven_transport_animation"))
    ):
        base_map = _entry_int(packet_entry, "client_animation_base_map", int(state.map_id))
        packet_entry["map"] = int(base_map)
        packet_entry["map_id"] = int(base_map)
        packet_entry["x"] = _entry_float(packet_entry, "client_animation_base_x")
        packet_entry["y"] = _entry_float(packet_entry, "client_animation_base_y")
        packet_entry["z"] = _entry_float(packet_entry, "client_animation_base_z")
        packet_entry["orientation"] = _entry_float(
            packet_entry,
            "client_animation_base_orientation",
            float(state.orientation),
        )
    else:
        packet_entry["map"] = int(state.map_id)
        packet_entry["map_id"] = int(state.map_id)
        packet_entry["x"] = float(state.x)
        packet_entry["y"] = float(state.y)
        packet_entry["z"] = float(state.z)
        packet_entry["orientation"] = float(state.orientation)
    packet_entry["transport_path_progress"] = int(state.path_progress_ms) & 0xFFFFFFFF
    if int(getattr(state, "route_period_ms", 0) or 0) > 0:
        packet_entry["transport_period"] = int(state.route_period_ms)
    return packet_entry


def _resolve_packet_gameobject(
    entry: Mapping[str, Any],
    *,
    map_id: int,
    realm_id: int,
    gameobject: GameObject | None,
) -> GameObject:
    """Resolve matching passive runtime state without changing cache authority."""
    if gameobject is not None:
        world_guid = int(gameobject.runtime_guid)
        identity_mapping = {
            "guid": entry.get("guid", 0),
            "entry": entry.get("entry", 0),
            "map_id": _entry_map_id(entry, int(map_id)),
            "instance_id": entry.get("instance_id", 0),
        }
        gameobject_type = int(gameobject.gameobject_type) & 0xFF
        uses_transport_runtime = gameobject_type in (
            _GAMEOBJECT_TYPE_TRANSPORT,
            _GAMEOBJECT_TYPE_MO_TRANSPORT,
        )
        matcher = (
            gameobject_matches_mapping
            if uses_transport_runtime
            else gameobject_identity_matches_mapping
        )
        matching_mapping: Mapping[str, Any] = identity_mapping
        if uses_transport_runtime:
            transport_mapping = dict(entry)
            transport_mapping["map_id"] = _entry_map_id(entry, int(map_id))
            matching_mapping = transport_mapping
        if matcher(
            gameobject,
            matching_mapping,
            runtime_guid=world_guid,
        ):
            return gameobject
    world_guid = _resolve_world_guid(entry, realm_id)
    packet_mapping = dict(entry)
    packet_mapping["map_id"] = _entry_map_id(entry, int(map_id))
    return resolve_gameobject_runtime(
        packet_mapping,
        runtime_guid=world_guid,
    )


def _build_gameobject_field_values(
    entry: Mapping[str, Any],
    *,
    world_guid: int,
    gameobject: GameObject | None = None,
    transport: WorldObject | None = None,
) -> dict[int, int]:
    """Build update-field values for a single GameObject create packet."""
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    ) & 0xFF
    gameobject_flags = (
        int(gameobject.flags)
        if gameobject is not None
        else _entry_int(entry, "flags")
    )
    if gameobject_type in (_GAMEOBJECT_TYPE_TRANSPORT, _GAMEOBJECT_TYPE_MO_TRANSPORT):
        gameobject_flags |= _GO_FLAG_TRANSPORT
    field_values: dict[int, int] = {
        _OBJECT_FIELD_GUID_LOW: int(world_guid) & 0xFFFFFFFF,
        _OBJECT_FIELD_GUID_HIGH: (int(world_guid) >> 32) & 0xFFFFFFFF,
        _OBJECT_FIELD_TYPE: 33,
        _OBJECT_FIELD_ENTRY: (
            int(transport.entry)
            if transport is not None
            else int(gameobject.entry)
            if gameobject is not None
            else _entry_int(entry, "entry")
        ),
        _OBJECT_FIELD_DYNAMIC_FLAGS: _gameobject_dynamic_flags(entry, gameobject),
        _OBJECT_FIELD_SCALE: _u32_from_float(
            transport.scale
            if transport is not None
            else gameobject.scale
            if gameobject is not None
            else _entry_float(entry, "size", 1.0)
        ),
        _GAMEOBJECT_FIELD_DISPLAY_ID: (
            int(gameobject.display_id)
            if gameobject is not None
            else _entry_int(entry, "display_id")
        ),
        _GAMEOBJECT_FIELD_FLAGS: gameobject_flags,
        _GAMEOBJECT_FIELD_PERCENT_HEALTH: _pack_gameobject_percent_health(
            entry,
            gameobject,
        ),
        _GAMEOBJECT_FIELD_STATE_SPELL_VISUAL_ID: (
            _pack_gameobject_state_spell_visual_id(entry, gameobject)
        ),
    }
    if gameobject_type in (_GAMEOBJECT_TYPE_TRANSPORT, _GAMEOBJECT_TYPE_MO_TRANSPORT):
        field_values[_GAMEOBJECT_FIELD_LEVEL] = _entry_int(
            entry,
            "transport_period",
            _client_transport_period(entry, gameobject),
        )
    faction = (
        int(gameobject.faction)
        if gameobject is not None
        else _entry_int(entry, "faction")
    )
    if faction != 0:
        field_values[_GAMEOBJECT_FIELD_FACTION] = faction
    rotation_object = transport if transport is not None else gameobject
    for offset, value in enumerate(_rotation_components(entry, rotation_object)):
        if value != 0.0:
            field_values[_GAMEOBJECT_FIELD_ROTATION_START + offset] = _u32_from_float(value)
    return field_values


def _packet_transform_object(
    entry: Mapping[str, Any],
    gameobject: GameObject,
    transport: WorldObject | None,
) -> RuntimeObject:
    """Select the existing packet-visible transform without changing rules."""
    if transport is None:
        return gameobject
    if bool(entry.get("_bootstrap_runtime_transform_pinned")):
        return gameobject
    if bool(entry.get("client_driven_transport_animation")):
        return gameobject
    return transport


def _resolve_packet_transport(
    entry: Mapping[str, Any],
    gameobject: GameObject | None,
    transport: WorldObject | None,
) -> WorldObject | None:
    """Resolve the moving WorldObject without creating simulation state."""
    if transport is not None:
        return transport
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    )
    if gameobject_type not in (
        _GAMEOBJECT_TYPE_TRANSPORT,
        _GAMEOBJECT_TYPE_MO_TRANSPORT,
    ):
        return None
    world_guid = (
        int(gameobject.runtime_guid)
        if gameobject is not None
        else _resolve_world_guid(entry, _entry_int(entry, "realm_id", 1))
    )
    try:
        return _manager_transport_for_guid(world_guid, entry)
    except Exception:
        return None


def _build_gameobject_update_payload(
    *,
    map_id: int,
    entry: Mapping[str, Any],
    realm_id: int,
    gameobject: GameObject | None = None,
    transport: WorldObject | None = None,
) -> bytes:
    """Encode a GameObject CREATE_OBJECT payload through the DSL definition."""
    transport = _resolve_packet_transport(entry, gameobject, transport)
    entry = _transport_runtime_packet_entry(entry, gameobject, transport)
    gameobject = _resolve_packet_gameobject(
        entry,
        map_id=map_id,
        realm_id=realm_id,
        gameobject=gameobject,
    )
    transform_object = _packet_transform_object(entry, gameobject, transport)
    world_guid = int(transform_object.runtime_guid)
    packet_map_id = int(transform_object.map_id)
    update_flags = _gameobject_update_flags(entry, gameobject)
    create_flags = gameobject_defs.build_gameobject_create_flags(update_flags)
    field_values = _build_gameobject_field_values(
        entry,
        world_guid=world_guid,
        gameobject=gameobject,
        transport=(
            transport
            if transform_object is transport
            else None
        ),
    )
    mask_bytes, field_bytes = _build_fixed_u32_field_block(
        field_values,
        mask_blocks=_GAMEOBJECT_MASK_BLOCKS,
    )

    stationary_y = float(transform_object.y)
    stationary_z = float(transform_object.z)
    stationary_orientation = _stationary_orientation(entry, transform_object)
    stationary_x = float(transform_object.x)
    packet_rotation = _rotation_components(entry, transform_object)
    packed_rotation = _gameobject_rotation_packed(entry, transform_object)
    _log_gameobject_orientation_debug(
        entry,
        gameobject=gameobject,
        stationary_orientation=stationary_orientation,
        packet_rotation=packet_rotation,
        packed_rotation=packed_rotation,
    )
    _log_mo_transport_create_debug(
        entry,
        gameobject=gameobject,
        world_guid=world_guid,
        packet_map_id=int(packet_map_id),
        packet_x=stationary_x,
        packet_y=stationary_y,
        packet_z=stationary_z,
        packet_orientation=stationary_orientation,
    )
    movement_block_uint32 = _gameobject_movement_block_uint32(entry, gameobject)
    return EncoderHandler.encode_packet(
        "GAMEOBJECT_CREATE",
        {
            "map_id": int(packet_map_id) & 0xFFFF,
            "update_count": _GAMEOBJECT_UPDATE_COUNT,
            "update_type": _GAMEOBJECT_UPDATE_TYPE,
            "guid": {"guid": world_guid},
            "object_type": _GAMEOBJECT_OBJECT_TYPE,
            "create_flag_0": create_flags[0],
            "create_flag_1": create_flags[1],
            "create_flag_2": create_flags[2],
            "create_flag_3": create_flags[3],
            "create_flag_4": create_flags[4],
            "create_flag_5": create_flags[5],
            "stationary_y": stationary_y,
            "stationary_z": stationary_z,
            "stationary_orientation": stationary_orientation,
            "stationary_x": stationary_x,
            "has_transport_block": bool(update_flags & _UPDATEFLAG_TRANSPORT),
            "movement_block_uint32": movement_block_uint32,
            "gameobject_rotation_packed": packed_rotation,
            "mask_blocks": len(mask_bytes) // 4,
            "mask": mask_bytes,
            "fields": field_bytes,
            "dynamic_mask_blocks": _GAMEOBJECT_DYNAMIC_MASK_BLOCKS,
        },
    )


def _build_gameobject_values_update_payload(
    *,
    map_id: int,
    entry: Mapping[str, Any],
    realm_id: int,
    gameobject: GameObject | None = None,
    transport: WorldObject | None = None,
) -> bytes:
    """Encode a minimal GameObject VALUES update for an already-created object."""
    transport = _resolve_packet_transport(entry, gameobject, transport)
    entry = _transport_runtime_packet_entry(entry, gameobject, transport)
    gameobject = _resolve_packet_gameobject(
        entry,
        map_id=map_id,
        realm_id=realm_id,
        gameobject=gameobject,
    )
    transform_object = _packet_transform_object(entry, gameobject, transport)
    world_guid = int(transform_object.runtime_guid)
    packet_map_id = int(transform_object.map_id)
    all_fields = _build_gameobject_field_values(
        entry,
        world_guid=world_guid,
        gameobject=gameobject,
        transport=(
            transport
            if transform_object is transport
            else None
        ),
    )
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
    payload += struct.pack("<HI", int(packet_map_id) & 0xFFFF, _GAMEOBJECT_UPDATE_COUNT)
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
    gameobject: GameObject | None = None,
    world_guid: int,
    packet_map_id: int,
    packet_x: float,
    packet_y: float,
    packet_z: float,
    packet_orientation: float,
) -> None:
    gameobject_type = (
        int(gameobject.gameobject_type)
        if gameobject is not None
        else _entry_int(entry, "type")
    )
    if gameobject_type != _GAMEOBJECT_TYPE_MO_TRANSPORT:
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
            int(gameobject.entry) if gameobject is not None else _entry_int(entry, "entry"),
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

    _transport_debug_log(
        "[MO_TRANSPORT_CREATE] world_guid=0x%016X entry=%s transport_type=%s "
        "source_path=%s runtime_state_found=%s runtime_map=%s "
        "runtime_pos=(%.3f %.3f %.3f) packet_map=%s "
        "packet_pos=(%.3f %.3f %.3f %.3f) phase_ms=%s "
        "transport_path_progress=%s",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(gameobject.entry) if gameobject is not None else _entry_int(entry, "entry"),
        gameobject_type,
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
    loaded_gameobject_entries = getattr(session, "loaded_gameobject_entries", None)
    if not isinstance(loaded_gameobject_entries, dict):
        loaded_gameobject_entries = {}
        session.loaded_gameobject_entries = loaded_gameobject_entries
    filtered_entries: list[tuple[GameObject, dict, WorldObject | None]] = []
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
        runtime_object = resolve_gameobject_runtime(
            entry,
            runtime_guid=world_guid,
        )
        world_guid = int(runtime_object.runtime_guid)
        if seen is not None and runtime_object.runtime_guid in seen:
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
        if not _transport_packet_context_matches_map(entry, map_id):
            _discard_transport_packet_snapshot(
                session,
                world_guids=(original_world_guid, world_guid),
            )
            log_transport_packet_snapshot(
                session,
                opcode="SMSG_UPDATE_OBJECT_SKIPPED",
                source_subsystem="gameobject_bootstrap_discovery",
                batch_id=(
                    f"{int(getattr(session, 'world_transition_generation', 0) or 0)}:"
                    "world-bootstrap"
                ),
                map_id=map_id,
                position=(
                    _entry_float(entry, "x"),
                    _entry_float(entry, "y"),
                    _entry_float(entry, "z"),
                    _entry_float(entry, "orientation"),
                ),
                object_guid=world_guid,
                object_map_context=_entry_map_id(entry, map_id),
            )
            _transport_debug_log(
                "[TransportPacket] bootstrap create skipped source=database "
                "object_guid=0x%016X packet_map=%s object_map=%s "
                "reason=map_context_mismatch",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                map_id,
                _entry_map_id(entry, map_id),
            )
            continue
        if world_guid != original_world_guid:
            loaded_transports = getattr(session, "loaded_transport_entries", None)
            if isinstance(loaded_transports, dict):
                loaded_transports.pop(original_world_guid, None)
                loaded_transports[world_guid] = dict(entry)
        if not gameobject_matches_mapping(
            runtime_object,
            entry,
            runtime_guid=world_guid,
        ):
            runtime_object = resolve_gameobject_runtime(
                entry,
                runtime_guid=world_guid,
            )
        filtered_entries.append(
            (
                runtime_object,
                entry,
                _manager_transport_for_guid(world_guid, entry),
            )
        )
        loaded_gameobject_entries[world_guid] = dict(entry)
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
        runtime_object = resolve_gameobject_runtime(
            entry,
            runtime_guid=world_guid,
        )
        loaded_gameobject_entries[world_guid] = dict(entry)
        register_loaded_transport_entry(
            session,
            entry,
            world_guid=world_guid,
            map_id=int(entry.get("map", map_id) or map_id),
        )
        filtered_entries.append(
            (
                runtime_object,
                entry,
                _manager_transport_for_guid(world_guid, entry),
            )
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
    for runtime_object, entry, transport in filtered_entries:
        entry = cached_transport_runtime_entry(session, entry)
        packet_runtime_guid = int(
            entry.get("world_guid", runtime_object.runtime_guid)
            or runtime_object.runtime_guid
        )
        if not _transport_packet_context_matches_map(entry, map_id):
            _discard_transport_packet_snapshot(
                session,
                world_guids=(
                    int(runtime_object.runtime_guid),
                    packet_runtime_guid,
                ),
            )
            log_transport_packet_snapshot(
                session,
                opcode="SMSG_UPDATE_OBJECT_SKIPPED",
                source_subsystem="gameobject_bootstrap_serialize",
                batch_id=(
                    f"{int(getattr(session, 'world_transition_generation', 0) or 0)}:"
                    "world-bootstrap"
                ),
                map_id=map_id,
                position=(
                    _entry_float(entry, "x"),
                    _entry_float(entry, "y"),
                    _entry_float(entry, "z"),
                    _entry_float(entry, "orientation"),
                ),
                object_guid=packet_runtime_guid,
                object_map_context=_entry_map_id(entry, map_id),
            )
            _transport_debug_log(
                "[TransportPacket] bootstrap create skipped source=serialize "
                "object_guid=0x%016X packet_map=%s object_map=%s "
                "reason=map_context_changed",
                packet_runtime_guid & 0xFFFFFFFFFFFFFFFF,
                map_id,
                _entry_map_id(entry, map_id),
            )
            continue
        if not gameobject_matches_mapping(
            runtime_object,
            entry,
            runtime_guid=packet_runtime_guid,
        ):
            runtime_object = resolve_gameobject_runtime(
                entry,
                runtime_guid=packet_runtime_guid,
            )
        payload = _build_gameobject_update_payload(
            map_id=map_id,
            entry=entry,
            realm_id=realm_id,
            gameobject=runtime_object,
            transport=transport,
        )
        if _entry_int(entry, "type") == 15 or entry.get(
            "use_transport_guid"
        ):
            log_transport_packet_snapshot(
                session,
                opcode="SMSG_UPDATE_OBJECT",
                source_subsystem="gameobject_bootstrap_create",
                batch_id=(
                    f"{int(getattr(session, 'world_transition_generation', 0) or 0)}:"
                    "world-bootstrap"
                ),
                map_id=map_id,
                position=(
                    _entry_float(entry, "x"),
                    _entry_float(entry, "y"),
                    _entry_float(entry, "z"),
                    _entry_float(entry, "orientation"),
                ),
                object_guid=packet_runtime_guid,
                object_map_context=_entry_map_id(entry, map_id),
            )
        if bool(entry.get("synthetic_transport")):
            _transport_debug_log(
                "[WorldTransport] synthetic create guid=%s entry=%s type=%s "
                "payload=%s pos=(%.2f %.2f %.2f) o=%.3f",
                runtime_object.spawn_id,
                runtime_object.entry,
                runtime_object.gameobject_type,
                len(payload),
                runtime_object.x,
                runtime_object.y,
                runtime_object.z,
                runtime_object.orientation,
            )
        if int(runtime_object.gameobject_type) == 11:
            _transport_debug_log(
                "[TransportElevator] stream create guid=%s entry=%s payload=%s "
                "pos=(%.2f %.2f %.2f)",
                runtime_object.spawn_id,
                runtime_object.entry,
                len(payload),
                runtime_object.x,
                runtime_object.y,
                runtime_object.z,
            )
        if int(runtime_object.gameobject_type) == 15:
            _transport_debug_log(
                "[WorldTransport] stream create guid=%s entry=%s payload=%s "
                "pos=(%.2f %.2f %.2f) o=%.3f",
                runtime_object.spawn_id,
                runtime_object.entry,
                len(payload),
                runtime_object.x,
                runtime_object.y,
                runtime_object.z,
                runtime_object.orientation,
            )
        responses.append(make_update_object_response(payload))
    return responses


def build_gameobject_create_response(
    session,
    entry: Mapping[str, Any],
    *,
    gameobject: GameObject | None = None,
) -> tuple[str, bytes]:
    """Build CREATE using matching runtime state and persistent metadata."""
    map_id = int(
        entry.get(
            "map_id",
            entry.get("map", getattr(session, "map_id", 0)),
        )
        or 0
    )
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    return make_update_object_response(
        _build_gameobject_update_payload(
            map_id=map_id,
            entry=entry,
            realm_id=realm_id,
            gameobject=gameobject,
        )
    )


def build_gameobject_destroy_response(
    session,
    world_guid: int,
    *,
    gameobject: GameObject | None = None,
) -> tuple[str, bytes]:
    """Build the canonical out-of-range response used to unload a GameObject."""
    from server.modules.handlers.world.opcodes.movement import (
        _build_out_of_range_update_object_payload,
    )

    runtime_guid = int(world_guid)
    map_id = int(getattr(session, "map_id", 0) or 0)
    if gameobject is not None and int(gameobject.runtime_guid) == runtime_guid:
        runtime_guid = int(gameobject.runtime_guid)
        if int(gameobject.map_id) == map_id:
            map_id = int(gameobject.map_id)

    return (
        "SMSG_UPDATE_OBJECT",
        _build_out_of_range_update_object_payload(
            map_id=map_id,
            guid=runtime_guid,
        ),
    )
