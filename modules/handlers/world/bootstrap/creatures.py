#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import struct

from shared.Logger import Logger
from server.modules.game.guid import CreatureGuid, GuidHelper
from server.modules.handlers.world.bootstrap.playerobjects import (
    make_update_object_response,
)
from server.modules.handlers.world.protocol.update_object import creature as creature_defs
from server.modules.handlers.world.protocol.update_object.serializers import (
    build_fixed_u32_field_block,
    serialize_create_object_entry,
    u32_from_float,
)

for _definition_name in creature_defs.__all__:
    globals()[f"_{_definition_name}"] = getattr(creature_defs, _definition_name)


def _normalize_orientation(value: float) -> float:
    orientation = math.fmod(float(value or 0.0), math.tau)
    if orientation < 0.0:
        orientation += math.tau
    return float(orientation)


def _npc_orientation_debug_enabled() -> bool:
    try:
        from server.modules.handlers.world.feature_config import npc_orientation_debug_enabled

        return bool(npc_orientation_debug_enabled())
    except Exception:
        return False


def _log_npc_orientation_debug(
    *,
    entry: dict,
    world_guid: int,
    spawn_yaw: float,
    runtime_yaw: float,
    packet_yaw: float,
    movement_yaw: float | None = None,
) -> None:
    if not _npc_orientation_debug_enabled():
        return

    normalized_yaw = _normalize_orientation(packet_yaw)
    Logger.info(
        "NPC_DEBUG entry=%s guid=%s spawn_yaw=%.6f runtime_yaw=%.6f "
        "movement_yaw=%s packet_yaw=%.6f normalized_yaw=%.6f",
        int(entry.get("entry", 0) or 0),
        int(world_guid),
        float(spawn_yaw),
        float(runtime_yaw),
        "none" if movement_yaw is None else f"{float(movement_yaw):.6f}",
        float(packet_yaw),
        float(normalized_yaw),
    )


def _u32_from_float(value: float) -> int:
    return u32_from_float(value)


def _build_create_update_object_entry(
    *,
    guid: int,
    object_type: int,
    create_flags: bytes,
    body: bytes,
    update_type: int = 1,
) -> bytes:
    return serialize_create_object_entry(
        guid=guid,
        object_type=object_type,
        create_flags=create_flags,
        body=body,
        update_type=update_type,
    )


def _build_fixed_u32_field_block(fields: dict[int, int], *, mask_blocks: int = 1) -> tuple[bytes, bytes]:
    return build_fixed_u32_field_block(fields, mask_blocks=mask_blocks)


def _build_creature_create_flags() -> bytes:
    # Living-unit create flags for the 5.4.8 UPDATE_OBJECT layout.
    # Keep this byte-aligned; otherwise the movement block starts mid-bit.
    return bytes(_CREATURE_CREATE_FLAGS)


def _resolve_creature_display_id(entry: dict) -> int:
    display_id = int(entry.get("modelid", 0) or 0)
    if display_id > 0:
        return display_id

    template = entry.get("template")
    if isinstance(template, dict):
        for key in ("modelid1", "modelid2", "modelid3", "modelid4"):
            display_id = int(template.get(key, 0) or 0)
            if display_id > 0:
                return display_id
    return 15476


def _build_creature_field_values(entry: dict, *, world_guid: int) -> dict[int, int]:
    display_id = _resolve_creature_display_id(entry)
    template = entry.get("template")
    template_flags = int(template.get("npcflag", 0) or 0) if isinstance(template, dict) else 0
    npc_flags = int(entry.get("npcflag", 0) or template_flags or 0)
    return {
        _OBJECT_FIELD_GUID_LOW: int(world_guid) & 0xFFFFFFFF,
        _OBJECT_FIELD_GUID_HIGH: (int(world_guid) >> 32) & 0xFFFFFFFF,
        _OBJECT_FIELD_TYPE: _CREATURE_OBJECT_TYPE_FIELD_VALUE,
        _OBJECT_FIELD_ENTRY: int(entry.get("entry", 0) or 0),
        _OBJECT_FIELD_DYNAMIC_FLAGS: _CREATURE_DYNAMIC_FLAGS_DEFAULT,
        _OBJECT_FIELD_SCALE_X: _u32_from_float(_CREATURE_SCALE_DEFAULT),
        _UNIT_FIELD_BYTES_0: _CREATURE_BYTES_0_DEFAULT,
        _UNIT_FIELD_BYTES_1: _CREATURE_BYTES_1_DEFAULT,
        _UNIT_FIELD_HEALTH: _CREATURE_HEALTH_DEFAULT,
        _UNIT_FIELD_MAX_HEALTH: _CREATURE_HEALTH_DEFAULT,
        _UNIT_FIELD_POWER_1: _CREATURE_POWER_DEFAULT,
        _UNIT_FIELD_LEVEL: _CREATURE_LEVEL_DEFAULT,
        _UNIT_FIELD_FACTION_TEMPLATE: _CREATURE_FACTION_TEMPLATE_DEFAULT,
        _UNIT_FIELD_FLAGS: _CREATURE_FLAGS_DEFAULT,
        63: _CREATURE_FLAGS_3_DEFAULT,
        64: _CREATURE_POWER_REGEN_DEFAULT,
        65: _CREATURE_POWER_REGEN_DEFAULT,
        _UNIT_FIELD_BOUNDING_RADIUS: _u32_from_float(_CREATURE_BOUNDING_RADIUS_DEFAULT),
        _UNIT_FIELD_COMBAT_REACH: _u32_from_float(_CREATURE_COMBAT_REACH_DEFAULT),
        _UNIT_FIELD_DISPLAY_ID: int(display_id),
        _UNIT_FIELD_NATIVE_DISPLAY_ID: int(display_id),
        _UNIT_FIELD_MOUNT_DISPLAY_ID: _CREATURE_MOUNT_DISPLAY_ID_DEFAULT,
        81: _u32_from_float(_CREATURE_UNIT_MOD_DEFAULT),
        82: _u32_from_float(_CREATURE_UNIT_MOD_DEFAULT),
        _UNIT_FIELD_NPC_FLAGS: npc_flags,
        128: _CREATURE_FIELD_128_DEFAULT,
        _UNIT_FIELD_HOVER_HEIGHT: _u32_from_float(_CREATURE_HOVER_HEIGHT_DEFAULT),
        157: _CREATURE_FIELD_157_DEFAULT,
    }


def _build_creature_update_payload(*, map_id: int, entry: dict, realm_id: int) -> bytes:
    world_guid = int(
        entry.get("world_guid")
        or CreatureGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), int(realm_id) or 1)
    )
    raw_guid = GuidHelper.to_le_bytes(world_guid)
    mask_bytes, field_bytes = _build_fixed_u32_field_block(
        _build_creature_field_values(entry, world_guid=world_guid),
        mask_blocks=_CREATURE_MASK_BLOCKS,
    )

    x = float(entry.get("x", 0.0) or 0.0)
    y = float(entry.get("y", 0.0) or 0.0)
    z = float(entry.get("z", 0.0) or 0.0)
    spawn_orientation = float(entry.get("spawn_orientation", entry.get("orientation", 0.0)) or 0.0)
    orientation = _normalize_orientation(spawn_orientation)

    body = bytearray()
    body += struct.pack("<B", raw_guid[4])
    body += struct.pack("<f", 7.0)
    body += struct.pack("<B", raw_guid[2])
    body += struct.pack("<B", raw_guid[1])
    body += struct.pack("<f", 3.1415939331054688)
    body += struct.pack("<f", 4.7)
    body += struct.pack("<B", raw_guid[7])
    body += struct.pack("<f", 3.140000104904175)
    body += struct.pack("<f", x)
    body += struct.pack("<f", orientation)
    body += struct.pack("<f", 2.5)
    body += struct.pack("<f", y)
    body += struct.pack("<f", 4.5)
    body += struct.pack("<B", raw_guid[5])
    body += struct.pack("<B", raw_guid[6])
    body += struct.pack("<B", raw_guid[0])
    body += struct.pack("<f", 2.5)
    body += struct.pack("<f", 8.000020027160645)
    body += struct.pack("<f", 4.722221851348877)
    body += struct.pack("<f", z)
    body += struct.pack("<B", len(mask_bytes) // 4)
    body += bytes(mask_bytes)
    body += bytes(field_bytes)
    body += struct.pack("<B", 0)

    _log_npc_orientation_debug(
        entry=entry,
        world_guid=world_guid,
        spawn_yaw=spawn_orientation,
        runtime_yaw=orientation,
        # TODO: feed this from creature spline/waypoint runtime once NPC movement is implemented.
        movement_yaw=None,
        packet_yaw=orientation,
    )

    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
    payload += _build_create_update_object_entry(
        guid=world_guid,
        object_type=_CREATURE_OBJECT_TYPE,
        create_flags=_build_creature_create_flags(),
        body=bytes(body),
        update_type=_CREATURE_UPDATE_TYPE,
    )
    return bytes(payload)


def build_database_creature_responses(session, *, loaded_guids: set[int] | None = None):
    from server.modules.database.DatabaseConnection import DatabaseConnection
    from server.modules.handlers.world.feature_config import npcs_enabled

    if not npcs_enabled():
        return []
    if not getattr(session, "npcs_visible", False):
        return []

    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)

    entries = DatabaseConnection.get_creatures_near(
        map_id,
        x,
        y,
        radius=_CREATURE_VISIBILITY_RADIUS,
        limit=_CREATURE_PACKET_LIMIT,
    )

    if not entries:
        return []

    seen = loaded_guids if isinstance(loaded_guids, set) else None
    responses = []
    realm_id = int(getattr(session, "realm_id", 1) or 1)

    for entry in entries:
        entry_id = int(entry.get("entry", 1))
        spawn_guid = int(entry.get("guid", 0) or 0)
        world_guid = CreatureGuid.from_spawn_guid(spawn_guid, realm_id)

        if seen is not None:
            if world_guid in seen:
                continue
            seen.add(world_guid)

        template = DatabaseConnection.get_creature_template(entry_id) or {}
        template_name = str(template.get("name", "") or "").lower()
        if template_name.startswith("[dnd]") or "trigger" in template_name:
            continue

        spawn_orientation = float(entry.get("orientation", 0.0) or 0.0)
        runtime_orientation = _normalize_orientation(spawn_orientation)
        spawn = {
            "guid": spawn_guid,
            "entry": entry_id,
            "modelid": int(entry.get("modelid", 0) or 0),
            "npcflag": int(entry.get("npcflag", 0) or template.get("npcflag", 0) or 0),
            "template": template,
            "x": float(entry.get("x", 0.0) or 0.0),
            "y": float(entry.get("y", 0.0) or 0.0),
            "z": float(entry.get("z", 0.0) or 0.0),
            "spawn_orientation": spawn_orientation,
            "orientation": runtime_orientation,
        }
        npc_flags_by_guid = getattr(session, "npc_flags_by_guid", None)
        if not isinstance(npc_flags_by_guid, dict):
            npc_flags_by_guid = {}
            session.npc_flags_by_guid = npc_flags_by_guid
        npc_flags_by_guid[int(world_guid)] = int(spawn["npcflag"])
        npc_flags_by_guid[int(spawn_guid)] = int(spawn["npcflag"])
        npc_positions_by_guid = getattr(session, "npc_positions_by_guid", None)
        if not isinstance(npc_positions_by_guid, dict):
            npc_positions_by_guid = {}
            session.npc_positions_by_guid = npc_positions_by_guid
        npc_position = (
            int(map_id),
            float(spawn["x"]),
            float(spawn["y"]),
            float(spawn["z"]),
            float(runtime_orientation),
        )
        npc_positions_by_guid[int(world_guid)] = npc_position
        npc_positions_by_guid[int(spawn_guid)] = npc_position
        npc_names_by_guid = getattr(session, "npc_names_by_guid", None)
        if not isinstance(npc_names_by_guid, dict):
            npc_names_by_guid = {}
            session.npc_names_by_guid = npc_names_by_guid
        npc_name = str(template.get("name", "") or "")
        npc_names_by_guid[int(world_guid)] = npc_name
        npc_names_by_guid[int(spawn_guid)] = npc_name

        Logger.info(
            "[SPAWN_NPC] guid=%s world_guid=0x%016X entry=%s name=%s display=%s "
            "npcflag=0x%X pos=(%.2f %.2f %.2f) o=%.6f",
            spawn["guid"],
            world_guid & 0xFFFFFFFFFFFFFFFF,
            spawn["entry"],
            str(template.get("name", "") or ""),
            _resolve_creature_display_id(spawn),
            int(spawn["npcflag"]),
            spawn["x"],
            spawn["y"],
            spawn["z"],
            float(runtime_orientation),
        )

        payload = _build_creature_update_payload(
            map_id=map_id,
            entry=spawn,
            realm_id=realm_id,
        )
        responses.append(make_update_object_response(payload))

    return responses
