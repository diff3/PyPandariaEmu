#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import struct
from types import SimpleNamespace

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
from server.modules.handlers.world.protocol.orientation import normalize_orientation
from server.modules.handlers.world.runtime.creature import (
    CREATURE_FLAG_EXTRA_TRIGGER,
    INVISIBLE_TRIGGER_DISPLAY_ID,
    Creature,
)
from server.modules.handlers.world.runtime.creature_store import (
    creature_identity_matches_mapping,
    get_creature_runtime_store,
    resolve_creature_runtime,
)

for _definition_name in creature_defs.__all__:
    globals()[f"_{_definition_name}"] = getattr(creature_defs, _definition_name)


_normalize_orientation = normalize_orientation
_TRANSPORT_CREATURE_GUID_BASE = 0x00800000


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


def _build_creature_create_flags_with_movement(movement_flags: int) -> bytes:
    """Add canonical Unit movement flags to the existing 5.4.8 living bits."""
    movement_flags = int(movement_flags) & 0x3FFFFFFF
    if not movement_flags:
        return _build_creature_create_flags()
    base_bits = [
        (byte >> (7 - bit)) & 1
        for byte in _build_creature_create_flags()
        for bit in range(8)
    ]
    # SkyFire Living update layout: MSEHasMovementFlags is bit 76. The
    # 19-bit MSEBits168 block and MSEHasFallData follow it; the optional
    # 30-bit MovementFlags value therefore begins at bit 97.
    base_bits[76] = 0
    flag_bits = [(movement_flags >> shift) & 1 for shift in range(29, -1, -1)]
    bits = base_bits[:97] + flag_bits + base_bits[97:]
    output = bytearray((len(bits) + 7) // 8)
    for index, value in enumerate(bits):
        if value:
            output[index // 8] |= 1 << (7 - (index % 8))
    return bytes(output)


def _creature_movement_flags(template: dict) -> int:
    inhabit_type = int(template.get("InhabitType", 3) or 3)
    if inhabit_type & 0x04:
        # SkyFire creatures remain airborne through DISABLE_GRAVITY. CAN_FLY
        # only advertises a capability and is insufficient to prevent the
        # client from dropping an otherwise stationary creature to terrain.
        return 0x00000200
    return 0


def _resolve_creature_display_id(
    entry: dict,
    creature: Creature | None = None,
) -> int:
    if creature is not None:
        return int(creature.display_id)
    template = entry.get("template")
    if isinstance(template, dict):
        if int(template.get("flags_extra", 0) or 0) & CREATURE_FLAG_EXTRA_TRIGGER:
            return int(template.get("modelid2", 0) or 0) or INVISIBLE_TRIGGER_DISPLAY_ID
    display_id = int(entry.get("modelid", 0) or 0)
    if display_id > 0:
        return display_id

    if isinstance(template, dict):
        for key in ("modelid1", "modelid2", "modelid3", "modelid4"):
            display_id = int(template.get(key, 0) or 0)
            if display_id > 0:
                return display_id
    return 15476


def _build_creature_field_values(
    entry: dict,
    *,
    world_guid: int,
    creature: Creature | None = None,
) -> dict[int, int]:
    display_id = _resolve_creature_display_id(entry, creature)
    if creature is not None:
        npc_flags = int(creature.npc_flags)
    else:
        template = entry.get("template")
        template_flags = (
            int(template.get("npcflag", 0) or 0)
            if isinstance(template, dict)
            else 0
        )
        npc_flags = int(entry.get("npcflag", 0) or template_flags or 0)
    template = entry.get("template") if isinstance(entry.get("template"), dict) else {}
    addon = entry.get("addon") if isinstance(entry.get("addon"), dict) else {}
    return {
        _OBJECT_FIELD_GUID_LOW: int(world_guid) & 0xFFFFFFFF,
        _OBJECT_FIELD_GUID_HIGH: (int(world_guid) >> 32) & 0xFFFFFFFF,
        _OBJECT_FIELD_TYPE: _CREATURE_OBJECT_TYPE_FIELD_VALUE,
        _OBJECT_FIELD_ENTRY: (
            int(creature.entry)
            if creature is not None
            else int(entry.get("entry", 0) or 0)
        ),
        _OBJECT_FIELD_DYNAMIC_FLAGS: _CREATURE_DYNAMIC_FLAGS_DEFAULT,
        _OBJECT_FIELD_SCALE_X: _u32_from_float(_CREATURE_SCALE_DEFAULT),
        _UNIT_FIELD_BYTES_0: _CREATURE_BYTES_0_DEFAULT,
        _UNIT_FIELD_BYTES_1: int(addon.get("bytes1", _CREATURE_BYTES_1_DEFAULT) or _CREATURE_BYTES_1_DEFAULT),
        _UNIT_FIELD_HEALTH: _CREATURE_HEALTH_DEFAULT,
        _UNIT_FIELD_MAX_HEALTH: _CREATURE_HEALTH_DEFAULT,
        _UNIT_FIELD_POWER_1: _CREATURE_POWER_DEFAULT,
        _UNIT_FIELD_LEVEL: _CREATURE_LEVEL_DEFAULT,
        _UNIT_FIELD_FACTION_TEMPLATE: int(template.get("faction_A", _CREATURE_FACTION_TEMPLATE_DEFAULT) or _CREATURE_FACTION_TEMPLATE_DEFAULT),
        _UNIT_FIELD_FLAGS: int(template.get("unit_flags", _CREATURE_FLAGS_DEFAULT) or _CREATURE_FLAGS_DEFAULT),
        63: _CREATURE_FLAGS_3_DEFAULT,
        64: _CREATURE_POWER_REGEN_DEFAULT,
        65: _CREATURE_POWER_REGEN_DEFAULT,
        _UNIT_FIELD_BOUNDING_RADIUS: _u32_from_float(_CREATURE_BOUNDING_RADIUS_DEFAULT),
        _UNIT_FIELD_COMBAT_REACH: _u32_from_float(_CREATURE_COMBAT_REACH_DEFAULT),
        _UNIT_FIELD_DISPLAY_ID: int(display_id),
        _UNIT_FIELD_NATIVE_DISPLAY_ID: int(display_id),
        _UNIT_FIELD_MOUNT_DISPLAY_ID: int(addon.get("mount", _CREATURE_MOUNT_DISPLAY_ID_DEFAULT) or 0),
        81: _u32_from_float(_CREATURE_UNIT_MOD_DEFAULT),
        82: _u32_from_float(_CREATURE_UNIT_MOD_DEFAULT),
        _UNIT_FIELD_NPC_FLAGS: npc_flags,
        128: _CREATURE_FIELD_128_DEFAULT,
        _UNIT_FIELD_HOVER_HEIGHT: _u32_from_float(float(template.get("HoverHeight", _CREATURE_HOVER_HEIGHT_DEFAULT) or _CREATURE_HOVER_HEIGHT_DEFAULT)),
        157: _CREATURE_FIELD_157_DEFAULT,
    }


def _resolve_packet_creature(
    entry: dict,
    *,
    map_id: int,
    realm_id: int,
    creature: Creature | None,
) -> Creature:
    world_guid = int(
        entry.get("world_guid")
        or CreatureGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), int(realm_id) or 1)
    )
    if creature is not None:
        identity_mapping = {
            "guid": entry.get("guid", 0),
            "entry": entry.get("entry", 0),
            "map_id": entry.get("map_id", map_id),
            "instance_id": entry.get("instance_id", creature.instance_id),
        }
        if creature_identity_matches_mapping(
            creature,
            identity_mapping,
            runtime_guid=world_guid,
        ):
            return creature
    runtime_mapping = dict(entry)
    runtime_mapping["map_id"] = int(entry.get("map_id", map_id) or map_id)
    return resolve_creature_runtime(
        runtime_mapping,
        runtime_guid=world_guid,
    )


def _build_creature_update_payload(
    *,
    map_id: int,
    entry: dict,
    realm_id: int,
    creature: Creature | None = None,
) -> bytes:
    creature = _resolve_packet_creature(
        entry,
        map_id=map_id,
        realm_id=realm_id,
        creature=creature,
    )
    world_guid = int(creature.runtime_guid)
    packet_map_id = int(creature.map_id)
    raw_guid = GuidHelper.to_le_bytes(world_guid)
    mask_bytes, field_bytes = _build_fixed_u32_field_block(
        _build_creature_field_values(
            entry,
            world_guid=world_guid,
            creature=creature,
        ),
        mask_blocks=_CREATURE_MASK_BLOCKS,
    )

    x = float(creature.x)
    y = float(creature.y)
    z = float(creature.z)
    if "spawn_orientation" in entry:
        spawn_orientation = float(entry.get("spawn_orientation", 0.0) or 0.0)
    else:
        spawn_orientation = float(entry.get("orientation", 0.0) or 0.0)
    orientation = normalize_orientation(creature.orientation)

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
    payload += struct.pack("<HI", packet_map_id & 0xFFFF, 1)
    template = entry.get("template") if isinstance(entry.get("template"), dict) else {}
    movement_flags = _creature_movement_flags(template)
    transport_data = entry.get("transport") if isinstance(entry.get("transport"), dict) else None
    if transport_data is not None:
        from server.modules.handlers.world.bootstrap.playerobjects import (
            build_skyfire_player_create_living_movement_block,
        )

        movement_ctx = SimpleNamespace(
            world_guid=world_guid,
            player_guid=world_guid,
            char_guid=world_guid,
            x=x,
            y=y,
            z=z,
            orientation=orientation,
            movement_flags=movement_flags,
            movement_flags2=0,
            movement_counter=0,
            movement_timestamp=int(transport_data.get("time", 0) or 0),
            pitch=0.0,
            fall_time=0,
            fall_zspeed=0.0,
            fall_cos_angle=0.0,
            fall_sin_angle=0.0,
            fall_xy_speed=0.0,
            spline_elevation=0.0,
            has_transport_data=True,
            transport_guid=int(transport_data.get("guid", 0) or 0),
            transport_x=float(transport_data.get("x", 0.0) or 0.0),
            transport_y=float(transport_data.get("y", 0.0) or 0.0),
            transport_z=float(transport_data.get("z", 0.0) or 0.0),
            transport_orientation=float(transport_data.get("orientation", 0.0) or 0.0),
            transport_time=int(transport_data.get("time", 0) or 0),
            transport_time2=0,
            transport_time3=0,
            transport_seat=-1,
        )
        movement_block = build_skyfire_player_create_living_movement_block(
            movement_ctx,
            is_self=False,
        )
        attached_body = bytearray(mask_bytes)
        attached_body += field_bytes
        attached_body += struct.pack("<B", 0)
        payload += _build_create_update_object_entry(
            guid=world_guid,
            object_type=_CREATURE_OBJECT_TYPE,
            create_flags=movement_block,
            body=bytes(attached_body),
            update_type=_CREATURE_UPDATE_TYPE,
        )
        return bytes(payload)
    payload += _build_create_update_object_entry(
        guid=world_guid,
        object_type=_CREATURE_OBJECT_TYPE,
        create_flags=_build_creature_create_flags_with_movement(movement_flags),
        body=bytes(body),
        update_type=_CREATURE_UPDATE_TYPE,
    )
    return bytes(payload)


def _transport_creature_entries(session, DatabaseConnection) -> list[dict]:
    loaded = getattr(session, "loaded_transport_entries", None)
    if not isinstance(loaded, dict) or not loaded:
        return []
    from server.modules.handlers.world.transport_runtime import (
        authoritative_transport_entry_for_guid,
    )

    session_map_id = int(getattr(session, "map_id", 0) or 0)
    visible_transports: dict[int, list[dict]] = {}
    for world_guid, loaded_entry in loaded.items():
        current = authoritative_transport_entry_for_guid(int(world_guid)) or dict(loaded_entry)
        transport_map_id = int(current.get("map", current.get("map_id", 0)) or 0)
        if transport_map_id != session_map_id:
            continue
        transport_entry = int(current.get("entry", 0) or 0)
        if transport_entry > 0:
            visible_transports.setdefault(transport_entry, []).append(
                {**current, "world_guid": int(world_guid)}
            )

    loader = getattr(DatabaseConnection, "get_creature_transport_rows", None)
    rows = loader(tuple(visible_transports)) if callable(loader) else []
    result: list[dict] = []
    for row in rows:
        for transport in visible_transports.get(int(row.get("transport_entry", 0) or 0), ()):
            local_x = float(row.get("TransOffsetX", 0.0) or 0.0)
            local_y = float(row.get("TransOffsetY", 0.0) or 0.0)
            local_z = float(row.get("TransOffsetZ", 0.0) or 0.0)
            local_o = float(row.get("TransOffsetO", 0.0) or 0.0)
            transport_o = float(transport.get("orientation", 0.0) or 0.0)
            cos_o = math.cos(transport_o)
            sin_o = math.sin(transport_o)
            row_guid = int(row.get("guid", 0) or 0)
            result.append({
                "guid": _TRANSPORT_CREATURE_GUID_BASE | row_guid,
                "entry": int(row.get("npc_entry", 0) or 0),
                "map_id": int(transport.get("map", transport.get("map_id", 0)) or 0),
                "x": float(transport.get("x", 0.0) or 0.0) + cos_o * local_x - sin_o * local_y,
                "y": float(transport.get("y", 0.0) or 0.0) + sin_o * local_x + cos_o * local_y,
                "z": float(transport.get("z", 0.0) or 0.0) + local_z,
                "orientation": _normalize_orientation(transport_o + local_o),
                "transport": {
                    "guid": int(transport["world_guid"]),
                    "x": local_x,
                    "y": local_y,
                    "z": local_z,
                    "orientation": local_o,
                    "time": int(transport.get("transport_path_progress", 0) or 0),
                },
            })
    return result


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

    entries = list(DatabaseConnection.get_creatures_near(
        map_id,
        x,
        y,
        radius=_CREATURE_VISIBILITY_RADIUS,
        limit=_CREATURE_PACKET_LIMIT,
    ))
    entries.extend(_transport_creature_entries(session, DatabaseConnection))

    if not entries:
        return []

    addon_loader = getattr(DatabaseConnection, "get_creature_addons", None)
    addon_rows = (
        addon_loader(
            [int(entry.get("guid", 0) or 0) for entry in entries],
            [int(entry.get("entry", 0) or 0) for entry in entries],
        )
        if callable(addon_loader)
        else {}
    )
    spawn_addons = addon_rows.get("spawn", {}) if isinstance(addon_rows, dict) else {}
    template_addons = addon_rows.get("template", {}) if isinstance(addon_rows, dict) else {}

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
        entry = dict(entry)
        entry["addon"] = dict(
            spawn_addons.get(spawn_guid)
            or template_addons.get(entry_id)
            or {}
        )
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
            "addon": entry["addon"],
            "transport": entry.get("transport"),
            "x": float(entry.get("x", 0.0) or 0.0),
            "y": float(entry.get("y", 0.0) or 0.0),
            "z": float(entry.get("z", 0.0) or 0.0),
            "spawn_orientation": spawn_orientation,
            "orientation": runtime_orientation,
        }
        runtime_mapping = {
            **spawn,
            "map_id": map_id,
            "instance_id": int(getattr(session, "instance_id", 0) or 0),
        }
        runtime_creature = resolve_creature_runtime(
            runtime_mapping,
            runtime_guid=world_guid,
        )
        if isinstance(spawn.get("transport"), dict):
            runtime_creature.set_position(spawn["x"], spawn["y"], spawn["z"])
            runtime_creature.set_orientation(spawn["orientation"])
        get_creature_runtime_store().add(runtime_creature)
        npc_flags_by_guid = getattr(session, "npc_flags_by_guid", None)
        if not isinstance(npc_flags_by_guid, dict):
            npc_flags_by_guid = {}
            session.npc_flags_by_guid = npc_flags_by_guid
        npc_flags_by_guid[int(world_guid)] = int(runtime_creature.npc_flags)
        npc_flags_by_guid[int(spawn_guid)] = int(runtime_creature.npc_flags)
        npc_entries_by_guid = getattr(session, "npc_entries_by_guid", None)
        if not isinstance(npc_entries_by_guid, dict):
            npc_entries_by_guid = {}
            session.npc_entries_by_guid = npc_entries_by_guid
        npc_entries_by_guid[int(world_guid)] = int(runtime_creature.entry)
        npc_entries_by_guid[int(spawn_guid)] = int(runtime_creature.entry)
        npc_positions_by_guid = getattr(session, "npc_positions_by_guid", None)
        if not isinstance(npc_positions_by_guid, dict):
            npc_positions_by_guid = {}
            session.npc_positions_by_guid = npc_positions_by_guid
        npc_position = (
            int(runtime_creature.map_id),
            float(runtime_creature.x),
            float(runtime_creature.y),
            float(runtime_creature.z),
            float(runtime_creature.orientation),
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
            runtime_creature.spawn_id,
            runtime_creature.runtime_guid & 0xFFFFFFFFFFFFFFFF,
            runtime_creature.entry,
            str(template.get("name", "") or ""),
            runtime_creature.display_id,
            runtime_creature.npc_flags,
            runtime_creature.x,
            runtime_creature.y,
            runtime_creature.z,
            runtime_creature.orientation,
        )

        payload = _build_creature_update_payload(
            map_id=map_id,
            entry=spawn,
            realm_id=realm_id,
            creature=runtime_creature,
        )
        responses.append(make_update_object_response(payload))

    return responses
