from __future__ import annotations

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import CreatureGuid
from server.modules.handlers.world.bootstrap.creatures import (
    _build_creature_update_payload,
)
from server.modules.handlers.world.bootstrap.playerobjects import (
    make_update_object_response,
)
from server.modules.handlers.world.opcodes.movement import (
    _build_out_of_range_update_object_payload,
)
from server.modules.handlers.world.protocol.movement.spline import (
    SplineVector,
    build_basic_spline_move,
)


def _ensure_loaded_npcs(session) -> set[int]:
    loaded = getattr(session, "loaded_npcs", None)
    if not isinstance(loaded, set):
        loaded = set()
        session.loaded_npcs = loaded
    return loaded


def _ensure_guid_dict(session, attr_name: str) -> dict[int, object]:
    value = getattr(session, attr_name, None)
    if not isinstance(value, dict):
        value = {}
        setattr(session, attr_name, value)
    return value


def build_creature_spawn_response(
    session,
    *,
    world_guid: int,
    entry_id: int,
    x: float,
    y: float,
    z: float,
    orientation: float = 0.0,
) -> tuple[str, bytes]:
    template = DatabaseConnection.get_creature_template(int(entry_id)) or {}
    spawn_guid = int(world_guid) & 0xFFFFFFFF
    payload = _build_creature_update_payload(
        map_id=int(getattr(session, "map_id", 0) or 0),
        entry={
            "guid": spawn_guid,
            "world_guid": int(world_guid),
            "entry": int(entry_id),
            "template": dict(template),
            "npcflag": 0,
            "x": float(x),
            "y": float(y),
            "z": float(z),
            "spawn_orientation": float(orientation),
            "orientation": float(orientation),
        },
        realm_id=int(getattr(session, "realm_id", 1) or 1),
    )

    loaded_npcs = _ensure_loaded_npcs(session)
    loaded_npcs.add(int(world_guid))

    npc_flags_by_guid = _ensure_guid_dict(session, "npc_flags_by_guid")
    npc_flags_by_guid[int(world_guid)] = 0
    npc_flags_by_guid[int(spawn_guid)] = 0

    npc_positions_by_guid = _ensure_guid_dict(session, "npc_positions_by_guid")
    npc_position = (
        int(getattr(session, "map_id", 0) or 0),
        float(x),
        float(y),
        float(z),
        float(orientation),
    )
    npc_positions_by_guid[int(world_guid)] = npc_position
    npc_positions_by_guid[int(spawn_guid)] = npc_position

    npc_names_by_guid = _ensure_guid_dict(session, "npc_names_by_guid")
    npc_name = str(template.get("name", "") or "")
    npc_names_by_guid[int(world_guid)] = npc_name
    npc_names_by_guid[int(spawn_guid)] = npc_name

    return make_update_object_response(payload)


def build_creature_move_response(
    session,
    *,
    world_guid: int,
    start_x: float,
    start_y: float,
    start_z: float,
    end_x: float,
    end_y: float,
    end_z: float,
    duration_ms: int,
    spline_id: int,
) -> tuple[str, bytes]:
    positions = _ensure_guid_dict(session, "npc_positions_by_guid")
    spawn_guid = int(world_guid) & 0xFFFFFFFF
    positions[int(world_guid)] = (
        int(getattr(session, "map_id", 0) or 0),
        float(end_x),
        float(end_y),
        float(end_z),
        0.0,
    )
    positions[int(spawn_guid)] = positions[int(world_guid)]
    return (
        "SMSG_ON_MONSTER_MOVE",
        build_basic_spline_move(
            mover_guid=int(world_guid),
            spline_id=int(spline_id),
            start_position=SplineVector(float(start_x), float(start_y), float(start_z)),
            destination_position=SplineVector(float(end_x), float(end_y), float(end_z)),
            duration_ms=max(1, int(duration_ms)),
        ),
    )


def build_creature_despawn_response(session, *, world_guid: int) -> tuple[str, bytes]:
    loaded_npcs = _ensure_loaded_npcs(session)
    loaded_npcs.discard(int(world_guid))
    for attr_name in ("npc_flags_by_guid", "npc_positions_by_guid", "npc_names_by_guid"):
        mapping = getattr(session, attr_name, None)
        if isinstance(mapping, dict):
            mapping.pop(int(world_guid), None)
            mapping.pop(int(world_guid) & 0xFFFFFFFF, None)
    return (
        "SMSG_UPDATE_OBJECT",
        _build_out_of_range_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=int(world_guid),
        ),
    )


def dispatch_responses(session, responses: list[tuple[str, bytes]]) -> None:
    if not responses:
        return
    sender = getattr(session, "send_response", None)
    if not callable(sender):
        return
    try:
        sender(list(responses))
    except Exception as exc:
        Logger.warning("[PvG] response dispatch failed: %s", exc)


def make_creature_world_guid(realm_id: int, local_low_guid: int) -> int:
    return CreatureGuid.from_spawn_guid(int(local_low_guid), int(realm_id) or 1)
