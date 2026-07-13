from __future__ import annotations

import math
from typing import Any

from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import CreatureGuid, GameObjectGuid, MoTransportGuid
from server.modules.handlers.world.transport_runtime import (
    GAMEOBJECT_TYPE_MO_TRANSPORT,
    GAMEOBJECT_TYPE_TRANSPORT,
)


DEFAULT_SEARCH_RADIUS = 10.0
FRONT_DOT_EPSILON = 0.05
RUNTIME_ONLY_KEYS = ("synthetic_transport", "_transport_create_source_path")
GAMEOBJECT_TYPE = "GameObject"
CREATURE_TYPE = "Creature"


def entry_int(entry: dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(entry.get(key, default) or default)
    except Exception:
        return int(default)


def entry_float(entry: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(entry.get(key, default) or default)
    except Exception:
        return float(default)


def player_position(session) -> tuple[float, float, float, float]:
    return (
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )


def gameobject_world_guid(session, entry: dict[str, Any]) -> int:
    world_guid = int(entry.get("world_guid", 0) or 0)
    if world_guid > 0:
        return world_guid
    spawn_id = entry_int(entry, "guid")
    go_type = entry_int(entry, "type", -1)
    if go_type == GAMEOBJECT_TYPE_MO_TRANSPORT or bool(entry.get("use_transport_guid")):
        return int(MoTransportGuid.from_spawn_guid(spawn_id))
    return int(GameObjectGuid.from_spawn_guid(spawn_id, int(getattr(session, "realm_id", 1) or 1)))


def creature_world_guid(session, entry: dict[str, Any]) -> int:
    world_guid = int(entry.get("world_guid", 0) or 0)
    if world_guid > 0:
        return world_guid
    spawn_id = entry_int(entry, "guid")
    return int(CreatureGuid.from_spawn_guid(spawn_id, int(getattr(session, "realm_id", 1) or 1)))


def _entry_map_id(entry: dict[str, Any]) -> int:
    return entry_int(entry, "map_id", entry_int(entry, "map"))


def _distance_3d(session, entry: dict[str, Any]) -> float:
    px, py, pz, _orientation = player_position(session)
    dx = entry_float(entry, "x") - px
    dy = entry_float(entry, "y") - py
    dz = entry_float(entry, "z") - pz
    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz))


def _front_dot(session, entry: dict[str, Any]) -> float:
    px, py, _pz, orientation = player_position(session)
    dx = entry_float(entry, "x") - px
    dy = entry_float(entry, "y") - py
    horizontal = math.sqrt((dx * dx) + (dy * dy))
    if horizontal <= 0.000001:
        return 1.0
    return ((dx / horizontal) * math.cos(orientation)) + ((dy / horizontal) * math.sin(orientation))


def is_editable_gameobject(entry: dict[str, Any]) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry_int(entry, "guid") <= 0:
        return False
    go_type = entry_int(entry, "type", -1)
    if go_type in (GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT):
        return False
    if any(bool(entry.get(key)) for key in RUNTIME_ONLY_KEYS):
        return False
    return True


def _persistent_gameobject_spawn(entry: dict[str, Any]) -> dict[str, Any] | None:
    spawn_id = entry_int(entry, "guid")
    if spawn_id <= 0:
        return None
    return DatabaseConnection.get_gameobject_spawn(spawn_id)


def _persistent_creature_spawn(entry: dict[str, Any]) -> dict[str, Any] | None:
    spawn_id = entry_int(entry, "guid")
    if spawn_id <= 0:
        return None
    getter = getattr(DatabaseConnection, "get_creature_spawn", None)
    if not callable(getter):
        return None
    return getter(spawn_id)


def find_nearby_gameobjects(session, radius: float = DEFAULT_SEARCH_RADIUS) -> list[tuple[dict[str, Any], float]]:
    radius = max(0.0, float(radius or DEFAULT_SEARCH_RADIUS))
    px, py, _pz, _orientation = player_position(session)
    map_id = int(getattr(session, "map_id", 0) or 0)
    raw_entries = DatabaseConnection.get_gameobjects_near(
        map_id,
        px,
        py,
        radius=radius,
        limit=120,
    )

    candidates: list[tuple[int, float, float, int, dict[str, Any]]] = []
    for raw in raw_entries or ():
        entry = dict(raw)
        if _entry_map_id(entry) not in (0, map_id):
            continue
        if not is_editable_gameobject(entry):
            continue
        if _persistent_gameobject_spawn(entry) is None:
            continue
        distance = _distance_3d(session, entry)
        if distance > radius:
            continue
        dot = _front_dot(session, entry)
        entry["realm_id"] = int(getattr(session, "realm_id", 1) or 1)
        entry["world_guid"] = gameobject_world_guid(session, entry)
        candidates.append((0 if dot >= FRONT_DOT_EPSILON else 1, distance, -dot, entry_int(entry, "guid"), entry))

    if not candidates:
        return []
    has_front = any(rank == 0 for rank, _distance, _dot, _guid, _entry in candidates)
    if has_front:
        candidates = [candidate for candidate in candidates if candidate[0] == 0]
    candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
    return [(entry, float(distance)) for _rank, distance, _dot, _guid, entry in candidates]


def find_nearest_gameobject(session, radius: float = DEFAULT_SEARCH_RADIUS) -> tuple[dict[str, Any], float] | None:
    nearby = find_nearby_gameobjects(session, radius)
    if not nearby:
        return None
    return nearby[0]


def find_nearby_creatures(session, radius: float = DEFAULT_SEARCH_RADIUS) -> list[tuple[dict[str, Any], float]]:
    radius = max(0.0, float(radius or DEFAULT_SEARCH_RADIUS))
    px, py, _pz, _orientation = player_position(session)
    map_id = int(getattr(session, "map_id", 0) or 0)
    raw_entries = DatabaseConnection.get_creatures_near(
        map_id,
        px,
        py,
        radius=radius,
        limit=120,
    )

    candidates: list[tuple[int, float, float, int, dict[str, Any]]] = []
    for raw in raw_entries or ():
        entry = dict(raw)
        if _entry_map_id(entry) not in (0, map_id):
            continue
        if entry_int(entry, "guid") <= 0 or entry_int(entry, "entry") <= 0:
            continue
        if _persistent_creature_spawn(entry) is None:
            continue
        distance = _distance_3d(session, entry)
        if distance > radius:
            continue
        dot = _front_dot(session, entry)
        entry["realm_id"] = int(getattr(session, "realm_id", 1) or 1)
        entry["world_guid"] = creature_world_guid(session, entry)
        candidates.append((0 if dot >= FRONT_DOT_EPSILON else 1, distance, -dot, entry_int(entry, "guid"), entry))

    if not candidates:
        return []
    has_front = any(rank == 0 for rank, _distance, _dot, _guid, _entry in candidates)
    if has_front:
        candidates = [candidate for candidate in candidates if candidate[0] == 0]
    candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
    return [(entry, float(distance)) for _rank, distance, _dot, _guid, entry in candidates]


def find_nearest_creature(session, radius: float = DEFAULT_SEARCH_RADIUS) -> tuple[dict[str, Any], float] | None:
    nearby = find_nearby_creatures(session, radius)
    if not nearby:
        return None
    return nearby[0]


def _selection_store(session) -> dict[str, Any] | None:
    selection = getattr(session, "_world_editor_selection", None)
    return selection if isinstance(selection, dict) else None


def set_selection(
    session,
    object_type: str,
    *,
    entry: int,
    spawn_id: int,
    runtime_guid: int,
) -> dict[str, Any]:
    selected = {
        "object_type": str(object_type or ""),
        "entry": int(entry or 0),
        "spawn_id": int(spawn_id or 0),
        "runtime_guid": int(runtime_guid or 0),
    }
    session._world_editor_selection = selected
    return dict(selected)


def get_selection(session, object_type: str | None = None) -> dict[str, Any] | None:
    selected = _selection_store(session)
    if selected is None:
        return None
    if object_type is not None and str(selected.get("object_type", "")) != str(object_type or ""):
        return None
    return dict(selected)


def clear_selection(session, object_type: str | None = None) -> bool:
    selected = _selection_store(session)
    if selected is None:
        return False
    if object_type is not None and str(selected.get("object_type", "")) != str(object_type or ""):
        return False
    session._world_editor_selection = None
    return True


def selection_from_gameobject(session, entry: dict[str, Any]) -> dict[str, Any]:
    return set_selection(
        session,
        GAMEOBJECT_TYPE,
        entry=entry_int(entry, "entry"),
        spawn_id=entry_int(entry, "guid"),
        runtime_guid=gameobject_world_guid(session, entry),
    )


def selection_from_creature(session, entry: dict[str, Any]) -> dict[str, Any]:
    return set_selection(
        session,
        CREATURE_TYPE,
        entry=entry_int(entry, "entry"),
        spawn_id=entry_int(entry, "guid"),
        runtime_guid=creature_world_guid(session, entry),
    )
