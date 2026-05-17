#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import threading
import time
from typing import Any

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.dbc import read_dbc
from server.modules.handlers.world.bootstrap.gameobjects import _build_gameobject_update_payload
from server.modules.game.guid import GameObjectGuid, MoTransportGuid
from server.modules.handlers.world.bootstrap.playerobjects import make_update_object_response

GAMEOBJECT_TYPE_TRANSPORT = 11
GAMEOBJECT_TYPE_MO_TRANSPORT = 15

ENABLE_TRANSPORT_RUNTIME_UPDATES = True
ENABLE_SYNTHETIC_TRANSPORT_TEST_SPAWNS = False
_TRANSPORT_TICK_SECONDS = 0.25
_TRANSPORT_VISIBILITY_RADIUS = 700.0
_DEFAULT_ROUTE_DISTANCE = 320.0
_DEFAULT_ROUTE_SPEED = 22.0
_DEFAULT_ROUTE_WAIT_SECONDS = 1.0
_DEFAULT_MO_TRANSPORT_PERIOD_MS = 180_000
_DEFAULT_MO_TRANSPORT_ROUTE_DISTANCE = 420.0
_DEFAULT_MO_TRANSPORT_ROUTE_LATERAL = 90.0
_DEFAULT_MO_TRANSPORT_WAIT_SECONDS = 4.0
_ELEVATOR_ROUTE_WAIT_SECONDS = 2.0
_THREAD_IDLE_TIMEOUT_SECONDS = 20.0
_SYNTHETIC_TRANSPORT_RADIUS = 700.0
_TRANSPORT_SEND_DISTANCE = 2.0
_USE_LEGACY_GUID_FOR_SYNTHETIC_TRANSPORTS = True
_THUNDER_BLUFF_ELEVATOR_ENTRIES = frozenset({4170, 4171, 47296})
_THUNDER_BLUFF_ELEVATOR_LOW_Z = 68.586
_THUNDER_BLUFF_ELEVATOR_HIGH_Z = 130.080
_THUNDER_BLUFF_ELEVATOR_PERIOD_SECONDS = 32.0
_TRANSPORT_ANIMATION_FORMAT = "diifffx"
_TRANSPORT_TAXI_PATH_NODE_FORMAT = "diiifffiiii"
_TRANSPORT_ANIMATION_FALLBACKS = (
    Path("/home/magnus/projects/mistofpandaria/TransportAnimation.dbc"),
)
_TRANSPORT_DBC_FALLBACKS = (
    Path("/home/magnus/projects/mistofpandaria"),
)
_WORLD_DB_TRANSPORT_VISIBILITY_RADIUS = 900.0

# Entry-specific boat/zeppelin routes can be added here without touching the
# runtime state machine. Nodes may cross maps; the tick code logs transitions.
_HARDCODED_TRANSPORT_ROUTES: dict[int, list[tuple[int, float, float, float, float]]] = {}

_SYNTHETIC_TRANSPORTS: tuple[dict[str, Any], ...] = (
    {
        "guid": 9_500_101,
        "entry": 176310,
        "display_id": 3015,
        "name": "Ship (Ratchet Static Visibility Test)",
        "type": 5,
        "route": (
            (1, -1000.0, -3826.0, 5.8, 0.0),
            (1, -1000.0, -3826.0, 5.8, 0.0),
        ),
    },
    {
        "guid": 9_500_001,
        "entry": 20808,
        "display_id": 3015,
        "name": "Ship (The Maiden's Fancy)",
        "route": (
            (0, -14297.2, 531.0, 8.8, 1.0),
            (0, -14370.0, 760.0, 8.8, 1.0),
            (0, -14297.2, 531.0, 8.8, 1.0),
        ),
    },
    {
        "guid": 9_500_002,
        "entry": 176310,
        "display_id": 3015,
        "name": "Ship (The Bravery)",
        "route": (
            (1, -1005.0, -3828.0, 5.6, 1.0),
            (1, -1215.0, -3920.0, 5.6, 1.0),
            (1, -1005.0, -3828.0, 5.6, 1.0),
        ),
    },
    {
        "guid": 9_500_003,
        "entry": 176231,
        "display_id": 3015,
        "name": "Ship (The Lady Mehley)",
        "route": (
            (0, -3805.0, -725.0, 33.4, 1.0),
            (0, -4050.0, -1120.0, 33.4, 1.0),
            (0, -3805.0, -725.0, 33.4, 1.0),
        ),
    },
    {
        "guid": 9_500_005,
        "entry": 176231,
        "display_id": 3015,
        "name": "Ship (Auberdine Ferry)",
        "route": (
            (1, 6428.0, 821.0, 7.0, 1.0),
            (1, 6180.0, 1040.0, 7.0, 1.0),
            (1, 6428.0, 821.0, 7.0, 1.0),
        ),
    },
    {
        "guid": 9_500_004,
        "entry": 164871,
        "display_id": 3031,
        "name": "Zeppelin (The Thundercaller)",
        "route": (
            (1, -1025.0, -3825.0, 42.0, 1.0),
            (1, -1325.0, -4100.0, 80.0, 1.0),
            (1, -1025.0, -3825.0, 42.0, 1.0),
        ),
    },
    {
        "guid": 9_500_006,
        "entry": 164871,
        "display_id": 3031,
        "name": "Zeppelin (Orgrimmar Tower)",
        "route": (
            (1, 1346.0, -4635.0, 70.0, 2.0),
            (1, 1160.0, -4865.0, 105.0, 1.0),
            (0, 2062.0, 274.0, 112.0, 2.0),
            (0, 2300.0, 400.0, 132.0, 1.0),
            (1, 1346.0, -4635.0, 70.0, 2.0),
        ),
    },
    {
        "guid": 9_500_007,
        "entry": 164871,
        "display_id": 3031,
        "name": "Zeppelin (Undercity Tower)",
        "route": (
            (0, 2062.0, 274.0, 112.0, 2.0),
            (0, 2300.0, 400.0, 132.0, 1.0),
            (1, 1346.0, -4635.0, 70.0, 2.0),
            (1, 1160.0, -4865.0, 105.0, 1.0),
            (0, 2062.0, 274.0, 112.0, 2.0),
        ),
    },
)


@dataclass(frozen=True)
class TransportRouteNode:
    map_id: int
    x: float
    y: float
    z: float
    wait_time: float = 0.0
    time_ms: int = 0


@dataclass(frozen=True)
class TransportAnimationNode:
    time_ms: int
    x: float
    y: float
    z: float


@dataclass(frozen=True)
class TransportAnimationPath:
    entry: int
    nodes: tuple[TransportAnimationNode, ...]
    period_ms: int


@dataclass(frozen=True)
class TransportTaxiPathNode:
    path_id: int
    node_index: int
    map_id: int
    x: float
    y: float
    z: float


@dataclass
class RuntimeTransportState:
    guid: int
    entry: int
    spawn_guid: int
    display_id: int
    route: list[TransportRouteNode]
    speed: float
    node_index: int
    x: float
    y: float
    z: float
    orientation: float
    map_id: int
    last_tick: float
    wait_until: float
    last_logged_node: int = -1
    tick_log_after: float = 0.0
    last_sent_x: float = float("inf")
    last_sent_y: float = float("inf")
    last_sent_z: float = float("inf")
    last_sent_map_id: int = -1
    path_progress_ms: float = 0.0
    timed_route: bool = False
    route_period_ms: int = 0


def register_loaded_transport_entry(
    session: Any,
    entry: dict[str, Any],
    *,
    world_guid: int,
    map_id: int,
) -> None:
    """Remember visible moving transports so the runtime can move them."""
    if not is_runtime_transport_entry(entry):
        return

    loaded_transports = getattr(session, "loaded_transport_entries", None)
    if not isinstance(loaded_transports, dict):
        loaded_transports = {}
        session.loaded_transport_entries = loaded_transports

    transport_entry = dict(entry)
    transport_entry["world_guid"] = int(world_guid)
    transport_entry["map"] = int(map_id)
    loaded_transports[int(world_guid)] = transport_entry

    if ENABLE_TRANSPORT_RUNTIME_UPDATES:
        ensure_transport_runtime_for_session(session)
    if is_thunder_bluff_elevator_entry(entry):
        Logger.info(
            "[WorldElevator] transport spawned guid=%s world_guid=0x%016X entry=%s "
            "pos=(%.2f %.2f %.2f) low=%.3f high=%.3f",
            int(entry.get("guid", 0) or 0),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(entry.get("entry", 0) or 0),
            float(entry.get("x", 0.0) or 0.0),
            float(entry.get("y", 0.0) or 0.0),
            float(entry.get("z", 0.0) or 0.0),
            _THUNDER_BLUFF_ELEVATOR_LOW_Z,
            _THUNDER_BLUFF_ELEVATOR_HIGH_Z,
        )
    else:
        Logger.info(
            "[WorldTransport] stream register guid=%s world_guid=0x%016X entry=%s "
            "name=%r display=%s pos=(%.2f %.2f %.2f)",
            int(entry.get("guid", 0) or 0),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(entry.get("entry", 0) or 0),
            str(entry.get("name", "") or ""),
            int(entry.get("display_id", 0) or 0),
            float(entry.get("x", 0.0) or 0.0),
            float(entry.get("y", 0.0) or 0.0),
            float(entry.get("z", 0.0) or 0.0),
        )


def is_runtime_transport_entry(entry: dict[str, Any]) -> bool:
    gameobject_type = int(entry.get("type", 0) or 0)
    return bool(
        gameobject_type == GAMEOBJECT_TYPE_MO_TRANSPORT
        or _has_transport_animation(entry)
        or is_thunder_bluff_elevator_entry(entry)
    )


def _has_transport_animation(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    gameobject_type = int(entry.get("type", 0) or 0)
    original_type = int(entry.get("original_type", gameobject_type) or gameobject_type)
    if gameobject_type != GAMEOBJECT_TYPE_TRANSPORT:
        return False
    if original_type != GAMEOBJECT_TYPE_TRANSPORT:
        return False
    return _transport_animation_for_entry(int(entry.get("entry", 0) or 0)) is not None


def is_thunder_bluff_elevator_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    gameobject_type = int(entry.get("type", 0) or 0)
    original_type = int(entry.get("original_type", gameobject_type) or gameobject_type)
    if gameobject_type not in (GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT):
        return False
    if original_type not in (GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT):
        return False
    if int(entry.get("map", entry.get("map_id", 0)) or 0) != 1:
        return False
    if int(entry.get("entry", 0) or 0) in _THUNDER_BLUFF_ELEVATOR_ENTRIES:
        return True
    z = float(entry.get("z", 0.0) or 0.0)
    return (
        abs(z - _THUNDER_BLUFF_ELEVATOR_LOW_Z) <= 1.0
        or abs(z - _THUNDER_BLUFF_ELEVATOR_HIGH_Z) <= 1.0
    )


def prepare_runtime_transport_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize runtime transport metadata without changing client-visible lift type."""
    prepared = dict(entry)
    gameobject_type = int(prepared.get("type", 0) or 0)
    animation = _transport_animation_for_entry(int(prepared.get("entry", 0) or 0))
    if animation is None and gameobject_type == GAMEOBJECT_TYPE_MO_TRANSPORT:
        prepared["use_transport_guid"] = True
        prepared["transport_period"] = int(
            prepared.get("transport_period", 0)
            or prepared.get("data0", 0)
            or _DEFAULT_MO_TRANSPORT_PERIOD_MS
        )
        prepared["data0"] = int(prepared.get("data0", 0) or prepared["transport_period"])
        prepared["data1"] = int(prepared.get("data1", 0) or 30)
        prepared["data2"] = int(prepared.get("data2", 0) or 1)
        prepared["data3"] = int(prepared.get("data3", 0) or 0)
        prepared["same_map_transport_route"] = True
        return prepared

    if animation is None and not is_thunder_bluff_elevator_entry(prepared):
        return prepared

    original_type = int(prepared.get("type", 0) or 0)
    prepared["original_type"] = int(prepared.get("original_type", original_type) or original_type)
    prepared["use_transport_guid"] = True
    period_ms = (
        int(animation.period_ms)
        if animation is not None
        else int(_THUNDER_BLUFF_ELEVATOR_PERIOD_SECONDS * 1000.0)
    )
    prepared["transport_period"] = int(period_ms)
    prepared["data0"] = int(prepared.get("data0", 0) or prepared["transport_period"])
    prepared["data1"] = int(prepared.get("data1", 0) or 30)
    prepared["data2"] = int(prepared.get("data2", 0) or 1)
    prepared["data3"] = int(prepared.get("data3", 0) or 0)
    return prepared


def unregister_loaded_transport_entry(session: Any, world_guid: int) -> None:
    loaded_transports = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transports, dict):
        loaded_transports.pop(int(world_guid), None)


def clear_loaded_transport_entries(session: Any) -> None:
    loaded_transports = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transports, dict):
        loaded_transports.clear()


def synthetic_transport_entries_near(
    session: Any,
    *,
    loaded_guids: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Return server-owned route transports near the current player."""
    if not bool(getattr(session, "gameobjects_visible", True)):
        return []

    entries = _world_db_transport_entries_near(session, loaded_guids=loaded_guids)
    if not ENABLE_SYNTHETIC_TRANSPORT_TEST_SPAWNS:
        return entries

    session_map = int(getattr(session, "map_id", 0) or 0)
    session_x = float(getattr(session, "x", 0.0) or 0.0)
    session_y = float(getattr(session, "y", 0.0) or 0.0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)

    for spec in _SYNTHETIC_TRANSPORTS:
        world_guid = _synthetic_transport_world_guid(
            int(spec["guid"]),
            realm_id=realm_id,
        )
        if isinstance(loaded_guids, set) and world_guid in loaded_guids:
            continue

        entry = _entry_from_synthetic_spec(
            spec,
            world_guid=world_guid,
            realm_id=realm_id,
            near_map=session_map,
            near_x=session_x,
            near_y=session_y,
        )
        moved_entry = apply_transport_runtime_position(session, entry)
        if int(moved_entry.get("map", session_map) or session_map) != session_map:
            continue

        dx = float(moved_entry.get("x", 0.0) or 0.0) - session_x
        dy = float(moved_entry.get("y", 0.0) or 0.0) - session_y
        if math.hypot(dx, dy) > _SYNTHETIC_TRANSPORT_RADIUS:
            continue

        entries.append(moved_entry)

    return entries


def _world_db_transport_entries_near(
    session: Any,
    *,
    loaded_guids: set[int] | None = None,
) -> list[dict[str, Any]]:
    transports = _load_world_db_transports()
    if not transports:
        return []

    session_map = int(getattr(session, "map_id", 0) or 0)
    session_x = float(getattr(session, "x", 0.0) or 0.0)
    session_y = float(getattr(session, "y", 0.0) or 0.0)
    entries: list[dict[str, Any]] = []

    for spec in transports:
        spawn_guid = _same_map_transport_spawn_guid(
            int(spec.get("guid", 0) or 0),
            map_id=session_map,
        )
        world_guid = int(MoTransportGuid.from_spawn_guid(spawn_guid))
        if isinstance(loaded_guids, set) and world_guid in loaded_guids:
            continue

        route = _build_same_map_taxi_transport_route(
            int(spec.get("path_id", 0) or 0),
            map_id=session_map,
        )
        if len(route) < 2:
            continue

        nearest_index = _nearest_route_node_index(
            route,
            map_id=session_map,
            x=session_x,
            y=session_y,
        )
        nearest = route[nearest_index]
        if math.hypot(float(nearest.x) - session_x, float(nearest.y) - session_y) > _WORLD_DB_TRANSPORT_VISIBILITY_RADIUS:
            continue

        entry = _entry_from_world_db_transport_spec(
            spec,
            world_guid=world_guid,
            route=route,
            start_index=nearest_index,
        )
        moved_entry = apply_transport_runtime_position(session, entry)
        if int(moved_entry.get("map", session_map) or session_map) != session_map:
            continue
        entries.append(moved_entry)

    return entries


def _synthetic_transport_world_guid(spawn_guid: int, *, realm_id: int) -> int:
    if _USE_LEGACY_GUID_FOR_SYNTHETIC_TRANSPORTS:
        return int(GameObjectGuid.from_spawn_guid(int(spawn_guid), int(realm_id) or 1))
    return int(MoTransportGuid.from_spawn_guid(int(spawn_guid)))


def _same_map_transport_spawn_guid(transport_guid: int, *, map_id: int) -> int:
    return (max(0, int(map_id)) * 100_000) + int(transport_guid)


def _entry_from_synthetic_spec(
    spec: dict[str, Any],
    *,
    world_guid: int,
    realm_id: int,
    near_map: int,
    near_x: float,
    near_y: float,
) -> dict[str, Any]:
    route = [
        TransportRouteNode(
            int(node[0]),
            float(node[1]),
            float(node[2]),
            float(node[3]),
            float(node[4]),
        )
        for node in spec["route"]
    ]
    start_index = _nearest_route_node_index(
        route,
        map_id=int(near_map),
        x=float(near_x),
        y=float(near_y),
    )
    first = route[start_index]
    second = route[(start_index + 1) % len(route)] if len(route) > 1 else first
    entry = {
        "guid": int(spec["guid"]),
        "world_guid": int(world_guid),
        "entry": int(spec["entry"]),
        "map": int(first.map_id),
        "map_id": int(first.map_id),
        "x": float(first.x),
        "y": float(first.y),
        "z": float(first.z),
        "orientation": _orientation_between(first, second, 0.0),
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "animprogress": 0,
        "state": 0,
        "type": int(spec.get("type", GAMEOBJECT_TYPE_MO_TRANSPORT)),
        "display_id": int(spec["display_id"]),
        "name": str(spec["name"]),
        "faction": 0,
        "flags": 0,
        "size": 1.0,
        "data0": 0,
        "data1": 30,
        "data2": 1,
        "data3": 0,
        "realm_id": int(realm_id),
        "route_start_index": int(start_index),
        "synthetic_transport": True,
    }
    _HARDCODED_TRANSPORT_ROUTES[int(spec["entry"])] = [
        (int(node.map_id), float(node.x), float(node.y), float(node.z), float(node.wait_time))
        for node in route
    ]
    return entry


def _entry_from_world_db_transport_spec(
    spec: dict[str, Any],
    *,
    world_guid: int,
    route: list[TransportRouteNode],
    start_index: int,
) -> dict[str, Any]:
    route = list(route)
    first = route[int(start_index) % len(route)]
    second = route[(int(start_index) + 1) % len(route)] if len(route) > 1 else first
    spawn_guid = int(world_guid) & 0xFFFFFFFF
    entry = {
        "guid": int(spawn_guid),
        "transport_db_guid": int(spec.get("guid", 0) or 0),
        "world_guid": int(world_guid),
        "entry": int(spec.get("entry", 0) or 0),
        "map": int(first.map_id),
        "map_id": int(first.map_id),
        "x": float(first.x),
        "y": float(first.y),
        "z": float(first.z),
        "orientation": _orientation_between(first, second, 0.0),
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "animprogress": 0,
        "state": 0,
        "type": GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": int(spec.get("display_id", 0) or 0),
        "name": str(spec.get("name", "") or ""),
        "faction": int(spec.get("faction", 0) or 0),
        "flags": int(spec.get("flags", 0) or 0),
        "size": float(spec.get("size", 1.0) or 1.0),
        "data0": int(spec.get("path_id", 0) or 0),
        "data1": int(spec.get("data1", 0) or 30),
        "data2": int(spec.get("data2", 0) or 1),
        "data3": int(spec.get("data3", 0) or 0),
        "transport_period": int(spec.get("period", 0) or _DEFAULT_MO_TRANSPORT_PERIOD_MS),
        "route_start_index": int(start_index) % len(route),
        "world_db_transport": True,
        "use_transport_guid": True,
    }
    _HARDCODED_TRANSPORT_ROUTES[int(entry["entry"])] = [
        (int(node.map_id), float(node.x), float(node.y), float(node.z), float(node.wait_time))
        for node in route
    ]
    return entry


def _nearest_route_node_index(
    route: list[TransportRouteNode],
    *,
    map_id: int,
    x: float,
    y: float,
) -> int:
    best_index = 0
    best_distance = float("inf")
    for index, node in enumerate(route):
        if int(node.map_id) != int(map_id):
            continue
        distance = math.hypot(float(node.x) - float(x), float(node.y) - float(y))
        if distance < best_distance:
            best_distance = distance
            best_index = int(index)
    return best_index


def apply_transport_runtime_position(session: Any, entry: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of entry with current runtime transport coordinates."""
    if not is_runtime_transport_entry(entry):
        return entry
    if not ENABLE_TRANSPORT_RUNTIME_UPDATES:
        return entry

    world_guid = int(entry.get("world_guid", 0) or 0)
    state = _transport_state_for_entry(entry)
    if state is None:
        return entry

    _tick_transport_state(state)
    moved_entry = dict(entry)
    moved_entry["map"] = int(state.map_id)
    moved_entry["x"] = float(state.x)
    moved_entry["y"] = float(state.y)
    moved_entry["z"] = float(state.z)
    moved_entry["orientation"] = float(state.orientation)
    moved_entry["world_guid"] = world_guid
    moved_entry["transport_path_progress"] = int(state.path_progress_ms) & 0xFFFFFFFF
    moved_entry["transport_period"] = int(_transport_period_ms(moved_entry))
    return moved_entry


def ensure_transport_runtime_for_session(session: Any) -> None:
    if not ENABLE_TRANSPORT_RUNTIME_UPDATES:
        return

    if bool(getattr(session, "_transport_runtime_running", False)):
        return

    session._transport_runtime_running = True
    thread = threading.Thread(
        target=_transport_runtime_loop,
        args=(session,),
        name=f"world-transport-{int(getattr(session, 'char_guid', 0) or 0)}",
        daemon=True,
    )
    thread.start()
    Logger.info(
        "[WorldTransport] runtime start char=%s",
        int(getattr(session, "char_guid", 0) or 0),
    )


def _transport_runtime_loop(session: Any) -> None:
    idle_since: float | None = None
    try:
        while True:
            entries = getattr(session, "loaded_transport_entries", None)
            if not isinstance(entries, dict) or not entries:
                if idle_since is None:
                    idle_since = time.monotonic()
                elif time.monotonic() - idle_since >= _THREAD_IDLE_TIMEOUT_SECONDS:
                    return
                time.sleep(_TRANSPORT_TICK_SECONDS)
                continue

            idle_since = None
            responses = _build_visible_transport_updates(session, entries)
            _send_responses(session, responses)
            time.sleep(_TRANSPORT_TICK_SECONDS)
    except Exception as exc:
        Logger.warning("[WorldTransport] runtime failed err=%s", exc)
    finally:
        session._transport_runtime_running = False
        Logger.info(
            "[WorldTransport] runtime stop char=%s",
            int(getattr(session, "char_guid", 0) or 0),
        )


def _build_visible_transport_updates(
    session: Any,
    entries: dict[int, dict[str, Any]],
) -> list[tuple[str, bytes]]:
    if not bool(getattr(session, "gameobjects_visible", True)):
        return []

    session_map = int(getattr(session, "map_id", 0) or 0)
    session_x = float(getattr(session, "x", 0.0) or 0.0)
    session_y = float(getattr(session, "y", 0.0) or 0.0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    responses: list[tuple[str, bytes]] = []

    for world_guid, entry in list(entries.items()):
        moved_entry = apply_transport_runtime_position(session, entry)
        state = _runtime_transport_states().get(int(world_guid))
        if state is not None and not _should_send_transport_update(state):
            continue
        if int(moved_entry.get("map", session_map) or session_map) != session_map:
            continue

        dx = float(moved_entry.get("x", 0.0) or 0.0) - session_x
        dy = float(moved_entry.get("y", 0.0) or 0.0) - session_y
        if math.hypot(dx, dy) > _TRANSPORT_VISIBILITY_RADIUS:
            continue

        payload = _build_gameobject_update_payload(
            map_id=session_map,
            entry=moved_entry,
            realm_id=realm_id,
        )
        responses.append(make_update_object_response(payload))
        if state is not None:
            _mark_transport_update_sent(state)
        _maybe_log_transport_tick(int(world_guid), moved_entry)

    return responses


def _should_send_transport_update(state: RuntimeTransportState) -> bool:
    if int(state.map_id) != int(state.last_sent_map_id):
        return True

    dx = float(state.x) - float(state.last_sent_x)
    dy = float(state.y) - float(state.last_sent_y)
    dz = float(state.z) - float(state.last_sent_z)
    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz)) >= _TRANSPORT_SEND_DISTANCE


def _mark_transport_update_sent(state: RuntimeTransportState) -> None:
    state.last_sent_x = float(state.x)
    state.last_sent_y = float(state.y)
    state.last_sent_z = float(state.z)
    state.last_sent_map_id = int(state.map_id)


def _send_responses(session: Any, responses: list[tuple[str, bytes]]) -> None:
    sender = getattr(session, "send_response", None)
    if not callable(sender) or not responses:
        return

    try:
        sender(responses)
    except Exception as exc:
        Logger.warning(
            "[WorldTransport] send failed char=%s err=%s",
            int(getattr(session, "char_guid", 0) or 0),
            exc,
        )


def _transport_state_for_entry(entry: dict[str, Any]) -> RuntimeTransportState | None:
    world_guid = int(entry.get("world_guid", 0) or 0)
    if world_guid <= 0:
        return None

    states = _runtime_transport_states()
    state = states.get(world_guid)
    if state is not None:
        return state

    route = _build_default_route(entry)
    if len(route) < 2:
        return None

    start_index = int(entry.get("route_start_index", 0) or 0)
    if start_index > 0:
        start_index %= len(route)
        route = route[start_index:] + route[:start_index]

    now = time.monotonic()
    first = route[0]
    second = route[1]
    timed_route = _is_timed_route(route)
    route_period_ms = _route_period_ms(route) or _transport_period_ms(entry)
    state = RuntimeTransportState(
        guid=world_guid,
        entry=int(entry.get("entry", 0) or 0),
        spawn_guid=int(entry.get("guid", 0) or 0),
        display_id=int(entry.get("display_id", 0) or 0),
        route=route,
        speed=_resolve_transport_speed(entry),
        node_index=0,
        x=float(first.x),
        y=float(first.y),
        z=float(first.z),
        orientation=_orientation_between(first, second, float(entry.get("orientation", 0.0) or 0.0)),
        map_id=int(first.map_id),
        last_tick=now,
        wait_until=now + max(0.0, float(first.wait_time)),
        timed_route=timed_route,
        route_period_ms=route_period_ms,
    )
    states[world_guid] = state
    Logger.info(
        "[WorldTransport] route load world_guid=0x%016X entry=%s display=%s "
        "map=%s nodes=%s speed=%.2f period=%sms timed=%s start=(%.2f %.2f %.2f)",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(state.entry),
        int(state.display_id),
        int(state.map_id),
        len(route),
        float(state.speed),
        int(state.route_period_ms),
        bool(state.timed_route),
        float(state.x),
        float(state.y),
        float(state.z),
    )
    return state


def _runtime_transport_states() -> dict[int, RuntimeTransportState]:
    states = getattr(_runtime_transport_states, "_states", None)
    if not isinstance(states, dict):
        states = {}
        setattr(_runtime_transport_states, "_states", states)
    return states


def _transport_animation_for_entry(entry_id: int) -> TransportAnimationPath | None:
    if int(entry_id) <= 0:
        return None
    paths = _transport_animation_paths()
    return paths.get(int(entry_id))


def _transport_animation_paths() -> dict[int, TransportAnimationPath]:
    cached = getattr(_transport_animation_paths, "_paths", None)
    if isinstance(cached, dict):
        return cached

    paths: dict[int, TransportAnimationPath] = {}
    dbc_path = _resolve_transport_animation_dbc_path()
    if dbc_path is None:
        setattr(_transport_animation_paths, "_paths", paths)
        Logger.warning("[WorldTransport] TransportAnimation.dbc not found; local lifts stay hardcoded only")
        return paths

    try:
        rows = read_dbc(dbc_path, _TRANSPORT_ANIMATION_FORMAT)
    except Exception as exc:
        setattr(_transport_animation_paths, "_paths", paths)
        Logger.warning("[WorldTransport] TransportAnimation.dbc load failed path=%s err=%s", dbc_path, exc)
        return paths

    grouped: dict[int, list[TransportAnimationNode]] = {}
    for row in rows:
        try:
            entry_id = int(row[1])
            time_ms = int(row[2])
            node = TransportAnimationNode(
                time_ms=max(0, time_ms),
                x=float(row[3]),
                y=float(row[4]),
                z=float(row[5]),
            )
        except (TypeError, ValueError, IndexError):
            continue
        grouped.setdefault(entry_id, []).append(node)

    for entry_id, nodes in grouped.items():
        ordered = tuple(sorted(nodes, key=lambda node: int(node.time_ms)))
        if len(ordered) < 2:
            continue
        period_ms = max(int(node.time_ms) for node in ordered)
        if period_ms <= 0:
            continue
        paths[int(entry_id)] = TransportAnimationPath(
            entry=int(entry_id),
            nodes=ordered,
            period_ms=int(period_ms),
        )

    setattr(_transport_animation_paths, "_paths", paths)
    Logger.info(
        "[WorldTransport] TransportAnimation.dbc loaded path=%s animated_entries=%s",
        dbc_path,
        len(paths),
    )
    return paths


def _resolve_transport_animation_dbc_path() -> Path | None:
    return _resolve_dbc_file("TransportAnimation.dbc", explicit_fallbacks=_TRANSPORT_ANIMATION_FALLBACKS)


def _resolve_dbc_file(
    filename: str,
    *,
    explicit_fallbacks: tuple[Path, ...] = (),
) -> Path | None:
    roots: list[Path] = []
    configured_root = get_dbc_root()
    if configured_root is not None:
        roots.append(Path(configured_root))
    roots.extend(_TRANSPORT_DBC_FALLBACKS)
    roots.extend(path.parent for path in explicit_fallbacks)

    seen: set[Path] = set()
    for root in roots:
        candidate = Path(root) / str(filename)
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.exists():
            return candidate
    for candidate in explicit_fallbacks:
        if candidate.exists():
            return candidate
    return None


def _load_world_db_transports() -> tuple[dict[str, Any], ...]:
    cached = getattr(_load_world_db_transports, "_transports", None)
    if isinstance(cached, tuple):
        return cached

    try:
        from server.modules.database.DatabaseConnection import DatabaseConnection
        from sqlalchemy import text

        session = DatabaseConnection.world()
        rows = session.execute(
            text(
                """
                SELECT
                    t.guid,
                    t.entry,
                    t.name,
                    t.period,
                    gt.displayId AS display_id,
                    gt.faction,
                    gt.flags,
                    gt.size,
                    gt.data0,
                    gt.data1,
                    gt.data2,
                    gt.data3
                FROM transports t
                JOIN gameobject_template gt ON gt.entry = t.entry
                WHERE gt.type = :transport_type
                """
            ),
            {"transport_type": GAMEOBJECT_TYPE_MO_TRANSPORT},
        ).mappings()
    except Exception as exc:
        setattr(_load_world_db_transports, "_transports", ())
        Logger.warning("[WorldTransport] transports table lookup failed err=%s", exc)
        return ()

    transports: list[dict[str, Any]] = []
    for row in rows:
        path_id = int(row.get("data0", 0) or 0)
        display_id = int(row.get("display_id", 0) or 0)
        if path_id <= 0 or display_id <= 0:
            continue
        transports.append(
            {
                "guid": int(row.get("guid", 0) or 0),
                "entry": int(row.get("entry", 0) or 0),
                "name": str(row.get("name", "") or ""),
                "period": int(row.get("period", 0) or 0),
                "display_id": display_id,
                "faction": int(row.get("faction", 0) or 0),
                "flags": int(row.get("flags", 0) or 0),
                "size": float(row.get("size", 1.0) or 1.0),
                "path_id": path_id,
                "data1": int(row.get("data1", 0) or 0),
                "data2": int(row.get("data2", 0) or 0),
                "data3": int(row.get("data3", 0) or 0),
            }
        )

    result = tuple(transports)
    setattr(_load_world_db_transports, "_transports", result)
    Logger.info("[WorldTransport] loaded world DB transports count=%s", len(result))
    return result


def _transport_taxi_path_nodes_by_path() -> dict[int, tuple[TransportTaxiPathNode, ...]]:
    cached = getattr(_transport_taxi_path_nodes_by_path, "_paths", None)
    if isinstance(cached, dict):
        return cached

    paths: dict[int, tuple[TransportTaxiPathNode, ...]] = {}
    dbc_path = _resolve_dbc_file("TaxiPathNode.dbc")
    if dbc_path is None:
        setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
        Logger.warning("[WorldTransport] TaxiPathNode.dbc not found; DB transports cannot spawn")
        return paths

    grouped: dict[int, list[TransportTaxiPathNode]] = {}
    try:
        rows = read_dbc(dbc_path, _TRANSPORT_TAXI_PATH_NODE_FORMAT)
    except Exception as exc:
        setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
        Logger.warning("[WorldTransport] TaxiPathNode.dbc load failed path=%s err=%s", dbc_path, exc)
        return paths

    for row in rows:
        try:
            path_id = int(row[1])
            node = TransportTaxiPathNode(
                path_id=path_id,
                node_index=int(row[2]),
                map_id=int(row[3]),
                x=float(row[4]),
                y=float(row[5]),
                z=float(row[6]),
            )
        except (TypeError, ValueError, IndexError):
            continue
        grouped.setdefault(path_id, []).append(node)

    for path_id, nodes in grouped.items():
        ordered = tuple(sorted(nodes, key=lambda node: int(node.node_index)))
        if len(ordered) >= 2:
            paths[int(path_id)] = ordered

    setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
    Logger.info(
        "[WorldTransport] TaxiPathNode.dbc loaded path=%s transport_paths=%s",
        dbc_path,
        len(paths),
    )
    return paths


def _build_same_map_taxi_transport_route(path_id: int, *, map_id: int) -> list[TransportRouteNode]:
    nodes = _transport_taxi_path_nodes_by_path().get(int(path_id), ())
    if len(nodes) < 2:
        return []
    route = [
        TransportRouteNode(
            int(node.map_id),
            float(node.x),
            float(node.y),
            float(node.z),
            0.0,
        )
        for node in nodes
        if int(node.map_id) == int(map_id)
    ]
    if len(route) < 2:
        return []
    return route


def _build_default_route(entry: dict[str, Any]) -> list[TransportRouteNode]:
    dbc_route = _build_dbc_animation_route(entry)
    if dbc_route:
        return dbc_route

    if is_thunder_bluff_elevator_entry(entry):
        map_id = int(entry.get("map", entry.get("map_id", 1)) or 1)
        x = float(entry.get("x", 0.0) or 0.0)
        y = float(entry.get("y", 0.0) or 0.0)
        static_z = float(entry.get("z", _THUNDER_BLUFF_ELEVATOR_LOW_Z) or _THUNDER_BLUFF_ELEVATOR_LOW_Z)
        low = _THUNDER_BLUFF_ELEVATOR_LOW_Z
        high = _THUNDER_BLUFF_ELEVATOR_HIGH_Z
        if abs(static_z - high) < abs(static_z - low):
            return [
                TransportRouteNode(map_id, x, y, high, _ELEVATOR_ROUTE_WAIT_SECONDS),
                TransportRouteNode(map_id, x, y, low, _ELEVATOR_ROUTE_WAIT_SECONDS),
            ]
        return [
            TransportRouteNode(map_id, x, y, low, _ELEVATOR_ROUTE_WAIT_SECONDS),
            TransportRouteNode(map_id, x, y, high, _ELEVATOR_ROUTE_WAIT_SECONDS),
        ]

    entry_id = int(entry.get("entry", 0) or 0)
    hardcoded = _HARDCODED_TRANSPORT_ROUTES.get(entry_id)
    if hardcoded:
        return [
            TransportRouteNode(
                int(node[0]),
                float(node[1]),
                float(node[2]),
                float(node[3]),
                float(node[4]),
            )
            for node in hardcoded
        ]

    if int(entry.get("type", 0) or 0) == GAMEOBJECT_TYPE_MO_TRANSPORT:
        return _build_same_map_mo_transport_route(entry)

    map_id = int(entry.get("map", entry.get("map_id", 0)) or 0)
    x = float(entry.get("x", 0.0) or 0.0)
    y = float(entry.get("y", 0.0) or 0.0)
    z = float(entry.get("z", 0.0) or 0.0)
    orientation = float(entry.get("orientation", 0.0) or 0.0)
    distance = _resolve_route_distance(entry)
    dx = math.cos(orientation) * distance
    dy = math.sin(orientation) * distance
    wait = _DEFAULT_ROUTE_WAIT_SECONDS
    return [
        TransportRouteNode(map_id, x, y, z, wait),
        TransportRouteNode(map_id, x + dx, y + dy, z, wait),
        TransportRouteNode(map_id, x, y, z, wait),
    ]


def _build_same_map_mo_transport_route(entry: dict[str, Any]) -> list[TransportRouteNode]:
    map_id = int(entry.get("map", entry.get("map_id", 0)) or 0)
    x = float(entry.get("x", 0.0) or 0.0)
    y = float(entry.get("y", 0.0) or 0.0)
    z = float(entry.get("z", 0.0) or 0.0)
    orientation = float(entry.get("orientation", 0.0) or 0.0)
    forward_x = math.cos(orientation)
    forward_y = math.sin(orientation)
    lateral_x = math.cos(orientation + (math.pi * 0.5))
    lateral_y = math.sin(orientation + (math.pi * 0.5))
    distance = _resolve_mo_transport_route_distance(entry)
    lateral = min(_DEFAULT_MO_TRANSPORT_ROUTE_LATERAL, distance * 0.35)
    wait = _DEFAULT_MO_TRANSPORT_WAIT_SECONDS
    return [
        TransportRouteNode(map_id, x, y, z, wait),
        TransportRouteNode(
            map_id,
            x + (forward_x * distance),
            y + (forward_y * distance),
            z,
            0.0,
        ),
        TransportRouteNode(
            map_id,
            x + (forward_x * distance) + (lateral_x * lateral),
            y + (forward_y * distance) + (lateral_y * lateral),
            z,
            wait,
        ),
        TransportRouteNode(
            map_id,
            x + (lateral_x * lateral),
            y + (lateral_y * lateral),
            z,
            0.0,
        ),
        TransportRouteNode(map_id, x, y, z, wait),
    ]


def _resolve_mo_transport_route_distance(entry: dict[str, Any]) -> float:
    size = float(entry.get("size", 1.0) or 1.0)
    scaled = _DEFAULT_MO_TRANSPORT_ROUTE_DISTANCE * max(0.65, min(1.4, size))
    return max(180.0, min(700.0, scaled))


def _build_dbc_animation_route(entry: dict[str, Any]) -> list[TransportRouteNode]:
    animation = _transport_animation_for_entry(int(entry.get("entry", 0) or 0))
    if animation is None:
        return []

    map_id = int(entry.get("map", entry.get("map_id", 0)) or 0)
    base_x = float(entry.get("x", 0.0) or 0.0)
    base_y = float(entry.get("y", 0.0) or 0.0)
    base_z = float(entry.get("z", 0.0) or 0.0)
    orientation = float(entry.get("orientation", 0.0) or 0.0)
    cos_o = math.cos(orientation)
    sin_o = math.sin(orientation)

    route: list[TransportRouteNode] = []
    for node in animation.nodes:
        world_x = base_x + (float(node.x) * cos_o) - (float(node.y) * sin_o)
        world_y = base_y + (float(node.x) * sin_o) + (float(node.y) * cos_o)
        world_z = base_z + float(node.z)
        route.append(
            TransportRouteNode(
                map_id,
                world_x,
                world_y,
                world_z,
                0.0,
                int(node.time_ms),
            )
        )

    if len(route) >= 2:
        Logger.info(
            "[WorldTransport] DBC route entry=%s nodes=%s period=%sms base=(%.2f %.2f %.2f)",
            int(animation.entry),
            len(route),
            int(animation.period_ms),
            float(base_x),
            float(base_y),
            float(base_z),
        )
    return route


def _is_timed_route(route: list[TransportRouteNode]) -> bool:
    if len(route) < 2:
        return False
    return any(int(node.time_ms) > 0 for node in route)


def _route_period_ms(route: list[TransportRouteNode]) -> int:
    if not _is_timed_route(route):
        return 0
    return max(1, max(int(node.time_ms) for node in route))


def _resolve_route_distance(entry: dict[str, Any]) -> float:
    data0 = int(entry.get("data0", 0) or 0)
    if data0 > 0:
        return max(160.0, min(900.0, float(data0) * 0.25))
    return _DEFAULT_ROUTE_DISTANCE


def _resolve_transport_speed(entry: dict[str, Any]) -> float:
    animation = _transport_animation_for_entry(int(entry.get("entry", 0) or 0))
    if animation is not None:
        return _average_animation_speed(entry, animation)

    if int(entry.get("type", 0) or 0) == GAMEOBJECT_TYPE_MO_TRANSPORT:
        period_seconds = max(30.0, float(_transport_period_ms(entry)) / 1000.0)
        route = _build_same_map_mo_transport_route(entry)
        distance = 0.0
        for current, target in zip(route, route[1:]):
            dx = float(target.x) - float(current.x)
            dy = float(target.y) - float(current.y)
            dz = float(target.z) - float(current.z)
            distance += math.sqrt((dx * dx) + (dy * dy) + (dz * dz))
        return max(2.0, min(_DEFAULT_ROUTE_SPEED, distance / period_seconds))

    if is_thunder_bluff_elevator_entry(entry):
        travel_seconds = max(1.0, _THUNDER_BLUFF_ELEVATOR_PERIOD_SECONDS * 0.5)
        return abs(_THUNDER_BLUFF_ELEVATOR_HIGH_Z - _THUNDER_BLUFF_ELEVATOR_LOW_Z) / travel_seconds

    size = float(entry.get("size", 1.0) or 1.0)
    if size > 4.0:
        return _DEFAULT_ROUTE_SPEED * 0.85
    return _DEFAULT_ROUTE_SPEED


def _average_animation_speed(entry: dict[str, Any], animation: TransportAnimationPath) -> float:
    route = _build_dbc_animation_route(entry)
    if len(route) < 2:
        return _DEFAULT_ROUTE_SPEED

    distance = 0.0
    for current, target in zip(route, route[1:]):
        dx = float(target.x) - float(current.x)
        dy = float(target.y) - float(current.y)
        dz = float(target.z) - float(current.z)
        distance += math.sqrt((dx * dx) + (dy * dy) + (dz * dz))
    seconds = max(1.0, float(animation.period_ms) / 1000.0)
    return max(0.1, distance / seconds)


def _transport_period_ms(entry: dict[str, Any]) -> int:
    period = int(entry.get("transport_period", 0) or 0)
    if period > 0:
        return period
    animation = _transport_animation_for_entry(int(entry.get("entry", 0) or 0))
    if animation is not None:
        return int(animation.period_ms)
    if int(entry.get("type", 0) or 0) == GAMEOBJECT_TYPE_MO_TRANSPORT:
        return _DEFAULT_MO_TRANSPORT_PERIOD_MS
    if is_thunder_bluff_elevator_entry(entry):
        return int(_THUNDER_BLUFF_ELEVATOR_PERIOD_SECONDS * 1000.0)
    data0 = int(entry.get("data0", 0) or 0)
    return max(1, int(data0))


def _tick_transport_state(state: RuntimeTransportState) -> None:
    now = time.monotonic()
    elapsed = max(0.0, min(2.0, now - float(state.last_tick)))
    state.last_tick = now
    if elapsed <= 0.0:
        return
    period = max(1, int(state.route_period_ms))
    state.path_progress_ms = (float(state.path_progress_ms) + (elapsed * 1000.0)) % float(period)
    if bool(state.timed_route):
        _apply_timed_route_position(state)
        return
    if now < float(state.wait_until):
        return

    remaining = float(elapsed) * float(state.speed)
    while remaining > 0.0:
        current = state.route[state.node_index]
        next_index = (state.node_index + 1) % len(state.route)
        target = state.route[next_index]
        if int(current.map_id) != int(target.map_id):
            state.x = float(target.x)
            state.y = float(target.y)
            state.z = float(target.z)
            _advance_transport_node(state, next_index, target, now)
            return

        dx = float(target.x) - float(state.x)
        dy = float(target.y) - float(state.y)
        dz = float(target.z) - float(state.z)
        distance = math.sqrt((dx * dx) + (dy * dy) + (dz * dz))
        if distance <= 0.001:
            _advance_transport_node(state, next_index, target, now)
            break

        if remaining < distance:
            ratio = remaining / distance
            state.x += dx * ratio
            state.y += dy * ratio
            state.z += dz * ratio
            state.orientation = math.atan2(dy, dx)
            state.map_id = int(current.map_id)
            return

        state.x = float(target.x)
        state.y = float(target.y)
        state.z = float(target.z)
        state.orientation = math.atan2(dy, dx)
        remaining -= distance
        _advance_transport_node(state, next_index, target, now)
        if state.wait_until > now:
            return


def _apply_timed_route_position(state: RuntimeTransportState) -> None:
    route = state.route
    if len(route) < 2:
        return

    progress = int(state.path_progress_ms) % max(1, int(state.route_period_ms or 1))
    current_index = 0
    target_index = 1
    for index in range(len(route) - 1):
        current = route[index]
        target = route[index + 1]
        if int(current.time_ms) <= progress <= int(target.time_ms):
            current_index = index
            target_index = index + 1
            break
    else:
        current_index = len(route) - 1
        target_index = 0

    current = route[current_index]
    target = route[target_index]
    start_ms = int(current.time_ms)
    end_ms = int(target.time_ms)
    if target_index == 0:
        end_ms = max(start_ms + 1, int(state.route_period_ms))

    duration_ms = max(1, end_ms - start_ms)
    ratio = max(0.0, min(1.0, float(progress - start_ms) / float(duration_ms)))
    if target_index == 0 and progress < start_ms:
        ratio = 1.0

    state.node_index = int(current_index)
    state.map_id = int(current.map_id)
    if int(current.map_id) != int(target.map_id):
        if ratio >= 1.0:
            state.map_id = int(target.map_id)
            state.x = float(target.x)
            state.y = float(target.y)
            state.z = float(target.z)
        return

    dx = float(target.x) - float(current.x)
    dy = float(target.y) - float(current.y)
    dz = float(target.z) - float(current.z)
    state.x = float(current.x) + (dx * ratio)
    state.y = float(current.y) + (dy * ratio)
    state.z = float(current.z) + (dz * ratio)
    if abs(dx) > 0.001 or abs(dy) > 0.001:
        state.orientation = math.atan2(dy, dx)

    if int(current_index) != int(state.last_logged_node):
        state.last_logged_node = int(current_index)
        Logger.info(
            "[WorldTransport] node world_guid=0x%016X entry=%s node=%s/%s "
            "map=%s pos=(%.2f %.2f %.2f) progress=%sms",
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            int(state.entry),
            int(current_index),
            len(route),
            int(state.map_id),
            float(state.x),
            float(state.y),
            float(state.z),
            int(progress),
        )
        if is_thunder_bluff_elevator_state(state):
            Logger.info(
                "[WorldElevator] node transition world_guid=0x%016X entry=%s node=%s/%s "
                "z=%.3f progress=%sms",
                int(state.guid) & 0xFFFFFFFFFFFFFFFF,
                int(state.entry),
                int(current_index),
                len(route),
                float(state.z),
                int(progress),
            )


def _advance_transport_node(
    state: RuntimeTransportState,
    next_index: int,
    target: TransportRouteNode,
    now: float,
) -> None:
    old_map = int(state.map_id)
    state.node_index = int(next_index)
    state.map_id = int(target.map_id)
    state.wait_until = now + max(0.0, float(target.wait_time))
    Logger.info(
        "[WorldTransport] node world_guid=0x%016X entry=%s node=%s/%s "
        "map=%s pos=(%.2f %.2f %.2f) wait=%.2f",
        int(state.guid) & 0xFFFFFFFFFFFFFFFF,
        int(state.entry),
        int(state.node_index),
        len(state.route),
        int(state.map_id),
        float(state.x),
        float(state.y),
        float(state.z),
        float(target.wait_time),
    )
    if is_thunder_bluff_elevator_state(state):
        Logger.info(
            "[WorldElevator] node transition world_guid=0x%016X entry=%s node=%s/%s "
            "z=%.3f pause=%.2f",
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            int(state.entry),
            int(state.node_index),
            len(state.route),
            float(state.z),
            float(target.wait_time),
        )
        if float(target.wait_time) > 0.0:
            Logger.info(
                "[WorldElevator] endpoint pause world_guid=0x%016X seconds=%.2f",
                int(state.guid) & 0xFFFFFFFFFFFFFFFF,
                float(target.wait_time),
            )
        Logger.info(
            "[WorldElevator] reverse direction world_guid=0x%016X next_node=%s",
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            int((state.node_index + 1) % len(state.route)),
        )
    if old_map != int(state.map_id):
        Logger.info(
            "[WorldTransport] map transition world_guid=0x%016X entry=%s %s -> %s",
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            int(state.entry),
            int(old_map),
            int(state.map_id),
        )


def _orientation_between(
    current: TransportRouteNode,
    target: TransportRouteNode,
    fallback: float,
) -> float:
    dx = float(target.x) - float(current.x)
    dy = float(target.y) - float(current.y)
    if abs(dx) <= 0.001 and abs(dy) <= 0.001:
        return float(fallback)
    return math.atan2(dy, dx)


def _maybe_log_transport_tick(world_guid: int, entry: dict[str, Any]) -> None:
    states = _runtime_transport_states()
    state = states.get(int(world_guid))
    if state is None:
        return

    now = time.monotonic()
    if now < float(state.tick_log_after):
        return

    state.tick_log_after = now + 5.0
    if is_thunder_bluff_elevator_entry(entry):
        Logger.debug(
            "[WorldElevator] transport tick world_guid=0x%016X entry=%s node=%s "
            "pos=(%.2f %.2f %.2f)",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(entry.get("entry", 0) or 0),
            int(state.node_index),
            float(entry.get("x", 0.0) or 0.0),
            float(entry.get("y", 0.0) or 0.0),
            float(entry.get("z", 0.0) or 0.0),
        )
    else:
        Logger.debug(
            "[WorldTransport] tick world_guid=0x%016X entry=%s map=%s "
            "node=%s pos=(%.2f %.2f %.2f) o=%.3f",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(entry.get("entry", 0) or 0),
            int(entry.get("map", 0) or 0),
            int(state.node_index),
            float(entry.get("x", 0.0) or 0.0),
            float(entry.get("y", 0.0) or 0.0),
            float(entry.get("z", 0.0) or 0.0),
            float(entry.get("orientation", 0.0) or 0.0),
        )


def is_thunder_bluff_elevator_state(state: RuntimeTransportState) -> bool:
    return int(state.entry) in _THUNDER_BLUFF_ELEVATOR_ENTRIES
