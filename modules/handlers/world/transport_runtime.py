#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
import math
import threading
import time
from typing import Any

from shared.Logger import Logger
from server.modules.handlers.world.feature_config import (
    elevators_enabled,
    moving_transports_enabled,
)
from server.modules.handlers.world.bootstrap.gameobjects import _build_gameobject_update_payload
from server.modules.game.guid import MoTransportGuid
from server.modules.handlers.world.bootstrap.playerobjects import make_update_object_response
from server.modules.handlers.world.movements.cache import get_movement_cache

GAMEOBJECT_TYPE_TRANSPORT = 11
GAMEOBJECT_TYPE_MO_TRANSPORT = 15

TRANSPORT_STATE_ACTIVE = "ACTIVE"
TRANSPORT_STATE_ARRIVING = "ARRIVING"
TRANSPORT_STATE_DOCKED = "DOCKED"
TRANSPORT_STATE_DEPARTING = "DEPARTING"
TRANSPORT_STATE_TRANSFER_PENDING = "TRANSFER_PENDING"
TRANSPORT_STATE_DESPAWNED = "DESPAWNED"

ATTACH_STATE_DETACHED = "DETACHED"
ATTACH_STATE_ATTACHING = "ATTACHING"
ATTACH_STATE_ATTACHED = "ATTACHED"
ATTACH_STATE_DETACHING = "DETACHING"
ATTACH_STATE_TRANSFERRING = "TRANSFERRING"

ENABLE_TRANSPORT_RUNTIME_UPDATES = True
_TRANSPORT_TICK_SECONDS = 0.25
_TRANSPORT_VISIBILITY_RADIUS = 700.0
_DEFAULT_ROUTE_DISTANCE = 320.0
_DEFAULT_ROUTE_SPEED = 22.0
_DEFAULT_ROUTE_WAIT_SECONDS = 1.0
_DEFAULT_MO_TRANSPORT_PERIOD_MS = 180_000
_ELEVATOR_ROUTE_WAIT_SECONDS = 2.0
_THREAD_IDLE_TIMEOUT_SECONDS = 20.0
_TRANSPORT_SEND_DISTANCE = 2.0
_THUNDER_BLUFF_ELEVATOR_ENTRIES = frozenset({4170, 4171, 11898, 11899, 47296, 47297})
_TRANSPORT_CROSS_MAP_HOLD_SECONDS = 15.0
_TRANSPORT_CROSS_MAP_DISTANCE = _DEFAULT_ROUTE_SPEED * _TRANSPORT_CROSS_MAP_HOLD_SECONDS
_WORLD_DB_TRANSPORT_VISIBILITY_RADIUS = 900.0
_DEEPRUN_TRAM_MAP_ID = 369
_DEEPRUN_TRAM_ENTRY = 194675
_DEEPRUN_TRAM_DISPLAY_ID = 8587


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
    last_node_event_index: int = -1
    last_node_event_progress_ms: int = 0
    last_node_event_reason: str = ""
    lifecycle_state: str = TRANSPORT_STATE_ACTIVE
    previous_lifecycle_state: str = ""
    tick_log_after: float = 0.0
    last_sent_x: float = float("inf")
    last_sent_y: float = float("inf")
    last_sent_z: float = float("inf")
    last_sent_map_id: int = -1
    path_progress_ms: float = 0.0
    last_timed_route_progress_ms: int = -1
    timed_route: bool = False
    route_period_ms: int = 0
    shared_clock_key: str = ""
    route_kind: str = ""
    elevator_phase_state: str = ""
    passengers: set[int] = field(default_factory=set)


class WorldTransportManager:
    def __init__(self) -> None:
        self.entries: dict[int, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_tick_log: float = 0.0

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._register_builtin_transports_locked()
            self._running = True
            self._thread = threading.Thread(
                target=self._run_loop,
                name="world-transport-manager",
                daemon=True,
            )
            self._thread.start()
            Logger.info("[TransportManager] start transports=%s", len(self.entries))

    def stop(self) -> None:
        with self._lock:
            self._running = False

    def reset_for_tests(self) -> None:
        with self._lock:
            self.entries.clear()
            _runtime_transport_states().clear()
            self._running = False
            self._thread = None

    def register_transport(self, entry: dict[str, Any], *, source: str = "runtime") -> RuntimeTransportState | None:
        if not isinstance(entry, dict):
            return None
        if not is_runtime_transport_entry(entry):
            return None
        if not _runtime_enabled_for_entry(entry):
            return None

        world_guid = int(entry.get("world_guid", 0) or 0)
        if world_guid <= 0:
            return None

        with self._lock:
            if world_guid in self.entries:
                Logger.info(
                    "[TransportDuplicate] transport=0x%016X entry=%s source=%s",
                    world_guid & 0xFFFFFFFFFFFFFFFF,
                    int(entry.get("entry", 0) or 0),
                    str(source),
                )
                return _runtime_transport_states().get(world_guid)
            duplicate_guid = self._duplicate_runtime_guid_locked(entry)
            if duplicate_guid:
                Logger.info(
                    "[TransportDuplicate] transport=0x%016X entry=%s duplicate_of=0x%016X source=%s",
                    world_guid & 0xFFFFFFFFFFFFFFFF,
                    int(entry.get("entry", 0) or 0),
                    duplicate_guid & 0xFFFFFFFFFFFFFFFF,
                    str(source),
                )
                return _runtime_transport_states().get(duplicate_guid)

            transport_entry = dict(entry)
            transport_entry["world_guid"] = world_guid
            transport_entry.setdefault(
                "home_map",
                int(transport_entry.get("map", transport_entry.get("map_id", 0)) or 0),
            )
            self.entries[world_guid] = transport_entry
            state = _transport_state_for_entry(transport_entry)
            Logger.info(
                "[TransportRegister] transport=0x%016X entry=%s map=%s source=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(transport_entry.get("entry", 0) or 0),
                int(transport_entry.get("map", transport_entry.get("map_id", 0)) or 0),
                str(source),
            )
            if is_thunder_bluff_elevator_entry(transport_entry):
                Logger.info(
                    "[TransportElevator] transport=0x%016X entry=%s map=%s pos=(%.2f %.2f %.2f)",
                    world_guid & 0xFFFFFFFFFFFFFFFF,
                    int(transport_entry.get("entry", 0) or 0),
                    int(transport_entry.get("map", transport_entry.get("map_id", 0)) or 0),
                    float(transport_entry.get("x", 0.0) or 0.0),
                    float(transport_entry.get("y", 0.0) or 0.0),
                    float(transport_entry.get("z", 0.0) or 0.0),
                )
            return state

    def _duplicate_runtime_guid_locked(self, entry: dict[str, Any]) -> int:
        if not is_thunder_bluff_elevator_entry(entry):
            return 0
        entry_id = int(entry.get("entry", 0) or 0)
        map_id = int(entry.get("map", entry.get("map_id", 0)) or 0)
        x = round(float(entry.get("x", 0.0) or 0.0), 1)
        y = round(float(entry.get("y", 0.0) or 0.0), 1)
        for existing_guid, existing in self.entries.items():
            if not is_thunder_bluff_elevator_entry(existing):
                continue
            if int(existing.get("entry", 0) or 0) != entry_id:
                continue
            if int(existing.get("map", existing.get("map_id", 0)) or 0) != map_id:
                continue
            if round(float(existing.get("x", 0.0) or 0.0), 1) != x:
                continue
            if round(float(existing.get("y", 0.0) or 0.0), 1) != y:
                continue
            return int(existing_guid)
        return 0

    def entry_for_guid(self, world_guid: int) -> dict[str, Any] | None:
        with self._lock:
            entry = self.entries.get(int(world_guid))
            return dict(entry) if isinstance(entry, dict) else None

    def state_for_guid(self, world_guid: int) -> RuntimeTransportState | None:
        return _runtime_transport_states().get(int(world_guid))

    def lifecycle_state_for_guid(self, world_guid: int) -> str:
        state = self.state_for_guid(int(world_guid))
        if state is None:
            return TRANSPORT_STATE_DESPAWNED
        return str(getattr(state, "lifecycle_state", TRANSPORT_STATE_ACTIVE) or TRANSPORT_STATE_ACTIVE)

    def can_attach(self, session: Any, world_guid: int) -> bool:
        world_guid = int(world_guid)
        state = self.state_for_guid(world_guid)
        if state is None:
            Logger.warning(
                "[TransportAttach] denied reason=unknown transport=0x%016X player=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(getattr(session, "char_guid", 0) or 0),
            )
            return False
        if int(getattr(session, "map_id", 0) or 0) != int(state.map_id):
            Logger.warning(
                "[TransportAttach] denied reason=wrong_map transport=0x%016X player=%s "
                "player_map=%s transport_map=%s state=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(getattr(session, "char_guid", 0) or 0),
                int(getattr(session, "map_id", 0) or 0),
                int(state.map_id),
                str(getattr(state, "lifecycle_state", "")),
            )
            return False
        lifecycle = str(getattr(state, "lifecycle_state", TRANSPORT_STATE_ACTIVE) or TRANSPORT_STATE_ACTIVE)
        if lifecycle not in (TRANSPORT_STATE_ACTIVE, TRANSPORT_STATE_DOCKED):
            Logger.warning(
                "[TransportAttach] denied reason=lifecycle transport=0x%016X player=%s state=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(getattr(session, "char_guid", 0) or 0),
                lifecycle,
            )
            return False
        return True

    def record_attach(self, session: Any, world_guid: int, *, opcode_name: str = "") -> None:
        state = self.state_for_guid(int(world_guid))
        char_guid = int(getattr(session, "char_guid", 0) or 0)
        if state is not None and char_guid > 0:
            state.passengers.add(char_guid)
        session.transport_attach_state = ATTACH_STATE_ATTACHED
        session.transport_attach_timestamp = float(time.monotonic())
        session.transport_attach_source_map = int(getattr(session, "map_id", 0) or 0)
        Logger.info(
            "[TransportAttach] opcode=%s player=%s transport=0x%016X state=%s "
            "map=%s passengers=%s",
            str(opcode_name),
            char_guid,
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            str(getattr(state, "lifecycle_state", "")) if state is not None else "unknown",
            int(getattr(session, "map_id", 0) or 0),
            len(state.passengers) if state is not None else 0,
        )

    def record_detach(self, session: Any, world_guid: int, *, opcode_name: str = "", reason: str = "client") -> None:
        state = self.state_for_guid(int(world_guid))
        char_guid = int(getattr(session, "char_guid", 0) or 0)
        if state is not None and char_guid > 0:
            state.passengers.discard(char_guid)
        session.transport_attach_state = ATTACH_STATE_DETACHED
        Logger.info(
            "[TransportDetach] opcode=%s reason=%s player=%s transport=0x%016X "
            "state=%s map=%s passengers=%s",
            str(opcode_name),
            str(reason),
            char_guid,
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            str(getattr(state, "lifecycle_state", "")) if state is not None else "unknown",
            int(getattr(session, "map_id", 0) or 0),
            len(state.passengers) if state is not None else 0,
        )

    def entries_near(
        self,
        session: Any,
        *,
        loaded_guids: set[int] | None = None,
        radius: float = _TRANSPORT_VISIBILITY_RADIUS,
    ) -> list[dict[str, Any]]:
        session_map = int(getattr(session, "map_id", 0) or 0)
        session_x = float(getattr(session, "x", 0.0) or 0.0)
        session_y = float(getattr(session, "y", 0.0) or 0.0)
        entries: list[dict[str, Any]] = []
        with self._lock:
            source_entries = list(self.entries.items())

        for world_guid, entry in source_entries:
            if isinstance(loaded_guids, set) and int(world_guid) in loaded_guids:
                continue
            home_map = entry.get("home_map")
            if home_map is not None and int(home_map) != session_map:
                continue
            moved_entry = apply_transport_runtime_position(session, entry)
            moved_map = moved_entry.get("map", session_map)
            if moved_map is None:
                moved_map = session_map
            if int(moved_map) != session_map:
                continue
            dx = float(moved_entry.get("x", 0.0) or 0.0) - session_x
            dy = float(moved_entry.get("y", 0.0) or 0.0) - session_y
            if math.hypot(dx, dy) > float(radius):
                continue
            entries.append(moved_entry)
            Logger.debug(
                "[TransportStream] streamed transport=0x%016X player=%s phase=%s node=%s state=%s map=%s",
                int(world_guid) & 0xFFFFFFFFFFFFFFFF,
                int(getattr(session, "char_guid", 0) or 0),
                int(moved_entry.get("transport_path_progress", 0) or 0),
                int(getattr(_runtime_transport_states().get(int(world_guid)), "node_index", 0) or 0),
                str(getattr(_runtime_transport_states().get(int(world_guid)), "lifecycle_state", "")),
                int(session_map),
            )
        return entries

    def _run_loop(self) -> None:
        while True:
            with self._lock:
                if not self._running:
                    return
                states = list(_runtime_transport_states().items())
            for _world_guid, state in states:
                _tick_transport_state(state)
            self._log_tick(states)
            time.sleep(_TRANSPORT_TICK_SECONDS)

    def _log_tick(self, states: list[tuple[int, RuntimeTransportState]]) -> None:
        now = time.monotonic()
        if now < self._last_tick_log + 5.0:
            return
        self._last_tick_log = now
        Logger.debug("[TransportManager] tick transports=%s", len(states))

    def _register_builtin_transports_locked(self) -> None:
        self._register_deeprun_trams_locked()
        self._register_world_db_transports_locked()
        self._register_thunder_bluff_elevators_locked()

    def _register_deeprun_trams_locked(self) -> None:
        Logger.warning("[MovementManager] Deeprun Tram has no DBC template; not spawning hardcoded tram")

    def _register_world_db_transports_locked(self) -> None:
        for spec in _load_world_db_transports():
            route = _build_timed_taxi_transport_route(
                int(spec.get("path_id", 0) or 0),
                period_ms=int(spec.get("period", 0) or _DEFAULT_MO_TRANSPORT_PERIOD_MS),
            )
            if len(route) < 2:
                continue
            map_ids = sorted({int(node.map_id) for node in route})
            for map_id in map_ids:
                world_guid = int(
                    MoTransportGuid.from_spawn_guid(
                        _same_map_transport_spawn_guid(int(spec.get("guid", 0) or 0), map_id=map_id)
                    )
                )
                start_index = _nearest_route_node_index(
                    route,
                    map_id=map_id,
                    x=route[0].x,
                    y=route[0].y,
                )
                entry = _entry_from_world_db_transport_spec(
                    spec,
                    world_guid=world_guid,
                    route=route,
                    start_index=start_index,
                )
                entry["map"] = int(map_id)
                entry["map_id"] = int(map_id)
                entry["home_map"] = int(map_id)
                self.register_transport(entry, source="world-db")

    def _register_thunder_bluff_elevators_locked(self) -> None:
        for entry in _load_thunder_bluff_elevator_entries():
            prepared = prepare_runtime_transport_entry(entry)
            world_guid = int(
                prepared.get("world_guid")
                or MoTransportGuid.from_spawn_guid(int(prepared.get("guid", 0) or 0))
            )
            prepared["world_guid"] = world_guid
            self.register_transport(prepared, source="thunder-bluff-elevator")


_WORLD_TRANSPORT_MANAGER = WorldTransportManager()


def get_world_transport_manager() -> WorldTransportManager:
    return _WORLD_TRANSPORT_MANAGER


def start_world_transport_manager() -> None:
    if not (elevators_enabled() or moving_transports_enabled()):
        Logger.info("[TransportManager] start skipped; transports disabled")
        return
    _WORLD_TRANSPORT_MANAGER.start()


def reset_world_transport_manager_for_tests() -> None:
    _WORLD_TRANSPORT_MANAGER.reset_for_tests()


def register_loaded_transport_entry(
    session: Any,
    entry: dict[str, Any],
    *,
    world_guid: int,
    map_id: int,
) -> bool:
    """Remember visible moving transports so the runtime can move them."""
    if not is_runtime_transport_entry(entry):
        return True
    if not _runtime_enabled_for_entry(entry):
        return True

    loaded_transports = getattr(session, "loaded_transport_entries", None)
    if not isinstance(loaded_transports, dict):
        loaded_transports = {}
        session.loaded_transport_entries = loaded_transports

    transport_entry = dict(entry)
    transport_entry["world_guid"] = int(world_guid)
    transport_entry["map"] = int(map_id)
    state = get_world_transport_manager().register_transport(transport_entry, source="stream")
    if state is not None and int(state.guid) != int(world_guid):
        return False
    loaded_transports[int(world_guid)] = transport_entry

    if ENABLE_TRANSPORT_RUNTIME_UPDATES:
        ensure_transport_runtime_for_session(session)
    if is_thunder_bluff_elevator_entry(entry):
        Logger.info(
            "[TransportElevator] transport spawned guid=%s world_guid=0x%016X entry=%s "
            "pos=(%.2f %.2f %.2f)",
            int(entry.get("guid", 0) or 0),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(entry.get("entry", 0) or 0),
            float(entry.get("x", 0.0) or 0.0),
            float(entry.get("y", 0.0) or 0.0),
            float(entry.get("z", 0.0) or 0.0),
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
    return True


def is_runtime_transport_entry(entry: dict[str, Any]) -> bool:
    gameobject_type = int(entry.get("type", 0) or 0)
    return bool(
        gameobject_type == GAMEOBJECT_TYPE_MO_TRANSPORT
        or _has_transport_animation(entry)
        or is_thunder_bluff_elevator_entry(entry)
    )


def _runtime_enabled_for_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    gameobject_type = int(entry.get("type", 0) or 0)
    if is_thunder_bluff_elevator_entry(entry):
        return elevators_enabled()
    if gameobject_type == GAMEOBJECT_TYPE_MO_TRANSPORT:
        return moving_transports_enabled()
    if _has_transport_animation(entry):
        return elevators_enabled()
    return moving_transports_enabled()


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
    entry_id = int(entry.get("entry", 0) or 0)
    return entry_id in _THUNDER_BLUFF_ELEVATOR_ENTRIES


def is_deeprun_tram_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    return bool(
        entry.get("deeprun_tram")
        and int(entry.get("map", entry.get("map_id", -1)) or -1) == _DEEPRUN_TRAM_MAP_ID
        and int(entry.get("entry", 0) or 0) == _DEEPRUN_TRAM_ENTRY
    )


def prepare_runtime_transport_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize runtime transport metadata without changing client-visible lift type."""
    prepared = dict(entry)
    gameobject_type = int(prepared.get("type", 0) or 0)
    if not _runtime_enabled_for_entry(prepared):
        return prepared
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
        else int(prepared.get("data0", 0) or 1)
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

    if not moving_transports_enabled():
        return []

    entries = get_world_transport_manager().entries_near(
        session,
        loaded_guids=loaded_guids,
        radius=max(_TRANSPORT_VISIBILITY_RADIUS, _WORLD_DB_TRANSPORT_VISIBILITY_RADIUS),
    )
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

        route = _build_timed_taxi_transport_route(
            int(spec.get("path_id", 0) or 0),
            period_ms=int(spec.get("period", 0) or _DEFAULT_MO_TRANSPORT_PERIOD_MS),
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


def _same_map_transport_spawn_guid(transport_guid: int, *, map_id: int) -> int:
    return (max(0, int(map_id)) * 100_000) + int(transport_guid)


def _shared_route_phase_ms(clock_key: str, period_ms: int) -> int:
    _ = str(clock_key or "")
    period = max(1, int(period_ms or 1))
    return int(time.monotonic() * 1000.0) % period


def linked_transport_world_guid(entry: dict[str, Any], *, map_id: int) -> int:
    base_guid = int(
        entry.get("transport_db_guid", 0)
        or entry.get("source_transport_guid", 0)
        or entry.get("guid", 0)
        or 0
    )
    if base_guid <= 0:
        return int(entry.get("world_guid", 0) or 0)
    return int(MoTransportGuid.from_spawn_guid(_same_map_transport_spawn_guid(base_guid, map_id=int(map_id))))


def runtime_transport_state_for_guid(world_guid: int) -> RuntimeTransportState | None:
    return _runtime_transport_states().get(int(world_guid))


def authoritative_transport_entry_for_guid(world_guid: int) -> dict[str, Any] | None:
    return get_world_transport_manager().entry_for_guid(int(world_guid))


def can_attach_transport(session: Any, world_guid: int) -> bool:
    return get_world_transport_manager().can_attach(session, int(world_guid))


def record_transport_attach(session: Any, world_guid: int, *, opcode_name: str = "") -> None:
    get_world_transport_manager().record_attach(session, int(world_guid), opcode_name=opcode_name)


def record_transport_detach(
    session: Any,
    world_guid: int,
    *,
    opcode_name: str = "",
    reason: str = "client",
) -> None:
    get_world_transport_manager().record_detach(
        session,
        int(world_guid),
        opcode_name=opcode_name,
        reason=reason,
    )


def build_linked_transport_destination_entry(
    source_entry: dict[str, Any],
    *,
    destination_map: int,
) -> dict[str, Any]:
    entry = dict(source_entry)
    world_guid = linked_transport_world_guid(entry, map_id=int(destination_map))
    entry["world_guid"] = int(world_guid)
    entry["guid"] = int(world_guid) & 0xFFFFFFFF
    entry["map"] = int(destination_map)
    entry["map_id"] = int(destination_map)
    entry["home_map"] = int(destination_map)
    entry["use_transport_guid"] = True
    entry["world_db_transport"] = bool(entry.get("world_db_transport", False))
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
        "home_map": int(first.map_id),
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
        "runtime_route": [
            (
                int(node.map_id),
                float(node.x),
                float(node.y),
                float(node.z),
                float(node.wait_time),
                int(node.time_ms),
            )
            for node in route
        ],
        "shared_route_clock_key": f"world-db-transport:{int(spec.get('guid', 0) or 0)}",
    }
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
    if not _runtime_enabled_for_entry(entry):
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
    if not (elevators_enabled() or moving_transports_enabled()):
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

    timed_route = _is_timed_route(route)
    start_index = int(entry.get("route_start_index", 0) or 0)
    if start_index > 0 and not timed_route:
        start_index %= len(route)
        route = route[start_index:] + route[:start_index]

    now = time.monotonic()
    first = route[0]
    second = route[1]
    route_period_ms = max(int(_route_period_ms(route) or 0), int(_transport_period_ms(entry) or 0))
    shared_clock_key = str(entry.get("shared_route_clock_key", "") or "")
    if not shared_clock_key and is_thunder_bluff_elevator_entry(entry):
        shared_clock_key = f"thunder-bluff-elevator:{world_guid}"
    path_progress_ms = (
        float(_shared_route_phase_ms(shared_clock_key, route_period_ms))
        if shared_clock_key
        else 0.0
    )
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
        path_progress_ms=path_progress_ms,
        shared_clock_key=shared_clock_key,
        route_kind="thunder_bluff_elevator"
        if is_thunder_bluff_elevator_entry(entry)
        else "deeprun_tram"
        if bool(entry.get("deeprun_tram"))
        else "",
    )
    if state.timed_route and state.shared_clock_key:
        _apply_timed_route_position(state)
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
    try:
        cache = get_movement_cache()
        cache.load()
    except Exception as exc:
        setattr(_transport_animation_paths, "_paths", paths)
        Logger.warning("[WorldTransport] movement cache load failed err=%s", exc)
        return paths

    for entry_id, template in cache.transport_animation.items():
        paths[int(entry_id)] = TransportAnimationPath(
            entry=int(entry_id),
            nodes=tuple(
                TransportAnimationNode(
                    time_ms=int(node.time_ms),
                    x=float(node.x),
                    y=float(node.y),
                    z=float(node.z),
                )
                for node in template.nodes
            ),
            period_ms=int(template.period_ms),
        )

    setattr(_transport_animation_paths, "_paths", paths)
    Logger.info(
        "[WorldTransport] DBC movement animation templates loaded animated_entries=%s",
        len(paths),
    )
    return paths


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


def _load_thunder_bluff_elevator_entries() -> tuple[dict[str, Any], ...]:
    cached = getattr(_load_thunder_bluff_elevator_entries, "_entries", None)
    if isinstance(cached, tuple):
        return cached

    try:
        from server.modules.database.DatabaseConnection import DatabaseConnection
        from sqlalchemy import text

        session = DatabaseConnection.world()
        entry_list = ",".join(str(int(entry)) for entry in sorted(_THUNDER_BLUFF_ELEVATOR_ENTRIES))
        rows = session.execute(
            text(
                f"""
                SELECT
                    g.guid,
                    g.id AS entry,
                    g.map,
                    g.position_x AS x,
                    g.position_y AS y,
                    g.position_z AS z,
                    g.orientation,
                    gt.displayId AS display_id,
                    gt.type,
                    gt.faction,
                    gt.flags,
                    gt.size,
                    gt.data0,
                    gt.data1,
                    gt.data2,
                    gt.data3
                FROM gameobject g
                JOIN gameobject_template gt ON gt.entry = g.id
                WHERE g.map = 1
                  AND g.id IN ({entry_list})
                """
            ),
        ).mappings()
    except Exception as exc:
        setattr(_load_thunder_bluff_elevator_entries, "_entries", ())
        Logger.warning("[TransportManager] Thunder Bluff elevator preload failed err=%s", exc)
        return ()

    entries: list[dict[str, Any]] = []
    seen: set[tuple[int, int, int, int]] = set()
    for row in rows:
        guid = int(row.get("guid", 0) or 0)
        dedupe_key = (
            int(row.get("entry", 0) or 0),
            int(round(float(row.get("x", 0.0) or 0.0) * 10.0)),
            int(round(float(row.get("y", 0.0) or 0.0) * 10.0)),
            int(round(float(row.get("z", 0.0) or 0.0) * 10.0)),
        )
        if guid <= 0 or dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        entries.append(
            {
                "guid": guid,
                "entry": int(row.get("entry", 0) or 0),
                "map": int(row.get("map", 1) or 1),
                "map_id": int(row.get("map", 1) or 1),
                "x": float(row.get("x", 0.0) or 0.0),
                "y": float(row.get("y", 0.0) or 0.0),
                "z": float(row.get("z", 0.0) or 0.0),
                "orientation": float(row.get("orientation", 0.0) or 0.0),
                "type": int(row.get("type", GAMEOBJECT_TYPE_TRANSPORT) or GAMEOBJECT_TYPE_TRANSPORT),
                "display_id": int(row.get("display_id", 0) or 0),
                "faction": int(row.get("faction", 0) or 0),
                "flags": int(row.get("flags", 0) or 0),
                "size": float(row.get("size", 1.0) or 1.0),
                "data0": int(row.get("data0", 0) or 0),
                "data1": int(row.get("data1", 0) or 0),
                "data2": int(row.get("data2", 0) or 0),
                "data3": int(row.get("data3", 0) or 0),
                "name": "Thunder Bluff Elevator",
            }
        )

    result = tuple(entries)
    setattr(_load_thunder_bluff_elevator_entries, "_entries", result)
    Logger.info("[TransportManager] Thunder Bluff elevators loaded count=%s", len(result))
    return result


def _transport_taxi_path_nodes_by_path() -> dict[int, tuple[TransportTaxiPathNode, ...]]:
    cached = getattr(_transport_taxi_path_nodes_by_path, "_paths", None)
    if isinstance(cached, dict):
        return cached

    paths: dict[int, tuple[TransportTaxiPathNode, ...]] = {}
    try:
        cache = get_movement_cache()
        cache.load()
    except Exception as exc:
        setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
        Logger.warning("[WorldTransport] movement cache taxi load failed err=%s", exc)
        return paths

    for path_id, template in cache.taxi_paths.items():
        nodes: list[TransportTaxiPathNode] = []
        for index, node in enumerate(template.nodes):
            nodes.append(
                TransportTaxiPathNode(
                    path_id=int(path_id),
                    node_index=int(index),
                    map_id=int(node.map_id),
                    x=float(node.x),
                    y=float(node.y),
                    z=float(node.z),
                )
            )
        if len(nodes) >= 2:
            paths[int(path_id)] = tuple(nodes)

    setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
    Logger.info(
        "[WorldTransport] DBC movement taxi path templates loaded transport_paths=%s",
        len(paths),
    )
    return paths

def _build_timed_taxi_transport_route(path_id: int, *, period_ms: int) -> list[TransportRouteNode]:
    nodes = _transport_taxi_path_nodes_by_path().get(int(path_id), ())
    if len(nodes) < 2:
        return []

    distances: list[float] = [0.0]
    total = 0.0
    previous = nodes[0]
    for node in nodes[1:]:
        if int(previous.map_id) == int(node.map_id):
            total += math.sqrt(
                ((float(node.x) - float(previous.x)) ** 2)
                + ((float(node.y) - float(previous.y)) ** 2)
                + ((float(node.z) - float(previous.z)) ** 2)
            )
        else:
            total += float(_TRANSPORT_CROSS_MAP_DISTANCE)
        distances.append(total)
        previous = node

    period = max(1, int(period_ms or _DEFAULT_MO_TRANSPORT_PERIOD_MS))
    if total <= 0.0:
        step = period / max(1, len(nodes) - 1)
        return [
            TransportRouteNode(
                int(node.map_id),
                float(node.x),
                float(node.y),
                float(node.z),
                0.0,
                int(min(period, round(index * step))),
            )
            for index, node in enumerate(nodes)
        ]

    route: list[TransportRouteNode] = []
    for index, node in enumerate(nodes):
        time_ms = int(round((float(distances[index]) / total) * float(period)))
        if index == 0:
            time_ms = 0
        route.append(
            TransportRouteNode(
                int(node.map_id),
                float(node.x),
                float(node.y),
                float(node.z),
                0.0,
                min(period, max(0, time_ms)),
            )
        )
    return route


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
    runtime_route = entry.get("runtime_route")
    if isinstance(runtime_route, (list, tuple)):
        route: list[TransportRouteNode] = []
        for node in runtime_route:
            if not isinstance(node, (list, tuple)) or len(node) < 4:
                continue
            route.append(
                TransportRouteNode(
                    int(node[0]),
                    float(node[1]),
                    float(node[2]),
                    float(node[3]),
                    float(node[4]) if len(node) > 4 else 0.0,
                    int(node[5]) if len(node) > 5 else 0,
                )
            )
        if len(route) >= 2:
            return route

    dbc_route = _build_dbc_animation_route(entry)
    if dbc_route:
        return dbc_route

    if is_thunder_bluff_elevator_entry(entry):
        Logger.warning(
            "[TransportElevator] missing DBC route entry=%s guid=%s; not using fallback path",
            int(entry.get("entry", 0) or 0),
            int(entry.get("guid", 0) or 0),
        )
        return []

    Logger.warning(
        "[MovementManager] missing DBC movement entry=%s guid=%s type=%s; movement disabled",
        int(entry.get("entry", 0) or 0),
        int(entry.get("guid", 0) or 0),
        int(entry.get("type", 0) or 0),
    )
    return []


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
        return _DEFAULT_ROUTE_SPEED

    if is_thunder_bluff_elevator_entry(entry):
        animation = _transport_animation_for_entry(int(entry.get("entry", 0) or 0))
        if animation is not None:
            return _average_animation_speed(entry, animation)
        return _DEFAULT_ROUTE_SPEED

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
        animation = _transport_animation_for_entry(int(entry.get("entry", 0) or 0))
        if animation is not None:
            return int(animation.period_ms)
    data0 = int(entry.get("data0", 0) or 0)
    return max(1, int(data0))


def _tick_transport_state(state: RuntimeTransportState) -> None:
    now = time.monotonic()
    elapsed = max(0.0, min(2.0, now - float(state.last_tick)))
    state.last_tick = now
    if elapsed <= 0.0:
        return
    period = max(1, int(state.route_period_ms))
    if str(getattr(state, "shared_clock_key", "") or ""):
        state.path_progress_ms = float(_shared_route_phase_ms(state.shared_clock_key, period))
    else:
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

    period = max(1, int(state.route_period_ms or 1))
    progress = int(state.path_progress_ms) % period
    previous_progress = int(getattr(state, "last_timed_route_progress_ms", -1) or -1)
    state.last_timed_route_progress_ms = int(progress)
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
    lifecycle_state = _transport_lifecycle_for_segment(state, current, target, progress)
    state.map_id = int(current.map_id)
    if int(current.map_id) != int(target.map_id):
        _set_transport_lifecycle(
            state,
            TRANSPORT_STATE_TRANSFER_PENDING,
            node_index=int(current_index),
            progress_ms=int(progress),
            reason="transfer_node",
        )
        if ratio >= 1.0:
            state.node_index = int(target_index)
            state.map_id = int(target.map_id)
            state.x = float(target.x)
            state.y = float(target.y)
            state.z = float(target.z)
        _log_timed_route_node_events(state, previous_progress, progress, period, current_index)
        return

    dx = float(target.x) - float(current.x)
    dy = float(target.y) - float(current.y)
    dz = float(target.z) - float(current.z)
    state.x = float(current.x) + (dx * ratio)
    state.y = float(current.y) + (dy * ratio)
    state.z = float(current.z) + (dz * ratio)
    if abs(dx) > 0.001 or abs(dy) > 0.001:
        state.orientation = math.atan2(dy, dx)
    _set_transport_lifecycle(
        state,
        lifecycle_state,
        node_index=int(current_index),
        progress_ms=int(progress),
        reason="route_phase",
    )

    _log_timed_route_node_events(state, previous_progress, progress, period, current_index)


def _log_timed_route_node_events(
    state: RuntimeTransportState,
    previous_progress: int,
    progress: int,
    period: int,
    current_index: int,
) -> None:
    route = state.route
    if len(route) < 2:
        return

    if previous_progress < 0:
        _log_timed_route_node_event(state, int(current_index), int(progress), reason="initial")
        return

    crossed: list[int] = []
    previous = int(previous_progress)
    current = int(progress)
    route_period = max(1, int(period))
    if current >= previous:
        for index, node in enumerate(route):
            node_time = int(node.time_ms)
            if previous < node_time <= current:
                crossed.append(index)
    else:
        for index, node in enumerate(route):
            node_time = int(node.time_ms)
            if previous < node_time <= route_period:
                crossed.append(index)
        for index, node in enumerate(route):
            node_time = int(node.time_ms)
            if node_time > 0 and node_time <= current:
                crossed.append(index)

    if not crossed and int(current_index) != int(state.last_logged_node):
        crossed.append(int(current_index))

    for index in crossed:
        reason = "route_end" if int(index) == len(route) - 1 else "node"
        _log_timed_route_node_event(state, int(index), int(progress), reason=reason)


def _transport_lifecycle_for_segment(
    state: RuntimeTransportState,
    current: TransportRouteNode,
    target: TransportRouteNode,
    progress: int,
) -> str:
    if int(current.map_id) != int(target.map_id):
        return TRANSPORT_STATE_TRANSFER_PENDING

    route = state.route
    if len(route) < 2:
        return TRANSPORT_STATE_ACTIVE

    index = int(state.node_index)
    previous_index = (index - 1) % len(route)
    previous = route[previous_index]
    node_time = int(current.time_ms)
    next_time = int(target.time_ms)
    previous_time = int(previous.time_ms)
    if index == 0:
        previous_time = 0
    after_node_ms = max(0, int(progress) - node_time)
    to_next_ms = max(0, next_time - int(progress))
    arriving = bool(index > 0 and int(previous.map_id) == int(current.map_id) and after_node_ms <= 2_000)
    departing = bool(to_next_ms <= 2_000)
    docked = bool(next_time > node_time and after_node_ms <= 4_000)

    if arriving:
        return TRANSPORT_STATE_ARRIVING
    if docked:
        return TRANSPORT_STATE_DOCKED
    if departing:
        return TRANSPORT_STATE_DEPARTING
    _ = previous_time
    return TRANSPORT_STATE_ACTIVE


def _set_transport_lifecycle(
    state: RuntimeTransportState,
    lifecycle_state: str,
    *,
    node_index: int,
    progress_ms: int,
    reason: str,
) -> None:
    new_state = str(lifecycle_state or TRANSPORT_STATE_ACTIVE)
    old_state = str(getattr(state, "lifecycle_state", "") or "")
    if old_state == new_state:
        return
    state.previous_lifecycle_state = old_state
    state.lifecycle_state = new_state
    Logger.info(
        "[TransportState] guid=0x%016X entry=%s %s -> %s node=%s phase=%sms "
        "map=%s passengers=%s reason=%s",
        int(state.guid) & 0xFFFFFFFFFFFFFFFF,
        int(state.entry),
        old_state or "NONE",
        new_state,
        int(node_index),
        int(progress_ms),
        int(state.map_id),
        len(getattr(state, "passengers", set()) or set()),
        str(reason),
    )
    Logger.info(
        "[TransportPhase] guid=0x%016X entry=%s state=%s node=%s phase=%sms map=%s",
        int(state.guid) & 0xFFFFFFFFFFFFFFFF,
        int(state.entry),
        new_state,
        int(node_index),
        int(progress_ms),
        int(state.map_id),
    )
    if new_state == TRANSPORT_STATE_DOCKED:
        Logger.info(
            "[TransportDock] guid=0x%016X entry=%s node=%s phase=%sms map=%s",
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            int(state.entry),
            int(node_index),
            int(progress_ms),
            int(state.map_id),
        )


def _log_timed_route_node_event(
    state: RuntimeTransportState,
    node_index: int,
    progress: int,
    *,
    reason: str,
) -> None:
    route = state.route
    if not route:
        return
    index = max(0, min(len(route) - 1, int(node_index)))
    if index == int(state.last_logged_node) and str(reason) != "route_end":
        return

    node = route[index]
    state.last_logged_node = int(index)
    state.last_node_event_index = int(index)
    state.last_node_event_progress_ms = int(progress)
    state.last_node_event_reason = str(reason)
    Logger.info(
        "[WorldTransport] node world_guid=0x%016X entry=%s node=%s/%s "
        "map=%s pos=(%.2f %.2f %.2f) progress=%sms event=%s",
        int(state.guid) & 0xFFFFFFFFFFFFFFFF,
        int(state.entry),
        int(index),
        len(route),
        int(node.map_id),
        float(node.x),
        float(node.y),
        float(node.z),
        int(progress),
        str(reason),
    )
    if is_deeprun_tram_state(state):
        target = route[(index + 1) % len(route)]
        _log_deeprun_tram_node(state, node, target, index, progress)


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
            "[TransportElevator] node transition world_guid=0x%016X entry=%s node=%s/%s "
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
                "[TransportElevator] endpoint pause world_guid=0x%016X seconds=%.2f",
                int(state.guid) & 0xFFFFFFFFFFFFFFFF,
                float(target.wait_time),
            )
        Logger.info(
            "[TransportElevator] reverse direction world_guid=0x%016X next_node=%s",
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
            "[TransportElevator] transport tick world_guid=0x%016X entry=%s node=%s "
            "pos=(%.2f %.2f %.2f)",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(entry.get("entry", 0) or 0),
            int(state.node_index),
            float(entry.get("x", 0.0) or 0.0),
            float(entry.get("y", 0.0) or 0.0),
            float(entry.get("z", 0.0) or 0.0),
        )
    elif is_deeprun_tram_entry(entry):
        Logger.debug(
            "[Tram] transport tick world_guid=0x%016X node=%s phase=%sms "
            "pos=(%.2f %.2f %.2f) passenger_count=%s",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(state.node_index),
            int(state.path_progress_ms) & 0xFFFFFFFF,
            float(entry.get("x", 0.0) or 0.0),
            float(entry.get("y", 0.0) or 0.0),
            float(entry.get("z", 0.0) or 0.0),
            0,
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


def is_deeprun_tram_state(state: RuntimeTransportState) -> bool:
    return str(getattr(state, "route_kind", "") or "") == "deeprun_tram"


def _deeprun_station_name(node: TransportRouteNode) -> str:
    y = float(node.y)
    if y <= 100.0:
        return "stormwind"
    if y >= 2400.0:
        return "ironforge"
    return ""


def _log_deeprun_tram_node(
    state: RuntimeTransportState,
    current: TransportRouteNode,
    target: TransportRouteNode,
    current_index: int,
    progress: int,
) -> None:
    station = _deeprun_station_name(current)
    target_station = _deeprun_station_name(target)
    Logger.info(
        "[Tram] node reached world_guid=0x%016X node=%s/%s phase=%sms "
        "progress=%.3f pos=(%.2f %.2f %.2f) passenger_count=%s",
        int(state.guid) & 0xFFFFFFFFFFFFFFFF,
        int(current_index),
        len(state.route),
        int(progress),
        float(state.path_progress_ms) / float(max(1, state.route_period_ms)),
        float(state.x),
        float(state.y),
        float(state.z),
        0,
    )
    if station and station == target_station:
        Logger.info(
            "[Tram] station wait station=%s world_guid=0x%016X phase=%sms",
            station,
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            int(progress),
        )
    elif station:
        Logger.info(
            "[Tram] station depart station=%s world_guid=0x%016X phase=%sms",
            station,
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            int(progress),
        )
        Logger.info(
            "[Tram] route reverse station=%s world_guid=0x%016X",
            station,
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
        )
    elif target_station:
        Logger.info(
            "[Tram] station arrive station=%s world_guid=0x%016X phase=%sms",
            target_station,
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            int(progress),
        )
