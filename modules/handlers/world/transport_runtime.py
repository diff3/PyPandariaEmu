#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import struct
import threading
import time
from typing import Any

from shared.Logger import Logger
from shared.PathUtils import get_data_root
from server.modules.handlers.world.feature_config import (
    elevators_enabled,
    moving_transports_enabled,
    transport_movement_debug_enabled,
)
from server.modules.handlers.world.bootstrap.gameobjects import (
    _build_gameobject_update_payload,
    _build_gameobject_values_update_payload,
)
from server.modules.game.guid import GuidHelper, MoTransportGuid
from server.modules.handlers.world.bootstrap.playerobjects import make_update_object_response
from server.modules.handlers.world.movements.cache import get_movement_cache
from server.modules.handlers.world.movements.manager import get_movement_manager
from server.modules.handlers.world.movements.templates import build_template
from server.modules.handlers.world.movements.types import (
    MovementKind,
    MovementLifecycleEvent,
    MovementLifecycleEventType,
    MovementVisibilityState,
    MovementNode,
    InterpolationMode,
    PassengerAttachment,
    PassengerTransferState,
)

GAMEOBJECT_TYPE_TRANSPORT = 11
GAMEOBJECT_TYPE_MO_TRANSPORT = 15

TRANSPORT_STATE_ACTIVE = "ACTIVE"
TRANSPORT_STATE_TRANSFER_PENDING = "TRANSFER_PENDING"
TRANSPORT_STATE_DESPAWNED = "DESPAWNED"

TRANSPORT_VISIBILITY_ACTIVE = MovementVisibilityState.ACTIVE.value
TRANSPORT_VISIBILITY_WAITING = MovementVisibilityState.WAITING.value

ATTACH_STATE_DETACHED = "DETACHED"
ATTACH_STATE_ATTACHING = "ATTACHING"
ATTACH_STATE_ATTACHED = "ATTACHED"
ATTACH_STATE_DETACHING = "DETACHING"
ATTACH_STATE_TRANSFERRING = "TRANSFERRING"

ENABLE_TRANSPORT_RUNTIME_UPDATES = True
_TRANSPORT_TICK_SECONDS = 0.25
_TRANSPORT_VISIBILITY_RADIUS = 700.0
_DEFAULT_ROUTE_SPEED = 22.0
_DEFAULT_MO_TRANSPORT_PERIOD_MS = 180_000
_THREAD_IDLE_TIMEOUT_SECONDS = 20.0
_TRANSPORT_SEND_DISTANCE = 2.0
_TRANSPORT_CROSS_MAP_HOLD_SECONDS = 15.0
_TRANSPORT_CROSS_MAP_DISTANCE = 0.0
_WORLD_DB_TRANSPORT_VISIBILITY_RADIUS = 900.0
_DEEPRUN_TRAM_MAP_ID = 369
_DEEPRUN_TRAM_ENTRY = 194675
_DEEPRUN_TRAM_DISPLAY_ID = 8587
_ORGRIMMAR_ELEVATOR_ENTRIES = frozenset({
    219175, 219176, 219177, 220364,
})
_UNDERCITY_ELEVATOR_DOOR_ENTRIES = frozenset({
    20650, 20651, 20653, 20654, 20656, 20657,
})
_PHASELESS_ELEVATOR_MAP_ALIASES = {
    1136: 1,
}
_ZEPPELIN_NAME_TOKENS = ("zeppelin", "the thundercaller", "cloudkisser")
_ZEPPELIN_ENTRY_IDS = frozenset({176495, 186238})


def _transport_debug_log(message: str, *args) -> None:
    if not transport_movement_debug_enabled():
        return
    Logger.info(message, *args)


@dataclass(frozen=True)
class TransportRouteNode:
    map_id: int
    x: float
    y: float
    z: float
    wait_time: float = 0.0
    time_ms: int = 0
    transfer: bool = False


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
    flags: int = 0
    delay: int = 0


@dataclass
class RuntimeTransportState:
    guid: int
    entry: int
    spawn_guid: int
    display_id: int
    route: list[TransportRouteNode]
    node_index: int
    x: float
    y: float
    z: float
    orientation: float
    map_id: int
    tick_log_after: float = 0.0
    last_sent_x: float = float("inf")
    last_sent_y: float = float("inf")
    last_sent_z: float = float("inf")
    last_sent_map_id: int = -1
    path_progress_ms: float = 0.0
    timed_route: bool = False
    route_period_ms: int = 0
    shared_clock_key: str = ""
    affinity_map_id: int = -1
    lifecycle_state: str = TRANSPORT_STATE_ACTIVE
    previous_lifecycle_state: str = ""
    visibility_state: str = TRANSPORT_VISIBILITY_ACTIVE
    previous_visibility_state: str = ""
    last_event: str = ""
    transfer_active: bool = False
    transfer_destination_map: int | None = None
    lifecycle_events: tuple[MovementLifecycleEvent, ...] = ()
    last_node_index: int = -1
    passengers: dict[int, PassengerAttachment] | None = None
    pending_transfers: dict[int, PassengerTransferState] | None = None
    transport_db_guid: int = 0
    world_db_transport: bool = False
    clock_model: str = ""
    clock_started_at_ms: int = 0


class WorldTransportManager:
    def __init__(self) -> None:
        self.entries: dict[int, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_tick_log: float = 0.0
        self._last_snapshot_write: float = 0.0

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
            get_movement_manager().reset_for_tests()
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
            if transport_movement_debug_enabled():
                Logger.info(
                    "[TransportRegister] transport=0x%016X entry=%s map=%s source=%s",
                    world_guid & 0xFFFFFFFFFFFFFFFF,
                    int(transport_entry.get("entry", 0) or 0),
                    int(transport_entry.get("map", transport_entry.get("map_id", 0)) or 0),
                    str(source),
                )
            return state

    def _duplicate_runtime_guid_locked(self, entry: dict[str, Any]) -> int:
        if not is_runtime_transport_entry(entry):
            return 0

        entry_id = int(entry.get("entry", 0) or 0)
        map_id = int(entry.get("map", entry.get("map_id", 0)) or 0)
        x = round(float(entry.get("x", 0.0) or 0.0), 1)
        y = round(float(entry.get("y", 0.0) or 0.0), 1)

        for existing_guid, existing in self.entries.items():
            if not is_runtime_transport_entry(existing):
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

    def visibility_state_for_guid(self, world_guid: int) -> str:
        return _effective_transport_visibility_state(int(world_guid))

    def is_visible(self, world_guid: int) -> bool:
        return self.visibility_state_for_guid(int(world_guid)) in (
            TRANSPORT_VISIBILITY_ACTIVE,
            TRANSPORT_VISIBILITY_WAITING,
        )

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
        _sync_transport_state_from_movement_cache(state)
        if int(getattr(session, "map_id", 0) or 0) != int(state.map_id):
            Logger.warning(
                "[TransportAttach] denied reason=wrong_map transport=0x%016X player=%s "
                "player_map=%s transport_map=%s state=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(getattr(session, "char_guid", 0) or 0),
                int(getattr(session, "map_id", 0) or 0),
                int(state.map_id),
                _movement_lifecycle_state(world_guid),
            )
            return False
        visibility = self.visibility_state_for_guid(world_guid)
        if visibility not in (TRANSPORT_VISIBILITY_ACTIVE, TRANSPORT_VISIBILITY_WAITING):
            Logger.warning(
                "[TransportAttach] denied reason=visibility transport=0x%016X player=%s state=%s visibility=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(getattr(session, "char_guid", 0) or 0),
                _movement_lifecycle_state(world_guid),
                visibility,
            )
            return False
        return True

    def record_attach(self, session: Any, world_guid: int, *, opcode_name: str = "") -> None:
        state = self.state_for_guid(int(world_guid))
        char_guid = int(getattr(session, "char_guid", 0) or 0)
        if state is not None and char_guid > 0:
            movement_state = getattr(session, "movement_state", None)
            attach_transport_passenger(
                int(world_guid),
                char_guid,
                local_x=float(getattr(movement_state, "transport_x", 0.0) or 0.0),
                local_y=float(getattr(movement_state, "transport_y", 0.0) or 0.0),
                local_z=float(getattr(movement_state, "transport_z", 0.0) or 0.0),
                local_o=float(getattr(movement_state, "transport_orientation", 0.0) or 0.0),
                source_map=int(getattr(session, "map_id", 0) or 0),
            )
        session.transport_attach_state = ATTACH_STATE_ATTACHED
        session.transport_attach_timestamp = float(time.monotonic())
        session.transport_attach_source_map = int(getattr(session, "map_id", 0) or 0)
        Logger.info(
            "[TransportAttach] opcode=%s player=%s transport=0x%016X state=%s "
            "map=%s passengers=%s",
            str(opcode_name),
            char_guid,
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            _movement_lifecycle_state(int(world_guid)),
            int(getattr(session, "map_id", 0) or 0),
            _movement_passenger_count(int(world_guid)),
        )

    def record_detach(self, session: Any, world_guid: int, *, opcode_name: str = "", reason: str = "client") -> None:
        state = self.state_for_guid(int(world_guid))
        char_guid = int(getattr(session, "char_guid", 0) or 0)
        if state is not None and char_guid > 0:
            if str(reason) != "transfer":
                detach_transport_passenger(int(world_guid), char_guid)
        session.transport_attach_state = ATTACH_STATE_DETACHED
        if str(reason) != "transfer":
            movement_state = getattr(session, "movement_state", None)
            if movement_state is not None:
                movement_state.has_transport_data = False
                movement_state.transport_guid = 0
                movement_state.transport_x = 0.0
                movement_state.transport_y = 0.0
                movement_state.transport_z = 0.0
                movement_state.transport_orientation = 0.0
        Logger.info(
            "[TransportDetach] opcode=%s reason=%s player=%s transport=0x%016X "
            "state=%s map=%s passengers=%s",
            str(opcode_name),
            str(reason),
            char_guid,
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            _movement_lifecycle_state(int(world_guid)),
            int(getattr(session, "map_id", 0) or 0),
            _movement_passenger_count(int(world_guid)),
        )

    def entries_near(
        self,
        session: Any,
        *,
        loaded_guids: set[int] | None = None,
        radius: float = _TRANSPORT_VISIBILITY_RADIUS,
        context: str = "discovery",
    ) -> list[dict[str, Any]]:
        session_map = int(getattr(session, "map_id", 0) or 0)
        session_x = float(getattr(session, "x", 0.0) or 0.0)
        session_y = float(getattr(session, "y", 0.0) or 0.0)
        session_z = float(getattr(session, "z", 0.0) or 0.0)
        entries: list[dict[str, Any]] = []
        considered = 0
        visible_guids: list[int] = []
        rejected_guids: list[int] = []
        with self._lock:
            source_entries = list(self.entries.items())

        for world_guid, entry in source_entries:
            considered += 1
            state = _runtime_transport_states().get(int(world_guid))
            transport_entry = int(entry.get("entry", 0) or 0)
            visibility_state = self.visibility_state_for_guid(int(world_guid))
            if isinstance(loaded_guids, set) and int(world_guid) in loaded_guids:
                _log_transport_discovery_decision(
                    session,
                    world_guid=int(world_guid),
                    entry=transport_entry,
                    transport_map=int(getattr(state, "map_id", entry.get("map", session_map)) or session_map),
                    transport_x=float(getattr(state, "x", entry.get("x", 0.0)) or 0.0),
                    transport_y=float(getattr(state, "y", entry.get("y", 0.0)) or 0.0),
                    transport_z=float(getattr(state, "z", entry.get("z", 0.0)) or 0.0),
                    phase_ms=int(getattr(state, "phase_ms", entry.get("transport_path_progress", 0)) or 0),
                    state=_movement_lifecycle_state(int(world_guid)),
                    visibility_state=visibility_state,
                    distance=_transport_distance(
                        session_x,
                        session_y,
                        session_z,
                        float(getattr(state, "x", entry.get("x", 0.0)) or 0.0),
                        float(getattr(state, "y", entry.get("y", 0.0)) or 0.0),
                        float(getattr(state, "z", entry.get("z", 0.0)) or 0.0),
                    ),
                    visible=False,
                    reason="already_loaded",
                    context=context,
                )
                rejected_guids.append(int(world_guid))
                continue
            if not self.is_visible(int(world_guid)):
                Logger.debug(
                    "[TransportVisibility] stream skipped transport=0x%016X visibility=%s",
                    int(world_guid) & 0xFFFFFFFFFFFFFFFF,
                    self.visibility_state_for_guid(int(world_guid)),
                )
                _log_transport_discovery_decision(
                    session,
                    world_guid=int(world_guid),
                    entry=transport_entry,
                    transport_map=int(getattr(state, "map_id", entry.get("map", session_map)) or session_map),
                    transport_x=float(getattr(state, "x", entry.get("x", 0.0)) or 0.0),
                    transport_y=float(getattr(state, "y", entry.get("y", 0.0)) or 0.0),
                    transport_z=float(getattr(state, "z", entry.get("z", 0.0)) or 0.0),
                    phase_ms=int(getattr(state, "phase_ms", entry.get("transport_path_progress", 0)) or 0),
                    state=_movement_lifecycle_state(int(world_guid)),
                    visibility_state=visibility_state,
                    distance=_transport_distance(
                        session_x,
                        session_y,
                        session_z,
                        float(getattr(state, "x", entry.get("x", 0.0)) or 0.0),
                        float(getattr(state, "y", entry.get("y", 0.0)) or 0.0),
                        float(getattr(state, "z", entry.get("z", 0.0)) or 0.0),
                    ),
                    visible=False,
                    reason="runtime_missing" if state is None else "visibility_filter",
                    context=context,
                )
                rejected_guids.append(int(world_guid))
                continue
            home_map = entry.get("home_map")
            if state is None and home_map is not None and int(home_map) != session_map:
                _log_transport_discovery_decision(
                    session,
                    world_guid=int(world_guid),
                    entry=transport_entry,
                    transport_map=int(getattr(state, "map_id", entry.get("map", session_map)) or session_map),
                    transport_x=float(getattr(state, "x", entry.get("x", 0.0)) or 0.0),
                    transport_y=float(getattr(state, "y", entry.get("y", 0.0)) or 0.0),
                    transport_z=float(getattr(state, "z", entry.get("z", 0.0)) or 0.0),
                    phase_ms=int(getattr(state, "phase_ms", entry.get("transport_path_progress", 0)) or 0),
                    state=_movement_lifecycle_state(int(world_guid)),
                    visibility_state=visibility_state,
                    distance=_transport_distance(
                        session_x,
                        session_y,
                        session_z,
                        float(getattr(state, "x", entry.get("x", 0.0)) or 0.0),
                        float(getattr(state, "y", entry.get("y", 0.0)) or 0.0),
                        float(getattr(state, "z", entry.get("z", 0.0)) or 0.0),
                    ),
                    visible=False,
                    reason="map_mismatch",
                    context=context,
                )
                rejected_guids.append(int(world_guid))
                continue
            moved_entry = cached_transport_runtime_entry(session, entry)
            moved_map = moved_entry.get("map", session_map)
            if moved_map is None:
                moved_map = session_map
            if int(moved_map) != session_map:
                _log_transport_discovery_decision(
                    session,
                    world_guid=int(world_guid),
                    entry=transport_entry,
                    transport_map=int(moved_map),
                    transport_x=float(moved_entry.get("x", 0.0) or 0.0),
                    transport_y=float(moved_entry.get("y", 0.0) or 0.0),
                    transport_z=float(moved_entry.get("z", 0.0) or 0.0),
                    phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                    state=_movement_lifecycle_state(int(world_guid)),
                    visibility_state=visibility_state,
                    distance=_transport_distance(
                        session_x,
                        session_y,
                        session_z,
                        float(moved_entry.get("x", 0.0) or 0.0),
                        float(moved_entry.get("y", 0.0) or 0.0),
                        float(moved_entry.get("z", 0.0) or 0.0),
                    ),
                    visible=False,
                    reason="map_mismatch",
                    context=context,
                )
                rejected_guids.append(int(world_guid))
                continue
            dx = float(moved_entry.get("x", 0.0) or 0.0) - session_x
            dy = float(moved_entry.get("y", 0.0) or 0.0) - session_y
            distance = math.hypot(dx, dy)
            if distance > float(radius):
                _log_transport_discovery_decision(
                    session,
                    world_guid=int(world_guid),
                    entry=transport_entry,
                    transport_map=int(moved_map),
                    transport_x=float(moved_entry.get("x", 0.0) or 0.0),
                    transport_y=float(moved_entry.get("y", 0.0) or 0.0),
                    transport_z=float(moved_entry.get("z", 0.0) or 0.0),
                    phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                    state=_movement_lifecycle_state(int(world_guid)),
                    visibility_state=visibility_state,
                    distance=distance,
                    visible=False,
                    reason="distance",
                    context=context,
                )
                rejected_guids.append(int(world_guid))
                continue
            entries.append(moved_entry)
            visible_guids.append(int(world_guid))
            _log_transport_discovery_decision(
                session,
                world_guid=int(world_guid),
                entry=transport_entry,
                transport_map=int(moved_map),
                transport_x=float(moved_entry.get("x", 0.0) or 0.0),
                transport_y=float(moved_entry.get("y", 0.0) or 0.0),
                transport_z=float(moved_entry.get("z", 0.0) or 0.0),
                phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                state=_movement_lifecycle_state(int(world_guid)),
                visibility_state=visibility_state,
                distance=distance,
                visible=True,
                reason="accepted",
                context=context,
            )
            if transport_movement_debug_enabled():
                Logger.debug(
                    "[TransportStream] streamed transport=0x%016X player=%s phase=%s node=%s state=%s map=%s",
                    int(world_guid) & 0xFFFFFFFFFFFFFFFF,
                    int(getattr(session, "char_guid", 0) or 0),
                    int(moved_entry.get("transport_path_progress", 0) or 0),
                    int(getattr(_runtime_transport_states().get(int(world_guid)), "node_index", 0) or 0),
                    _movement_lifecycle_state(int(world_guid)),
                    int(session_map),
                )
        _log_transport_discovery_summary(
            session,
            considered=considered,
            visible_guids=visible_guids,
            rejected_guids=rejected_guids,
            context=context,
        )
        return entries

    def _run_loop(self) -> None:
        while True:
            with self._lock:
                if not self._running:
                    return
                states = list(_runtime_transport_states().items())
            for _world_guid, state in states:
                get_movement_manager().tick_instance(
                    int(_world_guid),
                    server_time_ms=_transport_server_time_ms(state),
                )
                _sync_transport_state_from_movement_cache(state)
            self._maybe_write_runtime_snapshot(states)
            self._log_tick(states)
            time.sleep(_TRANSPORT_TICK_SECONDS)

    def _maybe_write_runtime_snapshot(self, states: list[tuple[int, RuntimeTransportState]]) -> None:
        now = time.monotonic()
        if now < self._last_snapshot_write + 2.0:
            return
        self._last_snapshot_write = now
        write_world_runtime_snapshot(states)

    def _log_tick(self, states: list[tuple[int, RuntimeTransportState]]) -> None:
        if not transport_movement_debug_enabled():
            return
        now = time.monotonic()
        if now < self._last_tick_log + 5.0:
            return
        self._last_tick_log = now
        Logger.debug("[TransportManager] tick transports=%s", len(states))

    def _register_builtin_transports_locked(self) -> None:
        self._register_deeprun_trams_locked()
        self._register_world_db_transports_locked()
        self._register_world_db_elevators_locked()

    def _register_deeprun_trams_locked(self) -> None:
        # Deeprun Tram on map 369 is represented by DB-spawned type 11 gameobjects,
        # not by a runtime hardcoded transport registration.
        return

    def _register_world_db_transports_locked(self) -> None:
        for spec in _load_world_db_transports():
            route = _build_timed_taxi_transport_route(
                int(spec.get("path_id", 0) or 0),
                period_ms=int(spec.get("period", 0) or _DEFAULT_MO_TRANSPORT_PERIOD_MS),
            )
            if len(route) < 2:
                continue
            world_guid = int(
                MoTransportGuid.from_spawn_guid(int(spec.get("guid", 0) or 0))
            )
            entry = _entry_from_world_db_transport_spec(
                spec,
                world_guid=world_guid,
                route=route,
                start_index=0,
            )
            self.register_transport(entry, source="world-db")

    def _register_world_db_elevators_locked(self) -> None:
        if not elevators_enabled():
            return
        for entry in _load_world_db_elevator_entries():
            prepared = prepare_runtime_transport_entry(entry)
            world_guid = int(
                prepared.get("world_guid")
                or MoTransportGuid.from_spawn_guid(int(prepared.get("guid", 0) or 0))
            )
            prepared["world_guid"] = world_guid
            self.register_transport(prepared, source="world-db-elevator")

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
    if int(world_guid) in loaded_transports:
        Logger.info(
            "[TransportVisibility] duplicate visible registration suppressed transport=0x%016X player=%s",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(getattr(session, "char_guid", 0) or 0),
        )
        return True

    transport_entry = dict(entry)
    transport_entry["world_guid"] = int(world_guid)
    transport_entry["map"] = int(map_id)
    state = get_world_transport_manager().register_transport(transport_entry, source="stream")
    if state is None:
        Logger.warning(
            "[TransportVisibility] registration rejected transport=0x%016X player=%s reason=no_runtime_state",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(getattr(session, "char_guid", 0) or 0),
        )
        return False
    if state is not None and int(state.guid) != int(world_guid):
        return False
    if not get_world_transport_manager().is_visible(int(world_guid)):
        Logger.info(
            "[TransportVisibility] registration skipped transport=0x%016X player=%s visibility=%s",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(getattr(session, "char_guid", 0) or 0),
            get_world_transport_manager().visibility_state_for_guid(int(world_guid)),
        )
        return False
    loaded_transports[int(world_guid)] = transport_entry

    if ENABLE_TRANSPORT_RUNTIME_UPDATES:
        ensure_transport_runtime_for_session(session)
    _transport_debug_log(
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
    )


def _runtime_enabled_for_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    gameobject_type = int(entry.get("type", 0) or 0)
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


def is_deeprun_tram_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    return bool(
        entry.get("deeprun_tram")
        and int(entry.get("map", entry.get("map_id", -1)) or -1) == _DEEPRUN_TRAM_MAP_ID
        and int(entry.get("entry", 0) or 0) == _DEEPRUN_TRAM_ENTRY
    )


def is_cross_map_boat_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    if is_deeprun_tram_entry(entry):
        return False
    if int(entry.get("type", 0) or 0) != GAMEOBJECT_TYPE_MO_TRANSPORT:
        return False
    if not bool(entry.get("world_db_transport", False)):
        return False
    entry_id = int(entry.get("entry", 0) or 0)
    if entry_id in _ZEPPELIN_ENTRY_IDS:
        return False
    text = " ".join(
        str(value or "")
        for value in (
            entry.get("name"),
            entry.get("template_name"),
        )
    ).lower()
    if any(token in text for token in _ZEPPELIN_NAME_TOKENS):
        return False
    route = entry.get("runtime_route")
    if isinstance(route, (list, tuple)):
        maps = {
            int(node[0])
            for node in route
            if isinstance(node, (list, tuple)) and len(node) >= 1
        }
        if len(maps) >= 2:
            return True
    return True


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

    if animation is None:
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
    if animation is not None:
        prepared["client_driven_transport_animation"] = True
        prepared.setdefault("client_animation_base_map", int(prepared.get("map", 0) or 0))
        prepared.setdefault("client_animation_base_x", float(prepared.get("x", 0.0) or 0.0))
        prepared.setdefault("client_animation_base_y", float(prepared.get("y", 0.0) or 0.0))
        prepared.setdefault("client_animation_base_z", float(prepared.get("z", 0.0) or 0.0))
        prepared.setdefault(
            "client_animation_base_orientation",
            float(prepared.get("orientation", 0.0) or 0.0),
        )
    return prepared


def unregister_loaded_transport_entry(session: Any, world_guid: int) -> None:
    loaded_transports = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transports, dict):
        loaded_transports.pop(int(world_guid), None)


def clear_loaded_transport_entries(session: Any) -> None:
    loaded_transports = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transports, dict):
        loaded_transports.clear()


def _transport_distance(
    player_x: float,
    player_y: float,
    player_z: float,
    transport_x: float,
    transport_y: float,
    transport_z: float,
) -> float:
    _ = float(player_z), float(transport_z)
    return math.hypot(float(transport_x) - float(player_x), float(transport_y) - float(player_y))


def _format_transport_guid_list(guids: list[int]) -> str:
    return "[" + ",".join(f"0x{int(guid) & 0xFFFFFFFFFFFFFFFF:016X}" for guid in guids) + "]"


def _log_transport_discovery_decision(
    session: Any,
    *,
    world_guid: int,
    entry: int,
    transport_map: int,
    transport_x: float,
    transport_y: float,
    transport_z: float,
    phase_ms: int,
    state: str,
    visibility_state: str,
    distance: float,
    visible: bool,
    reason: str,
    context: str,
) -> None:
    _transport_debug_log(
        "[TRANSPORT_DISCOVERY] context=%s player_guid=%s player_map=%s "
        "player_pos=(%.3f %.3f %.3f) transport_guid=0x%016X entry=%s "
        "transport_map=%s transport_pos=(%.3f %.3f %.3f) phase_ms=%s "
        "state=%s visibility_state=%s distance=%.3f visible=%s reason=%s",
        str(context or "unknown"),
        int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or 0),
        int(getattr(session, "map_id", 0) or 0),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(entry),
        int(transport_map),
        float(transport_x),
        float(transport_y),
        float(transport_z),
        int(phase_ms),
        str(state or "unknown"),
        str(visibility_state or "unknown"),
        float(distance),
        "yes" if bool(visible) else "no",
        str(reason or "unknown"),
    )


def _log_transport_discovery_summary(
    session: Any,
    *,
    considered: int,
    visible_guids: list[int],
    rejected_guids: list[int],
    context: str,
) -> None:
    _transport_debug_log(
        "[TRANSPORT_DISCOVERY_SUMMARY] context=%s player_guid=%s "
        "transports_considered=%s transports_visible=%s transports_rejected=%s "
        "visible_guids=%s rejected_guids=%s",
        str(context or "unknown"),
        int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or 0),
        int(considered),
        len(visible_guids),
        len(rejected_guids),
        _format_transport_guid_list(visible_guids),
        _format_transport_guid_list(rejected_guids),
    )


def synthetic_transport_entries_near(
    session: Any,
    *,
    loaded_guids: set[int] | None = None,
    context: str = "discovery",
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
        context=context,
    )
    return entries


def _same_map_transport_spawn_guid(transport_guid: int, *, map_id: int) -> int:
    return (max(0, int(map_id)) * 100_000) + int(transport_guid)


def _shared_route_phase_ms(clock_key: str, period_ms: int) -> int:
    _ = str(clock_key or "")
    period = max(1, int(period_ms or 1))
    return _transport_epoch_ms() % period


_REFERENCE_TRANSPORT_CLOCK_MODEL = "reference-diff"
_SHARED_TRANSPORT_CLOCK_MODEL = "shared-wall-clock"
_TRANSPORT_EVALUATOR_PHASE_BIAS_MS = 11500


def _transport_epoch_ms() -> int:
    """Authoritative wall-clock transport epoch shared by runtime observers."""
    return int(time.time() * 1000.0)


def _transport_monotonic_ms() -> int:
    return int(time.monotonic() * 1000.0)


def _is_reference_clock_transport_state(state: RuntimeTransportState) -> bool:
    return str(getattr(state, "clock_model", "") or "") == _REFERENCE_TRANSPORT_CLOCK_MODEL


def _transport_base_guid(entry: dict[str, Any]) -> int:
    for key in ("transport_db_guid", "source_transport_guid"):
        value = int(entry.get(key, 0) or 0)
        if value > 0:
            return value

    spawn_guid = int(entry.get("guid", 0) or 0)
    if spawn_guid >= 100_000:
        base_guid = int(spawn_guid) % 100_000
        if base_guid > 0:
            return base_guid
    return spawn_guid


def _canonical_runtime_state_for_entry(
    session: Any,
    entry: dict[str, Any],
    *,
    current_world_guid: int,
    current_state: RuntimeTransportState | None,
) -> RuntimeTransportState | None:
    current_phase = int(
        getattr(current_state, "path_progress_ms", entry.get("transport_path_progress", 0)) or 0
    )

    base_guid = _transport_base_guid(entry)
    spawn_guid = int(entry.get("guid", 0) or 0)
    is_map_clone_alias = bool(spawn_guid >= 100_000 and base_guid > 0 and spawn_guid != base_guid)
    if not is_map_clone_alias:
        return current_state
    if current_phase > 0 and current_state is not None and int(current_state.spawn_guid) == int(base_guid):
        return current_state

    entry_id = int(entry.get("entry", 0) or 0)
    session_map = int(getattr(session, "map_id", entry.get("map", 0)) or 0)
    if base_guid <= 0 or entry_id <= 0:
        return current_state

    best_state = current_state
    best_distance = float("inf")
    session_x = float(getattr(session, "x", 0.0) or 0.0)
    session_y = float(getattr(session, "y", 0.0) or 0.0)
    for candidate_guid, candidate in list(_runtime_transport_states().items()):
        if int(candidate_guid) == int(current_world_guid):
            continue
        if int(candidate.entry) != int(entry_id):
            continue
        if int(candidate.spawn_guid) != int(base_guid):
            candidate_entry = get_world_transport_manager().entry_for_guid(int(candidate_guid))
            candidate_base = _transport_base_guid(candidate_entry or {})
            if int(candidate_base) != int(base_guid):
                continue
        _sync_transport_state_from_movement_cache(candidate)
        if int(candidate.map_id) != int(session_map):
            continue
        if int(candidate.path_progress_ms or 0) <= 0:
            continue
        distance = _transport_distance(
            session_x,
            session_y,
            float(getattr(session, "z", 0.0) or 0.0),
            float(candidate.x),
            float(candidate.y),
            float(candidate.z),
        )
        if distance < best_distance:
            best_state = candidate
            best_distance = float(distance)

    if best_state is not current_state and best_state is not None:
        Logger.info(
            "[TransportBootstrap] using authoritative runtime transport "
            "clone=0x%016X authoritative=0x%016X entry=%s phase=%s",
            int(current_world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(best_state.guid) & 0xFFFFFFFFFFFFFFFF,
            int(entry_id),
            int(best_state.path_progress_ms or 0),
        )
    return best_state


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


def attach_transport_passenger(
    world_guid: int,
    passenger_id: int,
    *,
    local_x: float = 0.0,
    local_y: float = 0.0,
    local_z: float = 0.0,
    local_o: float = 0.0,
    source_map: int = 0,
) -> bool:
    state = runtime_transport_state_for_guid(int(world_guid))
    if state is None:
        return False
    if state.passengers is None:
        state.passengers = {}
    if int(passenger_id) in state.passengers:
        Logger.warning(
            "[TransportPassenger] duplicate attach transport=0x%016X passenger=%s",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
        )
    state.passengers[int(passenger_id)] = PassengerAttachment(
        passenger_id=int(passenger_id),
        local_x=float(local_x),
        local_y=float(local_y),
        local_z=float(local_z),
        local_o=float(local_o),
        source_map=int(source_map),
        attached_at_ms=int(time.monotonic() * 1000.0),
    )
    Logger.info(
        "[TransportPassenger] attach transport=0x%016X passenger=%s count=%s",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(passenger_id),
        len(state.passengers),
    )
    return True


def detach_transport_passenger(world_guid: int, passenger_id: int) -> bool:
    state = runtime_transport_state_for_guid(int(world_guid))
    if state is None or state.passengers is None:
        return False
    existed = int(passenger_id) in state.passengers
    if not existed:
        Logger.warning(
            "[TransportPassenger] detach without attach transport=0x%016X passenger=%s",
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
        )
    state.passengers.pop(int(passenger_id), None)
    Logger.info(
        "[TransportPassenger] detach transport=0x%016X passenger=%s count=%s",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(passenger_id),
        len(state.passengers),
    )
    return existed


def transport_passenger_attachment(
    world_guid: int,
    passenger_id: int,
) -> PassengerAttachment | None:
    state = runtime_transport_state_for_guid(int(world_guid))
    if state is None or state.passengers is None:
        return None
    return state.passengers.get(int(passenger_id))


def begin_transport_passenger_transfer(
    source_world_guid: int,
    destination_world_guid: int,
    passenger_id: int,
    *,
    target_map_id: int,
) -> PassengerTransferState | None:
    source = runtime_transport_state_for_guid(int(source_world_guid))
    if source is None or source.passengers is None:
        Logger.warning(
            "[TransportPassenger] transfer without valid source transport=0x%016X passenger=%s",
            int(source_world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
        )
        return None
    attachment = source.passengers.pop(int(passenger_id), None)
    if attachment is None:
        Logger.warning(
            "[TransportPassenger] transfer without attach transport=0x%016X passenger=%s",
            int(source_world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
        )
        return None
    if source.pending_transfers is None:
        source.pending_transfers = {}
    transfer = PassengerTransferState(
        passenger_id=int(passenger_id),
        source_instance_id=int(source_world_guid),
        destination_instance_id=int(destination_world_guid),
        target_map_id=int(target_map_id),
        local_x=float(attachment.local_x),
        local_y=float(attachment.local_y),
        local_z=float(attachment.local_z),
        local_o=float(attachment.local_o),
        started_at_ms=int(time.monotonic() * 1000.0),
    )
    source.pending_transfers[int(passenger_id)] = transfer
    Logger.info(
        "[TransportPassenger] transfer begin source=0x%016X dest=0x%016X passenger=%s map=%s",
        int(source_world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(destination_world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(passenger_id),
        int(target_map_id),
    )
    return transfer


def complete_transport_passenger_transfer(
    source_world_guid: int,
    passenger_id: int,
) -> PassengerTransferState | None:
    source = runtime_transport_state_for_guid(int(source_world_guid))
    if source is None or source.pending_transfers is None:
        Logger.warning(
            "[TransportPassenger] transfer complete without pending source=0x%016X passenger=%s",
            int(source_world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
        )
        return None
    transfer = source.pending_transfers.pop(int(passenger_id), None)
    if transfer is None:
        Logger.warning(
            "[TransportPassenger] transfer complete missing passenger source=0x%016X passenger=%s",
            int(source_world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
        )
        return None
    attach_transport_passenger(
        int(transfer.destination_instance_id),
        int(passenger_id),
        local_x=float(transfer.local_x),
        local_y=float(transfer.local_y),
        local_z=float(transfer.local_z),
        local_o=float(transfer.local_o),
        source_map=int(transfer.target_map_id),
    )
    Logger.info(
        "[TransportPassenger] transfer complete source=0x%016X dest=0x%016X passenger=%s",
        int(source_world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(transfer.destination_instance_id) & 0xFFFFFFFFFFFFFFFF,
        int(passenger_id),
    )
    return transfer


def transport_transfer_destination_map_for_guid(world_guid: int) -> int | None:
    state = runtime_transport_state_for_guid(int(world_guid))
    if state is None:
        return None
    if bool(getattr(state, "transfer_active", False)):
        active_destination_map = getattr(state, "transfer_destination_map", None)
        if active_destination_map is not None:
            return int(active_destination_map)
    _sync_transport_state_from_movement_cache(state)
    latest_events = tuple(getattr(state, "lifecycle_events", ()) or ())
    latest_event = latest_events[-1] if latest_events else None
    if (
        latest_event is None
        or latest_event.event_type != MovementLifecycleEventType.TRANSFER_BEGIN
    ):
        if bool(getattr(state, "transfer_active", False)):
            active_destination_map = getattr(state, "transfer_destination_map", None)
            if active_destination_map is not None:
                return int(active_destination_map)
        return None
    destination_map = getattr(state, "transfer_destination_map", None)
    if destination_map is None:
        return None
    return int(destination_map)


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


def ensure_linked_transport_destination_entry(
    source_entry: dict[str, Any],
    *,
    destination_map: int,
    source_state: RuntimeTransportState | None = None,
) -> dict[str, Any]:
    """Ensure the destination-side transport instance exists before passenger reattach."""
    # TODO: Move destination-side transport ownership into WorldTransportManager once
    # map-local transport streaming no longer has to bridge legacy loaded GO state.
    destination_entry = build_linked_transport_destination_entry(
        source_entry,
        destination_map=int(destination_map),
    )
    if source_state is not None:
        destination_entry.setdefault("runtime_route", [
            (
                int(node.map_id),
                float(node.x),
                float(node.y),
                float(node.z),
                float(node.wait_time),
                int(node.time_ms),
            )
            for node in getattr(source_state, "route", ()) or ()
        ])
        destination_entry.setdefault(
            "transport_period",
            int(getattr(source_state, "route_period_ms", 0) or 0),
        )
        destination_entry.setdefault(
            "shared_route_clock_key",
            str(getattr(source_state, "shared_clock_key", "") or ""),
        )

    state = get_world_transport_manager().register_transport(
        destination_entry,
        source="transfer-destination",
    )
    if state is not None:
        _sync_transport_state_from_movement_cache(state)
        Logger.info(
            "[TransportTransfer] destination ready transport=0x%016X map=%s "
            "phase=%s node=%s passengers=%s",
            int(destination_entry.get("world_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
            int(destination_map),
            int(getattr(state, "path_progress_ms", 0) or 0),
            int(getattr(state, "node_index", 0) or 0),
            _movement_passenger_count(int(destination_entry.get("world_guid", 0) or 0)),
        )
    else:
        Logger.warning(
            "[TransportTransfer] destination registration failed transport=0x%016X map=%s entry=%s",
            int(destination_entry.get("world_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
            int(destination_map),
            int(destination_entry.get("entry", 0) or 0),
        )
    return destination_entry


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


def cached_transport_runtime_entry(session: Any, entry: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of entry with the cached authoritative transport coordinates."""
    if not is_runtime_transport_entry(entry):
        return entry
    if not _runtime_enabled_for_entry(entry):
        return entry
    if not ENABLE_TRANSPORT_RUNTIME_UPDATES:
        return entry

    world_guid = int(entry.get("world_guid", 0) or 0)
    state = _runtime_transport_states().get(int(world_guid))
    if state is None:
        missed_entry = dict(entry)
        missed_entry.setdefault("_transport_create_source_path", "database")
        missed_entry["_transport_runtime_state_found"] = False
        return missed_entry
    state = _canonical_runtime_state_for_entry(
        session,
        entry,
        current_world_guid=world_guid,
        current_state=state,
    )
    if state is not None:
        world_guid = int(state.guid)

    moved_entry = dict(entry)
    moved_entry["map"] = int(state.map_id)
    moved_entry["x"] = float(state.x)
    moved_entry["y"] = float(state.y)
    moved_entry["z"] = float(state.z)
    moved_entry["orientation"] = float(state.orientation)
    moved_entry["world_guid"] = world_guid
    moved_entry["_transport_create_source_path"] = "runtime"
    moved_entry["_transport_runtime_state_found"] = True
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
    _transport_debug_log(
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
        _transport_debug_log(
            "[WorldTransport] runtime stop char=%s",
            int(getattr(session, "char_guid", 0) or 0),
        )


def _build_visible_transport_updates(
    session: Any,
    entries: dict[int, dict[str, Any]],
    *,
    force: bool = False,
    context: str = "runtime_update",
) -> list[tuple[str, bytes]]:
    if not bool(getattr(session, "gameobjects_visible", True)):
        _log_transport_discovery_summary(
            session,
            considered=0,
            visible_guids=[],
            rejected_guids=[],
            context=f"{context}_session_filter",
        )
        return []

    session_map = int(getattr(session, "map_id", 0) or 0)
    session_x = float(getattr(session, "x", 0.0) or 0.0)
    session_y = float(getattr(session, "y", 0.0) or 0.0)
    session_z = float(getattr(session, "z", 0.0) or 0.0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    responses: list[tuple[str, bytes]] = []
    considered = 0
    visible_guids: list[int] = []
    rejected_guids: list[int] = []
    started_transport_transfer = False

    for world_guid, entry in list(entries.items()):
        considered += 1
        state = _runtime_transport_states().get(int(world_guid))
        if state is not None:
            _sync_transport_state_from_movement_cache(state)
        if not get_world_transport_manager().is_visible(int(world_guid)):
            _log_transport_discovery_decision(
                session,
                world_guid=int(world_guid),
                entry=int(entry.get("entry", 0) or 0),
                transport_map=int(getattr(state, "map_id", entry.get("map", session_map)) or session_map),
                transport_x=float(getattr(state, "x", entry.get("x", 0.0)) or 0.0),
                transport_y=float(getattr(state, "y", entry.get("y", 0.0)) or 0.0),
                transport_z=float(getattr(state, "z", entry.get("z", 0.0)) or 0.0),
                phase_ms=int(getattr(state, "phase_ms", entry.get("transport_path_progress", 0)) or 0),
                state=_movement_lifecycle_state(int(world_guid)),
                visibility_state=get_world_transport_manager().visibility_state_for_guid(int(world_guid)),
                distance=_transport_distance(
                    session_x,
                    session_y,
                    session_z,
                    float(getattr(state, "x", entry.get("x", 0.0)) or 0.0),
                    float(getattr(state, "y", entry.get("y", 0.0)) or 0.0),
                    float(getattr(state, "z", entry.get("z", 0.0)) or 0.0),
                ),
                visible=False,
                reason="runtime_missing" if state is None else "visibility_filter",
                context=context,
            )
            rejected_guids.append(int(world_guid))
            transfer_responses = _maybe_start_passenger_transport_transfer(
                session,
                int(world_guid),
                reason="visibility",
            )
            if transfer_responses:
                responses.extend(transfer_responses)
                started_transport_transfer = True
                continue
            responses.extend(
                _despawn_loaded_transport(
                    session,
                    entries,
                    int(world_guid),
                    map_id=session_map,
                    reason="lifecycle",
                )
            )
            continue

        moved_entry = cached_transport_runtime_entry(session, entry)
        moved_map = int(
            moved_entry.get("map")
            if moved_entry.get("map") is not None
            else session_map
        )
        if state is not None and not force and not _should_send_transport_update(state):
            if moved_map != session_map:
                _log_transport_discovery_decision(
                    session,
                    world_guid=int(world_guid),
                    entry=int(moved_entry.get("entry", entry.get("entry", 0)) or 0),
                    transport_map=moved_map,
                    transport_x=float(moved_entry.get("x", 0.0) or 0.0),
                    transport_y=float(moved_entry.get("y", 0.0) or 0.0),
                    transport_z=float(moved_entry.get("z", 0.0) or 0.0),
                    phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                    state=_movement_lifecycle_state(int(world_guid)),
                    visibility_state=get_world_transport_manager().visibility_state_for_guid(int(world_guid)),
                    distance=_transport_distance(
                        session_x,
                        session_y,
                        session_z,
                        float(moved_entry.get("x", 0.0) or 0.0),
                        float(moved_entry.get("y", 0.0) or 0.0),
                        float(moved_entry.get("z", 0.0) or 0.0),
                    ),
                    visible=False,
                    reason="map_mismatch",
                    context=context,
                )
                rejected_guids.append(int(world_guid))
                transfer_responses = _maybe_start_passenger_transport_transfer(
                    session,
                    int(world_guid),
                    reason="map",
                    forced_destination_map=moved_map,
                )
                if transfer_responses:
                    responses.extend(transfer_responses)
                    started_transport_transfer = True
                    continue
                responses.extend(
                    _despawn_loaded_transport(
                        session,
                        entries,
                        int(world_guid),
                        map_id=session_map,
                        reason="map",
                    )
                )
                continue
            _log_transport_discovery_decision(
                session,
                world_guid=int(world_guid),
                entry=int(moved_entry.get("entry", entry.get("entry", 0)) or 0),
                transport_map=int(moved_entry.get("map", session_map) or session_map),
                transport_x=float(moved_entry.get("x", 0.0) or 0.0),
                transport_y=float(moved_entry.get("y", 0.0) or 0.0),
                transport_z=float(moved_entry.get("z", 0.0) or 0.0),
                phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                state=_movement_lifecycle_state(int(world_guid)),
                visibility_state=get_world_transport_manager().visibility_state_for_guid(int(world_guid)),
                distance=_transport_distance(
                    session_x,
                    session_y,
                    session_z,
                    float(moved_entry.get("x", 0.0) or 0.0),
                    float(moved_entry.get("y", 0.0) or 0.0),
                    float(moved_entry.get("z", 0.0) or 0.0),
                ),
                visible=False,
                reason="not_streamable",
                context=context,
            )
            rejected_guids.append(int(world_guid))
            continue
        if moved_map != session_map:
            _log_transport_discovery_decision(
                session,
                world_guid=int(world_guid),
                entry=int(moved_entry.get("entry", entry.get("entry", 0)) or 0),
                transport_map=moved_map,
                transport_x=float(moved_entry.get("x", 0.0) or 0.0),
                transport_y=float(moved_entry.get("y", 0.0) or 0.0),
                transport_z=float(moved_entry.get("z", 0.0) or 0.0),
                phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                state=_movement_lifecycle_state(int(world_guid)),
                visibility_state=get_world_transport_manager().visibility_state_for_guid(int(world_guid)),
                distance=_transport_distance(
                    session_x,
                    session_y,
                    session_z,
                    float(moved_entry.get("x", 0.0) or 0.0),
                    float(moved_entry.get("y", 0.0) or 0.0),
                    float(moved_entry.get("z", 0.0) or 0.0),
                ),
                visible=False,
                reason="map_mismatch",
                context=context,
            )
            rejected_guids.append(int(world_guid))
            transfer_responses = _maybe_start_passenger_transport_transfer(
                session,
                int(world_guid),
                reason="map",
            )
            if transfer_responses:
                responses.extend(transfer_responses)
                started_transport_transfer = True
                continue
            responses.extend(
                _despawn_loaded_transport(
                    session,
                    entries,
                    int(world_guid),
                    map_id=session_map,
                    reason="map",
                )
            )
            continue

        dx = float(moved_entry.get("x", 0.0) or 0.0) - session_x
        dy = float(moved_entry.get("y", 0.0) or 0.0) - session_y
        distance = math.hypot(dx, dy)
        if distance > _TRANSPORT_VISIBILITY_RADIUS:
            _log_transport_discovery_decision(
                session,
                world_guid=int(world_guid),
                entry=int(moved_entry.get("entry", entry.get("entry", 0)) or 0),
                transport_map=int(moved_entry.get("map", session_map) or session_map),
                transport_x=float(moved_entry.get("x", 0.0) or 0.0),
                transport_y=float(moved_entry.get("y", 0.0) or 0.0),
                transport_z=float(moved_entry.get("z", 0.0) or 0.0),
                phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                state=_movement_lifecycle_state(int(world_guid)),
                visibility_state=get_world_transport_manager().visibility_state_for_guid(int(world_guid)),
                distance=distance,
                visible=False,
                reason="distance",
                context=context,
            )
            rejected_guids.append(int(world_guid))
            continue

        loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
        already_loaded = isinstance(loaded_gameobjects, set) and int(world_guid) in loaded_gameobjects
        if already_loaded:
            payload = _build_gameobject_values_update_payload(
                map_id=session_map,
                entry=moved_entry,
                realm_id=realm_id,
            )
        else:
            payload = _build_gameobject_update_payload(
                map_id=session_map,
                entry=moved_entry,
                realm_id=realm_id,
            )
            if isinstance(loaded_gameobjects, set):
                loaded_gameobjects.add(int(world_guid))
        responses.append(make_update_object_response(payload))
        visible_guids.append(int(world_guid))
        _log_transport_discovery_decision(
            session,
            world_guid=int(world_guid),
            entry=int(moved_entry.get("entry", entry.get("entry", 0)) or 0),
            transport_map=int(moved_entry.get("map", session_map) or session_map),
            transport_x=float(moved_entry.get("x", 0.0) or 0.0),
            transport_y=float(moved_entry.get("y", 0.0) or 0.0),
            transport_z=float(moved_entry.get("z", 0.0) or 0.0),
            phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
            state=_movement_lifecycle_state(int(world_guid)),
            visibility_state=get_world_transport_manager().visibility_state_for_guid(int(world_guid)),
            distance=distance,
            visible=True,
            reason="accepted",
            context=context,
        )
        if state is not None:
            _mark_transport_update_sent(state)
        _maybe_log_transport_tick(int(world_guid), moved_entry)

    _log_transport_discovery_summary(
        session,
        considered=considered,
        visible_guids=visible_guids,
        rejected_guids=rejected_guids,
        context=context,
    )
    if not started_transport_transfer:
        responses.extend(
            _build_new_visible_transport_creates(
                session,
                entries,
                context=f"{context}_lifecycle_spawn",
            )
        )
    return responses


def _build_new_visible_transport_creates(
    session: Any,
    entries: dict[int, dict[str, Any]],
    *,
    context: str,
) -> list[tuple[str, bytes]]:
    """Create transports that became visible after lifecycle despawns."""
    loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    if isinstance(loaded_gameobjects, set):
        loaded_guids = set(int(guid) for guid in loaded_gameobjects)
    else:
        loaded_guids = set(int(guid) for guid in entries)

    responses: list[tuple[str, bytes]] = []
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    map_id = int(getattr(session, "map_id", 0) or 0)
    for entry in synthetic_transport_entries_near(
        session,
        loaded_guids=loaded_guids,
        context=context,
    ):
        world_guid = int(entry.get("world_guid", 0) or 0)
        if world_guid <= 0 or world_guid in entries:
            continue
        if not register_loaded_transport_entry(
            session,
            entry,
            world_guid=world_guid,
            map_id=int(entry.get("map", map_id) or map_id),
        ):
            continue
        entries[world_guid] = dict(entry)
        if isinstance(loaded_gameobjects, set):
            loaded_gameobjects.add(world_guid)
        payload = _build_gameobject_update_payload(
            map_id=map_id,
            entry=entry,
            realm_id=realm_id,
        )
        responses.append(make_update_object_response(payload))
        loaded_guids.add(world_guid)
        Logger.info(
            "[TransportLifecycle] spawn transport=0x%016X player=%s map=%s context=%s",
            world_guid & 0xFFFFFFFFFFFFFFFF,
            int(getattr(session, "char_guid", 0) or 0),
            map_id,
            str(context),
        )
    return responses


def build_bootstrap_transport_value_updates(
    session: Any,
    *,
    context: str = "worldport_bootstrap",
) -> list[tuple[str, bytes]]:
    entries = getattr(session, "loaded_transport_entries", None)
    if not isinstance(entries, dict) or not entries:
        Logger.info(
            "[WORLDPORT_TRANSPORT] context=%s player_guid=0x%X map=%s x=%.3f y=%.3f z=%.3f transports=0",
            str(context),
            int(getattr(session, "world_guid", 0) or 0),
            int(getattr(session, "map_id", 0) or 0),
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
        )
        return []

    loaded_before = set(getattr(session, "loaded_gameobjects", set()) or set())
    responses = _build_visible_transport_updates(
        session,
        entries,
        force=True,
        context=context,
    )
    loaded_after = set(getattr(session, "loaded_gameobjects", set()) or set())
    for world_guid, entry in sorted(entries.items()):
        state = _runtime_transport_states().get(int(world_guid))
        Logger.info(
            "[WORLDPORT_TRANSPORT] context=%s player_guid=0x%X map=%s x=%.3f y=%.3f z=%.3f "
            "transport_guid=0x%016X entry=%s phase=%s position=(%.3f %.3f %.3f) "
            "loaded_before=%s loaded_after=%s",
            str(context),
            int(getattr(session, "world_guid", 0) or 0),
            int(getattr(session, "map_id", 0) or 0),
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(entry.get("entry", 0) or 0) if isinstance(entry, dict) else 0,
            int(getattr(state, "phase_ms", entry.get("transport_path_progress", 0)) or 0)
            if isinstance(entry, dict)
            else int(getattr(state, "phase_ms", 0) or 0),
            float(getattr(state, "x", entry.get("x", 0.0)) or 0.0)
            if isinstance(entry, dict)
            else float(getattr(state, "x", 0.0) or 0.0),
            float(getattr(state, "y", entry.get("y", 0.0)) or 0.0)
            if isinstance(entry, dict)
            else float(getattr(state, "y", 0.0) or 0.0),
            float(getattr(state, "z", entry.get("z", 0.0)) or 0.0)
            if isinstance(entry, dict)
            else float(getattr(state, "z", 0.0) or 0.0),
            int(world_guid) in loaded_before,
            int(world_guid) in loaded_after,
        )
    return responses


def _maybe_start_passenger_transport_transfer(
    session: Any,
    world_guid: int,
    *,
    reason: str,
    forced_destination_map: int | None = None,
) -> list[tuple[str, bytes]]:
    _log_transport_transfer_readiness(session, int(world_guid), reason=reason)
    attached = _session_is_transport_passenger(session, int(world_guid))
    movement_state = getattr(session, "movement_state", None)
    player_guid = int(getattr(session, "char_guid", 0) or 0)
    runtime_state = _runtime_transport_states().get(int(world_guid))
    loaded_entries = getattr(session, "loaded_transport_entries", None)
    entry = authoritative_transport_entry_for_guid(int(world_guid))
    if entry is None and isinstance(loaded_entries, dict):
        loaded_entry = loaded_entries.get(int(world_guid))
        if isinstance(loaded_entry, dict):
            entry = dict(loaded_entry)
    cross_map_boat = is_cross_map_boat_entry(entry)
    session_map = getattr(session, "map_id", None)
    destination_map = (
        getattr(runtime_state, "transfer_destination_map", None)
        if runtime_state is not None
        else None
    )
    try:
        runtime_attached = (
            transport_passenger_attachment(int(world_guid), player_guid) is not None
            if player_guid > 0
            else False
        )
    except Exception:
        runtime_attached = False

    def _log_transfer_exit(exit_reason: str, *, error: Exception | None = None) -> None:
        Logger.info(
            "[TRANSPORT_TRANSFER_GUARD] reason=%s trigger=%s transport_guid=0x%016X "
            "player_guid=%s destination_map=%s attached=%s runtime_attached=%s "
            "session_map=%s has_transport_data=%s movement_transport_guid=0x%016X "
            "transport_transfer_pending=%s worldport_ack_pending=%s attach_state=%s error=%s",
            str(exit_reason),
            str(reason),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            player_guid,
            "none" if destination_map is None else int(destination_map),
            bool(attached),
            bool(runtime_attached),
            "none" if session_map is None else int(session_map),
            bool(getattr(movement_state, "has_transport_data", False)),
            int(getattr(movement_state, "transport_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
            bool(getattr(session, "transport_transfer_pending", False)),
            bool(getattr(session, "worldport_ack_pending", False)),
            str(getattr(session, "transport_attach_state", "") or ""),
            "" if error is None else str(error),
        )

    Logger.info(
        "[ORIENTATION_WRITE_AUDIT] event=transport_transfer_check reason=%s "
        "player=%s transport=0x%016X player_attached_to_transport=%s "
        "session_orientation=%.6f movement_orientation=%.6f "
        "transport_offset=(%.3f %.3f %.3f) transport_orientation=%.6f attach_state=%s",
        str(reason),
        int(getattr(session, "char_guid", 0) or 0),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        bool(attached),
        float(getattr(session, "orientation", 0.0) or 0.0),
        float(getattr(movement_state, "orientation", getattr(session, "orientation", 0.0)) or 0.0),
        float(getattr(movement_state, "transport_x", 0.0) or 0.0),
        float(getattr(movement_state, "transport_y", 0.0) or 0.0),
        float(getattr(movement_state, "transport_z", 0.0) or 0.0),
        float(getattr(movement_state, "transport_orientation", 0.0) or 0.0),
        str(getattr(session, "transport_attach_state", "") or ""),
    )
    if cross_map_boat and not attached and runtime_attached and movement_state is not None:
        attachment = transport_passenger_attachment(int(world_guid), int(player_guid))
        if attachment is not None:
            movement_state.has_transport_data = True
            movement_state.transport_guid = int(world_guid)
            movement_state.transport_x = float(attachment.local_x)
            movement_state.transport_y = float(attachment.local_y)
            movement_state.transport_z = float(attachment.local_z)
            movement_state.transport_orientation = float(attachment.local_o)
            attached = True
    if not attached:
        _log_transfer_exit("not_attached")
        return []
    try:
        from server.modules.handlers.world.opcodes.movement import _maybe_start_transport_route_transfer
    except Exception as exc:
        _log_transfer_exit("route_transfer_import_failed", error=exc)
        Logger.warning("[TransportTransfer] auto-transfer unavailable reason=%s err=%s", reason, exc)
        return []

    if forced_destination_map is None and str(reason) == "map" and destination_map is not None:
        forced_destination_map = int(destination_map)
    if cross_map_boat:
        Logger.info(
            "[TransportTransfer] boundary transfer start player=%s transport=0x%016X",
            int(getattr(session, "char_guid", 0) or 0),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        )
    responses = _maybe_start_transport_route_transfer(
        session,
        f"TRANSPORT_RUNTIME_{str(reason).upper()}",
        forced_destination_map=forced_destination_map,
    )
    if not responses:
        _log_transfer_exit("route_transfer_returned_no_responses")
    return responses


def _log_transport_transfer_readiness(session: Any, world_guid: int, *, reason: str) -> None:
    state = _runtime_transport_states().get(int(world_guid))
    if state is None or not bool(getattr(state, "transfer_active", False)):
        return

    passengers = getattr(state, "passengers", None)
    pending_transfers = getattr(state, "pending_transfers", None)
    passenger_guids = sorted(int(guid) for guid in passengers) if isinstance(passengers, dict) else []
    pending_state = {
        int(guid): {
            "destination_instance_id": int(getattr(transfer, "destination_instance_id", 0) or 0),
            "target_map_id": int(getattr(transfer, "target_map_id", 0) or 0),
            "started_at_ms": int(getattr(transfer, "started_at_ms", 0) or 0),
        }
        for guid, transfer in (pending_transfers.items() if isinstance(pending_transfers, dict) else ())
    }
    movement_state = getattr(session, "movement_state", None)
    Logger.info(
        "[TRANSPORT_TRANSFER_READINESS] reason=%s transport_guid=0x%016X entry=%s "
        "transport_map=%s destination_map=%s passenger_count=%s passenger_guids=%s "
        "session_map=%s session_transport_guid=0x%016X pending_transfer_state=%s",
        str(reason),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(getattr(state, "entry", 0) or 0),
        int(getattr(state, "map_id", -1) or -1),
        getattr(state, "transfer_destination_map", None),
        len(passenger_guids),
        passenger_guids,
        int(getattr(session, "map_id", -1) or -1),
        int(getattr(movement_state, "transport_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
        pending_state,
    )


def _session_is_transport_passenger(session: Any, world_guid: int) -> bool:
    movement_state = getattr(session, "movement_state", None)
    if int(getattr(movement_state, "transport_guid", 0) or 0) == int(world_guid):
        return True

    passenger_id = int(getattr(session, "char_guid", 0) or 0)
    if passenger_id <= 0:
        return False
    try:
        return transport_passenger_attachment(int(world_guid), passenger_id) is not None
    except Exception:
        return False


def _despawn_loaded_transport(
    session: Any,
    entries: dict[int, dict[str, Any]],
    world_guid: int,
    *,
    map_id: int,
    reason: str,
) -> list[tuple[str, bytes]]:
    entry = entries.pop(int(world_guid), None)
    loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    if isinstance(loaded_gameobjects, set):
        loaded_gameobjects.discard(int(world_guid))
    visibility = get_world_transport_manager().visibility_state_for_guid(int(world_guid))
    Logger.info(
        "[TransportVisibility] despawn transport=0x%016X player=%s reason=%s visibility=%s entry=%s",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(getattr(session, "char_guid", 0) or 0),
        str(reason),
        visibility,
        int(entry.get("entry", 0) or 0) if isinstance(entry, dict) else 0,
    )
    payload = _build_transport_out_of_range_payload(
        map_id=int(map_id),
        world_guid=int(world_guid),
    )
    return [("SMSG_UPDATE_OBJECT", payload)]


def _build_transport_out_of_range_payload(*, map_id: int, world_guid: int) -> bytes:
    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
    payload += struct.pack("<B", 3)
    payload += struct.pack("<I", 1)
    payload += GuidHelper.pack(int(world_guid) & 0xFFFFFFFFFFFFFFFF)
    return bytes(payload)


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
    template = _movement_template_from_route(entry, route)
    if template is None:
        return None

    first = route[0]
    second = route[1]
    route_period_ms = max(int(_route_period_ms(route) or 0), int(_transport_period_ms(entry) or 0))
    shared_clock_key = str(entry.get("shared_route_clock_key", "") or "")
    reference_clock = bool(entry.get("world_db_transport")) and not shared_clock_key
    clock_started_at_ms = _transport_monotonic_ms() if reference_clock else 0
    path_progress_ms = (
        float(_shared_route_phase_ms(shared_clock_key, route_period_ms))
        if shared_clock_key
        else 0.0
    )
    if reference_clock:
        phase_offset_ms = _TRANSPORT_EVALUATOR_PHASE_BIAS_MS - int(clock_started_at_ms)
    else:
        phase_offset_ms = int(path_progress_ms) if not shared_clock_key else 0
    movement_instance = get_movement_manager().register_instance(
        world_guid,
        template,
        phase_offset_ms=phase_offset_ms,
    )
    if movement_instance is None:
        Logger.warning(
            "[MovementManager] transport activation rejected entry=%s guid=0x%016X",
            int(entry.get("entry", 0) or 0),
            world_guid & 0xFFFFFFFFFFFFFFFF,
        )
        return None
    state = RuntimeTransportState(
        guid=world_guid,
        entry=int(entry.get("entry", 0) or 0),
        spawn_guid=int(entry.get("guid", 0) or 0),
        display_id=int(entry.get("display_id", 0) or 0),
        route=route,
        node_index=0,
        x=float(first.x),
        y=float(first.y),
        z=float(first.z),
        orientation=_orientation_between(first, second, float(entry.get("orientation", 0.0) or 0.0)),
        map_id=int(first.map_id),
        timed_route=timed_route,
        route_period_ms=route_period_ms,
        path_progress_ms=path_progress_ms,
        shared_clock_key=shared_clock_key,
        affinity_map_id=_transport_affinity_map_id(entry, int(first.map_id)),
        transport_db_guid=int(entry.get("transport_db_guid", 0) or 0),
        world_db_transport=bool(entry.get("world_db_transport")),
        clock_model=(
            _REFERENCE_TRANSPORT_CLOCK_MODEL
            if reference_clock
            else (_SHARED_TRANSPORT_CLOCK_MODEL if shared_clock_key else "")
        ),
        clock_started_at_ms=int(clock_started_at_ms),
    )
    get_movement_manager().tick_instance(
        int(world_guid),
        server_time_ms=_transport_server_time_ms(state),
    )
    _sync_transport_state_from_movement_cache(state)
    states[world_guid] = state
    _transport_debug_log(
        "[WorldTransport] route load world_guid=0x%016X entry=%s display=%s "
        "map=%s nodes=%s period=%sms timed=%s start=(%.2f %.2f %.2f)",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(state.entry),
        int(state.display_id),
        int(state.map_id),
        len(route),
        int(state.route_period_ms),
        bool(state.timed_route),
        float(state.x),
        float(state.y),
        float(state.z),
    )
    return state


def _movement_template_from_route(entry: dict[str, Any], route: list[TransportRouteNode]):
    yaw = float(entry.get("orientation", 0.0) or 0.0)
    nodes = tuple(
        MovementNode(
            map_id=int(node.map_id),
            x=float(node.x),
            y=float(node.y),
            z=float(node.z),
            time_ms=int(node.time_ms),
            yaw=yaw,
            station=bool(float(node.wait_time) > 0.0),
            transfer=bool(node.transfer),
            delay=max(0, int(round(float(node.wait_time) * 1000.0))),
        )
        for node in route
    )
    template_id = "transport:%s:%s" % (
        int(entry.get("entry", 0) or 0),
        int(entry.get("world_guid", 0) or 0),
    )
    template, reason = build_template(
        template_id,
        _movement_kind_for_entry(entry),
        nodes,
        interpolation_mode=InterpolationMode.LINEAR,
        period_ms=int(_route_period_ms(route) or _transport_period_ms(entry) or 0),
    )
    if template is None:
        Logger.warning(
            "[MovementManager] invalid transport template entry=%s guid=0x%016X reason=%s",
            int(entry.get("entry", 0) or 0),
            int(entry.get("world_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
            str(reason),
        )
    return template


def _movement_kind_for_entry(entry: dict[str, Any]) -> MovementKind:
    if is_deeprun_tram_entry(entry):
        return MovementKind.TRAM
    if _has_transport_animation(entry):
        return MovementKind.ELEVATOR
    return MovementKind.TRANSPORT


def _runtime_transport_states() -> dict[int, RuntimeTransportState]:
    states = getattr(_runtime_transport_states, "_states", None)
    if not isinstance(states, dict):
        states = {}
        setattr(_runtime_transport_states, "_states", states)
    return states


def runtime_transport_snapshot_rows(
    states: list[tuple[int, RuntimeTransportState]] | None = None,
) -> list[dict[str, Any]]:
    state_items = states
    if state_items is None:
        state_items = list(_runtime_transport_states().items())

    result: list[dict[str, Any]] = []
    for world_guid, state in state_items:
        passengers = getattr(state, "passengers", None)
        pending_transfers = getattr(state, "pending_transfers", None)
        result.append({
            "world_guid": int(world_guid),
            "entry": int(state.entry),
            "spawn_guid": int(state.spawn_guid),
            "display_id": int(state.display_id),
            "map_id": int(state.map_id),
            "x": float(state.x),
            "y": float(state.y),
            "z": float(state.z),
            "orientation": float(state.orientation),
            "phase_ms": int(state.path_progress_ms),
            "period_ms": int(state.route_period_ms),
            "node_index": int(state.node_index),
            "next_node_index": int(state.node_index),
            "lifecycle_state": str(getattr(state, "lifecycle_state", TRANSPORT_STATE_ACTIVE)),
            "visibility_state": _effective_transport_visibility_state(int(world_guid)),
            "event": str(getattr(state, "last_event", "")),
            "transfer_active": bool(getattr(state, "transfer_active", False)),
            "transfer_destination_map": getattr(state, "transfer_destination_map", None),
            "passenger_count": len(passengers) if isinstance(passengers, dict) else 0,
            "pending_transfer_count": len(pending_transfers) if isinstance(pending_transfers, dict) else 0,
            "route_points": len(state.route),
            "shared_clock_key": str(state.shared_clock_key or ""),
        })
    result.sort(key=lambda row: (int(row["map_id"]), int(row["entry"]), int(row["world_guid"])))
    return result


def write_world_runtime_snapshot(
    states: list[tuple[int, RuntimeTransportState]] | None = None,
) -> None:
    try:
        from server.modules.handlers.world.state.runtime import weather_runtime_snapshot_rows

        root = get_data_root() / "runtime"
        root.mkdir(parents=True, exist_ok=True)
        path = root / "world_state.json"
        temporary = root / "world_state.json.tmp"
        payload = {
            "generated_at": int(time.time()),
            "transport_epoch_ms": int(_transport_epoch_ms()),
            "transports": runtime_transport_snapshot_rows(states),
            "weather": weather_runtime_snapshot_rows(),
        }
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(path)
    except Exception as exc:
        Logger.warning("[RuntimeSnapshot] write failed err=%s", exc)


def _movement_lifecycle_state(world_guid: int) -> str:
    runtime_state = _runtime_transport_states().get(int(world_guid))
    if runtime_state is not None:
        return str(
            getattr(runtime_state, "lifecycle_state", TRANSPORT_STATE_ACTIVE)
            or TRANSPORT_STATE_ACTIVE
        )
    state = get_movement_manager().get_state(int(world_guid))
    if state is None:
        return TRANSPORT_STATE_DESPAWNED
    return str(getattr(state, "lifecycle_state", TRANSPORT_STATE_ACTIVE) or TRANSPORT_STATE_ACTIVE)


def _movement_visibility_state(world_guid: int) -> str:
    runtime_state = _runtime_transport_states().get(int(world_guid))
    if runtime_state is not None:
        return str(
            getattr(runtime_state, "visibility_state", TRANSPORT_VISIBILITY_ACTIVE)
            or TRANSPORT_VISIBILITY_ACTIVE
        )
    return get_movement_manager().visibility_state(int(world_guid)).value


def _movement_passenger_count(world_guid: int) -> int:
    state = runtime_transport_state_for_guid(int(world_guid))
    passengers = getattr(state, "passengers", None)
    if not isinstance(passengers, dict):
        return 0
    return len(passengers)


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
    _transport_debug_log(
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
    _transport_debug_log("[WorldTransport] loaded world DB transports count=%s", len(result))
    return result


def _load_world_db_elevator_entries() -> tuple[dict[str, Any], ...]:
    cached = getattr(_load_world_db_elevator_entries, "_entries", None)
    if isinstance(cached, tuple):
        return cached

    animation_entry_ids = sorted(
        int(entry_id)
        for entry_id in _transport_animation_paths()
    )
    if not animation_entry_ids:
        setattr(_load_world_db_elevator_entries, "_entries", ())
        return ()

    try:
        from server.modules.database.DatabaseConnection import DatabaseConnection
        from sqlalchemy import text

        session = DatabaseConnection.world()
        entry_list = ",".join(str(int(entry)) for entry in animation_entry_ids)
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
                    gt.name,
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
                WHERE gt.type = :transport_type
                  AND g.id IN ({entry_list})
                """
            ),
            {"transport_type": GAMEOBJECT_TYPE_TRANSPORT},
        ).mappings()
    except Exception as exc:
        setattr(_load_world_db_elevator_entries, "_entries", ())
        Logger.warning("[TransportManager] world DB elevator preload failed err=%s", exc)
        return ()

    entries: list[dict[str, Any]] = []
    seen: set[tuple[int, int, int, int, int]] = set()
    for row in rows:
        guid = int(row.get("guid", 0) or 0)
        entry_id = int(row.get("entry", 0) or 0)
        if entry_id in _UNDERCITY_ELEVATOR_DOOR_ENTRIES:
            continue
        map_id = int(row.get("map", 0) or 0)
        if entry_id in _ORGRIMMAR_ELEVATOR_ENTRIES:
            map_id = int(_PHASELESS_ELEVATOR_MAP_ALIASES.get(map_id, map_id))
        dedupe_key = (
            entry_id,
            map_id,
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
                "entry": entry_id,
                "map": map_id,
                "map_id": map_id,
                "x": float(row.get("x", 0.0) or 0.0),
                "y": float(row.get("y", 0.0) or 0.0),
                "z": float(row.get("z", 0.0) or 0.0),
                "orientation": float(row.get("orientation", 0.0) or 0.0),
                "type": int(row.get("type", GAMEOBJECT_TYPE_TRANSPORT) or GAMEOBJECT_TYPE_TRANSPORT),
                "original_type": GAMEOBJECT_TYPE_TRANSPORT,
                "display_id": int(row.get("display_id", 0) or 0),
                "faction": int(row.get("faction", 0) or 0),
                "flags": int(row.get("flags", 0) or 0),
                "size": float(row.get("size", 1.0) or 1.0),
                "data0": int(row.get("data0", 0) or 0),
                "data1": int(row.get("data1", 0) or 0),
                "data2": int(row.get("data2", 0) or 0),
                "data3": int(row.get("data3", 0) or 0),
                "name": str(row.get("name", "") or ""),
            }
        )

    result = tuple(entries)
    setattr(_load_world_db_elevator_entries, "_entries", result)
    Logger.info("[TransportManager] world DB elevators loaded count=%s", len(result))
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
                    flags=int(getattr(node, "flags", 0) or 0),
                    delay=int(getattr(node, "delay", 0) or 0),
                )
            )
        if len(nodes) >= 2:
            paths[int(path_id)] = tuple(nodes)

    setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
    _transport_debug_log(
        "[WorldTransport] DBC movement taxi path templates loaded transport_paths=%s",
        len(paths),
    )
    return paths


def _build_timed_taxi_transport_route(path_id: int, *, period_ms: int) -> list[TransportRouteNode]:
    nodes = _transport_taxi_path_nodes_by_path().get(int(path_id), ())
    if len(nodes) < 2:
        return []

    # TODO: Model TrinityCore-style arrival/departure acceleration curves once
    # packet timing and client-side transport interpolation are fully mapped.
    period = max(1, int(period_ms or _DEFAULT_MO_TRANSPORT_PERIOD_MS))
    delay_ms_by_index = {
        index: max(0, int(node.delay)) * 1000
        for index, node in enumerate(nodes)
        if int(node.flags) == 2 and int(node.delay) > 0
    }
    total_delay_ms = sum(delay_ms_by_index.values())

    segment_distances: list[float] = []
    total_distance = 0.0
    for index, current in enumerate(nodes[:-1]):
        target = nodes[index + 1]
        if int(current.map_id) != int(target.map_id) or int(current.flags) == 1:
            distance = float(_TRANSPORT_CROSS_MAP_DISTANCE)
        else:
            distance = math.sqrt(
                ((float(target.x) - float(current.x)) ** 2)
                + ((float(target.y) - float(current.y)) ** 2)
                + ((float(target.z) - float(current.z)) ** 2)
            )
        segment_distances.append(float(distance))
        total_distance += float(distance)

    travel_period = max(1, int(period) - int(total_delay_ms))
    if total_distance <= 0.0:
        segment_times = [
            max(1, int(round(travel_period / max(1, len(nodes) - 1))))
            for _node in nodes[:-1]
        ]
    else:
        segment_times = [
            max(1, int(round((float(distance) / total_distance) * float(travel_period))))
            for distance in segment_distances
        ]

    route: list[TransportRouteNode] = [
        TransportRouteNode(
            int(nodes[0].map_id),
            float(nodes[0].x),
            float(nodes[0].y),
            float(nodes[0].z),
            0.0,
            0,
            transfer=bool(int(nodes[0].flags) == 1),
        )
    ]
    current_time = 0
    for index, current in enumerate(nodes[:-1]):
        delay_ms = int(delay_ms_by_index.get(index, 0))
        if delay_ms > 0:
            route[-1] = TransportRouteNode(
                route[-1].map_id,
                route[-1].x,
                route[-1].y,
                route[-1].z,
                float(delay_ms) / 1000.0,
                int(route[-1].time_ms),
                transfer=bool(route[-1].transfer),
            )
            current_time += delay_ms
            route.append(
                TransportRouteNode(
                    int(current.map_id),
                    float(current.x),
                    float(current.y),
                    float(current.z),
                    0.0,
                    int(min(period, current_time)),
                    transfer=bool(int(current.flags) == 1),
                )
            )
        current_time += int(segment_times[index])
        target = nodes[index + 1]
        route.append(
            TransportRouteNode(
                int(target.map_id),
                float(target.x),
                float(target.y),
                float(target.z),
                0.0,
                int(min(period, current_time)),
                transfer=bool(
                    int(current.flags) == 1
                    or int(current.map_id) != int(target.map_id)
                ),
            )
        )

    if route[-1].time_ms < period:
        route[-1] = TransportRouteNode(
            route[-1].map_id,
            route[-1].x,
            route[-1].y,
            route[-1].z,
            route[-1].wait_time,
            int(period),
            transfer=bool(route[-1].transfer),
        )
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
            return _expand_route_wait_nodes(route)

    dbc_route = _build_dbc_animation_route(entry)
    if dbc_route:
        return dbc_route

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
        _transport_debug_log(
            "[WorldTransport] DBC route entry=%s nodes=%s period=%sms base=(%.2f %.2f %.2f)",
            int(animation.entry),
            len(route),
            int(animation.period_ms),
            float(base_x),
            float(base_y),
            float(base_z),
        )
    return route


def _expand_route_wait_nodes(route: list[TransportRouteNode]) -> list[TransportRouteNode]:
    """Convert route wait_time values into same-position timed wait nodes."""

    if len(route) < 2:
        return route

    expanded: list[TransportRouteNode] = []
    accumulated_delay = 0

    for index, node in enumerate(route):
        adjusted_time = int(node.time_ms) + int(accumulated_delay)
        adjusted = TransportRouteNode(
            int(node.map_id),
            float(node.x),
            float(node.y),
            float(node.z),
            float(node.wait_time),
            int(adjusted_time),
            transfer=bool(node.transfer),
        )
        expanded.append(adjusted)

        delay_ms = max(0, int(round(float(node.wait_time) * 1000.0)))
        if delay_ms <= 0:
            continue

        next_node = route[index + 1] if index + 1 < len(route) else None
        wait_end_time = int(adjusted.time_ms) + int(delay_ms)

        if (
            next_node is not None
            and _same_route_position(node, next_node)
            and int(next_node.time_ms) + int(accumulated_delay) >= wait_end_time
        ):
            continue

        expanded.append(
            TransportRouteNode(
                int(adjusted.map_id),
                float(adjusted.x),
                float(adjusted.y),
                float(adjusted.z),
                0.0,
                int(wait_end_time),
                transfer=bool(adjusted.transfer),
            )
        )
        accumulated_delay += int(delay_ms)

    return expanded


def _same_route_position(a: TransportRouteNode, b: TransportRouteNode) -> bool:
    return bool(
        int(a.map_id) == int(b.map_id)
        and abs(float(a.x) - float(b.x)) <= 0.000001
        and abs(float(a.y) - float(b.y)) <= 0.000001
        and abs(float(a.z) - float(b.z)) <= 0.000001
    )


def _is_timed_route(route: list[TransportRouteNode]) -> bool:
    if len(route) < 2:
        return False
    return any(int(node.time_ms) > 0 for node in route)


def _route_period_ms(route: list[TransportRouteNode]) -> int:
    if not _is_timed_route(route):
        return 0
    return max(1, max(int(node.time_ms) for node in route))


def _transport_period_ms(entry: dict[str, Any]) -> int:
    period = int(entry.get("transport_period", 0) or 0)
    if period > 0:
        return period
    animation = _transport_animation_for_entry(int(entry.get("entry", 0) or 0))
    if animation is not None:
        return int(animation.period_ms)
    if int(entry.get("type", 0) or 0) == GAMEOBJECT_TYPE_MO_TRANSPORT:
        return _DEFAULT_MO_TRANSPORT_PERIOD_MS
    data0 = int(entry.get("data0", 0) or 0)
    return max(1, int(data0))


def _commit_transport_dynamic_state(state: RuntimeTransportState) -> None:
    """Commit the evaluated route transform into the transport runtime state."""
    _ensure_movement_instance_for_state(state)
    movement_state = get_movement_manager().get_state(int(state.guid))
    transform = get_movement_manager().get_transform(int(state.guid))
    if transform is None:
        return
    visible_transfer_node = _visible_transfer_destination_node(state, transform)
    if visible_transfer_node is not None:
        state.node_index = int(transform.next_node_index)
        state.map_id = int(visible_transfer_node.map_id)
    else:
        state.node_index = int(transform.node_index)
        state.map_id = int(transform.map_id)
    state.x = float(transform.x)
    state.y = float(transform.y)
    state.z = float(transform.z)
    state.orientation = float(transform.orientation)
    state.path_progress_ms = float(transform.phase_ms)
    if movement_state is not None:
        state.lifecycle_state = str(
            getattr(movement_state, "lifecycle_state", TRANSPORT_STATE_ACTIVE)
            or TRANSPORT_STATE_ACTIVE
        )
        state.previous_lifecycle_state = str(
            getattr(movement_state, "previous_lifecycle_state", "") or ""
        )
        state.visibility_state = str(
            getattr(movement_state, "visibility_state", TRANSPORT_VISIBILITY_ACTIVE)
            or TRANSPORT_VISIBILITY_ACTIVE
        )
        state.previous_visibility_state = str(
            getattr(movement_state, "previous_visibility_state", "") or ""
        )
        state.last_event = str(getattr(movement_state, "last_event", "") or "")
        state.transfer_active = bool(getattr(movement_state, "transfer_active", False))
        state.transfer_destination_map = getattr(movement_state, "transfer_destination_map", None)
        state.lifecycle_events = tuple(getattr(movement_state, "lifecycle_events", ()) or ())
        last_node_index = getattr(movement_state, "last_node_index", -1)
        state.last_node_index = -1 if last_node_index is None else int(last_node_index)


def _sync_transport_state_from_movement_cache(state: RuntimeTransportState) -> None:
    _commit_transport_dynamic_state(state)


def _transport_affinity_map_id(entry: dict[str, Any], fallback: int) -> int:
    for key in ("home_map", "map", "map_id"):
        if key in entry and entry.get(key) is not None:
            return int(entry.get(key))
    return int(fallback)


def _transport_server_time_ms(state: RuntimeTransportState) -> int:
    period = max(1, int(state.route_period_ms or 1))
    if str(getattr(state, "shared_clock_key", "") or ""):
        return int(_shared_route_phase_ms(str(state.shared_clock_key), period))
    return int(time.monotonic() * 1000.0)


def _ensure_movement_instance_for_state(state: RuntimeTransportState) -> None:
    if get_movement_manager().runtime_state(int(state.guid)) is not None:
        return
    entry = {
        "entry": int(state.entry),
        "world_guid": int(state.guid),
        "type": GAMEOBJECT_TYPE_MO_TRANSPORT,
        "transport_period": int(state.route_period_ms),
    }
    template = _movement_template_from_route(entry, list(state.route))
    if template is None:
        return
    phase_offset_ms = 0
    if _is_reference_clock_transport_state(state):
        phase_offset_ms = (
            _TRANSPORT_EVALUATOR_PHASE_BIAS_MS
            + int(float(getattr(state, "path_progress_ms", 0.0) or 0.0))
            - _transport_monotonic_ms()
        )
    instance = get_movement_manager().register_instance(
        int(state.guid),
        template,
        phase_offset_ms=int(phase_offset_ms),
    )
    if instance is None:
        return
    get_movement_manager().tick_instance(
        int(state.guid),
        server_time_ms=_transport_server_time_ms(state),
    )
    _transport_debug_log(
        "[TRANSPORT_DEBUG] rehydrate guid=0x%016X entry=%s map=%s phase=%s node=%s",
        int(state.guid) & 0xFFFFFFFFFFFFFFFF,
        int(state.entry),
        int(state.map_id),
        int(state.path_progress_ms) & 0xFFFFFFFF,
        int(state.node_index),
    )


def _movement_template_for_state(state: RuntimeTransportState):
    movement_state = get_movement_manager().get_state(int(state.guid))
    if movement_state is None:
        return None
    return get_movement_manager().templates.get(str(movement_state.instance.template_id))


def _visible_transfer_destination_node(
    state: RuntimeTransportState,
    transform: Any,
):
    if str(getattr(transform, "event", "") or "") != "transfer":
        return None
    template = _movement_template_for_state(state)
    next_index = int(getattr(transform, "next_node_index", -1) or -1)
    if template is None or next_index < 0 or next_index >= len(template.nodes):
        return None
    destination = template.nodes[next_index]
    if int(getattr(state, "affinity_map_id", -1)) != int(destination.map_id):
        if not _is_canonical_world_db_transport_state(state):
            return None
    return destination


def _is_canonical_world_db_transport_state(state: RuntimeTransportState) -> bool:
    if bool(getattr(state, "world_db_transport", False)):
        db_guid = int(getattr(state, "transport_db_guid", 0) or 0)
        if db_guid > 0:
            return int(getattr(state, "spawn_guid", 0) or 0) == db_guid
    clock_key = str(getattr(state, "shared_clock_key", "") or "")
    prefix = "world-db-transport:"
    if not clock_key.startswith(prefix):
        return False
    try:
        db_guid = int(clock_key[len(prefix):])
    except ValueError:
        return False
    return int(getattr(state, "spawn_guid", 0) or 0) == int(db_guid)


def _effective_transport_visibility_state(world_guid: int) -> str:
    visibility = _movement_visibility_state(int(world_guid))
    if visibility != MovementVisibilityState.TRANSFERRING.value:
        return visibility
    state = _runtime_transport_states().get(int(world_guid))
    if state is None:
        return visibility
    if (
        bool(getattr(state, "transfer_active", False))
        and str(getattr(state, "last_event", "") or "") == "transfer"
        and _is_canonical_world_db_transport_state(state)
        and getattr(state, "transfer_destination_map", None) is not None
    ):
        return TRANSPORT_VISIBILITY_ACTIVE
    movement_state = get_movement_manager().get_state(int(world_guid))
    transform = getattr(movement_state, "evaluated_transform", None)
    if state is not None and transform is not None:
        if _visible_transfer_destination_node(state, transform) is not None:
            return TRANSPORT_VISIBILITY_ACTIVE
    return visibility


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
    if is_deeprun_tram_entry(entry):
        if transport_movement_debug_enabled():
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
        if transport_movement_debug_enabled():
            Logger.debug(
                "[TRANSPORT_DEBUG] transport=0x%016X entry=%s map=%s "
                "phase=%s node=%s passengers=%s transfer=%s pos=(%.2f %.2f %.2f) o=%.3f",
                int(world_guid) & 0xFFFFFFFFFFFFFFFF,
                int(entry.get("entry", 0) or 0),
                int(entry.get("map", 0) or 0),
                int(state.path_progress_ms) & 0xFFFFFFFF,
                int(state.node_index),
                _movement_passenger_count(int(world_guid)),
                str(_movement_lifecycle_state(int(world_guid)) == TRANSPORT_STATE_TRANSFER_PENDING).lower(),
                float(entry.get("x", 0.0) or 0.0),
                float(entry.get("y", 0.0) or 0.0),
                float(entry.get("z", 0.0) or 0.0),
                float(entry.get("orientation", 0.0) or 0.0),
            )
