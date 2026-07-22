#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import copy
from dataclasses import dataclass, field
import json
import math
import struct
import threading
import time
from typing import Any

from shared.Logger import Logger
from shared.PathUtils import get_data_root, get_dbc_root
from server.modules.dbc import read_dbc
from server.modules.handlers.world.feature_config import (
    elevators_enabled,
    moving_transports_enabled,
    transport_movement_debug_enabled,
    transport_attachment_geometry_tolerances,
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
from server.modules.handlers.world.runtime.transport import Transport
from server.modules.handlers.world.runtime.player import Player
from server.modules.handlers.world.runtime.elevator import Elevator
from server.modules.handlers.world.runtime.elevator_store import (
    get_elevator_runtime_store,
    resolve_elevator_runtime,
)
from server.modules.handlers.world.runtime.world_object import WorldObject
from server.modules.handlers.world.transport_debug import (
    TransportDebugEvent,
    log_transport_event,
    log_transport_packet_snapshot,
    transport_location,
)
from server.modules.protocol.packet_batch import PacketBatch

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
# SkyFire's legacy local-transport compatibility maps old world DB template
# entries to the client entries that own their TransportAnimation.dbc paths.
_LOCAL_TRANSPORT_ENTRY_ALIASES = {
    176080: 218203,
    176081: 218204,
    176082: 218205,
    176083: 218206,
    176084: 218207,
    176085: 218208,
}


def _transport_debug_log(message: str, *args) -> None:
    if not transport_movement_debug_enabled():
        return
    Logger.info(message, *args)


def _transport_transition_identity(session: Any) -> tuple[int, str]:
    return (
        int(getattr(session, "world_transition_generation", 0) or 0),
        str(getattr(session, "world_transition_owner", "") or ""),
    )


def _bind_transport_batch_to_active_transition(
    session: Any,
    responses,
    *,
    transition_identity: tuple[int, str] | None = None,
):
    """Bind transport packets only when a transition currently owns them."""
    generation, owner = (
        _transport_transition_identity(session)
        if transition_identity is None
        else transition_identity
    )
    if not owner or generation <= 0:
        return responses
    return PacketBatch(
        responses,
        transition_bound=True,
        transition_generation=generation,
        transition_owner=owner,
    )


@dataclass(frozen=True)
class TransportRouteNode:
    map_id: int
    x: float
    y: float
    z: float
    wait_time: float = 0.0
    time_ms: int = 0
    transfer: bool = False
    source_node_index: int = -1
    transfer_destination_node_index: int | None = None
    arrival_event_id: int = 0
    departure_event_id: int = 0


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
    arrival_event_id: int = 0
    departure_event_id: int = 0


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
    skyfire_transport_route: bool = False
    clock_model: str = ""
    clock_started_at_ms: int = 0
    handled_boundary_events: set[tuple[int, int, int | None]] = field(default_factory=set)
    active_boundary_events: set[tuple[int, int, int | None]] = field(default_factory=set)
    transport: Transport | None = field(default=None, repr=False, compare=False)
    elevator: Elevator | None = field(default=None, repr=False, compare=False)


class WorldTransportManager:
    def __init__(self) -> None:
        self.entries: dict[int, dict[str, Any]] = {}
        self.transports: dict[int, Transport] = {}
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
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, _TRANSPORT_TICK_SECONDS * 2.0))
        with self._lock:
            get_elevator_runtime_store().clear()
            for state in _runtime_transport_states().values():
                state.elevator = None
            self._thread = None

    def reset_for_tests(self) -> None:
        with self._lock:
            self.entries.clear()
            self.transports.clear()
            get_elevator_runtime_store().clear()
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
                state = _runtime_transport_states().get(world_guid)
                if state is not None:
                    self._sync_runtime_object_locked(
                        state,
                        self.entries.get(world_guid),
                    )
                return state
            duplicate_guid = self._duplicate_runtime_guid_locked(entry)
            if duplicate_guid:
                Logger.info(
                    "[TransportDuplicate] transport=0x%016X entry=%s duplicate_of=0x%016X source=%s",
                    world_guid & 0xFFFFFFFFFFFFFFFF,
                    int(entry.get("entry", 0) or 0),
                    duplicate_guid & 0xFFFFFFFFFFFFFFFF,
                    str(source),
                )
                state = _runtime_transport_states().get(duplicate_guid)
                if state is not None:
                    self._sync_runtime_object_locked(
                        state,
                        self.entries.get(duplicate_guid),
                    )
                return state

            transport_entry = dict(entry)
            transport_entry["world_guid"] = world_guid
            transport_entry.setdefault(
                "home_map",
                int(transport_entry.get("map", transport_entry.get("map_id", 0)) or 0),
            )
            self.entries[world_guid] = transport_entry
            state = _transport_state_for_entry(transport_entry)
            if state is not None:
                self._sync_runtime_object_locked(state, transport_entry)
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

    def transport_for_guid(self, world_guid: int) -> Transport | None:
        """Return the stable shared runtime object for one transport."""
        with self._lock:
            return self.transports.get(int(world_guid))

    def elevator_for_guid(self, world_guid: int) -> Elevator | None:
        """Return the stable shared runtime object for one elevator."""
        return get_elevator_runtime_store().get(int(world_guid))

    def world_object_for_guid(self, world_guid: int) -> WorldObject | None:
        """Return the retained moving world object for a runtime GUID."""
        elevator = self.elevator_for_guid(int(world_guid))
        if elevator is not None:
            return elevator
        return self.transport_for_guid(int(world_guid))

    def resolve_world_object_by_spawn_id(
        self,
        spawn_id: int,
    ) -> tuple[WorldObject, RuntimeTransportState] | None:
        """Resolve stable persisted identity to the current runtime instance."""
        expected_spawn_id = int(spawn_id)
        if expected_spawn_id <= 0:
            return None
        with self._lock:
            for state in _runtime_transport_states().values():
                if int(getattr(state, "spawn_guid", 0) or 0) != expected_spawn_id:
                    continue
                runtime_object = self._sync_runtime_object_locked(state)
                if runtime_object is not None:
                    return runtime_object, state
        return None

    def resolve_world_object(
        self,
        world_guid: int,
        entry: dict[str, Any],
    ) -> WorldObject | None:
        """Resolve the retained object or an unregistered elevator fallback."""
        runtime_object = self.world_object_for_guid(int(world_guid))
        if runtime_object is not None:
            return runtime_object
        if not _has_transport_animation(entry):
            return None
        return resolve_elevator_runtime(
            entry,
            runtime_guid=int(world_guid),
            state=self.state_for_guid(int(world_guid)),
        )

    def _sync_elevator_object_locked(
        self,
        state: RuntimeTransportState,
        entry: dict[str, Any],
    ) -> Elevator:
        store = get_elevator_runtime_store()
        elevator = store.get(int(state.guid))
        if elevator is None:
            elevator = store.add(Elevator.from_runtime_state(state, entry))
        else:
            elevator.publish_transform(state)
        self.transports.pop(int(state.guid), None)
        state.transport = None
        state.elevator = elevator
        return elevator

    def _sync_runtime_object_locked(
        self,
        state: RuntimeTransportState,
        entry: dict[str, Any] | None = None,
    ) -> WorldObject | None:
        source = entry if isinstance(entry, dict) else self.entries.get(int(state.guid))
        if not isinstance(source, dict) or not source:
            return None
        if _uses_elevator_runtime(source):
            return self._sync_elevator_object_locked(state, source)
        state.elevator = None
        get_elevator_runtime_store().remove(int(state.guid))
        return self._sync_transport_object_locked(state, source)

    def _sync_transport_object_locked(
        self,
        state: RuntimeTransportState,
        entry: dict[str, Any] | None = None,
    ) -> Transport | None:
        world_guid = int(state.guid)
        transport = self.transports.get(world_guid)
        if transport is None:
            source = entry if isinstance(entry, dict) else self.entries.get(world_guid, {})
            if not isinstance(source, dict) or not source:
                return None
            transport = Transport.from_runtime_state(state, source)
            self.transports[world_guid] = transport
        else:
            transport.sync_from_runtime_state(state)
        state.transport = transport
        return transport

    def sync_transport_object(
        self,
        state: RuntimeTransportState,
    ) -> WorldObject | None:
        """Synchronize the stable world object from simulation output."""
        with self._lock:
            if str(
                getattr(state, "lifecycle_state", TRANSPORT_STATE_ACTIVE)
            ) == TRANSPORT_STATE_DESPAWNED:
                get_elevator_runtime_store().remove(int(state.guid))
                state.elevator = None
                return None
            return self._sync_runtime_object_locked(state)

    def update_entry_transform_from_state(self, state: RuntimeTransportState) -> None:
        with self._lock:
            if str(
                getattr(state, "lifecycle_state", TRANSPORT_STATE_ACTIVE)
            ) == TRANSPORT_STATE_DESPAWNED:
                get_elevator_runtime_store().remove(int(state.guid))
                state.elevator = None
            else:
                self._sync_runtime_object_locked(state)
            entry = self.entries.get(int(state.guid))
            if not isinstance(entry, dict):
                return
            entry["map"] = int(state.map_id)
            entry["map_id"] = int(state.map_id)
            entry["x"] = float(state.x)
            entry["y"] = float(state.y)
            entry["z"] = float(state.z)
            entry["orientation"] = float(state.orientation)
            entry["transport_path_progress"] = int(state.path_progress_ms) & 0xFFFFFFFF

    def state_for_guid(self, world_guid: int) -> RuntimeTransportState | None:
        return _runtime_transport_states().get(int(world_guid))

    def visibility_state_for_guid(self, world_guid: int) -> str:
        return _effective_transport_visibility_state(int(world_guid))

    def is_visible(self, world_guid: int) -> bool:
        return self.visibility_state_for_guid(int(world_guid)) in (
            TRANSPORT_VISIBILITY_ACTIVE,
            TRANSPORT_VISIBILITY_WAITING,
        )

    def can_attach(self, player: Player, world_guid: int) -> bool:
        world_guid = int(world_guid)
        state = self.state_for_guid(world_guid)
        if state is None:
            Logger.warning(
                "[TransportAttach] denied reason=unknown_runtime transport=0x%016X player=%s map=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(player.character_guid),
                int(player.map_id),
            )
            return False
        _sync_transport_state_from_movement_cache(state)
        if int(player.map_id) != int(state.map_id):
            Logger.warning(
                "[TransportAttach] denied reason=wrong_map transport=0x%016X player=%s "
                "player_map=%s transport_map=%s state=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(player.character_guid),
                int(player.map_id),
                int(state.map_id),
                _movement_lifecycle_state(world_guid),
            )
            return False
        visibility = self.visibility_state_for_guid(world_guid)
        if visibility not in (TRANSPORT_VISIBILITY_ACTIVE, TRANSPORT_VISIBILITY_WAITING):
            Logger.warning(
                "[TransportAttach] denied reason=visibility transport=0x%016X player=%s state=%s visibility=%s",
                world_guid & 0xFFFFFFFFFFFFFFFF,
                int(player.character_guid),
                _movement_lifecycle_state(world_guid),
                visibility,
            )
            return False
        return True

    def record_attach(
        self,
        session: Any,
        world_guid: int,
        *,
        opcode_name: str = "",
        local_x: float | None = None,
        local_y: float | None = None,
        local_z: float | None = None,
        local_o: float | None = None,
        transport_time: int | None = None,
        transport_time2: int = 0,
        transport_time3: int = 0,
        seat: int = -1,
        vehicle_id: int = 0,
    ) -> None:
        state = self.state_for_guid(int(world_guid))
        char_guid = int(getattr(session, "char_guid", 0) or 0)
        previous_guid = int(getattr(session, "transport_attached_guid", 0) or 0)
        if previous_guid and previous_guid != int(world_guid):
            detach_session_transport_passenger(
                session,
                reason="new_transport",
                world_guid=previous_guid,
                opcode_name=opcode_name,
            )
        if state is not None and char_guid > 0:
            movement_state = getattr(session, "movement_state", None)
            attachment_x = float(
                getattr(movement_state, "transport_x", 0.0)
                if local_x is None else local_x
            )
            attachment_y = float(
                getattr(movement_state, "transport_y", 0.0)
                if local_y is None else local_y
            )
            attachment_z = float(
                getattr(movement_state, "transport_z", 0.0)
                if local_z is None else local_z
            )
            attachment_o = float(
                getattr(movement_state, "transport_orientation", 0.0)
                if local_o is None else local_o
            )
            attach_transport_passenger(
                int(world_guid),
                char_guid,
                local_x=attachment_x,
                local_y=attachment_y,
                local_z=attachment_z,
                local_o=attachment_o,
                source_map=int(getattr(session, "map_id", 0) or 0),
            )
            attachment = transport_passenger_attachment(int(world_guid), char_guid)
            if attachment is not None:
                from server.modules.handlers.world.position.publication import (
                    publish_transport_local_offset,
                )

                publish_transport_local_offset(
                    session,
                    state,
                    attachment,
                    local_x=attachment_x,
                    local_y=attachment_y,
                    local_z=attachment_z,
                    local_o=attachment_o,
                    transport_time=transport_time,
                    transport_time2=transport_time2,
                    transport_time3=transport_time3,
                    seat=seat,
                    vehicle_id=vehicle_id,
                )
        session.transport_attach_state = ATTACH_STATE_ATTACHED
        session.transport_attached_guid = int(world_guid)
        session.transport_attach_timestamp = float(time.monotonic())
        session.transport_attach_source_map = int(getattr(session, "map_id", 0) or 0)
        movement_state = getattr(session, "movement_state", None)
        log_transport_attachment_lifetime(
            "ATTACH",
            session=session,
            world_guid=int(world_guid),
            reason=f"record_attach:{opcode_name}",
            movement_packet_has_transport=bool(getattr(movement_state, "has_transport_data", False)),
            movement_transport_guid=int(getattr(movement_state, "transport_guid", 0) or 0),
        )
        if state is not None and char_guid > 0:
            try:
                from server.modules.handlers.world.transport_debug_messages import send_message

                movement_state = getattr(session, "movement_state", None)
                send_message(
                    session,
                    "attach",
                    "[Transport] ATTACH guid=0x%016X entry=%s map=%s offset=(%.3f,%.3f,%.3f,%.3f)"
                    % (
                        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
                        int(getattr(state, "entry", 0) or 0),
                        int(getattr(session, "map_id", 0) or 0),
                        float(getattr(movement_state, "transport_x", 0.0) or 0.0),
                        float(getattr(movement_state, "transport_y", 0.0) or 0.0),
                        float(getattr(movement_state, "transport_z", 0.0) or 0.0),
                        float(getattr(movement_state, "transport_orientation", 0.0) or 0.0),
                    ),
                    transfer_id=(
                        f"attach-{int(world_guid)}-"
                        f"{int(float(getattr(session, 'transport_attach_timestamp', 0.0) or 0.0) * 1000.0)}"
                    ),
                )
            except Exception as exc:
                Logger.warning("[TransportDebug] attach message failed error=%s", str(exc))

    def record_detach(self, session: Any, world_guid: int, *, opcode_name: str = "", reason: str = "client") -> None:
        if str(reason) == "transfer":
            session.transport_attach_state = ATTACH_STATE_TRANSFERRING
            return
        detach_session_transport_passenger(
            session,
            reason=str(reason),
            world_guid=int(world_guid),
            opcode_name=opcode_name,
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
            transport = self.resolve_world_object(int(world_guid), moved_entry)
            moved_map = (
                int(transport.map_id)
                if transport is not None
                else moved_entry.get("map", session_map)
            )
            if moved_map is None:
                moved_map = session_map
            moved_x = float(
                transport.x
                if transport is not None
                else moved_entry.get("x", 0.0) or 0.0
            )
            moved_y = float(
                transport.y
                if transport is not None
                else moved_entry.get("y", 0.0) or 0.0
            )
            moved_z = float(
                transport.z
                if transport is not None
                else moved_entry.get("z", 0.0) or 0.0
            )
            if int(moved_map) != session_map:
                _log_transport_discovery_decision(
                    session,
                    world_guid=int(world_guid),
                    entry=transport_entry,
                    transport_map=int(moved_map),
                    transport_x=moved_x,
                    transport_y=moved_y,
                    transport_z=moved_z,
                    phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                    state=_movement_lifecycle_state(int(world_guid)),
                    visibility_state=visibility_state,
                    distance=_transport_distance(
                        session_x,
                        session_y,
                        session_z,
                        moved_x,
                        moved_y,
                        moved_z,
                    ),
                    visible=False,
                    reason="map_mismatch",
                    context=context,
                )
                rejected_guids.append(int(world_guid))
                continue
            dx = moved_x - session_x
            dy = moved_y - session_y
            distance = math.hypot(dx, dy)
            if distance > float(radius):
                _log_transport_discovery_decision(
                    session,
                    world_guid=int(world_guid),
                    entry=transport_entry,
                    transport_map=int(moved_map),
                    transport_x=moved_x,
                    transport_y=moved_y,
                    transport_z=moved_z,
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
                transport_x=moved_x,
                transport_y=moved_y,
                transport_z=moved_z,
                phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                state=_movement_lifecycle_state(int(world_guid)),
                visibility_state=visibility_state,
                distance=distance,
                visible=True,
                reason="accepted",
                context=context,
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
                self._tick_transport_state(int(_world_guid), state)
            self._maybe_write_runtime_snapshot(states)
            time.sleep(_TRANSPORT_TICK_SECONDS)

    def _tick_transport_state(
        self,
        world_guid: int,
        state: RuntimeTransportState,
    ) -> bool:
        """Advance and publish one transport from the global owner loop."""
        previous_transform = (
            int(state.map_id),
            float(state.x),
            float(state.y),
            float(state.z),
            float(state.orientation),
        )
        get_movement_manager().tick_instance(
            int(world_guid),
            server_time_ms=_transport_server_time_ms(state),
        )
        _commit_transport_state_from_movement_cache(state)
        boundary_started = _trigger_boundary_on_runtime_map_transition(
            state,
            previous_transform=previous_transform,
        )
        self.update_entry_transform_from_state(state)
        current_transform = (
            int(state.map_id),
            float(state.x),
            float(state.y),
            float(state.z),
            float(state.orientation),
        )
        if current_transform != previous_transform:
            from server.modules.handlers.world.world_refresh import (
                get_world_refresh_service,
            )

            refresh_service = get_world_refresh_service()
            refresh_observers = getattr(
                refresh_service,
                "refresh_for_moved_transport",
                None,
            )
            if callable(refresh_observers):
                refresh_observers(
                    world_guid=int(world_guid),
                    previous_map_id=int(previous_transform[0]),
                    current_map_id=int(current_transform[0]),
                )
        if not bool(getattr(state, "transfer_active", False)):
            from server.modules.handlers.world.position.publication import (
                publish_transport,
            )

            for passenger_id, attachment in list(
                _canonical_runtime_passengers(state, reason="position_publish").items()
            ):
                passenger_session = _find_transport_passenger_session(int(passenger_id))
                if passenger_session is None:
                    continue
                if int(getattr(passenger_session, "map_id", -1)) != int(state.map_id):
                    continue
                before_position = (
                    float(getattr(passenger_session, "x", 0.0) or 0.0),
                    float(getattr(passenger_session, "y", 0.0) or 0.0),
                    float(getattr(passenger_session, "z", 0.0) or 0.0),
                )
                position = publish_transport(passenger_session, state, attachment)
                after_position = (float(position.x), float(position.y), float(position.z))
                if after_position != before_position:
                    from server.modules.handlers.world.teleport.area_trigger import (
                        check_movement_segment_for_area_triggers,
                    )

                    area_trigger_responses = check_movement_segment_for_area_triggers(
                        passenger_session,
                        before_position,
                        after_position,
                    )
                    if area_trigger_responses:
                        _send_responses(passenger_session, area_trigger_responses)
                        continue
                    from server.modules.handlers.world.world_refresh import (
                        get_world_refresh_service,
                    )

                    visibility_responses = (
                        get_world_refresh_service().refresh_after_movement(
                            passenger_session,
                            context="movement:transport-passenger",
                        )
                    )
                    _send_responses(passenger_session, visibility_responses)
        return bool(boundary_started)

    def _maybe_write_runtime_snapshot(self, states: list[tuple[int, RuntimeTransportState]]) -> None:
        now = time.monotonic()
        if now < self._last_snapshot_write + 2.0:
            return
        self._last_snapshot_write = now
        write_world_runtime_snapshot(states)

    def _register_builtin_transports_locked(self) -> None:
        self._register_world_db_transports_locked()
        self._register_world_db_elevators_locked()

    def _register_world_db_transports_locked(self) -> None:
        for spec in _load_world_db_transports():
            route = _build_skyfire_taxi_transport_route(
                int(spec.get("path_id", 0) or 0),
                move_speed=float(spec.get("data1", 0) or 0),
                acceleration=float(spec.get("data2", 0) or 0),
                can_be_stopped=bool(int(spec.get("data8", 0) or 0)),
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


def stop_world_transport_manager() -> None:
    """Stop transport simulation and release retained elevator objects."""
    _WORLD_TRANSPORT_MANAGER.stop()


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


def _uses_elevator_runtime(entry: dict[str, Any] | None) -> bool:
    """Separate legacy local transports from vertical type-11 elevators."""
    if not _has_transport_animation(entry):
        return False
    db_entry = int(entry.get("db_entry", entry.get("entry", 0)) or 0)
    return db_entry not in _LOCAL_TRANSPORT_ENTRY_ALIASES


def _canonical_local_transport_entry_id(entry_id: int) -> int:
    """Resolve an old world DB entry to its canonical client transport entry."""
    return int(_LOCAL_TRANSPORT_ENTRY_ALIASES.get(int(entry_id), int(entry_id)))


def is_cross_map_boat_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
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


def is_cross_map_zeppelin_entry(entry: dict[str, Any] | None) -> bool:
    """Identify cross-map zeppelins for diagnostics without changing runtime policy."""
    if not isinstance(entry, dict):
        return False
    if int(entry.get("type", 0) or 0) != GAMEOBJECT_TYPE_MO_TRANSPORT:
        return False
    if not bool(entry.get("world_db_transport", False)):
        return False
    entry_id = int(entry.get("entry", 0) or 0)
    text = " ".join(
        str(value or "")
        for value in (
            entry.get("name"),
            entry.get("template_name"),
        )
    ).lower()
    return bool(
        entry_id in _ZEPPELIN_ENTRY_IDS
        or any(token in text for token in _ZEPPELIN_NAME_TOKENS)
    )


def prepare_runtime_transport_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize runtime transport metadata without changing client-visible lift type."""
    prepared = dict(entry)
    gameobject_type = int(prepared.get("type", 0) or 0)
    db_entry = int(prepared.get("entry", 0) or 0)
    client_entry = _canonical_local_transport_entry_id(db_entry)
    if gameobject_type == GAMEOBJECT_TYPE_TRANSPORT and client_entry != db_entry:
        prepared["db_entry"] = db_entry
        prepared["entry"] = client_entry
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
    _ = (
        session,
        world_guid,
        entry,
        transport_map,
        transport_x,
        transport_y,
        transport_z,
        phase_ms,
        state,
        visibility_state,
        distance,
        visible,
        reason,
        context,
    )


def _log_transport_discovery_summary(
    session: Any,
    *,
    considered: int,
    visible_guids: list[int],
    rejected_guids: list[int],
    context: str,
) -> None:
    _ = session, considered, visible_guids, rejected_guids, context


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


def _runtime_passenger_container_name() -> str:
    return "RuntimeTransportState.passengers"


def _canonical_runtime_passengers(
    state: RuntimeTransportState,
    *,
    reason: str,
) -> dict[int, PassengerAttachment]:
    """Return the single authoritative passenger registry for a runtime transport.

    Older movement-manager instances also have a passengers field.  Runtime
    transports must not keep a parallel passenger list there; if one exists from
    a stale path, adopt it into the runtime state once and clear the legacy
    container.
    """
    if state.passengers is None:
        state.passengers = {}

    movement_state = get_movement_manager().get_state(int(state.guid))
    movement_passengers = getattr(movement_state, "passengers", None)
    if isinstance(movement_passengers, dict) and movement_passengers:
        adopted = 0
        for passenger_id, attachment in list(movement_passengers.items()):
            passenger_key = int(passenger_id)
            if passenger_key not in state.passengers:
                state.passengers[passenger_key] = attachment
                adopted += 1
        movement_passengers.clear()
        Logger.info(
            "[TransportPassenger] adopt guid=0x%016X "
            "from_container=MovementRuntimeState.passengers "
            "to_container=%s adopted=%s count=%s reason=%s",
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            _runtime_passenger_container_name(),
            int(adopted),
            len(state.passengers),
            str(reason),
        )
    return state.passengers


def current_runtime_transport_state_for_guid(
    world_guid: int,
) -> RuntimeTransportState | None:
    """Refresh and return the transport's current authoritative route transform."""
    state = runtime_transport_state_for_guid(int(world_guid))
    if state is None:
        return None
    _sync_transport_state_from_movement_cache(state)
    return state


def _clear_session_transport_state(session: Any) -> None:
    movement_state = getattr(session, "movement_state", None)
    if movement_state is not None:
        movement_state.has_transport_data = False
        movement_state.transport_guid = 0
        movement_state.transport_x = 0.0
        movement_state.transport_y = 0.0
        movement_state.transport_z = 0.0
        movement_state.transport_orientation = 0.0
        movement_state.transport_o = 0.0
        movement_state.transport_time = 0
        movement_state.transport_time2 = 0
        movement_state.transport_time3 = 0
        movement_state.transport_seat = -1
        movement_state.transport_vehicle_id = 0
    session.transport_attach_state = ATTACH_STATE_DETACHED
    session.transport_attached_guid = 0
    session.transport_attach_source_map = 0
    session.transport_attach_timestamp = 0.0
    session._movement_rebuild_transport_guard = None
    session._transport_missing_metadata_guid = 0
    session._transport_missing_metadata_count = 0


def _current_session_transport_guid(session: Any) -> int:
    movement_state = getattr(session, "movement_state", None)
    movement_guid = int(getattr(movement_state, "transport_guid", 0) or 0) if movement_state is not None else 0
    session_guid = int(getattr(session, "transport_attached_guid", 0) or 0)
    return movement_guid or session_guid


def log_transport_attachment_lifetime(
    event: str,
    *,
    session: Any | None = None,
    player_guid: int | None = None,
    world_guid: int = 0,
    reason: str = "",
    attachment: PassengerAttachment | None = None,
    local_offset: tuple[float, float, float, float] | None = None,
    movement_packet_has_transport: bool | None = None,
    movement_transport_guid: int | None = None,
    would_detach: bool | None = None,
    detach_occurred: bool | None = None,
) -> None:
    """Compatibility hook retained without movement-packet diagnostics."""
    _ = (
        event,
        session,
        player_guid,
        world_guid,
        reason,
        attachment,
        local_offset,
        movement_packet_has_transport,
        movement_transport_guid,
        would_detach,
        detach_occurred,
    )


def _log_boundary_passenger_snapshot(
    event: str,
    state: RuntimeTransportState,
    passengers: dict[int, PassengerAttachment],
    *,
    reason: str,
) -> None:
    if not passengers:
        log_transport_attachment_lifetime(
            event,
            player_guid=0,
            world_guid=int(state.guid),
            reason=f"{reason}:empty",
        )
        return
    for passenger_id, attachment in passengers.items():
        log_transport_attachment_lifetime(
            event,
            player_guid=int(passenger_id),
            world_guid=int(state.guid),
            reason=reason,
            attachment=attachment,
            movement_packet_has_transport=None,
            movement_transport_guid=0,
        )


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
    passengers = _canonical_runtime_passengers(state, reason="attach")
    already_attached = int(passenger_id) in passengers
    passengers[int(passenger_id)] = PassengerAttachment(
        passenger_id=int(passenger_id),
        local_x=float(local_x),
        local_y=float(local_y),
        local_z=float(local_z),
        local_o=float(local_o),
        source_map=int(source_map),
        attached_at_ms=int(time.monotonic() * 1000.0),
    )
    if not already_attached:
        log_transport_event(
            TransportDebugEvent.PLAYER_ATTACHED,
            transport_guid=int(state.guid),
            entry=int(state.entry),
            player_guid=int(passenger_id),
            location=transport_location(map_id=int(state.map_id)),
        )
    log_transport_attachment_lifetime(
        "ATTACH",
        player_guid=int(passenger_id),
        world_guid=int(state.guid),
        reason="attach",
        attachment=passengers[int(passenger_id)],
        movement_packet_has_transport=True,
        movement_transport_guid=int(state.guid),
    )
    return True


def detach_transport_passenger(world_guid: int, passenger_id: int, *, reason: str = "client") -> bool:
    state = runtime_transport_state_for_guid(int(world_guid))
    if state is None:
        return False
    passengers = _canonical_runtime_passengers(state, reason="detach")
    existed = int(passenger_id) in passengers
    passengers.pop(int(passenger_id), None)
    if existed:
        log_transport_event(
            TransportDebugEvent.PLAYER_DETACHED,
            transport_guid=int(state.guid),
            entry=int(state.entry),
            player_guid=int(passenger_id),
            location=transport_location(map_id=int(state.map_id)),
            reason=str(reason),
        )
    log_transport_attachment_lifetime(
        "DETACH",
        player_guid=int(passenger_id),
        world_guid=int(state.guid),
        reason=str(reason),
        attachment=None,
        movement_packet_has_transport=False,
        movement_transport_guid=0,
        detach_occurred=bool(existed),
    )
    return existed


def detach_session_transport_passenger(
    session: Any,
    *,
    reason: str,
    world_guid: int | None = None,
    opcode_name: str = "",
    clear_pending_transfer: bool = True,
) -> bool:
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    current_guid = _current_session_transport_guid(session)
    detach_guid = int(world_guid) if world_guid is not None else int(current_guid)
    if detach_guid <= 0:
        if clear_pending_transfer:
            session.transport_transfer_pending = False
            session.pending_transport_transfer = None
        _clear_session_transport_state(session)
        return False

    existed = False
    state = runtime_transport_state_for_guid(int(detach_guid))
    movement_state = getattr(session, "movement_state", None)
    if (
        str(getattr(session, "transport_attach_state", "") or "")
        == ATTACH_STATE_TRANSFERRING
        and str(reason) not in {"teleport", "worldport", "transfer"}
    ):
        log_transport_event(
            TransportDebugEvent.UNEXPECTED_DETACH,
            transport_guid=int(detach_guid),
            entry=int(getattr(state, "entry", 0) or 0),
            player_guid=char_guid,
            reason=str(reason),
        )
    log_transport_attachment_lifetime(
        "DETACH",
        session=session,
        world_guid=int(detach_guid),
        reason=f"{reason}:before_clear",
        movement_packet_has_transport=bool(getattr(movement_state, "has_transport_data", False)),
        movement_transport_guid=int(getattr(movement_state, "transport_guid", 0) or 0),
        would_detach=True,
    )
    if state is not None and char_guid > 0:
        existed = detach_transport_passenger(int(detach_guid), char_guid, reason=str(reason))

    if clear_pending_transfer:
        session.transport_transfer_pending = False
        session.pending_transport_transfer = None
    _clear_session_transport_state(session)
    if str(reason) == "movement_validation":
        log_transport_attachment_lifetime(
            "VALIDATION_DETACH",
            session=session,
            world_guid=int(detach_guid),
            reason="movement_validation",
            movement_packet_has_transport=False,
            movement_transport_guid=0,
            would_detach=True,
            detach_occurred=bool(existed),
        )
    return bool(existed)


def clear_player_transport_state(
    session: Any,
    *,
    reason: str = "teleport",
    opcode_name: str = "",
) -> None:
    """Remove every transport attachment owned by one player session.

    Ordinary teleports use this as their single transport-state boundary.  It
    clears canonical and legacy passenger membership, pending transfers, the
    session attachment, and movement-info transport data without changing
    unrelated movement values.
    """
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    pending_transition = getattr(session, "pending_transport_transfer", None)
    candidate_guids = {_current_session_transport_guid(session)}

    for value in (
        getattr(session, "pending_transport_transfer", None),
        getattr(session, "post_bootstrap_transport_reattach_request", None),
    ):
        if not isinstance(value, dict):
            continue
        for key in ("source_guid", "destination_guid", "transport_guid"):
            candidate_guids.add(int(value.get(key, 0) or 0))

    for state in list(_runtime_transport_states().values()):
        passengers = getattr(state, "passengers", None)
        pending_transfers = getattr(state, "pending_transfers", None)
        if char_guid > 0 and (
            (isinstance(passengers, dict) and char_guid in passengers)
            or (isinstance(pending_transfers, dict) and char_guid in pending_transfers)
        ):
            candidate_guids.add(int(state.guid))

    movement_manager = get_movement_manager()
    for world_guid, state in list(movement_manager.instances.items()):
        passengers = getattr(state, "passengers", None)
        pending_transfers = getattr(state, "pending_transfers", None)
        if char_guid > 0 and (
            (isinstance(passengers, dict) and char_guid in passengers)
            or (isinstance(pending_transfers, dict) and char_guid in pending_transfers)
        ):
            candidate_guids.add(int(world_guid))

    for world_guid in sorted(guid for guid in candidate_guids if int(guid) > 0):
        runtime_state = runtime_transport_state_for_guid(int(world_guid))
        if runtime_state is not None:
            passengers = _canonical_runtime_passengers(
                runtime_state,
                reason="teleport_reset",
            )
            if char_guid > 0 and char_guid in passengers:
                detach_transport_passenger(
                    int(world_guid),
                    char_guid,
                    reason=str(reason),
                )
            pending_transfers = getattr(runtime_state, "pending_transfers", None)
            if isinstance(pending_transfers, dict):
                pending_transfers.pop(char_guid, None)

        movement_state = movement_manager.get_state(int(world_guid))
        passengers = getattr(movement_state, "passengers", None)
        if isinstance(passengers, dict):
            passengers.pop(char_guid, None)
        pending_transfers = getattr(movement_state, "pending_transfers", None)
        if isinstance(pending_transfers, dict):
            pending_transfers.pop(char_guid, None)

    session.transport_transfer_pending = False
    if isinstance(pending_transition, dict):
        finalize_transport_boundary_event(
            pending_transition,
            outcome=f"cancelled:{reason}",
        )
    session.pending_transport_transfer = None
    session.post_bootstrap_transport_reattach_request = None
    session.transport_debug_transfer_id = ""
    session.transport_debug_message_stages = set()
    session._worldporttest_transport_guid = 0
    session._transport_bootstrap_first_movement_logged = False
    session._player_bootstrap_runtime_transport = None
    _clear_session_transport_state(session)


def transport_passenger_attachment(
    world_guid: int,
    passenger_id: int,
) -> PassengerAttachment | None:
    state = runtime_transport_state_for_guid(int(world_guid))
    if state is None:
        return None
    passengers = _canonical_runtime_passengers(state, reason="lookup")
    return passengers.get(int(passenger_id))


def validate_attached_passenger_geometry(
    session: Any,
    *,
    has_transport_data: bool,
    transport_guid: int,
    world_x: float,
    world_y: float,
    world_z: float,
    local_x: float = 0.0,
    local_y: float = 0.0,
    local_z: float = 0.0,
) -> tuple[bool, str, dict[str, float]]:
    """Validate one accepted movement sample against canonical attachment geometry."""
    current_guid = int(
        getattr(getattr(session, "movement_state", None), "transport_guid", 0)
        or getattr(session, "transport_attached_guid", 0)
        or 0
    )
    passenger_id = int(getattr(session, "char_guid", 0) or 0)
    state = runtime_transport_state_for_guid(current_guid)
    attachment = transport_passenger_attachment(current_guid, passenger_id)
    if state is None or attachment is None:
        return True, "not_attached", {}
    if bool(has_transport_data) and int(transport_guid) != current_guid:
        return True, "changed_transport", {}
    if int(getattr(state, "map_id", -1)) != int(getattr(session, "map_id", -2)):
        return True, "map_transition", {}

    horizontal_tolerance, vertical_tolerance, max_local_radius = (
        transport_attachment_geometry_tolerances()
    )
    transport_o = float(getattr(state, "orientation", 0.0) or 0.0)
    cos_o = math.cos(transport_o)
    sin_o = math.sin(transport_o)
    expected_x = float(state.x) + cos_o * float(attachment.local_x) - sin_o * float(attachment.local_y)
    expected_y = float(state.y) + sin_o * float(attachment.local_x) + cos_o * float(attachment.local_y)
    expected_z = float(state.z) + float(attachment.local_z)
    canonical_horizontal = math.hypot(float(world_x) - expected_x, float(world_y) - expected_y)
    canonical_vertical = abs(float(world_z) - expected_z)
    metrics = {
        "canonical_horizontal": canonical_horizontal,
        "canonical_vertical": canonical_vertical,
        "horizontal_tolerance": horizontal_tolerance,
        "vertical_tolerance": vertical_tolerance,
        "max_local_radius": max_local_radius,
    }
    if canonical_horizontal > horizontal_tolerance or canonical_vertical > vertical_tolerance:
        return False, "absolute_position", metrics

    if bool(has_transport_data):
        local_radius = math.sqrt(
            float(local_x) * float(local_x)
            + float(local_y) * float(local_y)
            + float(local_z) * float(local_z)
        )
        candidate_x = float(state.x) + cos_o * float(local_x) - sin_o * float(local_y)
        candidate_y = float(state.y) + sin_o * float(local_x) + cos_o * float(local_y)
        candidate_z = float(state.z) + float(local_z)
        reported_horizontal = math.hypot(float(world_x) - candidate_x, float(world_y) - candidate_y)
        reported_vertical = abs(float(world_z) - candidate_z)
        metrics.update(
            local_radius=local_radius,
            reported_horizontal=reported_horizontal,
            reported_vertical=reported_vertical,
        )
        if local_radius > max_local_radius:
            return False, "local_offset_radius", metrics
        if reported_horizontal > horizontal_tolerance or reported_vertical > vertical_tolerance:
            return False, "reported_local_mismatch", metrics
    return True, "within_tolerance", metrics


def begin_transport_passenger_transfer(
    source_world_guid: int,
    destination_world_guid: int,
    passenger_id: int,
    *,
    target_map_id: int,
) -> PassengerTransferState | None:
    source = runtime_transport_state_for_guid(int(source_world_guid))
    if source is None:
        Logger.warning(
            "[TransportPassenger] transfer without valid source transport=0x%016X passenger=%s",
            int(source_world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
        )
        return None
    passengers = _canonical_runtime_passengers(source, reason="transfer_begin")
    attachment = passengers.get(int(passenger_id))
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
        "[TransportPassenger] transfer begin source=0x%016X dest=0x%016X "
        "passenger=%s map=%s container=%s",
        int(source_world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(destination_world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(passenger_id),
        int(target_map_id),
        _runtime_passenger_container_name(),
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
    if int(transfer.destination_instance_id) != int(source_world_guid):
        _canonical_runtime_passengers(source, reason="transfer_complete").pop(
            int(passenger_id),
            None,
        )
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


def can_attach_transport(player: Player, world_guid: int) -> bool:
    return get_world_transport_manager().can_attach(player, int(world_guid))


def record_transport_attach(session: Any, world_guid: int, *, opcode_name: str = "", **offsets) -> None:
    get_world_transport_manager().record_attach(
        session,
        int(world_guid),
        opcode_name=opcode_name,
        **offsets,
    )


def update_transport_passenger_offset(
    session: Any,
    world_guid: int,
    **offsets,
) -> bool:
    """Update canonical and movement-local passenger coordinates together."""
    state = runtime_transport_state_for_guid(int(world_guid))
    attachment = transport_passenger_attachment(
        int(world_guid),
        int(getattr(session, "char_guid", 0) or 0),
    )
    if state is None or attachment is None:
        return False
    from server.modules.handlers.world.position.publication import (
        publish_transport_local_offset,
    )

    publish_transport_local_offset(session, state, attachment, **offsets)
    return True


def prepare_attached_movement_rebuild(session: Any, *, reason: str) -> bool:
    """Refresh an attached passenger offset and arm a bounded rebuild guard."""
    world_guid = int(
        getattr(session, "transport_attached_guid", 0)
        or getattr(getattr(session, "movement_state", None), "transport_guid", 0)
        or 0
    )
    passenger_id = int(getattr(session, "char_guid", 0) or 0)
    state = runtime_transport_state_for_guid(world_guid)
    attachment = transport_passenger_attachment(world_guid, passenger_id)
    if state is None or attachment is None:
        session._movement_rebuild_transport_guard = None
        return False

    from server.modules.handlers.world.position.publication import (
        publish_transport_local_from_absolute,
    )

    publish_transport_local_from_absolute(session, state, attachment)
    updated = transport_passenger_attachment(world_guid, passenger_id)
    if updated is None:
        session._movement_rebuild_transport_guard = None
        return False

    generation = int(
        getattr(session, "_movement_rebuild_transport_generation", 0) or 0
    ) + 1
    session._movement_rebuild_transport_generation = generation
    session._movement_rebuild_transport_guard = {
        "generation": generation,
        "transport_guid": world_guid,
        "attachment_generation": int(getattr(updated, "attached_at_ms", 0) or 0),
        "attachment_token": id(updated),
        "missing_budget": 2,
        "expires_at": float(time.monotonic()) + 2.0,
        "reason": str(reason),
    }
    return True


def publish_current_transport_attachment(session: Any) -> bool:
    """Atomically rebase and publish an attachment without moving the player."""
    world_guid = int(
        getattr(session, "transport_attached_guid", 0)
        or getattr(getattr(session, "movement_state", None), "transport_guid", 0)
        or 0
    )
    passenger_id = int(getattr(session, "char_guid", 0) or 0)
    state = runtime_transport_state_for_guid(world_guid)
    attachment = transport_passenger_attachment(world_guid, passenger_id)
    if state is None or attachment is None:
        return False

    from server.modules.handlers.world.position.publication import (
        publish_transport,
        publish_transport_local_from_absolute,
    )

    # RuntimeTransportState is advanced by the transport thread.  Mount packet
    # construction must not inverse-project against one phase and forward-project
    # against another, especially immediately after a worldport releases its
    # bootstrap-pinned phase.
    pinned_state = copy.copy(state)
    publish_transport_local_from_absolute(session, pinned_state, attachment)
    updated = transport_passenger_attachment(world_guid, passenger_id)
    if updated is None:
        return False

    guard = getattr(session, "_movement_rebuild_transport_guard", None)
    if isinstance(guard, dict) and int(guard.get("transport_guid", 0) or 0) == world_guid:
        guard["attachment_generation"] = int(getattr(updated, "attached_at_ms", 0) or 0)
        guard["attachment_token"] = id(updated)

    publish_transport(session, pinned_state, updated)
    return True


def consume_movement_rebuild_transport_guard(
    session: Any,
    world_guid: int,
) -> bool:
    """Consume one temporary missing-transport allowance for this attachment."""
    guard = getattr(session, "_movement_rebuild_transport_guard", None)
    if not isinstance(guard, dict):
        return False
    attachment = transport_passenger_attachment(
        int(world_guid),
        int(getattr(session, "char_guid", 0) or 0),
    )
    valid = bool(
        int(guard.get("transport_guid", 0) or 0) == int(world_guid)
        and int(guard.get("generation", 0) or 0)
        == int(getattr(session, "_movement_rebuild_transport_generation", 0) or 0)
        and attachment is not None
        and int(guard.get("attachment_generation", 0) or 0)
        == int(getattr(attachment, "attached_at_ms", 0) or 0)
        and int(guard.get("attachment_token", 0) or 0) == id(attachment)
        and float(guard.get("expires_at", 0.0) or 0.0) >= float(time.monotonic())
        and int(guard.get("missing_budget", 0) or 0) > 0
    )
    if not valid:
        session._movement_rebuild_transport_guard = None
        return False
    guard["missing_budget"] = int(guard.get("missing_budget", 0) or 0) - 1
    if int(guard["missing_budget"]) <= 0:
        session._movement_rebuild_transport_guard = None
    return True


def clear_movement_rebuild_transport_guard(session: Any) -> None:
    session._movement_rebuild_transport_guard = None


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
        "data8": int(spec.get("data8", 0) or 0),
        "transport_period": int(_route_period_with_waits_ms(route)),
        "route_start_index": int(start_index) % len(route),
        "shared_route_clock_key": "world-db-transport:%s"
        % int(spec.get("guid", 0) or 0),
        "world_db_transport": True,
        "skyfire_transport_route": True,
        "use_transport_guid": True,
        "runtime_route": [
            (
                int(node.map_id),
                float(node.x),
                float(node.y),
                float(node.z),
                float(node.wait_time),
                int(node.time_ms),
                int(node.source_node_index),
                bool(node.transfer),
                node.transfer_destination_node_index,
                int(node.arrival_event_id),
                int(node.departure_event_id),
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
    bootstrap_runtime = getattr(session, "_player_bootstrap_runtime_transport", None)
    if (
        isinstance(bootstrap_runtime, dict)
        and int(bootstrap_runtime.get("transport_guid", 0) or 0) == world_guid
    ):
        moved_entry = dict(entry)
        moved_entry["map"] = int(bootstrap_runtime.get("map_id", 0) or 0)
        moved_entry["map_id"] = int(bootstrap_runtime.get("map_id", 0) or 0)
        moved_entry["x"] = float(bootstrap_runtime.get("x", 0.0) or 0.0)
        moved_entry["y"] = float(bootstrap_runtime.get("y", 0.0) or 0.0)
        moved_entry["z"] = float(bootstrap_runtime.get("z", 0.0) or 0.0)
        moved_entry["orientation"] = float(
            bootstrap_runtime.get("orientation", 0.0) or 0.0
        )
        moved_entry["world_guid"] = world_guid
        moved_entry["transport_path_progress"] = int(
            bootstrap_runtime.get("route_phase", 0) or 0
        ) & 0xFFFFFFFF
        moved_entry["_transport_create_source_path"] = "bootstrap-runtime"
        moved_entry["_bootstrap_runtime_transform_pinned"] = True
        moved_entry["_runtime_transport_orientation_authoritative"] = not (
            int(moved_entry.get("type", 0) or 0) == GAMEOBJECT_TYPE_TRANSPORT
            and bool(moved_entry.get("client_driven_transport_animation"))
        )
        bootstrap_runtime["transport_create_transform_matched"] = True
        Logger.info(
            "[TransportTransfer] transport_bootstrap_runtime "
            "transport_guid=0x%016X route_phase=%s "
            "runtime_transport_world=(%.3f %.3f %.3f) runtime_rotation=%.6f "
            "matches_player_runtime=true",
            world_guid & 0xFFFFFFFFFFFFFFFF,
            int(moved_entry["transport_path_progress"]),
            float(moved_entry["x"]),
            float(moved_entry["y"]),
            float(moved_entry["z"]),
            float(moved_entry["orientation"]),
        )
        return moved_entry
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


def _session_ready_for_runtime_transport_updates(session: Any) -> tuple[bool, str]:
    """Return whether periodic transport packets may be delivered to this session."""
    login_state = getattr(session, "login_state", None)
    state_name = str(getattr(login_state, "value", login_state) or "None")

    if bool(getattr(session, "teleport_pending", False)):
        return False, state_name
    if bool(getattr(session, "worldport_ack_pending", False)):
        return False, state_name
    if bool(getattr(session, "loading_screen_visible", False)):
        return False, state_name
    if login_state is not None and state_name != "IN_WORLD":
        return False, state_name
    return True, state_name


def _transport_phase_matches_session(session: Any, entry: dict[str, Any]) -> bool:
    session_phase = int(getattr(session, "phase_mask", 0) or 0)
    transport_phase = int(
        entry.get("phase_mask", entry.get("phaseMask", entry.get("phase", 0))) or 0
    )
    return (
        session_phase == 0
        or transport_phase == 0
        or bool(session_phase & transport_phase)
    )


def _transport_observer_sessions(
    world_guid: int,
    *,
    map_id: int | None = None,
) -> list[Any]:
    """Read transport subscribers from canonical per-session interest state."""
    from server.modules.handlers.world.state.runtime import iter_in_world_sessions

    observers: list[Any] = []
    for session in iter_in_world_sessions(map_id=map_id):
        ready, _state_name = _session_ready_for_runtime_transport_updates(session)
        if not ready:
            continue
        loaded = getattr(session, "loaded_transport_entries", None)
        subscribed = isinstance(loaded, dict) and int(world_guid) in loaded
        if not subscribed:
            subscribed = session_is_transport_passenger(session, int(world_guid))
        if subscribed:
            observers.append(session)
    return observers


def _transport_observer_count(world_guid: int, *, map_id: int | None = None) -> int:
    return len(_transport_observer_sessions(int(world_guid), map_id=map_id))


def _log_suppressed_runtime_transport_update(
    session: Any,
    world_guid: int,
    *,
    session_state: str,
    operation: str = "update",
) -> None:
    _ = session, world_guid, session_state, operation


def _suppressed_transport_visibility_operation(
    session: Any,
    world_guid: int,
    entry: dict[str, Any],
) -> str:
    session_map = int(getattr(session, "map_id", 0) or 0)
    transport_map = int(entry.get("map", entry.get("map_id", session_map)) or session_map)
    if transport_map != session_map:
        return "destroy"
    if not get_world_transport_manager().is_visible(int(world_guid)):
        return "destroy"
    loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    if isinstance(loaded_gameobjects, set) and int(world_guid) in loaded_gameobjects:
        return "update"
    return "create"


def _build_visible_transport_updates(
    session: Any,
    entries: dict[int, dict[str, Any]],
    *,
    force: bool = False,
    context: str = "runtime_update",
) -> list[tuple[str, bytes]]:
    transition_identity = _transport_transition_identity(session)
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
    runtime_updates_ready, runtime_session_state = _session_ready_for_runtime_transport_updates(
        session
    )

    if not runtime_updates_ready:
        for world_guid, entry in list(entries.items()):
            considered += 1
            operation = _suppressed_transport_visibility_operation(
                session,
                int(world_guid),
                entry,
            )
            _log_suppressed_runtime_transport_update(
                session,
                int(world_guid),
                session_state=runtime_session_state,
                operation=operation,
            )
            rejected_guids.append(int(world_guid))
        _log_transport_discovery_summary(
            session,
            considered=considered,
            visible_guids=visible_guids,
            rejected_guids=rejected_guids,
            context=f"{context}_worldport_suppressed",
        )
        return []

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
        transport = get_world_transport_manager().resolve_world_object(
            int(world_guid),
            moved_entry,
        )
        moved_map = int(
            transport.map_id
            if transport is not None
            else moved_entry.get("map")
            if moved_entry.get("map") is not None
            else session_map
        )
        moved_x = float(
            transport.x
            if transport is not None
            else moved_entry.get("x", 0.0) or 0.0
        )
        moved_y = float(
            transport.y
            if transport is not None
            else moved_entry.get("y", 0.0) or 0.0
        )
        moved_z = float(
            transport.z
            if transport is not None
            else moved_entry.get("z", 0.0) or 0.0
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

        dx = moved_x - session_x
        dy = moved_y - session_y
        distance = math.hypot(dx, dy)
        if distance > _TRANSPORT_VISIBILITY_RADIUS:
            _log_transport_discovery_decision(
                session,
                world_guid=int(world_guid),
                entry=int(moved_entry.get("entry", entry.get("entry", 0)) or 0),
                transport_map=int(moved_entry.get("map", session_map) or session_map),
                transport_x=moved_x,
                transport_y=moved_y,
                transport_z=moved_z,
                phase_ms=int(moved_entry.get("transport_path_progress", 0) or 0),
                state=_movement_lifecycle_state(int(world_guid)),
                visibility_state=get_world_transport_manager().visibility_state_for_guid(int(world_guid)),
                distance=distance,
                visible=False,
                reason="distance",
                context=context,
            )
            rejected_guids.append(int(world_guid))
            responses.extend(
                _despawn_loaded_transport(
                    session,
                    entries,
                    int(world_guid),
                    map_id=session_map,
                    reason="distance",
                )
            )
            continue

        loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
        already_loaded = isinstance(loaded_gameobjects, set) and int(world_guid) in loaded_gameobjects
        if already_loaded:
            payload = _build_gameobject_values_update_payload(
                map_id=session_map,
                entry=moved_entry,
                realm_id=realm_id,
                transport=transport,
            )
        else:
            payload = _build_gameobject_update_payload(
                map_id=session_map,
                entry=moved_entry,
                realm_id=realm_id,
                transport=transport,
            )
            if isinstance(loaded_gameobjects, set):
                loaded_gameobjects.add(int(world_guid))
        responses.append(make_update_object_response(payload))
        visible_guids.append(int(world_guid))
        _log_transport_discovery_decision(
            session,
            world_guid=int(world_guid),
            entry=int(moved_entry.get("entry", entry.get("entry", 0)) or 0),
            transport_map=moved_map,
            transport_x=moved_x,
            transport_y=moved_y,
            transport_z=moved_z,
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
    _log_transport_discovery_summary(
        session,
        considered=considered,
        visible_guids=visible_guids,
        rejected_guids=rejected_guids,
        context=context,
    )
    if runtime_updates_ready:
        responses.extend(
            _build_new_visible_transport_creates(
                session,
                entries,
                context=f"{context}_lifecycle_spawn",
            )
        )
    return _bind_transport_batch_to_active_transition(
        session,
        responses,
        transition_identity=transition_identity,
    )


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
            transport=get_world_transport_manager().resolve_world_object(
                world_guid,
                entry,
            ),
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
        if responses and int(world_guid) in loaded_after:
            log_transport_packet_snapshot(
                session,
                opcode="SMSG_UPDATE_OBJECT",
                source_subsystem="transport_bootstrap_values",
                batch_id=(
                    f"{int(getattr(session, 'world_transition_generation', 0) or 0)}:"
                    "world-bootstrap"
                ),
                map_id=int(getattr(session, "map_id", 0) or 0),
                position=(
                    float(
                        getattr(state, "x", entry.get("x", 0.0)) or 0.0
                    ),
                    float(
                        getattr(state, "y", entry.get("y", 0.0)) or 0.0
                    ),
                    float(
                        getattr(state, "z", entry.get("z", 0.0)) or 0.0
                    ),
                    float(
                        getattr(
                            state,
                            "orientation",
                            entry.get("orientation", 0.0),
                        )
                        or 0.0
                    ),
                ),
                object_guid=int(world_guid),
                object_map_context=int(
                    getattr(state, "map_id", entry.get("map", 0)) or 0
                ),
            )
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


def _boundary_event_key(event: MovementLifecycleEvent) -> tuple[int, int, int | None]:
    return (
        int(getattr(event, "phase_ms", 0) or 0),
        int(getattr(event, "node_index", 0) or 0),
        (
            None
            if getattr(event, "target_map_id", None) is None
            else int(getattr(event, "target_map_id"))
        ),
    )


def finalize_transport_boundary_event(
    pending: dict[str, Any] | None,
    *,
    outcome: str,
) -> bool:
    """Retire one in-flight boundary after a terminal passenger outcome."""
    if not isinstance(pending, dict):
        return False
    raw_key = pending.get("boundary_event_key")
    if not isinstance(raw_key, (tuple, list)) or len(raw_key) != 3:
        return False
    event_key = (
        int(raw_key[0]),
        int(raw_key[1]),
        None if raw_key[2] is None else int(raw_key[2]),
    )
    world_guid = int(
        pending.get("source_guid", 0)
        or pending.get("destination_guid", 0)
        or 0
    )
    state = runtime_transport_state_for_guid(world_guid)
    if state is None:
        return False
    active = getattr(state, "active_boundary_events", None)
    if isinstance(active, set):
        active.discard(event_key)
    handled = getattr(state, "handled_boundary_events", None)
    if not isinstance(handled, set):
        handled = set()
        state.handled_boundary_events = handled
    handled.add(event_key)
    _transport_debug_log(
        "[TransportBoundary] terminal event=%s guid=0x%016X outcome=%s",
        event_key,
        world_guid & 0xFFFFFFFFFFFFFFFF,
        str(outcome),
    )
    return True


def restore_transport_boundary_event(
    pending: dict[str, Any] | None,
    *,
    reason: str,
) -> bool:
    """Return an in-flight boundary to retryable state after failed handling."""
    if not isinstance(pending, dict):
        return False
    raw_key = pending.get("boundary_event_key")
    if not isinstance(raw_key, (tuple, list)) or len(raw_key) != 3:
        return False
    event_key = (
        int(raw_key[0]),
        int(raw_key[1]),
        None if raw_key[2] is None else int(raw_key[2]),
    )
    world_guid = int(
        pending.get("source_guid", 0)
        or pending.get("destination_guid", 0)
        or 0
    )
    state = runtime_transport_state_for_guid(world_guid)
    if state is None:
        return False
    active = getattr(state, "active_boundary_events", None)
    if isinstance(active, set):
        active.discard(event_key)
    _transport_debug_log(
        "[TransportBoundary] restored event=%s guid=0x%016X reason=%s",
        event_key,
        world_guid & 0xFFFFFFFFFFFFFFFF,
        str(reason),
    )
    return True


def _latest_unhandled_boundary_event(
    state: RuntimeTransportState,
) -> MovementLifecycleEvent | None:
    events = tuple(getattr(state, "lifecycle_events", ()) or ())
    for event in reversed(events):
        if event.event_type != MovementLifecycleEventType.TRANSFER_BEGIN:
            continue
        key = _boundary_event_key(event)
        handled = getattr(state, "handled_boundary_events", None)
        if isinstance(handled, set) and key in handled:
            return None
        active = getattr(state, "active_boundary_events", None)
        if isinstance(active, set) and key in active:
            return None
        return event
    return None


def _boundary_event_for_runtime_map_transition(
    state: RuntimeTransportState,
    *,
    target_map_id: int,
) -> MovementLifecycleEvent:
    event = _latest_unhandled_boundary_event(state)
    if event is not None and int(getattr(event, "target_map_id", target_map_id)) == int(target_map_id):
        return event
    return MovementLifecycleEvent(
        event_type=MovementLifecycleEventType.TRANSFER_BEGIN,
        instance_id=int(state.guid),
        phase_ms=int(getattr(state, "path_progress_ms", 0) or 0),
        node_index=int(getattr(state, "node_index", 0) or 0),
        target_map_id=int(target_map_id),
        message="runtime-map-transition",
    )


def _trigger_boundary_on_runtime_map_transition(
    state: RuntimeTransportState,
    *,
    previous_transform: tuple[int, float, float, float, float],
) -> bool:
    previous_map = int(previous_transform[0])
    current_map_value = getattr(state, "map_id", previous_map)
    current_map = previous_map if current_map_value is None else int(current_map_value)
    if current_map == previous_map:
        return False

    event = _boundary_event_for_runtime_map_transition(
        state,
        target_map_id=current_map,
    )
    handled = getattr(state, "handled_boundary_events", None)
    if isinstance(handled, set) and _boundary_event_key(event) in handled:
        return False

    passenger_source = _canonical_runtime_passengers(
        state,
        reason="boundary-trigger",
    )
    _log_boundary_passenger_snapshot(
        "BOUNDARY_BEGIN",
        state,
        dict(passenger_source),
        reason="before_transport_crossed_map_boundary",
    )
    result = transport_crossed_map_boundary(
        int(state.guid),
        previous_map_id=int(previous_map),
        boundary_event=event,
    )
    _log_boundary_passenger_snapshot(
        "BOUNDARY_END",
        state,
        dict(getattr(state, "passengers", {}) or {}),
        reason=f"after_transport_crossed_map_boundary:result={str(bool(result)).lower()}",
    )
    return result


def _find_transport_passenger_session(passenger_id: int) -> Any | None:
    from server.modules.handlers.world.state.runtime import iter_in_world_sessions

    for session in iter_in_world_sessions():
        if int(getattr(session, "char_guid", 0) or 0) == int(passenger_id):
            return session
    return None


def _remove_previous_map_transport_visibility(
    *,
    world_guid: int,
    from_map: int,
    passenger_ids: set[int],
) -> int:
    from server.modules.handlers.world.state.runtime import iter_in_world_sessions

    removed = 0
    for session in iter_in_world_sessions(map_id=int(from_map)):
        if int(getattr(session, "char_guid", 0) or 0) in passenger_ids:
            continue
        entries = getattr(session, "loaded_transport_entries", None)
        loaded = getattr(session, "loaded_gameobjects", None)
        if not (
            (isinstance(entries, dict) and int(world_guid) in entries)
            or (isinstance(loaded, set) and int(world_guid) in loaded)
        ):
            continue
        if not isinstance(entries, dict):
            entries = {}
            session.loaded_transport_entries = entries
        responses = _despawn_loaded_transport(
            session,
            entries,
            int(world_guid),
            map_id=int(from_map),
            reason="boundary",
        )
        _send_responses(session, responses)
        removed += 1
    return removed


def _start_boundary_worldport_for_passenger(
    session: Any,
    state: RuntimeTransportState,
    attachment: PassengerAttachment,
    *,
    from_map: int,
    to_map: int,
    transfer_id: str,
    boundary_event_key: tuple[int, int, int | None] | None = None,
) -> bool:
    player_guid = int(getattr(session, "char_guid", 0) or 0)
    source_player_x = float(getattr(session, "x", 0.0) or 0.0)
    source_player_y = float(getattr(session, "y", 0.0) or 0.0)
    source_player_z = float(getattr(session, "z", 0.0) or 0.0)
    source_player_o = float(getattr(session, "orientation", 0.0) or 0.0)
    has_pending_transfer = bool(getattr(session, "transport_transfer_pending", False))
    has_pending_payload = isinstance(
        getattr(session, "pending_transport_transfer", None),
        dict,
    )
    is_already_transferring = (
        str(getattr(session, "transport_attach_state", "") or "")
        == ATTACH_STATE_TRANSFERRING
    )
    has_teleport_pending = bool(getattr(session, "teleport_pending", False))
    has_worldport_ack_pending = bool(getattr(session, "worldport_ack_pending", False))
    has_near_teleport_pending = bool(
        getattr(session, "near_teleport_pending", False)
    )
    attachment_missing = (
        transport_passenger_attachment(int(state.guid), player_guid) is None
    )
    # The transport boundary owns this transition.  Session-local movement and
    # teleport timing are diagnostic only; canonical attachment is the sole
    # passenger-specific participation condition.
    blocked = attachment_missing
    _transport_debug_log(
        "[TransportBoundary] passenger_worldport_guard "
        "transfer_id=%s guid=0x%016X passenger=%s "
        "pending_transfer=%s pending_payload=%s already_transferring=%s "
        "teleport_pending=%s worldport_ack_pending=%s "
        "near_teleport_pending=%s attachment_missing=%s blocked=%s",
        str(transfer_id),
        int(state.guid) & 0xFFFFFFFFFFFFFFFF,
        player_guid,
        str(has_pending_transfer).lower(),
        str(has_pending_payload).lower(),
        str(is_already_transferring).lower(),
        str(has_teleport_pending).lower(),
        str(has_worldport_ack_pending).lower(),
        str(has_near_teleport_pending).lower(),
        str(attachment_missing).lower(),
        str(blocked).lower(),
    )
    if blocked:
        log_transport_event(
            TransportDebugEvent.PASSENGER_TRANSFER_REJECTED,
            transport_guid=int(state.guid),
            entry=int(state.entry),
            player_guid=player_guid,
            transfer_id=str(transfer_id),
            reason="attachment_missing",
        )
        return False
    movement_state = getattr(session, "movement_state", None)
    from server.modules.handlers.world.position.publication import (
        publish_transport_local_offset,
    )

    publish_transport_local_offset(
        session,
        state,
        attachment,
        local_x=float(attachment.local_x),
        local_y=float(attachment.local_y),
        local_z=float(attachment.local_z),
        local_o=float(attachment.local_o),
        transport_time=int(getattr(state, "path_progress_ms", 0) or 0),
        transport_time2=int(getattr(movement_state, "transport_time2", 0) or 0),
        transport_time3=int(getattr(movement_state, "transport_time3", 0) or 0),
    )

    transport_o = float(getattr(state, "orientation", 0.0) or 0.0)
    cos_o = math.cos(transport_o)
    sin_o = math.sin(transport_o)
    local_x = float(attachment.local_x)
    local_y = float(attachment.local_y)
    local_z = float(attachment.local_z)
    local_o = float(attachment.local_o)
    world_x = float(state.x) + (cos_o * local_x - sin_o * local_y)
    world_y = float(state.y) + (sin_o * local_x + cos_o * local_y)
    world_z = float(state.z) + local_z
    world_o = transport_o + local_o

    destination_entry = get_world_transport_manager().entry_for_guid(int(state.guid)) or {}
    destination_entry.update(
        {
            "world_guid": int(state.guid),
            "entry": int(state.entry),
            "map": int(to_map),
            "map_id": int(to_map),
            "x": float(state.x),
            "y": float(state.y),
            "z": float(state.z),
            "orientation": transport_o,
            "transport_path_progress": int(getattr(state, "path_progress_ms", 0) or 0) & 0xFFFFFFFF,
        }
    )
    session.transport_transfer_pending = True
    session.pending_transport_transfer = {
        "transfer_id": transfer_id,
        "source_guid": int(state.guid),
        "destination_guid": int(state.guid),
        "source_map": int(from_map),
        "destination_map": int(to_map),
        "node_index": int(getattr(state, "node_index", 0) or 0),
        "route_phase": int(getattr(state, "path_progress_ms", 0) or 0),
        "local_x": local_x,
        "local_y": local_y,
        "local_z": local_z,
        "local_o": local_o,
        "base_source": "boundary_runtime",
        "base_x": float(state.x),
        "base_y": float(state.y),
        "base_z": float(state.z),
        "base_o": transport_o,
        "final_x": world_x,
        "final_y": world_y,
        "final_z": world_z,
        "final_o": world_o,
        "destination_entry": dict(destination_entry),
        "safe_map": int(from_map),
        "safe_x": float(source_player_x),
        "safe_y": float(source_player_y),
        "safe_z": float(source_player_z),
        "safe_o": float(source_player_o),
        "boundary_event_key": boundary_event_key,
    }
    session.transport_attach_state = ATTACH_STATE_TRANSFERRING
    session.transport_debug_transfer_id = transfer_id

    try:
        from server.modules.handlers.world.teleport.map_transfer import (
            TeleportDestination,
            apply_map_transfer,
        )

        _transport_debug_log(
            "[TransportBoundary] apply_map_transfer_enter "
            "transfer_id=%s guid=0x%016X passenger=%s from_map=%s to_map=%s "
            "keep_transport=true transport_entry=%s",
            str(transfer_id),
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            player_guid,
            int(from_map),
            int(to_map),
            int(state.entry),
        )
        responses = apply_map_transfer(
            session,
            TeleportDestination(
                map_id=int(to_map),
                x=world_x,
                y=world_y,
                z=world_z,
                orientation=world_o,
                name=f"transport:{int(state.entry)}:{int(from_map)}->{int(to_map)}",
            ),
            reason="transport",
            keep_transport=True,
            source_map_id=int(from_map),
            transport_entry=int(state.entry),
        )
        opcodes = [str(opcode) for opcode, _payload in list(responses or [])]
        has_transfer_pending = "SMSG_TRANSFER_PENDING" in opcodes
        has_new_world = "SMSG_NEW_WORLD" in opcodes
        _transport_debug_log(
            "[TransportBoundary] apply_map_transfer_return "
            "transfer_id=%s guid=0x%016X passenger=%s returned=true packets=%s "
            "smsg_transfer_pending=%s smsg_new_world=%s opcodes=%s",
            str(transfer_id),
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            player_guid,
            len(opcodes),
            str(has_transfer_pending).lower(),
            str(has_new_world).lower(),
            ",".join(opcodes),
        )
        sent = _send_responses(session, responses)
        _transport_debug_log(
            "[TransportBoundary] passenger_worldport_sent "
            "transfer_id=%s guid=0x%016X passenger=%s send_called=%s "
            "smsg_transfer_pending=%s smsg_new_world=%s",
            str(transfer_id),
            int(state.guid) & 0xFFFFFFFFFFFFFFFF,
            player_guid,
            str(sent).lower(),
            str(has_transfer_pending).lower(),
            str(has_new_world).lower(),
        )
        log_transport_event(
            TransportDebugEvent.PASSENGER_TRANSFER_STARTED,
            transport_guid=int(state.guid),
            entry=int(state.entry),
            player_guid=player_guid,
            transfer_id=str(transfer_id),
            source=transport_location(map_id=int(from_map)),
            destination=transport_location(map_id=int(to_map)),
        )
        return True
    except Exception as exc:
        log_transport_event(
            TransportDebugEvent.WORLDPORT_REJECTED,
            transport_guid=int(state.guid),
            entry=int(state.entry),
            player_guid=player_guid,
            transfer_id=str(transfer_id),
            reason=f"map_transfer_exception:{exc}",
        )
        return False


def transport_crossed_map_boundary(
    world_guid: int,
    *,
    previous_map_id: int | None = None,
    boundary_event: MovementLifecycleEvent | None = None,
) -> bool:
    state = runtime_transport_state_for_guid(int(world_guid))
    if state is None:
        return False
    event = boundary_event if boundary_event is not None else _latest_unhandled_boundary_event(state)
    if event is None:
        return False
    handled = getattr(state, "handled_boundary_events", None)
    if isinstance(handled, set) and _boundary_event_key(event) in handled:
        return False
    active = getattr(state, "active_boundary_events", None)
    if isinstance(active, set) and _boundary_event_key(event) in active:
        return False
    to_map = getattr(event, "target_map_id", None)
    if to_map is None:
        return False
    from_map = (
        int(previous_map_id)
        if previous_map_id is not None
        else int(getattr(state, "map_id", 0) or 0)
    )
    to_map = int(to_map)
    passenger_source = _canonical_runtime_passengers(state, reason="boundary")
    passengers = dict(passenger_source)
    passenger_ids = {int(passenger_id) for passenger_id in passengers}
    _log_boundary_passenger_snapshot(
        "BOUNDARY_BEGIN",
        state,
        passengers,
        reason="transport_crossed_map_boundary",
    )
    old_visibility_removed = _remove_previous_map_transport_visibility(
        world_guid=int(world_guid),
        from_map=from_map,
        passenger_ids=passenger_ids,
    )

    worldports_started = 0
    transfer_id = (
        f"boundary-{int(world_guid) & 0xFFFFFFFFFFFFFFFF}-"
        f"{int(getattr(event, 'phase_ms', 0) or 0)}-"
        f"{int(getattr(event, 'node_index', 0) or 0)}"
    )
    log_transport_event(
        TransportDebugEvent.BOUNDARY_REACHED,
        transport_guid=int(world_guid),
        entry=int(state.entry),
        transfer_id=str(transfer_id),
        source=transport_location(map_id=int(from_map)),
        destination=transport_location(map_id=int(to_map)),
        participants=len(passengers),
    )
    for passenger_id, attachment in passengers.items():
        _transport_debug_log(
            "[TransportBoundary] passenger_evaluate "
            "transfer_id=%s guid=0x%016X passenger=%s in_passenger_list=true "
            "from_map=%s to_map=%s",
            str(transfer_id),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
            int(from_map),
            int(to_map),
        )
        session = _find_transport_passenger_session(int(passenger_id))
        if session is None:
            log_transport_attachment_lifetime(
                "BOUNDARY_CANDIDATE",
                player_guid=int(passenger_id),
                world_guid=int(world_guid),
                reason="session_not_found",
                attachment=attachment,
                movement_packet_has_transport=False,
                movement_transport_guid=0,
            )
            log_transport_event(
                TransportDebugEvent.PASSENGER_TRANSFER_REJECTED,
                transport_guid=int(world_guid),
                entry=int(state.entry),
                player_guid=int(passenger_id),
                transfer_id=str(transfer_id),
                reason="session_not_found",
            )
            continue
        movement_state = getattr(session, "movement_state", None)
        runtime_passenger = int(passenger_id) in passengers
        movement_has_transport = bool(getattr(movement_state, "has_transport_data", False))
        movement_transport_guid = int(getattr(movement_state, "transport_guid", 0) or 0)
        canonical_transport_guid = _current_session_transport_guid(session)
        local_offset_length = math.sqrt(
            float(attachment.local_x) * float(attachment.local_x)
            + float(attachment.local_y) * float(attachment.local_y)
            + float(attachment.local_z) * float(attachment.local_z)
        )
        _transport_debug_log(
            "[TransportBoundary] passenger_candidate transfer_id=%s guid=0x%016X "
            "passenger=%s runtime_passenger=%s movement_has_transport=%s "
            "movement_transport_guid=0x%016X canonical_transport_guid=0x%016X "
            "local_offset_length=%.3f attach_state=%s",
            str(transfer_id),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
            str(runtime_passenger).lower(),
            str(movement_has_transport).lower(),
            movement_transport_guid & 0xFFFFFFFFFFFFFFFF,
            int(canonical_transport_guid) & 0xFFFFFFFFFFFFFFFF,
            local_offset_length,
            str(getattr(session, "transport_attach_state", "") or ""),
        )
        log_transport_attachment_lifetime(
            "BOUNDARY_CANDIDATE",
            session=session,
            world_guid=int(world_guid),
            reason="passenger_candidate",
            attachment=attachment,
            movement_packet_has_transport=movement_has_transport,
            movement_transport_guid=movement_transport_guid,
        )
        if _start_boundary_worldport_for_passenger(
            session,
            state,
            attachment,
            from_map=from_map,
            to_map=to_map,
            transfer_id=transfer_id,
            boundary_event_key=_boundary_event_key(event),
        ):
            worldports_started += 1

    handled = getattr(state, "handled_boundary_events", None)
    if not isinstance(handled, set):
        handled = set()
        state.handled_boundary_events = handled
    active = getattr(state, "active_boundary_events", None)
    if not isinstance(active, set):
        active = set()
        state.active_boundary_events = active
    event_key = _boundary_event_key(event)
    if worldports_started:
        active.add(event_key)
    elif not passengers:
        handled.add(event_key)
    get_world_transport_manager().update_entry_transform_from_state(state)

    destination_visibility_created = 0
    _transport_debug_log(
        "[TransportBoundary] guid=0x%016X from_map=%s to_map=%s "
        "passenger_count=%s old_visibility_removed=%s worldports_started=%s "
        "runtime_map_changed=%s destination_visibility_created=%s",
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(from_map),
        int(to_map),
        len(passengers),
        int(old_visibility_removed),
        int(worldports_started),
        str(int(getattr(state, "map_id", to_map) or to_map) == int(to_map)).lower(),
        int(destination_visibility_created),
    )
    if worldports_started:
        log_transport_event(
            TransportDebugEvent.WORLDPORT_STARTED,
            transport_guid=int(world_guid),
            entry=int(state.entry),
            transfer_id=str(transfer_id),
            source=transport_location(map_id=int(from_map)),
            destination=transport_location(map_id=int(to_map)),
            participants=int(worldports_started),
        )
    elif passengers:
        log_transport_event(
            TransportDebugEvent.WORLDPORT_REJECTED,
            transport_guid=int(world_guid),
            entry=int(state.entry),
            transfer_id=str(transfer_id),
            reason="no_attached_passenger_started",
            participants=len(passengers),
        )
    _log_boundary_passenger_snapshot(
        "BOUNDARY_END",
        state,
        dict(getattr(state, "passengers", {}) or {}),
        reason="transport_crossed_map_boundary",
    )
    return True


def _disabled_legacy_passenger_transport_transfer_impl(
    session: Any,
    world_guid: int,
    *,
    reason: str,
    forced_destination_map: int | None = None,
) -> list[tuple[str, bytes]]:
    _log_transport_transfer_readiness(session, int(world_guid), reason=reason)
    Logger.info(
        "[TRANSPORT_TRANSFER_GUARD] reason=boundary_only trigger=%s "
        "transport_guid=0x%016X player_guid=%s forced_destination_map=%s",
        str(reason),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(getattr(session, "char_guid", 0) or 0),
        "none" if forced_destination_map is None else int(forced_destination_map),
    )
    return []
    attached = session_is_transport_passenger(session, int(world_guid))
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
    if cross_map_boat and runtime_attached:
        attached = True

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
    if (
        cross_map_boat
        and runtime_attached
        and movement_state is not None
        and int(getattr(movement_state, "transport_guid", 0) or 0) != int(world_guid)
    ):
        attachment = transport_passenger_attachment(int(world_guid), int(player_guid))
        if attachment is not None:
            from server.modules.handlers.world.position.publication import (
                publish_transport_local_offset,
            )

            publish_transport_local_offset(
                session,
                runtime_state_for_guid(int(world_guid)),
                attachment,
                local_x=float(attachment.local_x),
                local_y=float(attachment.local_y),
                local_z=float(attachment.local_z),
                local_o=float(attachment.local_o),
            )
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


def _maybe_start_passenger_transport_transfer(
    session: Any,
    world_guid: int,
    *,
    reason: str,
    forced_destination_map: int | None = None,
) -> list[tuple[str, bytes]]:
    _log_transport_transfer_readiness(session, int(world_guid), reason=reason)
    Logger.info(
        "[TRANSPORT_TRANSFER_GUARD] reason=boundary_only trigger=%s "
        "transport_guid=0x%016X player_guid=%s forced_destination_map=%s",
        str(reason),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        int(getattr(session, "char_guid", 0) or 0),
        "none" if forced_destination_map is None else int(forced_destination_map),
    )
    return []


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


def session_is_transport_passenger(session: Any, world_guid: int) -> bool:
    """Return whether *session* is canonically attached to this transport."""
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
    if session_is_transport_passenger(session, int(world_guid)):
        detach_session_transport_passenger(
            session,
            reason=f"transport_visibility:{reason}",
            world_guid=int(world_guid),
        )
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


def _send_responses(session: Any, responses: list[tuple[str, bytes]]) -> bool:
    sender = getattr(session, "send_response", None)
    if not callable(sender) or not responses:
        return False

    try:
        sender(responses)
        return True
    except Exception as exc:
        Logger.warning(
            "[WorldTransport] send failed char=%s err=%s",
            int(getattr(session, "char_guid", 0) or 0),
            exc,
        )
        return False


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
    if bool(entry.get("skyfire_transport_route")):
        route_period_ms = int(_route_period_with_waits_ms(route) or 0)
    else:
        route_period_ms = max(
            int(_route_period_ms(route) or 0),
            int(_transport_period_ms(entry) or 0),
        )
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
        skyfire_transport_route=bool(entry.get("skyfire_transport_route")),
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
    _initialize_transport_state_from_movement_cache(state)
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
    skyfire_world_transport = bool(
        bool(entry.get("skyfire_transport_route"))
        and int(entry.get("type", 0) or 0) == GAMEOBJECT_TYPE_MO_TRANSPORT
        and any(int(node.source_node_index) >= 0 for node in route)
    )
    if skyfire_world_transport:
        movement_nodes: list[MovementNode] = []
        for node in route:
            wait_ms = max(0, int(round(float(node.wait_time) * 1000.0)))
            movement_nodes.append(
                MovementNode(
                    map_id=int(node.map_id),
                    x=float(node.x),
                    y=float(node.y),
                    z=float(node.z),
                    time_ms=int(node.time_ms),
                    yaw=yaw,
                    station=wait_ms > 0,
                    transfer=bool(node.transfer),
                    delay=0,
                )
            )
            if wait_ms > 0:
                movement_nodes.append(
                    MovementNode(
                        map_id=int(node.map_id),
                        x=float(node.x),
                        y=float(node.y),
                        z=float(node.z),
                        time_ms=int(node.time_ms) + wait_ms,
                        yaw=yaw,
                        station=False,
                        transfer=False,
                        delay=0,
                    )
                )
        nodes = tuple(movement_nodes)
        interpolation_mode = InterpolationMode.SPLINE
    else:
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
        interpolation_mode = InterpolationMode.LINEAR
    template_id = "transport:%s:%s" % (
        int(entry.get("entry", 0) or 0),
        int(entry.get("world_guid", 0) or 0),
    )
    route_period_ms = (
        _route_period_with_waits_ms(route)
        if skyfire_world_transport
        else _route_period_ms(route)
    )
    template, reason = build_template(
        template_id,
        _movement_kind_for_entry(entry),
        nodes,
        interpolation_mode=interpolation_mode,
        period_ms=int(route_period_ms or _transport_period_ms(entry) or 0),
        map_local_splines=skyfire_world_transport,
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
        passengers = _canonical_runtime_passengers(state, reason="snapshot")
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
            "passenger_count": len(passengers),
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
    if state is None:
        return 0
    passengers = _canonical_runtime_passengers(state, reason="count")
    return len(passengers)


def _transport_animation_for_entry(entry_id: int) -> TransportAnimationPath | None:
    if int(entry_id) <= 0:
        return None
    paths = _transport_animation_paths()
    return paths.get(_canonical_local_transport_entry_id(int(entry_id)))


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
                    gt.data3,
                    gt.data8
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
                "data8": int(row.get("data8", 0) or 0),
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
        {
            *(int(entry_id) for entry_id in _transport_animation_paths()),
            *(int(entry_id) for entry_id in _LOCAL_TRANSPORT_ENTRY_ALIASES),
        }
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
                    g.rotation0,
                    g.rotation1,
                    g.rotation2,
                    g.rotation3,
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
                "rotation0": float(row.get("rotation0", 0.0) or 0.0),
                "rotation1": float(row.get("rotation1", 0.0) or 0.0),
                "rotation2": float(row.get("rotation2", 0.0) or 0.0),
                "rotation3": float(
                    row.get("rotation3")
                    if row.get("rotation3") is not None
                    else 1.0
                ),
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
    dbc_root = get_dbc_root()
    dbc_path = None if dbc_root is None else dbc_root / "TaxiPathNode.dbc"
    if dbc_path is None or not dbc_path.exists():
        setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
        Logger.warning("[WorldTransport] missing TaxiPathNode.dbc")
        return paths

    try:
        rows = read_dbc(dbc_path, "diiifffiiii")
    except Exception as exc:
        setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
        Logger.warning("[WorldTransport] TaxiPathNode load failed err=%s", exc)
        return paths

    grouped: dict[int, list[TransportTaxiPathNode]] = {}
    for row in rows:
        try:
            path_id = int(row[1])
            grouped.setdefault(path_id, []).append(
                TransportTaxiPathNode(
                    path_id=int(path_id),
                    node_index=int(row[2]),
                    map_id=int(row[3]),
                    x=float(row[4]),
                    y=float(row[5]),
                    z=float(row[6]),
                    flags=int(row[7]),
                    delay=max(0, int(row[8])),
                    arrival_event_id=max(0, int(row[9])),
                    departure_event_id=max(0, int(row[10])),
                )
            )
        except (IndexError, TypeError, ValueError):
            continue

    for path_id, nodes in grouped.items():
        nodes.sort(key=lambda node: int(node.node_index))
        if len(nodes) >= 2:
            paths[int(path_id)] = tuple(nodes)

    setattr(_transport_taxi_path_nodes_by_path, "_paths", paths)
    _transport_debug_log(
        "[WorldTransport] DBC movement taxi path templates loaded transport_paths=%s",
        len(paths),
    )
    return paths


def _build_skyfire_taxi_transport_route(
    path_id: int,
    *,
    move_speed: float,
    acceleration: float,
    can_be_stopped: bool,
) -> list[TransportRouteNode]:
    """Build one type-15 route from SkyFire-compatible executable keyframes."""
    raw_nodes = _transport_taxi_path_nodes_by_path().get(int(path_id), ())
    keyframes = _skyfire_transport_keyframes(
        raw_nodes,
        can_be_stopped=bool(can_be_stopped),
    )
    if len(keyframes) < 2:
        return []

    speed = float(move_speed)
    accel = float(acceleration)
    if speed <= 0.0 or accel <= 0.0:
        Logger.warning(
            "[WorldTransport] invalid motion path=%s speed=%s acceleration=%s",
            int(path_id),
            float(speed),
            float(accel),
        )
        return []

    segment_distances = _map_local_transport_segment_distances(keyframes)
    arrival_times = _skyfire_transport_arrival_times(
        keyframes,
        segment_distances,
        move_speed=speed,
        acceleration=accel,
    )
    if len(arrival_times) != len(keyframes):
        return []

    boundary_destinations = _transport_boundary_destinations(keyframes)
    route: list[TransportRouteNode] = []
    for index, node in enumerate(keyframes):
        destination_index = boundary_destinations.get(index)
        route.append(
            TransportRouteNode(
                map_id=int(node.map_id),
                x=float(node.x),
                y=float(node.y),
                z=float(node.z),
                wait_time=(float(node.delay) if int(node.flags) == 2 else 0.0),
                time_ms=int(arrival_times[index]),
                transfer=destination_index is not None,
                source_node_index=int(node.node_index),
                transfer_destination_node_index=(
                    None
                    if destination_index is None
                    else int(keyframes[destination_index].node_index)
                ),
                arrival_event_id=int(node.arrival_event_id),
                departure_event_id=int(node.departure_event_id),
            )
        )
    return route


def _skyfire_transport_keyframes(
    raw_nodes: tuple[TransportTaxiPathNode, ...],
    *,
    can_be_stopped: bool,
) -> tuple[TransportTaxiPathNode, ...]:
    """Remove DBC spline controls that surround cross-map teleport boundaries."""
    if len(raw_nodes) < 2:
        return ()

    retained: list[TransportTaxiPathNode] = []
    skip_next = False
    for index, node in enumerate(raw_nodes):
        if skip_next:
            skip_next = False
            continue
        if index + 1 < len(raw_nodes):
            following = raw_nodes[index + 1]
            if int(node.flags) == 1 or int(node.map_id) != int(following.map_id):
                skip_next = True
                continue
        retained.append(node)

    if not can_be_stopped and len(retained) >= 2:
        retained = retained[1:-1]
    return tuple(retained)


def _transport_boundary_destinations(
    keyframes: tuple[TransportTaxiPathNode, ...],
) -> dict[int, int]:
    """Map every cross-map source keyframe to its cyclic destination keyframe."""
    result: dict[int, int] = {}
    if len(keyframes) < 2:
        return result
    for index, node in enumerate(keyframes):
        destination_index = (index + 1) % len(keyframes)
        destination = keyframes[destination_index]
        if int(node.map_id) != int(destination.map_id):
            result[index] = destination_index
    return result


def _map_local_transport_segment_distances(
    keyframes: tuple[TransportTaxiPathNode, ...],
) -> tuple[float, ...]:
    """Measure cyclic route edges without cross-map spline control points."""
    result = [0.0 for _node in keyframes]
    section_start = 0
    while section_start < len(keyframes):
        section_end = section_start + 1
        while (
            section_end < len(keyframes)
            and int(keyframes[section_end].map_id) == int(keyframes[section_start].map_id)
        ):
            section_end += 1
        section = keyframes[section_start:section_end]
        section_lengths = _catmull_rom_section_lengths(section)
        for offset, distance in enumerate(section_lengths):
            result[section_start + offset] = float(distance)
        section_start = section_end
    return tuple(result)


def _catmull_rom_section_lengths(
    section: tuple[TransportTaxiPathNode, ...],
) -> tuple[float, ...]:
    """Approximate SkyFire's three-sample Catmull-Rom segment lengths."""
    if len(section) < 2:
        return ()
    points = [(float(node.x), float(node.y), float(node.z)) for node in section]
    first_virtual = tuple(
        (2.0 * points[0][axis]) - points[1][axis]
        for axis in range(3)
    )
    controls = [first_virtual, *points, points[-1]]
    lengths: list[float] = []
    for index in range(len(points) - 1):
        previous = points[index]
        distance = 0.0
        control = controls[index:index + 4]
        for step in range(1, 4):
            current = _catmull_rom_transport_point(control, float(step) / 3.0)
            distance += math.dist(previous, current)
            previous = current
        lengths.append(float(distance))
    return tuple(lengths)


def _catmull_rom_transport_point(
    control: list[tuple[float, float, float]],
    ratio: float,
) -> tuple[float, float, float]:
    value = float(ratio)
    value_squared = value * value
    value_cubed = value_squared * value
    result: list[float] = []
    for axis in range(3):
        p0, p1, p2, p3 = (point[axis] for point in control)
        result.append(
            0.5 * (
                (2.0 * p1)
                + ((-p0 + p2) * value)
                + ((2.0 * p0 - 5.0 * p1 + 4.0 * p2 - p3) * value_squared)
                + ((-p0 + 3.0 * p1 - 3.0 * p2 + p3) * value_cubed)
            )
        )
    return (result[0], result[1], result[2])


def _skyfire_transport_arrival_times(
    keyframes: tuple[TransportTaxiPathNode, ...],
    segment_distances: tuple[float, ...],
    *,
    move_speed: float,
    acceleration: float,
) -> tuple[int, ...]:
    """Derive keyframe arrival times from stops and the transport speed profile."""
    station_indices = tuple(
        index
        for index, node in enumerate(keyframes)
        if int(node.flags) == 2
    )
    if len(segment_distances) != len(keyframes):
        return ()
    timing_station_indices = station_indices or (0,)

    time_to_stop: list[float] = []
    for index in range(len(keyframes)):
        distance_since = _distance_from_previous_station(
            index,
            timing_station_indices,
            segment_distances,
        )
        distance_until = _distance_to_next_station(
            index,
            timing_station_indices,
            segment_distances,
        )
        time_to_stop.append(
            _transport_time_to_stop(
                distance_since,
                distance_until,
                move_speed=float(move_speed),
                acceleration=float(acceleration),
            )
        )

    first_node = keyframes[0]
    current_seconds = (
        float(max(0, int(first_node.delay)))
        if int(first_node.flags) == 2
        else 0.0
    )
    arrival_times = [0]
    for index in range(1, len(keyframes)):
        current_seconds += float(time_to_stop[index - 1])
        node = keyframes[index]
        if int(node.flags) == 2:
            arrival_seconds = current_seconds
            current_seconds += float(max(0, int(node.delay)))
        else:
            current_seconds -= float(time_to_stop[index])
            arrival_seconds = current_seconds
        arrival_times.append(max(0, int(arrival_seconds * 1000.0)))

    # Cross-map teleports are explicit lifecycle markers, not interpolation.
    for source_index, destination_index in _transport_boundary_destinations(keyframes).items():
        if destination_index == 0:
            continue
        minimum_destination_time = arrival_times[source_index] + 1
        if arrival_times[destination_index] < minimum_destination_time:
            adjustment = minimum_destination_time - arrival_times[destination_index]
            for index in range(destination_index, len(arrival_times)):
                arrival_times[index] += int(adjustment)
    return tuple(arrival_times)


def _distance_from_previous_station(
    node_index: int,
    station_indices: tuple[int, ...],
    segment_distances: tuple[float, ...],
) -> float:
    if node_index in station_indices:
        return 0.0
    distance = 0.0
    cursor = int(node_index)
    while cursor not in station_indices:
        previous = (cursor - 1) % len(segment_distances)
        distance += float(segment_distances[previous])
        cursor = previous
    return float(distance)


def _distance_to_next_station(
    node_index: int,
    station_indices: tuple[int, ...],
    segment_distances: tuple[float, ...],
) -> float:
    segment_count = len(segment_distances)
    if segment_count <= 0:
        raise ValueError("transport route has no segments")

    start_index = int(node_index)
    if start_index < 0 or start_index >= segment_count:
        raise ValueError(f"transport node index out of range: {start_index}")

    stations = frozenset(int(index) for index in station_indices)
    distance = 0.0
    cursor = start_index
    for _step in range(segment_count):
        distance += float(segment_distances[cursor])
        cursor = (cursor + 1) % segment_count
        if cursor in stations:
            return float(distance)

    raise ValueError(
        "transport route has no reachable station "
        f"from node {start_index} after {segment_count} segments"
    )


def _transport_time_to_stop(
    distance_since: float,
    distance_until: float,
    *,
    move_speed: float,
    acceleration: float,
) -> float:
    total_distance = float(distance_since) + float(distance_until)
    acceleration_distance = 0.5 * move_speed * move_speed / acceleration
    if total_distance < 2.0 * acceleration_distance:
        if distance_since < distance_until:
            segment_time = 2.0 * math.sqrt(total_distance / acceleration)
            return segment_time - math.sqrt(2.0 * distance_since / acceleration)
        return math.sqrt(2.0 * distance_until / acceleration)
    if distance_since < acceleration_distance:
        segment_time = (total_distance / move_speed) + (move_speed / acceleration)
        return segment_time - math.sqrt(2.0 * distance_since / acceleration)
    if distance_until < acceleration_distance:
        return math.sqrt(2.0 * distance_until / acceleration)
    return (distance_until / move_speed) + (0.5 * move_speed / acceleration)


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
                    transfer=bool(node[7]) if len(node) > 7 else False,
                    source_node_index=int(node[6]) if len(node) > 6 else -1,
                    transfer_destination_node_index=(
                        None
                        if len(node) <= 8 or node[8] is None
                        else int(node[8])
                    ),
                    arrival_event_id=int(node[9]) if len(node) > 9 else 0,
                    departure_event_id=int(node[10]) if len(node) > 10 else 0,
                )
            )
        if len(route) >= 2:
            if bool(entry.get("skyfire_transport_route")):
                return route
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
    rotation = (
        float(entry.get("rotation0", 0.0) or 0.0),
        float(entry.get("rotation1", 0.0) or 0.0),
        float(entry.get("rotation2", 0.0) or 0.0),
        float(entry.get("rotation3", 0.0) or 0.0),
    )
    rotation_norm = math.sqrt(sum(component * component for component in rotation))

    def rotate_offset(x: float, y: float, z: float) -> tuple[float, float, float]:
        if rotation_norm <= 0.000001:
            cos_o = math.cos(orientation)
            sin_o = math.sin(orientation)
            return (
                (x * cos_o) - (y * sin_o),
                (x * sin_o) + (y * cos_o),
                z,
            )

        qx, qy, qz, qw = (component / rotation_norm for component in rotation)
        tx = 2.0 * ((qy * z) - (qz * y))
        ty = 2.0 * ((qz * x) - (qx * z))
        tz = 2.0 * ((qx * y) - (qy * x))
        return (
            x + (qw * tx) + ((qy * tz) - (qz * ty)),
            y + (qw * ty) + ((qz * tx) - (qx * tz)),
            z + (qw * tz) + ((qx * ty) - (qy * tx)),
        )

    route: list[TransportRouteNode] = []
    for node in animation.nodes:
        offset_x, offset_y, offset_z = rotate_offset(
            float(node.x),
            float(node.y),
            float(node.z),
        )
        world_x = base_x + offset_x
        world_y = base_y + offset_y
        world_z = base_z + offset_z
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


def _route_period_with_waits_ms(route: list[TransportRouteNode]) -> int:
    """Return the final departure time for an arrival-timed route."""
    if not _is_timed_route(route):
        return 0
    period_ms = max(
        1,
        max(
            int(node.time_ms)
            + max(0, int(round(float(node.wait_time) * 1000.0)))
            for node in route
        ),
    )
    first = route[0]
    last = route[-1]
    if (
        bool(last.transfer)
        and int(last.map_id) != int(first.map_id)
        and (
            last.transfer_destination_node_index is None
            or int(last.transfer_destination_node_index)
            == int(first.source_node_index)
        )
    ):
        # The modulo clock never reaches a phase equal to period_ms.  Reserve
        # one lifecycle millisecond so the cyclic transfer source is selected
        # before the clock returns to the destination at phase zero.
        period_ms = max(
            int(period_ms),
            int(last.time_ms)
            + max(0, int(round(float(last.wait_time) * 1000.0)))
            + 1,
        )
    return int(period_ms)


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
    # Publish one coherent map-local transform.  During a cross-map transfer the
    # evaluator keeps the source transform live and exposes destination intent
    # separately through transfer_destination_map and the lifecycle event.
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
    """Publish the owner-committed state without advancing or committing it."""
    get_world_transport_manager().sync_transport_object(state)


def _commit_transport_state_from_movement_cache(state: RuntimeTransportState) -> None:
    """Commit movement output from the global transport owner loop."""
    _commit_transport_dynamic_state(state)
    get_world_transport_manager().sync_transport_object(state)


def _initialize_transport_state_from_movement_cache(state: RuntimeTransportState) -> None:
    """Initialize an unpublished transport before the owner loop can observe it."""
    _commit_transport_dynamic_state(state)
    get_world_transport_manager().sync_transport_object(state)


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
        "world_db_transport": bool(state.world_db_transport),
        "skyfire_transport_route": bool(state.skyfire_transport_route),
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
