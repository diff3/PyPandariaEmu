#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Dedicated player-local taxi flight runtime.

Taxi flights are not world transports. This module keeps taxi state attached
to one player session and advances it with deterministic server ticks.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.handlers.world.feature_config import flight_paths_enabled
from server.modules.handlers.world.protocol.movement.spline import (
    TAXI_SPLINE_FLAGS,
    SplineVector,
    build_basic_spline_move,
)
from server.modules.handlers.world.state.runtime import broadcast_player_state_update


TAXI_TICK_SECONDS = 0.05
DEFAULT_TAXI_SPEED = 42.0
DEFAULT_TAXI_MOUNT_DISPLAY_ID = 6851
TAXI_ARC_SAMPLES_PER_SEGMENT = 6
TAXI_CURVE_TENSION = 0.85
TAXI_ORIENTATION_LOOKAHEAD_YARDS = 12.0
TAXI_DIRECT_ARC_MIN_DISTANCE = 35.0
TAXI_DIRECT_ARC_MAX_HEIGHT = 70.0
TAXI_DIRECT_ARC_SIDE_MAX_OFFSET = 28.0
TAXI_Z_SMOOTHING_WINDOW_YARDS = 42.0
TAXI_Z_SMOOTHING_PASSES = 2
TAXI_Z_SMOOTHING_MAX_OFFSET = 8.0
TAXI_MAX_Z_SLOPE_PER_YARD = 0.30
TAXI_MAX_Z_DELTA_PER_TICK = 1.75
TAXI_MAX_Z_SPEED = 34.0
TAXI_MAX_RUNTIME_DT_SECONDS = TAXI_TICK_SECONDS * 2.0
TAXI_MAX_RUNTIME_SAMPLE_SPACING = 4.0

TAXI_STATE_NORMAL = "NORMAL"
TAXI_STATE_FLIGHT = "TAXI_FLIGHT"
TAXI_STATE_TRANSFER = "TAXI_TRANSFER"
TAXI_STATE_ARRIVAL = "TAXI_ARRIVAL"
TAXI_STATE_CANCELLED = "TAXI_CANCELLED"

_MOVEMENTFLAG_CAN_FLY = 0x00800000
_MOVEMENTFLAG_FLYING = 0x01000000
_MOVEMENTFLAG_ASCENDING = 0x00200000
_MOVEMENTFLAG_DESCENDING = 0x00400000
_MOVEMENTFLAG_FORWARD = 0x00000001
_MOVEMENTFLAG_BACKWARD = 0x00000002
_MOVEMENTFLAG_STRAFE_LEFT = 0x00000004
_MOVEMENTFLAG_STRAFE_RIGHT = 0x00000008
_MOVEMENTFLAG_TURN_LEFT = 0x00000010
_MOVEMENTFLAG_TURN_RIGHT = 0x00000020
_MOVEMENTFLAG_TAXI_STOP_MASK = (
    _MOVEMENTFLAG_FORWARD
    | _MOVEMENTFLAG_BACKWARD
    | _MOVEMENTFLAG_STRAFE_LEFT
    | _MOVEMENTFLAG_STRAFE_RIGHT
    | _MOVEMENTFLAG_TURN_LEFT
    | _MOVEMENTFLAG_TURN_RIGHT
    | _MOVEMENTFLAG_ASCENDING
    | _MOVEMENTFLAG_DESCENDING
)


@dataclass(frozen=True)
class TaxiPathPoint:
    x: float
    y: float
    z: float
    orientation: float | None = None
    map_id: int | None = None


@dataclass(frozen=True)
class TaxiPathSample:
    x: float
    y: float
    z: float
    orientation: float
    map_id: int | None
    segment_index: int
    segment_progress: float
    distance: float


@dataclass(frozen=True)
class TaxiPath:
    points: tuple[TaxiPathPoint, ...]
    segment_lengths: tuple[float, ...]
    arc_samples: tuple[TaxiPathSample, ...]
    total_length: float
    source_node: int = 0
    destination_node: int = 0
    source_map: int = 0
    destination_map: int = 0


@dataclass
class TaxiFlightSession:
    active: bool
    path: TaxiPath
    current_segment: int
    segment_progress: float
    total_progress: float
    speed: float
    started_at: float
    destination_map: int
    destination_node: int
    phase: str = TAXI_STATE_FLIGHT
    completed: bool = False
    generation: int = 0
    original_can_fly: bool = False
    original_is_flying: bool = False
    original_is_mounted: bool = False
    original_mount_spell: int | None = None
    original_mount_display_id: int = 0
    original_unit_flags: int = 0
    original_run_speed: float = 7.0
    original_fly_speed: float = 7.0
    original_fly_back_speed: float = 4.5
    last_node_logged: int = -1
    last_applied_z: float | None = None
    last_target_z: float | None = None
    last_traveled: float = 0.0
    last_tick_at: float | None = None
    traveled_distance: float = 0.0
    tick_index: int = 0
    current_sample_index: int = 0
    sample_progress: float = 0.0
    current_sample_spacing: float = 0.0
    max_z_delta_observed: float = 0.0
    movement_timestamp_ms: int = 0
    last_elapsed_seconds: float = 0.0
    last_packet_at: float | None = None
    cancelled: bool = False
    cancel_reason: str = ""
    route_nodes: tuple[int, ...] = ()
    current_leg_index: int = 0
    spline_id: int = 0
    destination_landing_point: TaxiPathPoint | None = None

    @property
    def path_points(self) -> list[TaxiPathPoint]:
        return list(self.path.points)


# Compatibility alias for older local tests/imports.
TaxiRuntimeState = TaxiFlightSession


def build_taxi_path(
    path_points: list[TaxiPathPoint],
    *,
    source_node: int = 0,
    destination_node: int = 0,
    source_map: int = 0,
    destination_map: int = 0,
) -> TaxiPath | None:
    if len(path_points) < 2:
        return None

    normalized = tuple(path_points)
    arc_samples = _build_taxi_arc_samples(normalized)
    if len(arc_samples) < 2:
        return None

    arc_samples = _densify_taxi_arc_samples(arc_samples)
    segment_lengths = _segment_lengths_from_samples(arc_samples, len(normalized) - 1)
    total_length = float(arc_samples[-1].distance)
    if total_length <= 0.001:
        return None

    return TaxiPath(
        points=normalized,
        segment_lengths=segment_lengths,
        arc_samples=arc_samples,
        total_length=float(total_length),
        source_node=int(source_node),
        destination_node=int(destination_node),
        source_map=int(source_map),
        destination_map=int(destination_map),
    )


def is_taxi_active(session) -> bool:
    state = getattr(session, "taxi_state", None)
    return bool(
        state is not None
        and getattr(state, "active", False)
        and not getattr(state, "completed", False)
        and not getattr(state, "cancelled", False)
    )


def start_taxi_flight(
    session,
    path_points: list[TaxiPathPoint],
    *,
    destination_map: int,
    destination_node: int,
    speed: float = DEFAULT_TAXI_SPEED,
    mount_display_id: int = DEFAULT_TAXI_MOUNT_DISPLAY_ID,
    source_node: int = 0,
    route_nodes: tuple[int, ...] = (),
    current_leg_index: int = 0,
    destination_landing_point: TaxiPathPoint | None = None,
) -> list[tuple[str, bytes]]:
    if is_taxi_active(session):
        Logger.warning(
            "[TAXI] start rejected reason=already_active player=%s destination=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(destination_node),
        )
        return []
    if not flight_paths_enabled():
        Logger.info("[TAXI] start blocked; flight paths disabled")
        return []

    # TODO: Persist enough taxi state to resume/recover reconnects mid-flight.
    path = build_taxi_path(
        list(path_points),
        source_node=int(source_node),
        destination_node=int(destination_node),
        source_map=int(getattr(session, "map_id", 0) or 0),
        destination_map=int(destination_map),
    )
    if path is None:
        Logger.warning("[TAXI] start rejected reason=invalid_path destination=%s", int(destination_node))
        return []

    generation = int(getattr(session, "_taxi_generation", 0) or 0) + 1
    session._taxi_generation = generation
    state = TaxiFlightSession(
        active=True,
        path=path,
        current_segment=0,
        segment_progress=0.0,
        total_progress=0.0,
        speed=max(1.0, float(speed)),
        started_at=time.monotonic(),
        destination_map=int(destination_map),
        destination_node=int(destination_node),
        generation=generation,
        original_can_fly=bool(getattr(session, "can_fly", False)),
        original_is_flying=bool(getattr(session, "is_flying", False)),
        original_is_mounted=bool(getattr(session, "is_mounted", False)),
        original_mount_spell=getattr(session, "mount_spell", None),
        original_mount_display_id=int(getattr(session, "mount_display_id", 0) or 0),
        original_unit_flags=int(getattr(session, "unit_flags", 0) or 0),
        original_run_speed=float(getattr(session, "run_speed", 7.0) or 7.0),
        original_fly_speed=float(getattr(session, "fly_speed", 7.0) or 7.0),
        original_fly_back_speed=float(getattr(session, "fly_back_speed", 4.5) or 4.5),
        route_nodes=tuple(int(node) for node in route_nodes),
        current_leg_index=int(current_leg_index),
        spline_id=_next_taxi_spline_id(session, generation),
        destination_landing_point=destination_landing_point,
    )
    session.taxi_state = state
    session.taxi_controls_locked = True
    session.player_travel_state = TAXI_STATE_FLIGHT

    responses = _apply_taxi_mount(session, state, mount_display_id)
    first = path.points[0]
    second = path.points[1]
    _apply_taxi_position(session, first, _segment_orientation(first, second))
    state.last_applied_z = float(first.z)
    state.last_tick_at = float(state.started_at)
    state.movement_timestamp_ms = _initial_taxi_movement_timestamp_ms(session)
    spline_response = _build_taxi_spline_response(session, state)
    if spline_response is not None:
        responses.append(spline_response)
    broadcast_player_state_update(session, force=True)

    Logger.info(
        "[TAXI] start player=%s source=%s destination=%s map=%s points=%s samples=%s speed=%.2f length=%.2f",
        int(getattr(session, "char_guid", 0) or 0),
        int(source_node),
        int(destination_node),
        int(destination_map),
        len(path.points),
        len(path.arc_samples),
        float(state.speed),
        float(path.total_length),
    )
    Logger.info(
        "[TAXI_XMAP_DEBUG] start player=%s route=%s leg=%s source=%s destination=%s "
        "source_map=%s destination_map=%s phase=%s pending=%s spline_response=%s",
        int(getattr(session, "char_guid", 0) or 0),
        list(state.route_nodes),
        int(state.current_leg_index),
        int(source_node),
        int(destination_node),
        int(path.source_map),
        int(path.destination_map),
        str(getattr(state, "phase", "")),
        getattr(session, "pending_taxi_transfer", None),
        int(spline_response is not None),
    )
    _taxi_debug(
        "[TAXI_DEBUG] speed player=%s base=%.2f length=%.2f estimated_seconds=%.2f packet_cadence=spline",
        int(getattr(session, "char_guid", 0) or 0),
        float(state.speed),
        float(path.total_length),
        float(path.total_length) / max(0.001, float(state.speed)),
    )
    _log_taxi_path_measurements(path)
    return responses


def continue_taxi_flight(
    session,
    path_points: list[TaxiPathPoint],
    *,
    destination_map: int,
    destination_node: int,
    source_node: int,
    destination_landing_point: TaxiPathPoint | None = None,
) -> list[tuple[str, bytes]]:
    state = getattr(session, "taxi_state", None)
    if state is None or bool(getattr(state, "completed", False)):
        return []

    sync_taxi_to_current_destination(session)
    path = build_taxi_path(
        list(path_points),
        source_node=int(source_node),
        destination_node=int(destination_node),
        source_map=int(getattr(session, "map_id", 0) or 0),
        destination_map=int(destination_map),
    )
    if path is None:
        cancel_taxi_flight(session, "invalid_continuation_path")
        return []

    state.path = path
    state.current_segment = 0
    state.segment_progress = 0.0
    state.total_progress = 0.0
    state.destination_map = int(destination_map)
    state.destination_node = int(destination_node)
    state.destination_landing_point = destination_landing_point
    state.started_at = time.monotonic()
    state.last_node_logged = -1
    state.last_applied_z = float(path.points[0].z)
    state.last_target_z = None
    state.last_traveled = 0.0
    state.last_tick_at = float(state.started_at)
    state.traveled_distance = 0.0
    state.tick_index = 0
    state.current_sample_index = 0
    state.sample_progress = 0.0
    state.current_sample_spacing = 0.0
    state.max_z_delta_observed = 0.0
    state.last_elapsed_seconds = 0.0
    state.last_packet_at = None
    state.current_leg_index += 1
    state.spline_id = _next_taxi_spline_id(session, int(getattr(session, "_taxi_generation", 0) or 0))
    session.player_travel_state = TAXI_STATE_FLIGHT

    first = path.points[0]
    second = path.points[1]
    _apply_taxi_position(session, first, _segment_orientation(first, second))
    response = _build_taxi_spline_response(session, state)
    broadcast_player_state_update(session, force=True)
    Logger.info(
        "[TAXI_XMAP_DEBUG] continue player=%s route=%s leg=%s source=%s destination=%s "
        "source_map=%s destination_map=%s phase=%s pending=%s spline_response=%s",
        int(getattr(session, "char_guid", 0) or 0),
        list(getattr(state, "route_nodes", ()) or ()),
        int(getattr(state, "current_leg_index", 0) or 0),
        int(source_node),
        int(destination_node),
        int(path.source_map),
        int(path.destination_map),
        str(getattr(state, "phase", "")),
        getattr(session, "pending_taxi_transfer", None),
        int(response is not None),
    )
    return [response] if response is not None else []


def complete_taxi_spline(session) -> None:
    state = getattr(session, "taxi_state", None)
    if state is None:
        return
    _complete_taxi(session, state)


def complete_taxi_for_disconnect(session) -> bool:
    state = getattr(session, "taxi_state", None)
    if state is None or bool(getattr(state, "completed", False)):
        return False

    _finish_taxi_state(session, state, send_updates=False)
    return True


def sync_taxi_to_current_destination(session) -> None:
    state = getattr(session, "taxi_state", None)
    if state is None:
        return
    final_point = state.path.points[-1]
    orientation = final_point.orientation
    if orientation is None and len(state.path.points) >= 2:
        orientation = _segment_orientation(state.path.points[-2], final_point)
    _apply_taxi_position(session, final_point, float(orientation or 0.0))


def taxi_tick(session, *, now: float | None = None) -> bool:
    state = getattr(session, "taxi_state", None)
    if state is None or not bool(getattr(state, "active", False)):
        return False
    if bool(getattr(state, "completed", False)) or bool(getattr(state, "cancelled", False)):
        return False

    path = state.path
    current_time = time.monotonic() if now is None else float(now)
    elapsed = _taxi_tick_delta_seconds(session, state, current_time, clamp_delta=now is None)
    state.last_elapsed_seconds = float(elapsed)
    traveled = min(
        float(path.total_length),
        float(state.traveled_distance) + (elapsed * float(state.speed)),
    )

    (
        point,
        segment_index,
        segment_progress,
        total_progress,
        sample_index,
        sample_progress,
        sample_spacing,
    ) = _interpolate_path(path, traveled)
    raw_z = float(point.z)
    previous_applied_z = state.last_applied_z
    previous_target_z = state.last_target_z
    applied_z = _stabilize_taxi_altitude(state, float(point.z), elapsed)
    applied_delta = 0.0
    if previous_applied_z is not None:
        applied_delta = float(applied_z) - float(previous_applied_z)
    state.max_z_delta_observed = max(
        float(state.max_z_delta_observed),
        abs(float(applied_delta)),
    )
    if abs(applied_z - float(point.z)) > 0.001:
        point = TaxiPathPoint(
            point.x,
            point.y,
            applied_z,
            point.orientation,
            point.map_id,
        )
    _log_taxi_altitude_tick(
        session,
        state,
        traveled=traveled,
        segment_index=segment_index,
        segment_progress=segment_progress,
        total_progress=total_progress,
        raw_z=raw_z,
        applied_z=applied_z,
        previous_applied_z=previous_applied_z,
        previous_target_z=previous_target_z,
        raw_x=float(point.x),
        raw_y=float(point.y),
        sample_index=sample_index,
        sample_progress=sample_progress,
        sample_spacing=sample_spacing,
        applied_delta=applied_delta,
        elapsed=elapsed,
    )
    state.tick_index += 1
    state.last_target_z = float(raw_z)
    state.last_traveled = float(traveled)
    state.traveled_distance = float(traveled)
    state.current_segment = int(segment_index)
    state.segment_progress = float(segment_progress)
    state.total_progress = float(total_progress)
    state.current_sample_index = int(sample_index)
    state.sample_progress = float(sample_progress)
    state.current_sample_spacing = float(sample_spacing)

    if state.last_node_logged != int(segment_index):
        Logger.info(
            "[TAXI] node advance player=%s segment=%s/%s progress=%.3f",
            int(getattr(session, "char_guid", 0) or 0),
            int(segment_index),
            max(0, len(path.points) - 2),
            float(total_progress),
        )
        _taxi_debug(
            "[TAXI_DEBUG] transition player=%s segment=%s segment_progress=%.3f traveled=%.3f",
            int(getattr(session, "char_guid", 0) or 0),
            int(segment_index),
            float(segment_progress),
            float(traveled),
        )
        state.last_node_logged = int(segment_index)

    if traveled >= path.total_length and abs(float(applied_z) - raw_z) <= 0.001:
        _complete_taxi(session, state)
        return False

    _apply_taxi_position(session, point, float(point.orientation or 0.0))
    _send_taxi_movement_update(session, state)
    return True


def cancel_taxi_flight(session, reason: str = "cancelled") -> None:
    state = getattr(session, "taxi_state", None)
    if state is None:
        return
    state.cancelled = True
    state.cancel_reason = str(reason)
    state.active = False
    state.phase = TAXI_STATE_CANCELLED
    session.taxi_controls_locked = False
    session.player_travel_state = TAXI_STATE_NORMAL
    session._taxi_generation = int(getattr(session, "_taxi_generation", 0) or 0) + 1
    _restore_pre_taxi_state(session, state)
    _send_self_movement(session)
    Logger.warning(
        "[TAXI] cancelled player=%s reason=%s",
        int(getattr(session, "char_guid", 0) or 0),
        str(reason),
    )
    session.taxi_state = None


def _taxi_arrival_point(state: TaxiFlightSession) -> TaxiPathPoint:
    landing_point = getattr(state, "destination_landing_point", None)
    if landing_point is not None:
        return landing_point
    return state.path.points[-1]


def _start_taxi_thread(session, generation: int) -> None:
    session._taxi_last_tick_at = time.monotonic()

    def _worker() -> None:
        while True:
            time.sleep(TAXI_TICK_SECONDS)
            if int(getattr(session, "_taxi_generation", 0) or 0) != int(generation):
                return
            if not taxi_tick(session):
                return

    threading.Thread(
        target=_worker,
        name=f"taxi-{int(getattr(session, 'char_guid', 0) or 0)}",
        daemon=True,
    ).start()


def _taxi_tick_delta_seconds(
    session,
    state: TaxiFlightSession,
    current_time: float,
    *,
    clamp_delta: bool,
) -> float:
    previous_tick = state.last_tick_at
    if previous_tick is None:
        previous_tick = float(getattr(session, "_taxi_last_tick_at", state.started_at) or state.started_at)
    if current_time < float(state.started_at):
        previous_tick = float(getattr(session, "_taxi_last_tick_at", previous_tick) or previous_tick)

    elapsed = max(0.0, float(current_time) - float(previous_tick))
    if clamp_delta:
        max_elapsed = max(float(TAXI_TICK_SECONDS), float(TAXI_MAX_RUNTIME_DT_SECONDS))
        if elapsed > max_elapsed:
            _taxi_debug(
                "[TAXI_DEBUG] tick_delta_guard player=%s elapsed=%.3f bounded=%.3f traveled=%.3f",
                int(getattr(session, "char_guid", 0) or 0),
                float(elapsed),
                float(max_elapsed),
                float(state.traveled_distance),
            )
            elapsed = max_elapsed

    state.last_tick_at = float(current_time)
    session._taxi_last_tick_at = float(current_time)
    return float(elapsed)


def _initial_taxi_movement_timestamp_ms(session) -> int:
    movement_state = getattr(session, "movement_state", None)
    if movement_state is not None:
        existing = int(getattr(movement_state, "server_movement_timestamp_ms", 0) or 0)
        if existing > 0:
            return existing & 0xFFFFFFFF
    return int(time.time() * 1000.0) & 0xFFFFFFFF


def _advance_taxi_movement_timestamp(state: TaxiFlightSession) -> int:
    elapsed_ms = max(1, int(round(float(state.last_elapsed_seconds) * 1000.0)))
    current = int(state.movement_timestamp_ms or 0)
    if current <= 0:
        current = int(time.time() * 1000.0)
    state.movement_timestamp_ms = (current + elapsed_ms) & 0xFFFFFFFF
    return int(state.movement_timestamp_ms)


def _next_taxi_spline_id(session, generation: int) -> int:
    current = int(getattr(session, "_taxi_spline_id", 0) or 0)
    if current <= 0:
        current = int(generation) & 0xFFFFFFFF
    current = (current + 1) & 0xFFFFFFFF
    if current <= 0:
        current = 1
    session._taxi_spline_id = int(current)
    return int(current)


def _build_taxi_spline_response(session, state: TaxiFlightSession) -> tuple[str, bytes] | None:
    guid = int(
        getattr(session, "char_guid", 0)
        or getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )
    if guid <= 0:
        Logger.warning("[TAXI] spline build failed reason=no_player_guid")
        return None

    points = tuple(state.path.points)
    if len(points) < 2:
        Logger.warning("[TAXI] spline build failed reason=insufficient_points")
        return None

    duration_ms = max(
        1,
        int(round((float(state.path.total_length) / max(0.001, float(state.speed))) * 1000.0)),
    )
    payload = build_basic_spline_move(
        mover_guid=guid,
        spline_id=int(state.spline_id or _next_taxi_spline_id(session, state.generation)),
        start_position=_spline_vector(points[0]),
        destination_position=_spline_vector(points[-1]),
        path_points=tuple(_spline_vector(point) for point in points[1:-1]),
        spline_flags=TAXI_SPLINE_FLAGS,
        duration_ms=duration_ms,
    )
    Logger.info(
        "[TAXI] spline player=%s spline=%s points=%s duration_ms=%s length=%.2f",
        guid,
        int(state.spline_id),
        len(points),
        int(duration_ms),
        float(state.path.total_length),
    )
    return "SMSG_ON_MONSTER_MOVE", payload


def _spline_vector(point: TaxiPathPoint) -> SplineVector:
    return SplineVector(float(point.x), float(point.y), float(point.z))


def _complete_taxi(session, state: TaxiFlightSession) -> None:
    _finish_taxi_state(session, state, send_updates=True)


def _finish_taxi_state(session, state: TaxiFlightSession, *, send_updates: bool) -> None:
    if state.completed:
        return
    state.completed = True
    state.active = False
    state.phase = TAXI_STATE_ARRIVAL
    session.taxi_controls_locked = False
    session.player_travel_state = TAXI_STATE_ARRIVAL
    session._taxi_generation = int(getattr(session, "_taxi_generation", 0) or 0) + 1

    final_point = _taxi_arrival_point(state)
    path_final_point = state.path.points[-1]
    orientation = path_final_point.orientation
    if orientation is None and len(state.path.points) >= 2:
        orientation = _segment_orientation(state.path.points[-2], path_final_point)
    _apply_taxi_position(session, final_point, float(orientation or 0.0))
    state.last_applied_z = float(final_point.z)
    _restore_pre_taxi_state(session, state)
    _stop_taxi_movement_state(session)
    if send_updates:
        _send_self_movement(session)
        broadcast_player_state_update(session, force=True)
        _send_self_responses(session, _build_mount_visual_responses(session, int(getattr(session, "mount_display_id", 0) or 0)))
        _broadcast_mount_visual(session, int(getattr(session, "mount_display_id", 0) or 0))

    Logger.info(
        "[TAXI] arrive player=%s destination=%s map=%s pos=(%.3f, %.3f, %.3f)",
        int(getattr(session, "char_guid", 0) or 0),
        int(state.destination_node),
        int(state.destination_map),
        float(session.x),
        float(session.y),
        float(session.z),
    )
    session.player_travel_state = TAXI_STATE_NORMAL
    session.taxi_state = None


def _interpolate_path(
    path: TaxiPath,
    traveled: float,
) -> tuple[TaxiPathPoint, int, float, float, int, float, float]:
    target_distance = max(0.0, min(float(traveled), float(path.total_length)))
    samples = path.arc_samples

    for index in range(1, len(samples)):
        end_sample = samples[index]
        if target_distance > float(end_sample.distance) and index != len(samples) - 1:
            continue

        start_sample = samples[index - 1]
        sample_distance = float(end_sample.distance) - float(start_sample.distance)
        progress = 0.0
        if sample_distance > 0.001:
            progress = (
                (target_distance - float(start_sample.distance))
                / sample_distance
            )
        progress = max(0.0, min(1.0, progress))

        x = _lerp(float(start_sample.x), float(end_sample.x), progress)
        y = _lerp(float(start_sample.y), float(end_sample.y), progress)
        z = _lerp(float(start_sample.z), float(end_sample.z), progress)
        orientation = _sample_orientation(path, target_distance, start_sample.orientation)
        if int(start_sample.segment_index) != int(end_sample.segment_index):
            segment_index = int(end_sample.segment_index)
            segment_progress = _lerp(0.0, float(end_sample.segment_progress), progress)
        else:
            segment_index = int(start_sample.segment_index)
            segment_progress = _lerp(
                float(start_sample.segment_progress),
                float(end_sample.segment_progress),
                progress,
            )

        point = TaxiPathPoint(
            x=x,
            y=y,
            z=z,
            orientation=orientation,
            map_id=end_sample.map_id if progress >= 1.0 else start_sample.map_id,
        )
        total_progress = target_distance / max(0.001, float(path.total_length))
        return (
            point,
            int(segment_index),
            float(segment_progress),
            float(total_progress),
            index - 1,
            float(progress),
            float(sample_distance),
        )

    final = path.points[-1]
    orientation = final.orientation
    if orientation is None and len(path.points) >= 2:
        orientation = _segment_orientation(path.points[-2], final)
    return (
        TaxiPathPoint(final.x, final.y, final.z, float(orientation or 0.0), final.map_id),
        max(0, len(path.points) - 2),
        1.0,
        1.0,
        max(0, len(samples) - 2),
        1.0,
        0.0,
    )


def _send_taxi_movement_update(session, state: TaxiFlightSession) -> None:
    timestamp_ms = _advance_taxi_movement_timestamp(state)
    session._taxi_movement_timestamp_override_ms = int(timestamp_ms)
    cached_response = _build_self_movement_response(session)
    session._cached_player_move_response = cached_response
    try:
        _send_self_movement(session)
        broadcast_player_state_update(session, force=True)
    finally:
        if getattr(session, "_cached_player_move_response", None) is cached_response:
            session._cached_player_move_response = None
        session._taxi_movement_timestamp_override_ms = None

    packet_delta = 0.0
    now = time.monotonic()
    if state.last_packet_at is not None:
        packet_delta = float(now) - float(state.last_packet_at)
    state.last_packet_at = float(now)
    Logger.debug(
        "[TAXI] tick player=%s segment=%s segment_progress=%.3f total_progress=%.3f pos=(%.3f, %.3f, %.3f)",
        int(getattr(session, "char_guid", 0) or 0),
        int(state.current_segment),
        float(state.segment_progress),
        float(state.total_progress),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
    )
    _taxi_debug(
        "[TAXI_DEBUG] packet player=%s tick=%s timestamp=%s cadence=%.3f payload=%s segment=%s segment_progress=%.4f total_progress=%.4f pos=(%.3f %.3f %.3f) o=%.3f",
        int(getattr(session, "char_guid", 0) or 0),
        int(state.tick_index),
        int(timestamp_ms),
        float(packet_delta),
        len(cached_response[1]) if cached_response is not None else 0,
        int(state.current_segment),
        float(state.segment_progress),
        float(state.total_progress),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )


def _send_self_movement(session) -> None:
    response = _build_self_movement_response(session)
    if response is not None:
        _send_self_responses(session, [response])


def _build_self_movement_response(session) -> tuple[str, bytes] | None:
    cached = getattr(session, "_cached_player_move_response", None)
    if cached is not None:
        return cached

    try:
        from server.modules.handlers.world.opcodes.movement import build_smsg_player_move_payload
    except Exception as exc:
        Logger.warning("[TAXI] movement payload import failed: %s", exc)
        return None

    payload = build_smsg_player_move_payload(session)
    if not payload:
        return None
    return "SMSG_PLAYER_MOVE", payload


def _send_self_responses(session, responses: list[tuple[str, bytes]]) -> None:
    sender = getattr(session, "send_response", None)
    if callable(sender) and responses:
        try:
            sender(responses)
        except Exception as exc:
            Logger.warning("[TAXI] self send failed guid=%s err=%s", int(getattr(session, "char_guid", 0) or 0), exc)


def _apply_taxi_mount(session, state: TaxiFlightSession, mount_display_id: int) -> list[tuple[str, bytes]]:
    display_id = int(mount_display_id or DEFAULT_TAXI_MOUNT_DISPLAY_ID)
    session.is_mounted = True
    session.mount_spell = None
    session.mount_display_id = display_id
    session.can_fly = True
    session.is_flying = True
    session.fly_speed = float(state.speed)
    session.fly_back_speed = float(state.speed)
    responses = _build_mount_visual_responses(session, display_id)
    _broadcast_mount_visual(session, display_id)
    return responses


def _restore_pre_taxi_state(session, state: TaxiFlightSession) -> None:
    session.can_fly = bool(state.original_can_fly)
    session.is_flying = bool(state.original_is_flying)
    session.is_mounted = bool(state.original_is_mounted)
    session.mount_spell = state.original_mount_spell
    session.mount_display_id = int(state.original_mount_display_id)
    session.unit_flags = int(state.original_unit_flags)
    session.run_speed = float(state.original_run_speed)
    session.fly_speed = float(state.original_fly_speed)
    session.fly_back_speed = float(state.original_fly_back_speed)

    movement_state = getattr(session, "movement_state", None)
    if movement_state is not None:
        flags = int(getattr(movement_state, "flags", 0) or 0)
        flags &= ~(
            _MOVEMENTFLAG_CAN_FLY
            | _MOVEMENTFLAG_FLYING
            | _MOVEMENTFLAG_ASCENDING
            | _MOVEMENTFLAG_DESCENDING
        )
        if bool(state.original_can_fly):
            flags |= _MOVEMENTFLAG_CAN_FLY
        if bool(state.original_is_flying):
            flags |= _MOVEMENTFLAG_FLYING
        movement_state.flags = int(flags)
        movement_state.is_ascending = False
        movement_state.is_descending = False


def _stop_taxi_movement_state(session) -> None:
    movement_state = getattr(session, "movement_state", None)
    if movement_state is None:
        return

    flags = int(getattr(movement_state, "flags", 0) or 0)
    movement_state.flags = int(flags & ~_MOVEMENTFLAG_TAXI_STOP_MASK)
    movement_state.is_ascending = False
    movement_state.is_descending = False
    movement_state.has_fall_data = False
    movement_state.fall_time = 0
    movement_state.fall_vertical_speed = 0.0
    movement_state.fall_horizontal_speed = 0.0
    movement_state.fall_sin_angle = 0.0
    movement_state.fall_cos_angle = 0.0


def _apply_taxi_position(session, point: TaxiPathPoint, orientation: float) -> None:
    orientation = _normalize_orientation(orientation)
    if point.map_id is not None:
        session.map_id = int(point.map_id)
    session.x = float(point.x)
    session.y = float(point.y)
    session.z = float(point.z)
    session.orientation = float(orientation)
    session.position_dirty = True

    movement_state = getattr(session, "movement_state", None)
    if movement_state is None:
        from server.session.world_session import MovementState

        movement_state = MovementState()
        session.movement_state = movement_state

    movement_state.x = float(point.x)
    movement_state.y = float(point.y)
    movement_state.z = float(point.z)
    movement_state.orientation = float(orientation)
    movement_state.last_valid_orientation = float(orientation)
    movement_state.has_fall_data = False
    movement_state.fall_time = 0
    movement_state.fall_vertical_speed = 0.0
    movement_state.fall_horizontal_speed = 0.0
    movement_state.fall_sin_angle = 0.0
    movement_state.fall_cos_angle = 0.0
    movement_state.is_ascending = False
    movement_state.is_descending = False
    movement_state.flags = (
        int(getattr(movement_state, "flags", 0) or 0)
        | _MOVEMENTFLAG_FORWARD
        | _MOVEMENTFLAG_CAN_FLY
        | _MOVEMENTFLAG_FLYING
    ) & ~(_MOVEMENTFLAG_ASCENDING | _MOVEMENTFLAG_DESCENDING)


def _build_mount_visual_responses(session, display_id: int) -> list[tuple[str, bytes]]:
    try:
        from server.modules.handlers.world.opcodes.spells import build_mount_visual_responses
    except Exception as exc:
        Logger.warning("[TAXI] mount visual import failed: %s", exc)
        return []
    return list(build_mount_visual_responses(session, int(display_id)))


def _broadcast_mount_visual(session, display_id: int) -> None:
    try:
        from server.modules.handlers.world.opcodes.spells import _broadcast_mount_visual_to_visible_peers
    except Exception as exc:
        Logger.warning("[TAXI] mount peer broadcast import failed: %s", exc)
        return
    _broadcast_mount_visual_to_visible_peers(session, int(display_id))


def _distance(a: TaxiPathPoint, b: TaxiPathPoint) -> float:
    dx = float(b.x) - float(a.x)
    dy = float(b.y) - float(a.y)
    dz = float(b.z) - float(a.z)
    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz))


def _sample_distance(a: TaxiPathSample, b: TaxiPathSample) -> float:
    dx = float(b.x) - float(a.x)
    dy = float(b.y) - float(a.y)
    dz = float(b.z) - float(a.z)
    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz))


def _build_taxi_arc_samples(points: tuple[TaxiPathPoint, ...]) -> tuple[TaxiPathSample, ...]:
    if len(points) < 2:
        return ()

    # TODO: Replace server-side sampled movement with native MoP taxi spline
    # packets once the packet builder can emit full client-owned spline state.
    first_orientation = points[0].orientation
    if first_orientation is None:
        first_orientation = _segment_orientation(points[0], points[1])

    samples: list[TaxiPathSample] = [
        TaxiPathSample(
            x=float(points[0].x),
            y=float(points[0].y),
            z=float(points[0].z),
            orientation=float(first_orientation or 0.0),
            map_id=points[0].map_id,
            segment_index=0,
            segment_progress=0.0,
            distance=0.0,
        )
    ]

    previous = samples[0]
    total_distance = 0.0
    for index in range(len(points) - 1):
        start = points[index]
        end = points[index + 1]
        if start.map_id is not None and end.map_id is not None and int(start.map_id) != int(end.map_id):
            orientation = _segment_orientation(start, end)
            sample = TaxiPathSample(
                x=float(end.x),
                y=float(end.y),
                z=float(end.z),
                orientation=float(orientation),
                map_id=end.map_id,
                segment_index=index,
                segment_progress=1.0,
                distance=total_distance,
            )
            samples.append(sample)
            previous = sample
            continue

        p0 = points[max(0, index - 1)]
        p3 = points[min(len(points) - 1, index + 2)]
        steps = max(2, int(TAXI_ARC_SAMPLES_PER_SEGMENT))
        for step_index in range(1, steps + 1):
            progress = float(step_index) / float(steps)
            x, y, z = _taxi_curve_position(p0, start, end, p3, progress, len(points))
            orientation = _segment_orientation(
                TaxiPathPoint(previous.x, previous.y, previous.z, previous.orientation, previous.map_id),
                TaxiPathPoint(x, y, z, None, start.map_id),
            )
            sample = TaxiPathSample(
                x=float(x),
                y=float(y),
                z=float(z),
                orientation=float(orientation),
                map_id=end.map_id if progress >= 1.0 else start.map_id,
                segment_index=index,
                segment_progress=float(progress),
                distance=0.0,
            )
            total_distance += _sample_distance(previous, sample)
            sample = TaxiPathSample(
                x=sample.x,
                y=sample.y,
                z=sample.z,
                orientation=sample.orientation,
                map_id=sample.map_id,
                segment_index=sample.segment_index,
                segment_progress=sample.segment_progress,
                distance=float(total_distance),
            )
            samples.append(sample)
            previous = sample

    samples = list(_smooth_taxi_altitude_samples(tuple(samples)))

    _taxi_debug(
        "[TAXI_DEBUG] arc points=%s samples=%s length=%.3f",
        len(points),
        len(samples),
        float(samples[-1].distance if samples else total_distance),
    )
    _log_taxi_arc_segments(tuple(samples), len(points) - 1)
    return tuple(samples)


def _densify_taxi_arc_samples(samples: tuple[TaxiPathSample, ...]) -> tuple[TaxiPathSample, ...]:
    if len(samples) < 2:
        return samples

    max_spacing = max(0.5, float(TAXI_MAX_RUNTIME_SAMPLE_SPACING))
    dense: list[TaxiPathSample] = [
        TaxiPathSample(
            x=float(samples[0].x),
            y=float(samples[0].y),
            z=float(samples[0].z),
            orientation=float(samples[0].orientation),
            map_id=samples[0].map_id,
            segment_index=int(samples[0].segment_index),
            segment_progress=float(samples[0].segment_progress),
            distance=0.0,
        )
    ]

    total_distance = 0.0
    previous = dense[0]
    inserted = 0
    for start, end in zip(samples, samples[1:]):
        spacing = _sample_distance(start, end)
        steps = max(1, int(math.ceil(spacing / max_spacing)))
        for step_index in range(1, steps + 1):
            progress = float(step_index) / float(steps)
            segment_index = int(start.segment_index if progress < 1.0 else end.segment_index)
            segment_progress = _lerp(float(start.segment_progress), float(end.segment_progress), progress)
            if int(start.segment_index) != int(end.segment_index) and progress < 1.0:
                segment_progress = float(start.segment_progress)
            candidate = TaxiPathSample(
                x=_lerp(float(start.x), float(end.x), progress),
                y=_lerp(float(start.y), float(end.y), progress),
                z=_lerp(float(start.z), float(end.z), progress),
                orientation=_lerp(float(start.orientation), float(end.orientation), progress),
                map_id=end.map_id if progress >= 1.0 else start.map_id,
                segment_index=segment_index,
                segment_progress=segment_progress,
                distance=0.0,
            )
            total_distance += _sample_distance(previous, candidate)
            dense.append(
                TaxiPathSample(
                    x=candidate.x,
                    y=candidate.y,
                    z=candidate.z,
                    orientation=candidate.orientation,
                    map_id=candidate.map_id,
                    segment_index=candidate.segment_index,
                    segment_progress=candidate.segment_progress,
                    distance=float(total_distance),
                )
            )
            previous = dense[-1]
            if step_index < steps:
                inserted += 1

    _taxi_debug(
        "[TAXI_DEBUG] densify input_samples=%s output_samples=%s inserted=%s max_spacing=%.3f",
        len(samples),
        len(dense),
        int(inserted),
        float(max_spacing),
    )
    return tuple(dense)


def _taxi_curve_position(
    p0: TaxiPathPoint,
    p1: TaxiPathPoint,
    p2: TaxiPathPoint,
    p3: TaxiPathPoint,
    progress: float,
    point_count: int,
) -> tuple[float, float, float]:
    t = max(0.0, min(1.0, float(progress)))
    t2 = t * t
    t3 = t2 * t

    if point_count <= 2:
        x, y = _direct_arc_xy(p1, p2, t)
        z = _direct_arc_z(p1, p2, t)
        return x, y, z

    x = _catmull_axis(float(p0.x), float(p1.x), float(p2.x), float(p3.x), t, t2, t3)
    y = _catmull_axis(float(p0.y), float(p1.y), float(p2.y), float(p3.y), t, t2, t3)

    z = _monotone_cubic_z(p0, p1, p2, p3, t, t2, t3)
    return x, y, z


def _catmull_axis(p0: float, p1: float, p2: float, p3: float, t: float, t2: float, t3: float) -> float:
    tension = float(TAXI_CURVE_TENSION)
    tangent_start = (p2 - p0) * tension
    tangent_end = (p3 - p1) * tension
    h00 = (2.0 * t3) - (3.0 * t2) + 1.0
    h10 = t3 - (2.0 * t2) + t
    h01 = (-2.0 * t3) + (3.0 * t2)
    h11 = t3 - t2
    return (
        (h00 * p1)
        + (h10 * tangent_start)
        + (h01 * p2)
        + (h11 * tangent_end)
    )


def _monotone_cubic_z(
    p0: TaxiPathPoint,
    p1: TaxiPathPoint,
    p2: TaxiPathPoint,
    p3: TaxiPathPoint,
    t: float,
    t2: float,
    t3: float,
) -> float:
    z1 = float(p1.z)
    z2 = float(p2.z)
    dz = z2 - z1
    if abs(dz) <= 0.0001:
        return z1

    h0 = _safe_tangent_distance(p0, p1)
    h1 = _safe_tangent_distance(p1, p2)
    h2 = _safe_tangent_distance(p2, p3)
    slope0 = (float(p1.z) - float(p0.z)) / h0
    slope1 = dz / h1
    slope2 = (float(p3.z) - float(p2.z)) / h2

    tangent_start = _monotone_tangent(slope0, slope1) * h1
    tangent_end = _monotone_tangent(slope1, slope2) * h1

    h00 = (2.0 * t3) - (3.0 * t2) + 1.0
    h10 = t3 - (2.0 * t2) + t
    h01 = (-2.0 * t3) + (3.0 * t2)
    h11 = t3 - t2
    value = (
        (h00 * z1)
        + (h10 * tangent_start)
        + (h01 * z2)
        + (h11 * tangent_end)
    )
    return _clamp(value, min(z1, z2), max(z1, z2))


def _monotone_tangent(previous_slope: float, next_slope: float) -> float:
    if previous_slope == 0.0 or next_slope == 0.0:
        return 0.0
    if (previous_slope < 0.0) != (next_slope < 0.0):
        return 0.0
    return (2.0 * previous_slope * next_slope) / (previous_slope + next_slope)


def _safe_tangent_distance(a: TaxiPathPoint, b: TaxiPathPoint) -> float:
    horizontal = math.sqrt(
        ((float(b.x) - float(a.x)) ** 2)
        + ((float(b.y) - float(a.y)) ** 2)
    )
    if horizontal > 0.001:
        return horizontal
    return max(0.001, _distance(a, b))


def _stabilize_taxi_altitude(state: TaxiFlightSession, target_z: float, elapsed: float) -> float:
    previous_z = state.last_applied_z
    if previous_z is None:
        state.last_applied_z = float(target_z)
        return float(target_z)

    elapsed_seconds = max(float(TAXI_TICK_SECONDS), float(elapsed))
    time_delta = max(float(TAXI_MAX_Z_DELTA_PER_TICK), float(TAXI_MAX_Z_SPEED) * elapsed_seconds)
    max_delta = max(0.0, time_delta)
    if max_delta <= 0.0:
        state.last_applied_z = float(target_z)
        return float(target_z)

    delta = float(target_z) - float(previous_z)
    if abs(delta) <= max_delta:
        state.last_applied_z = float(target_z)
        return float(target_z)

    applied_z = float(previous_z) + (math.copysign(max_delta, delta))
    state.last_applied_z = float(applied_z)
    _taxi_debug(
        "[TAXI_DEBUG] z_guard segment=%s progress=%.4f current_z=%.3f target_z=%.3f applied_z=%.3f delta=%.3f max_delta=%.3f elapsed=%.3f",
        int(state.current_segment),
        float(state.segment_progress),
        float(previous_z),
        float(target_z),
        float(applied_z),
        float(delta),
        float(max_delta),
        float(elapsed),
    )
    return float(applied_z)


def _log_taxi_altitude_tick(
    session,
    state: TaxiFlightSession,
    *,
    traveled: float,
    segment_index: int,
    segment_progress: float,
    total_progress: float,
    raw_z: float,
    applied_z: float,
    previous_applied_z: float | None,
    previous_target_z: float | None,
    raw_x: float,
    raw_y: float,
    sample_index: int,
    sample_progress: float,
    sample_spacing: float,
    applied_delta: float,
    elapsed: float,
) -> None:
    if not _taxi_debug_enabled():
        return

    target_delta = 0.0
    if previous_target_z is not None:
        target_delta = float(raw_z) - float(previous_target_z)
    dx = float(raw_x) - float(getattr(session, "_taxi_last_log_x", raw_x) or raw_x)
    dy = float(raw_y) - float(getattr(session, "_taxi_last_log_y", raw_y) or raw_y)
    dz = float(applied_z) - float(getattr(session, "_taxi_last_log_z", applied_z) or applied_z)
    actual_speed = 0.0
    if float(elapsed) > 0.001:
        actual_speed = math.sqrt((dx * dx) + (dy * dy) + (dz * dz)) / float(elapsed)
    session._taxi_last_log_x = float(raw_x)
    session._taxi_last_log_y = float(raw_y)
    session._taxi_last_log_z = float(applied_z)

    _taxi_debug(
        "TAXI_RUNTIME tick=%s player=%s sampleA=%s sampleB=%s t=%.4f "
        "segment=%s segment_progress=%.4f total_progress=%.4f "
        "dt=%.3f traveled=%.3f traveled_delta=%.3f raw_z=%.3f previous_target_z=%s "
        "target_delta=%.3f previous_applied_z=%s applied_z=%.3f applied_delta=%.3f "
        "dx=%.3f dy=%.3f dz=%.3f speed=%.3f max_dz=%.3f segment_length=%.3f sample_spacing=%.3f pos=(%.3f %.3f %.3f)",
        int(state.tick_index),
        int(getattr(session, "char_guid", 0) or 0),
        int(sample_index),
        int(sample_index) + 1,
        float(sample_progress),
        int(segment_index),
        float(segment_progress),
        float(total_progress),
        float(elapsed),
        float(traveled),
        float(traveled) - float(state.last_traveled),
        float(raw_z),
        _debug_float(previous_target_z),
        float(target_delta),
        _debug_float(previous_applied_z),
        float(applied_z),
        float(applied_delta),
        float(dx),
        float(dy),
        float(dz),
        float(actual_speed),
        float(state.max_z_delta_observed),
        float(sample_spacing),
        float(sample_spacing),
        float(raw_x),
        float(raw_y),
        float(applied_z),
    )


def _log_taxi_arc_segments(samples: tuple[TaxiPathSample, ...], segment_count: int) -> None:
    if not _taxi_debug_enabled():
        return

    for segment_index in range(max(0, int(segment_count))):
        segment_samples = [
            sample
            for sample in samples
            if int(sample.segment_index) == int(segment_index)
        ]
        if not segment_samples:
            continue

        min_sample = min(segment_samples, key=lambda sample: float(sample.z))
        max_sample = max(segment_samples, key=lambda sample: float(sample.z))
        max_step_delta = 0.0
        for start, end in zip(segment_samples, segment_samples[1:]):
            max_step_delta = max(max_step_delta, abs(float(end.z) - float(start.z)))

        first = segment_samples[0]
        last = segment_samples[-1]
        _taxi_debug(
            "[TAXI_DEBUG] z_segment segment=%s samples=%s distance=(%.3f %.3f) "
            "z_start=%.3f z_end=%.3f z_min=%.3f min_progress=%.3f "
            "z_max=%.3f max_progress=%.3f max_sample_delta=%.3f",
            int(segment_index),
            len(segment_samples),
            float(first.distance),
            float(last.distance),
            float(first.z),
            float(last.z),
            float(min_sample.z),
            float(min_sample.segment_progress),
            float(max_sample.z),
            float(max_sample.segment_progress),
            float(max_step_delta),
        )


def _log_taxi_path_measurements(path: TaxiPath) -> None:
    if not _taxi_debug_enabled():
        return
    spacings = [
        _sample_distance(start, end)
        for start, end in zip(path.arc_samples, path.arc_samples[1:])
    ]
    average_spacing = sum(spacings) / len(spacings) if spacings else 0.0
    max_spacing = max(spacings) if spacings else 0.0
    max_z_step = max(
        (abs(float(end.z) - float(start.z)) for start, end in zip(path.arc_samples, path.arc_samples[1:])),
        default=0.0,
    )
    _taxi_debug(
        "[TAXI_DEBUG] path_metrics source=%s destination=%s points=%s samples=%s length=%.3f avg_spacing=%.3f max_spacing=%.3f max_z_step=%.3f",
        int(path.source_node),
        int(path.destination_node),
        len(path.points),
        len(path.arc_samples),
        float(path.total_length),
        float(average_spacing),
        float(max_spacing),
        float(max_z_step),
    )


def _debug_float(value: float | None) -> str:
    if value is None:
        return "None"
    return "%.3f" % float(value)


def _smooth_taxi_altitude_samples(samples: tuple[TaxiPathSample, ...]) -> tuple[TaxiPathSample, ...]:
    if len(samples) <= 2:
        return samples
    if max(int(sample.segment_index) for sample in samples) <= 0:
        return samples

    raw_z = [float(sample.z) for sample in samples]
    distances = [float(sample.distance) for sample in samples]
    segment_bounds = _taxi_segment_z_bounds(samples, raw_z)
    smoothed_z = list(raw_z)

    window = max(0.0, float(TAXI_Z_SMOOTHING_WINDOW_YARDS))
    passes = max(0, int(TAXI_Z_SMOOTHING_PASSES))
    if window > 0.001 and passes > 0:
        radius = window * 0.5
        for _pass in range(passes):
            next_z = list(smoothed_z)
            for index in range(1, len(samples) - 1):
                center = distances[index]
                weighted_sum = 0.0
                weight_total = 0.0
                for other_index, other_z in enumerate(smoothed_z):
                    offset = abs(distances[other_index] - center)
                    if offset > radius:
                        continue
                    weight = 1.0 - (offset / radius) if radius > 0.001 else 1.0
                    weight = weight * weight
                    weighted_sum += float(other_z) * weight
                    weight_total += weight
                if weight_total > 0.001:
                    next_z[index] = weighted_sum / weight_total
            next_z[0] = raw_z[0]
            next_z[-1] = raw_z[-1]
            smoothed_z = next_z

    max_offset = max(0.0, float(TAXI_Z_SMOOTHING_MAX_OFFSET))
    if max_offset > 0.0:
        for index in range(1, len(samples) - 1):
            smoothed_z[index] = _clamp(
                smoothed_z[index],
                raw_z[index] - max_offset,
                raw_z[index] + max_offset,
            )

    smoothed_z = _clamp_taxi_altitude_to_segment_bounds(samples, smoothed_z, segment_bounds)
    smoothed_z = _limit_taxi_altitude_slope(distances, smoothed_z)
    smoothed_z = _clamp_taxi_altitude_to_segment_bounds(samples, smoothed_z, segment_bounds)
    return _rebuild_taxi_samples_with_z(samples, smoothed_z, raw_z)


def _taxi_segment_z_bounds(
    samples: tuple[TaxiPathSample, ...],
    z_values: list[float],
) -> dict[int, tuple[float, float]]:
    bounds: dict[int, tuple[float, float]] = {}
    for index, sample in enumerate(samples):
        segment_index = int(sample.segment_index)
        z = float(z_values[index])
        if segment_index not in bounds:
            bounds[segment_index] = (z, z)
            continue
        minimum, maximum = bounds[segment_index]
        bounds[segment_index] = (min(minimum, z), max(maximum, z))
    return bounds


def _clamp_taxi_altitude_to_segment_bounds(
    samples: tuple[TaxiPathSample, ...],
    z_values: list[float],
    segment_bounds: dict[int, tuple[float, float]],
) -> list[float]:
    clamped = list(z_values)
    for index in range(1, len(samples) - 1):
        bounds = segment_bounds.get(int(samples[index].segment_index))
        if bounds is None:
            continue
        clamped[index] = _clamp(clamped[index], bounds[0], bounds[1])
    clamped[0] = float(z_values[0])
    clamped[-1] = float(z_values[-1])
    return clamped


def _limit_taxi_altitude_slope(distances: list[float], z_values: list[float]) -> list[float]:
    if len(z_values) <= 2:
        return z_values

    total_distance = max(0.001, float(distances[-1]) - float(distances[0]))
    required_slope = abs(float(z_values[-1]) - float(z_values[0])) / total_distance
    max_slope = max(float(TAXI_MAX_Z_SLOPE_PER_YARD), required_slope * 1.05)
    limited = list(z_values)
    limited[0] = float(z_values[0])
    limited[-1] = float(z_values[-1])

    for _pass in range(4):
        limited[0] = float(z_values[0])
        for index in range(1, len(limited)):
            max_step = max_slope * max(0.001, float(distances[index]) - float(distances[index - 1]))
            limited[index] = _clamp(limited[index], limited[index - 1] - max_step, limited[index - 1] + max_step)

        limited[-1] = float(z_values[-1])
        for index in range(len(limited) - 2, -1, -1):
            max_step = max_slope * max(0.001, float(distances[index + 1]) - float(distances[index]))
            limited[index] = _clamp(limited[index], limited[index + 1] - max_step, limited[index + 1] + max_step)

    limited[0] = float(z_values[0])
    limited[-1] = float(z_values[-1])
    return limited


def _rebuild_taxi_samples_with_z(
    samples: tuple[TaxiPathSample, ...],
    z_values: list[float],
    raw_z: list[float],
) -> tuple[TaxiPathSample, ...]:
    rebuilt: list[TaxiPathSample] = []
    distance = 0.0
    previous: TaxiPathSample | None = None
    max_raw_delta = 0.0
    max_smoothed_delta = 0.0
    max_offset = 0.0

    for index, sample in enumerate(samples):
        rebuilt_sample = TaxiPathSample(
            x=float(sample.x),
            y=float(sample.y),
            z=float(z_values[index]),
            orientation=float(sample.orientation),
            map_id=sample.map_id,
            segment_index=int(sample.segment_index),
            segment_progress=float(sample.segment_progress),
            distance=float(distance),
        )
        if previous is not None:
            distance += _sample_distance(previous, rebuilt_sample)
            rebuilt_sample = TaxiPathSample(
                x=rebuilt_sample.x,
                y=rebuilt_sample.y,
                z=rebuilt_sample.z,
                orientation=rebuilt_sample.orientation,
                map_id=rebuilt_sample.map_id,
                segment_index=rebuilt_sample.segment_index,
                segment_progress=rebuilt_sample.segment_progress,
                distance=float(distance),
            )
            max_raw_delta = max(max_raw_delta, abs(float(raw_z[index]) - float(raw_z[index - 1])))
            max_smoothed_delta = max(max_smoothed_delta, abs(float(z_values[index]) - float(z_values[index - 1])))
        max_offset = max(max_offset, abs(float(z_values[index]) - float(raw_z[index])))
        rebuilt.append(rebuilt_sample)
        previous = rebuilt_sample

    _taxi_debug(
        "[TAXI_DEBUG] z_smooth samples=%s max_raw_delta=%.3f max_smoothed_delta=%.3f max_offset=%.3f",
        len(samples),
        float(max_raw_delta),
        float(max_smoothed_delta),
        float(max_offset),
    )
    return tuple(rebuilt)


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(float(minimum), min(float(maximum), float(value)))


def _direct_arc_z(p1: TaxiPathPoint, p2: TaxiPathPoint, progress: float) -> float:
    base_z = _lerp(float(p1.z), float(p2.z), progress)
    horizontal = math.sqrt(
        ((float(p2.x) - float(p1.x)) ** 2)
        + ((float(p2.y) - float(p1.y)) ** 2)
    )
    if horizontal < TAXI_DIRECT_ARC_MIN_DISTANCE:
        return base_z

    height = min(
        TAXI_DIRECT_ARC_MAX_HEIGHT,
        max(8.0, horizontal * 0.08),
    )
    arc = 4.0 * progress * (1.0 - progress)
    return base_z + (height * arc)


def _direct_arc_xy(p1: TaxiPathPoint, p2: TaxiPathPoint, progress: float) -> tuple[float, float]:
    start_x = float(p1.x)
    start_y = float(p1.y)
    end_x = float(p2.x)
    end_y = float(p2.y)
    base_x = _lerp(start_x, end_x, progress)
    base_y = _lerp(start_y, end_y, progress)

    dx = end_x - start_x
    dy = end_y - start_y
    horizontal = math.sqrt((dx * dx) + (dy * dy))
    if horizontal < TAXI_DIRECT_ARC_MIN_DISTANCE:
        return base_x, base_y

    side = 1.0
    if p1.orientation is not None:
        facing_cross = (
            (math.cos(float(p1.orientation)) * dy)
            - (math.sin(float(p1.orientation)) * dx)
        )
        if facing_cross < 0.0:
            side = -1.0

    offset = min(TAXI_DIRECT_ARC_SIDE_MAX_OFFSET, horizontal * 0.04)
    arc = 4.0 * progress * (1.0 - progress)
    normal_x = -dy / horizontal
    normal_y = dx / horizontal
    return (
        base_x + (normal_x * offset * arc * side),
        base_y + (normal_y * offset * arc * side),
    )


def _segment_lengths_from_samples(
    samples: tuple[TaxiPathSample, ...],
    segment_count: int,
) -> tuple[float, ...]:
    lengths = [0.0 for _index in range(max(0, int(segment_count)))]
    for start, end in zip(samples, samples[1:]):
        index = max(0, min(len(lengths) - 1, int(end.segment_index))) if lengths else 0
        if lengths:
            lengths[index] += _sample_distance(start, end)
    return tuple(float(length) for length in lengths)


def _sample_orientation(path: TaxiPath, distance: float, fallback: float) -> float:
    current = _sample_at_distance(path.arc_samples, distance)
    ahead = _sample_at_distance(
        path.arc_samples,
        min(float(path.total_length), float(distance) + TAXI_ORIENTATION_LOOKAHEAD_YARDS),
    )
    return _normalize_orientation(
        _segment_orientation(
            TaxiPathPoint(current.x, current.y, current.z, fallback, current.map_id),
            TaxiPathPoint(ahead.x, ahead.y, ahead.z, ahead.orientation, ahead.map_id),
        )
    )


def _sample_at_distance(samples: tuple[TaxiPathSample, ...], distance: float) -> TaxiPathSample:
    if not samples:
        raise ValueError("taxi path has no arc samples")
    target = max(0.0, float(distance))
    for index in range(1, len(samples)):
        end = samples[index]
        if target > float(end.distance) and index != len(samples) - 1:
            continue
        start = samples[index - 1]
        span = float(end.distance) - float(start.distance)
        progress = 0.0 if span <= 0.001 else (target - float(start.distance)) / span
        progress = max(0.0, min(1.0, progress))
        return TaxiPathSample(
            x=_lerp(float(start.x), float(end.x), progress),
            y=_lerp(float(start.y), float(end.y), progress),
            z=_lerp(float(start.z), float(end.z), progress),
            orientation=_lerp(float(start.orientation), float(end.orientation), progress),
            map_id=end.map_id if progress >= 1.0 else start.map_id,
            segment_index=int(start.segment_index),
            segment_progress=_lerp(float(start.segment_progress), float(end.segment_progress), progress),
            distance=target,
        )
    return samples[-1]


def _lerp(start: float, end: float, progress: float) -> float:
    return float(start) + ((float(end) - float(start)) * max(0.0, min(1.0, float(progress))))


def _path_length(points: list[TaxiPathPoint]) -> float:
    return sum(_distance(start, end) for start, end in zip(points, points[1:]))


def _segment_orientation(a: TaxiPathPoint, b: TaxiPathPoint) -> float:
    dx = float(b.x) - float(a.x)
    dy = float(b.y) - float(a.y)
    if abs(dx) <= 0.0001 and abs(dy) <= 0.0001:
        return float(a.orientation or b.orientation or 0.0)
    return _normalize_orientation(math.atan2(dy, dx))


def _normalize_orientation(value: float) -> float:
    result = float(value) % (math.pi * 2.0)
    if result < 0.0:
        result += math.pi * 2.0
    return result


def _taxi_debug(message: str, *args) -> None:
    if not _taxi_debug_enabled():
        return
    Logger.debug(message, *args)


def _taxi_debug_enabled() -> bool:
    try:
        config = ConfigLoader.load_config()
        taxi_config = config.get("Taxi", {}) if isinstance(config, dict) else {}
        return bool(taxi_config.get("DebugMovement", False))
    except Exception:
        return False
