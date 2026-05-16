#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from shared.Logger import Logger
from server.modules.handlers.world.state.runtime import broadcast_player_state_update


TAXI_TICK_SECONDS = 0.05
DEFAULT_TAXI_SPEED = 32.0
DEFAULT_TAXI_MOUNT_DISPLAY_ID = 6851

_MOVEMENTFLAG_CAN_FLY = 0x00800000
_MOVEMENTFLAG_FLYING = 0x01000000
_MOVEMENTFLAG_ASCENDING = 0x00200000
_MOVEMENTFLAG_DESCENDING = 0x00400000
_MOVEMENTFLAG_FORWARD = 0x00000001


@dataclass(frozen=True)
class TaxiPathPoint:
    x: float
    y: float
    z: float
    orientation: float | None = None


@dataclass
class TaxiRuntimeState:
    active: bool
    path_points: list[TaxiPathPoint]
    current_segment: int
    segment_progress: float
    speed: float
    started_at: float
    destination_map: int
    destination_node: int
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


def is_taxi_active(session) -> bool:
    state = getattr(session, "taxi_state", None)
    return bool(state is not None and getattr(state, "active", False) and not getattr(state, "completed", False))


def start_taxi_flight(
    session,
    path_points: list[TaxiPathPoint],
    *,
    destination_map: int,
    destination_node: int,
    speed: float = DEFAULT_TAXI_SPEED,
    mount_display_id: int = DEFAULT_TAXI_MOUNT_DISPLAY_ID,
) -> list[tuple[str, bytes]]:
    if len(path_points) < 2:
        Logger.warning("[TAXI] start rejected reason=too_few_points destination=%s", int(destination_node))
        return []

    generation = int(getattr(session, "_taxi_generation", 0) or 0) + 1
    session._taxi_generation = generation
    state = TaxiRuntimeState(
        active=True,
        path_points=list(path_points),
        current_segment=0,
        segment_progress=0.0,
        speed=max(1.0, float(speed)),
        started_at=time.time(),
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
    )
    session.taxi_state = state
    session.taxi_controls_locked = True

    responses = _apply_taxi_mount(session, state, mount_display_id)
    _apply_taxi_position(session, path_points[0], _segment_orientation(path_points[0], path_points[1]))
    initial_move_response = _build_self_movement_response(session)
    if initial_move_response is not None:
        responses.append(initial_move_response)
    broadcast_player_state_update(session, force=True)

    Logger.info(
        "[TAXI] start node=%s map=%s points=%s speed=%.2f",
        int(destination_node),
        int(destination_map),
        len(path_points),
        float(state.speed),
    )
    _start_taxi_thread(session, generation)
    return responses


def taxi_tick(session, *, now: float | None = None) -> bool:
    state = getattr(session, "taxi_state", None)
    if state is None or not bool(getattr(state, "active", False)):
        return False
    if bool(getattr(state, "completed", False)):
        return False

    current_time = time.time() if now is None else float(now)
    last_tick = float(getattr(session, "_taxi_last_tick_at", 0.0) or 0.0)
    if last_tick <= 0.0:
        last_tick = current_time
    elapsed = max(0.0, min(1.0, current_time - last_tick))
    session._taxi_last_tick_at = current_time

    distance_left = float(state.speed) * elapsed
    points = list(state.path_points)

    while distance_left >= 0.0 and state.current_segment < len(points) - 1:
        start = points[state.current_segment]
        end = points[state.current_segment + 1]
        segment_length = _distance(start, end)
        if segment_length <= 0.001:
            _advance_segment(state)
            continue

        segment_left = segment_length * (1.0 - float(state.segment_progress))
        if distance_left < segment_left:
            state.segment_progress += distance_left / segment_length
            orientation = _segment_orientation(start, end)
            _apply_taxi_position(session, _lerp_point(start, end, state.segment_progress), orientation)
            _send_taxi_movement_update(session, state)
            return True

        distance_left -= segment_left
        state.segment_progress = 1.0
        _apply_taxi_position(session, end, _segment_orientation(start, end))
        _advance_segment(state)

    _complete_taxi(session, state)
    return False


def _start_taxi_thread(session, generation: int) -> None:
    session._taxi_last_tick_at = time.time()

    def _worker() -> None:
        while True:
            time.sleep(TAXI_TICK_SECONDS)
            if int(getattr(session, "_taxi_generation", 0) or 0) != int(generation):
                return
            if not is_taxi_active(session):
                return
            taxi_tick(session)

    threading.Thread(
        target=_worker,
        name=f"taxi-{int(getattr(session, 'char_guid', 0) or 0)}",
        daemon=True,
    ).start()


def _advance_segment(state: TaxiRuntimeState) -> None:
    state.current_segment += 1
    state.segment_progress = 0.0
    Logger.info("[TAXI] segment=%s progress=%.2f", int(state.current_segment), 0.0)


def _complete_taxi(session, state: TaxiRuntimeState) -> None:
    if state.completed:
        return
    state.completed = True
    state.active = False
    session.taxi_controls_locked = False
    session._taxi_generation = int(getattr(session, "_taxi_generation", 0) or 0) + 1

    final_point = state.path_points[-1]
    orientation = final_point.orientation
    if orientation is None and len(state.path_points) >= 2:
        orientation = _segment_orientation(state.path_points[-2], final_point)
    _apply_taxi_position(session, final_point, float(orientation or 0.0))
    _restore_pre_taxi_state(session, state)
    _send_self_movement(session)
    broadcast_player_state_update(session, force=True)
    _send_self_responses(session, _build_mount_visual_responses(session, int(getattr(session, "mount_display_id", 0) or 0)))
    _broadcast_mount_visual(session, int(getattr(session, "mount_display_id", 0) or 0))

    Logger.info(
        "[TAXI] arrive destination=%s map=%s pos=(%.3f, %.3f, %.3f)",
        int(state.destination_node),
        int(state.destination_map),
        float(session.x),
        float(session.y),
        float(session.z),
    )
    session.taxi_state = None


def _send_taxi_movement_update(session, state: TaxiRuntimeState) -> None:
    _send_self_movement(session)
    broadcast_player_state_update(session, force=True)
    Logger.debug(
        "[TAXI] tick segment=%s progress=%.2f pos=(%.3f, %.3f, %.3f)",
        int(state.current_segment),
        float(state.segment_progress),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
    )
    Logger.debug("[TAXI] movement packets sent")


def _send_self_movement(session) -> None:
    response = _build_self_movement_response(session)
    if response is not None:
        _send_self_responses(session, [response])


def _build_self_movement_response(session) -> tuple[str, bytes] | None:
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


def _apply_taxi_mount(session, state: TaxiRuntimeState, mount_display_id: int) -> list[tuple[str, bytes]]:
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


def _restore_pre_taxi_state(session, state: TaxiRuntimeState) -> None:
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


def _apply_taxi_position(session, point: TaxiPathPoint, orientation: float) -> None:
    orientation = _normalize_orientation(orientation)
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


def _lerp_point(a: TaxiPathPoint, b: TaxiPathPoint, progress: float) -> TaxiPathPoint:
    t = max(0.0, min(1.0, float(progress)))
    return TaxiPathPoint(
        x=float(a.x) + ((float(b.x) - float(a.x)) * t),
        y=float(a.y) + ((float(b.y) - float(a.y)) * t),
        z=float(a.z) + ((float(b.z) - float(a.z)) * t),
        orientation=b.orientation,
    )


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
