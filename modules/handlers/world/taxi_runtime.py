#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from shared.Logger import Logger
from server.modules.handlers.world.feature_config import flight_paths_enabled
from server.modules.handlers.world.movements.manager import get_movement_manager
from server.modules.handlers.world.movements.templates import build_template
from server.modules.handlers.world.movements.types import InterpolationMode, MovementKind, MovementNode
from server.modules.handlers.world.state.runtime import broadcast_player_state_update


TAXI_TICK_SECONDS = 0.1
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
    movement_instance_id: int = 0
    movement_template_id: str = ""
    movement_period_ms: int = 0


def _taxi_instance_id(session) -> int:
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    if char_guid <= 0:
        char_guid = id(session) & 0x00FFFFFFFFFFFFFF
    return 0x7A00000000000000 | (char_guid & 0x00FFFFFFFFFFFFFF)


def _taxi_period_ms(path_points: list[TaxiPathPoint], speed: float) -> int:
    total = _path_length(list(path_points))
    return max(1, int((total / max(1.0, float(speed))) * 1000.0))


def _build_taxi_template(session, path_points: list[TaxiPathPoint], period_ms: int):
    total = max(0.001, _path_length(list(path_points)))
    traveled = 0.0
    previous: TaxiPathPoint | None = None
    nodes: list[MovementNode] = []
    for point in path_points:
        if previous is not None:
            traveled += _distance(previous, point)
        nodes.append(
            MovementNode(
                map_id=int(getattr(session, "map_id", 0) or 0),
                x=float(point.x),
                y=float(point.y),
                z=float(point.z),
                time_ms=int(round((traveled / total) * float(period_ms))),
                yaw=point.orientation,
            )
        )
        previous = point
    return build_template(
        "taxi:%s:%s" % (
            int(getattr(session, "char_guid", 0) or 0),
            int(time.time() * 1000.0),
        ),
        MovementKind.TAXI,
        tuple(nodes),
        interpolation_mode=InterpolationMode.SPLINE,
        period_ms=int(period_ms),
    )


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
    if not flight_paths_enabled():
        Logger.info("[TAXI] start blocked; flight paths disabled")
        return []

    speed = max(1.0, float(speed))
    period_ms = _taxi_period_ms(path_points, speed)
    template, reason = _build_taxi_template(session, path_points, period_ms)
    if template is None:
        Logger.warning("[TAXI] start rejected reason=invalid_template detail=%s", reason)
        return []

    generation = int(getattr(session, "_taxi_generation", 0) or 0) + 1
    session._taxi_generation = generation
    instance_id = _taxi_instance_id(session)
    now_ms = int(time.monotonic() * 1000.0)
    phase_offset_ms = -(now_ms % max(1, int(period_ms)))
    # phase_offset_ms = 0
    movement_instance = get_movement_manager().register_instance(
        instance_id,
        template,
        phase_offset_ms=phase_offset_ms,
    )
    if movement_instance is None:
        Logger.warning("[TAXI] start rejected reason=duplicate_movement_instance id=0x%016X", instance_id)
        return []
    state = TaxiRuntimeState(
        active=True,
        path_points=list(path_points),
        current_segment=0,
        segment_progress=0.0,
        speed=speed,
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
        movement_instance_id=int(instance_id),
        movement_template_id=str(template.template_id),
        movement_period_ms=int(period_ms),
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

    # Använd MONOTONIC överallt för att undvika klockdrift
    current_time = time.monotonic() if now is None else float(now)
    
    # Hämta starttid (måste vara satt med time.monotonic() i start_taxi_flight!)
    start_time = float(state.started_at)
    
    # Beräkna exakt tid som passerat SINCE START (lokal tid)
    local_elapsed_ms = int((current_time - start_time) * 1000.0)

    # Beräkna traveled för att avgöra när flygningen är klar (använder samma tid)
    traveled = max(0.0, current_time - start_time) * float(state.speed)
    
    total = _path_length(list(state.path_points))
    completion_threshold = max(
        0.5,
        total - (float(state.speed) * TAXI_TICK_SECONDS)
    )

    if total <= 0.001 or traveled >= completion_threshold:
        _complete_taxi(session, state)
        return False

    # Klipp inte ut "last_elapsed_ms" här om du vill ha exakt tid för taxi.
    # Taxi behöver exakt tid för att interpolera korrekt.
    # (Om du har problem med "spikes" kan du klippa, men försök utan först)
    
    # Anropa movement manager med DEN NYA metoden för Taxi
    # Detta ignorerar den globala started_at_ms i manager och använder din lokala tid
    transform = get_movement_manager().tick_taxi_instance(
        int(state.movement_instance_id),
        local_elapsed_ms=local_elapsed_ms
    )
    
    if transform is None:
        Logger.warning("[TAXI] missing movement instance id=0x%016X", int(state.movement_instance_id))
        _complete_taxi(session, state)
        return False
        
    point = TaxiPathPoint(float(transform.x), float(transform.y), float(transform.z), float(transform.orientation))
    state.current_segment = int(transform.node_index)
    state.segment_progress = max(0.0, min(1.0, traveled / max(0.001, total)))
    
    _apply_taxi_position(session, point, float(transform.orientation))
    _send_taxi_movement_update(session, state)
    return True


def _start_taxi_thread(session, generation: int) -> None:
    state = getattr(session, "taxi_state", None)
    session._taxi_last_tick_at = float(getattr(state, "started_at", time.time()) or time.time())

    def _worker() -> None:
        while True:
            time.sleep(TAXI_TICK_SECONDS)
            # Kontrollera generation först
            if int(getattr(session, "_taxi_generation", 0) or 0) != int(generation):
                return
            
            # KALLA ENDAST EN GÅNG
            if not taxi_tick(session):
                return
            
            # Ta bort den andra anropet!
            # taxi_tick(session)  <-- RADERA DENNA RAD

    threading.Thread(
        target=_worker,
        name=f"taxi-{int(getattr(session, 'char_guid', 0) or 0)}",
        daemon=True,
    ).start()

def _complete_taxi(session, state: TaxiRuntimeState) -> None:
    if state.completed:
        return
    state.completed = True
    state.active = False
    get_movement_manager().unregister_instance(int(state.movement_instance_id))
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
