from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Iterable, Mapping

from shared.Logger import Logger
from server.modules.game.guid import GameObjectGuid
from server.modules.handlers.world.bootstrap.gameobjects import _build_gameobject_update_payload
from server.modules.handlers.world.bootstrap.playerobjects import make_update_object_response
from server.modules.handlers.world.opcodes.movement import _build_out_of_range_update_object_payload
from server.modules.handlers.world.state.runtime import dispatch_responses_to_sessions

from .bounds import OrientedBounds

_DEBUG_MARKER_ENTRY = 179503
_DEBUG_MARKER_DISPLAY_ID = 6385
_DEBUG_MARKER_TYPE = 5
_DEBUG_MARKER_SCALE = 0.085
_DEBUG_RENDER_DURATION_MS = 10_000


@dataclass(frozen=True)
class DebugRenderHandle:
    token: int
    world_guids: tuple[int, ...]
    expires_at: float


def _debug_log(message: str, *args) -> None:
    Logger.info(f"[GOCollisionDebug] {message}", *args)


def _session_render_state(session) -> dict[int, dict[str, object]]:
    state = getattr(session, "_gocollision_debug_renders", None)
    if isinstance(state, dict):
        return state
    state = {}
    session._gocollision_debug_renders = state
    return state


def _session_render_lock(session) -> threading.RLock:
    lock = getattr(session, "_gocollision_debug_lock", None)
    if lock is not None and callable(getattr(lock, "acquire", None)) and callable(getattr(lock, "release", None)):
        return lock
    lock = threading.RLock()
    session._gocollision_debug_lock = lock
    return lock


def _next_render_token(session) -> int:
    token = int(getattr(session, "_gocollision_debug_next_token", 1) or 1)
    session._gocollision_debug_next_token = token + 1
    return token


def _next_marker_spawn_guid(session, *, count: int) -> list[int]:
    next_low = int(getattr(session, "_gocollision_debug_next_low_guid", 0x70000000) or 0x70000000)
    session._gocollision_debug_next_low_guid = next_low + max(0, int(count))
    return [next_low + index for index in range(max(0, int(count)))]


def _build_debug_marker_entry(
    *,
    world_guid: int,
    spawn_guid: int,
    position: tuple[float, float, float],
    orientation: float,
) -> dict[str, object]:
    return {
        "guid": int(spawn_guid),
        "world_guid": int(world_guid),
        "entry": _DEBUG_MARKER_ENTRY,
        "map_id": 0,
        "x": float(position[0]),
        "y": float(position[1]),
        "z": float(position[2]),
        "orientation": float(orientation),
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "animprogress": 255,
        "state": 1,
        "type": _DEBUG_MARKER_TYPE,
        "display_id": _DEBUG_MARKER_DISPLAY_ID,
        "name": "GO Collision Debug Marker",
        "faction": 0,
        "flags": 32,
        "size": _DEBUG_MARKER_SCALE,
        **{f"data{index}": 0 for index in range(24)},
    }


def _dispatch_debug_responses(session, responses: list[tuple[str, bytes]]) -> None:
    if responses:
        dispatch_responses_to_sessions([session], responses)


def _destroy_world_guids(session, world_guids: Iterable[int]) -> list[tuple[str, bytes]]:
    map_id = int(getattr(session, "map_id", 0) or 0)
    return [
        (
            "SMSG_UPDATE_OBJECT",
            _build_out_of_range_update_object_payload(map_id=map_id, guid=int(world_guid)),
        )
        for world_guid in sorted({int(value) for value in world_guids if int(value) > 0})
    ]


def clear_debug_visualizations(session) -> list[tuple[str, bytes]]:
    lock = _session_render_lock(session)
    with lock:
        state = _session_render_state(session)
        world_guids: set[int] = set()
        for payload in state.values():
            world_guids.update(int(value) for value in payload.get("world_guids", ()) or ())
            timer = payload.get("timer")
            if isinstance(timer, threading.Timer):
                timer.cancel()
        state.clear()
    responses = _destroy_world_guids(session, world_guids)
    if responses:
        _debug_log(
            "Clear player=%s markers=%s",
            int(getattr(session, "char_guid", 0) or 0),
            len(responses),
        )
    return responses


def _expire_render_group(session, token: int) -> None:
    lock = _session_render_lock(session)
    with lock:
        state = _session_render_state(session)
        payload = state.pop(int(token), None)
    if not payload:
        return
    responses = _destroy_world_guids(session, payload.get("world_guids", ()) or ())
    if responses:
        _dispatch_debug_responses(session, responses)


def render_collision_bounds(
    session,
    bounds: OrientedBounds,
    *,
    duration_ms: int = _DEBUG_RENDER_DURATION_MS,
    color: str = "green",
) -> DebugRenderHandle:
    del color
    points = bounds.wireframe_points(target_spacing=2.4, max_segments_per_edge=4)
    spawn_guids = _next_marker_spawn_guid(session, count=len(points))
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    map_id = int(getattr(session, "map_id", 0) or 0)
    responses: list[tuple[str, bytes]] = []
    world_guids: list[int] = []
    for point, spawn_guid in zip(points, spawn_guids):
        world_guid = int(GameObjectGuid.from_spawn_guid(int(spawn_guid), realm_id))
        world_guids.append(world_guid)
        entry = _build_debug_marker_entry(
            world_guid=world_guid,
            spawn_guid=spawn_guid,
            position=point,
            orientation=float(bounds.orientation),
        )
        entry["map_id"] = map_id
        payload = _build_gameobject_update_payload(map_id=map_id, entry=entry, realm_id=realm_id)
        responses.append(make_update_object_response(payload))
    _dispatch_debug_responses(session, responses)
    token = _next_render_token(session)
    expires_at = float(time.monotonic()) + (max(1, int(duration_ms)) / 1000.0)
    timer = threading.Timer(max(0.001, float(duration_ms) / 1000.0), _expire_render_group, args=(session, token))
    timer.daemon = True
    lock = _session_render_lock(session)
    with lock:
        _session_render_state(session)[int(token)] = {
            "world_guids": tuple(world_guids),
            "timer": timer,
            "expires_at": expires_at,
        }
    timer.start()
    return DebugRenderHandle(token=int(token), world_guids=tuple(world_guids), expires_at=expires_at)


def describe_collision_visualization(
    entry: Mapping[str, object] | None,
    bounds: OrientedBounds | None,
    *,
    eligible: bool,
    eligible_reason: str,
    indexed: bool,
) -> list[str]:
    if entry is None:
        return [
            "GameObject not found on current map.",
            f"Eligible: {eligible}",
            f"Indexed: {indexed}",
            f"EligibilityReason: {eligible_reason}",
        ]
    lines = [
        f"GO {int(entry.get('guid', 0) or 0)}",
        f"Entry: {int(entry.get('entry', 0) or 0)}",
        f"Display: {int(entry.get('display_id', 0) or 0)}",
        f"Scale: {float(entry.get('size', 1.0) or 1.0):.3f}",
        f"Map: {int(entry.get('map_id', entry.get('map', 0)) or 0)}",
        (
            "Position: "
            f"({float(entry.get('x', 0.0) or 0.0):.3f}, "
            f"{float(entry.get('y', 0.0) or 0.0):.3f}, "
            f"{float(entry.get('z', 0.0) or 0.0):.3f})"
        ),
        f"Rotation: {float(entry.get('orientation', 0.0) or 0.0):.3f}",
        f"Eligible: {eligible}",
        f"Indexed: {indexed}",
        f"EligibilityReason: {eligible_reason}",
    ]
    if bounds is not None:
        lines.extend(
            [
                (
                    "Center: "
                    f"({bounds.center[0]:.3f}, {bounds.center[1]:.3f}, {bounds.center[2]:.3f})"
                ),
                (
                    "Extents: "
                    f"({bounds.half_extents[0]:.3f}, {bounds.half_extents[1]:.3f}, {bounds.half_extents[2]:.3f})"
                ),
                f"Yaw: {float(bounds.orientation):.3f}",
            ]
        )
    return lines
