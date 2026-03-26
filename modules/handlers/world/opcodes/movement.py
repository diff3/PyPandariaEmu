from __future__ import annotations

import math
import struct
import time
from typing import Any, Optional, Tuple

from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.interpretation.utils import dsl_decode
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.position.position_service import (
    POSITION_AUTOSAVE_DISTANCE_THRESHOLD,
    POSITION_DEBUG_ENABLED,
    Position,
    format_position,
    normalize_position,
    position_from_session,
    position_moved_enough,
    save_player_position,
)


_MAX_MOVEMENT_POSITION_DELTA = 200.0
_MAX_MOVEMENT_Z_DELTA = 100.0
_POSITION_SAVE_INTERVAL_SECONDS = 30.0

# TODO:
# - Move replay_movement_focus_sequence* and related UPDATE_OBJECT replay helpers
#   into dedicated bootstrap/runtime modules once login packet builders are disentangled.
# - Move teleport-specific movement replay/broadcast helpers after the login
#   extraction phase so movement owns all movement-focused world transitions.


def _player_guid(session) -> int:
    return int(getattr(session, "world_guid", 0) or getattr(session, "player_guid", 0) or 0)


def _coerce_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_movement_from_decoded(session, decoded: dict[str, Any]) -> Optional[tuple[float, float, float, float]]:
    if not decoded:
        return None

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)

    x = _coerce_float(decoded.get("x"))
    if x is None:
        x = _coerce_float(decoded.get("position_x"))

    y = _coerce_float(decoded.get("y"))
    if y is None:
        y = _coerce_float(decoded.get("position_y"))

    z = _coerce_float(decoded.get("z"))
    if z is None:
        z = _coerce_float(decoded.get("position_z"))

    orientation = _coerce_float(decoded.get("facing"))
    if orientation is None:
        orientation = _coerce_float(decoded.get("orientation"))

    jump_cos = _coerce_float(decoded.get("jump_cos"))
    if (
        orientation is not None
        and jump_cos is not None
        and math.isfinite(orientation)
        and math.isfinite(jump_cos)
        and -math.pi * 4 <= jump_cos <= math.pi * 4
        and abs(math.cos(jump_cos) - orientation) <= 0.02
    ):
        orientation = jump_cos

    if orientation is None:
        return None

    if x is None:
        x = current_x
    if y is None:
        y = current_y
    if z is None:
        z = current_z

    if None not in (x, y, z):
        return (x, y, z, orientation)
    return None


def _score_movement_candidate(
    session,
    x: float,
    y: float,
    z: float,
    orientation: float,
) -> float:
    if not all(math.isfinite(value) for value in (x, y, z, orientation)):
        return float("inf")
    if abs(x) > 100000 or abs(y) > 100000 or abs(z) > 100000:
        return float("inf")
    if abs(orientation) > (math.pi * 8):
        return float("inf")

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)
    current_o = float(getattr(session, "orientation", 0.0) or 0.0)

    score = abs(x - current_x) + abs(y - current_y) + abs(z - current_z)
    score += min(abs(orientation - current_o), math.tau)
    return score


def _normalize_orientation(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        orientation = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(orientation):
        return None
    if abs(orientation) > (math.pi * 4):
        return None
    orientation = math.fmod(orientation, math.tau)
    if orientation < 0.0:
        orientation += math.tau
    return orientation


def _extract_movement_from_payload(session, payload: bytes) -> Optional[tuple[float, float, float, float]]:
    if len(payload) < 16:
        return None

    best: Optional[tuple[float, float, float, float]] = None
    best_score = float("inf")
    for offset in range(0, len(payload) - 15):
        try:
            x, y, z, orientation = struct.unpack_from("<ffff", payload, offset)
        except struct.error:
            continue

        score = _score_movement_candidate(session, x, y, z, orientation)
        if score < best_score:
            best = (x, y, z, orientation)
            best_score = score

    return best


def _accept_movement_update(
    session,
    opcode_name: str,
    x: float,
    y: float,
    z: float,
    orientation: float,
) -> bool:
    if not all(math.isfinite(value) for value in (x, y, z)):
        return False

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)

    if current_x == 0.0 and current_y == 0.0 and current_z == 0.0:
        return True

    planar_delta = math.hypot(x - current_x, y - current_y)
    vertical_delta = abs(z - current_z)

    if planar_delta > _MAX_MOVEMENT_POSITION_DELTA or vertical_delta > _MAX_MOVEMENT_Z_DELTA:
        log = Logger.debug if opcode_name in {"MSG_MOVE_FALL_LAND", "MSG_MOVE_HEARTBEAT"} else Logger.warning
        log(
            f"[Movement] ignoring implausible {opcode_name} update "
            f"dx={x - current_x:.3f} dy={y - current_y:.3f} dz={z - current_z:.3f}"
        )
        return False

    return True


def parse_movement_info(
    session,
    opcode_name: str,
    payload: bytes,
    decoded: dict[str, Any] | None = None,
) -> Optional[tuple[float, float, float, float]]:
    decoded = decoded or {}
    movement = _extract_movement_from_decoded(session, decoded)
    if movement is not None:
        return movement

    if opcode_name != "MSG_MOVE_HEARTBEAT":
        decoded = dsl_decode("MSG_MOVE_HEARTBEAT", payload, silent=True)
        movement = _extract_movement_from_decoded(session, decoded)
        if movement is not None:
            return movement

    return _extract_movement_from_payload(session, payload)


def _current_position_snapshot(session) -> tuple[int, int, Position | None]:
    position = normalize_position(
        Position(
            map=int(getattr(session, "persist_map_id", 0) or 0),
            x=float(getattr(session, "persist_x", 0.0) or 0.0),
            y=float(getattr(session, "persist_y", 0.0) or 0.0),
            z=float(getattr(session, "persist_z", 0.0) or 0.0),
            orientation=float(getattr(session, "persist_orientation", 0.0) or 0.0),
        ),
        safe_z=True,
    )
    return (
        int(getattr(session, "persist_zone", 0) or 0),
        int(getattr(session, "persist_instance_id", 0) or 0),
        position,
    )


def _saved_position_snapshot(session) -> tuple[int, int, Position | None]:
    position = normalize_position(
        Position(
            map=int(getattr(session, "last_saved_map_id", 0) or 0),
            x=float(getattr(session, "last_saved_x", 0.0) or 0.0),
            y=float(getattr(session, "last_saved_y", 0.0) or 0.0),
            z=float(getattr(session, "last_saved_z", 0.0) or 0.0),
            orientation=float(getattr(session, "last_saved_orientation", 0.0) or 0.0),
        ),
        safe_z=True,
    )
    return (
        int(getattr(session, "last_saved_zone", 0) or 0),
        int(getattr(session, "last_saved_instance_id", 0) or 0),
        position,
    )


def _mark_position_dirty(session) -> None:
    session.position_dirty = _current_position_snapshot(session) != _saved_position_snapshot(session)


def _capture_persist_position_from_session(session) -> None:
    raw_position = position_from_session(session)
    position = normalize_position(raw_position, safe_z=True)
    if position is None:
        Logger.warning(
            "[POS_SAVE] invalid live position player=%s raw=%s",
            int(getattr(session, "char_guid", 0) or 0),
            format_position(raw_position),
        )
        return
    session.persist_map_id = int(position.map)
    session.persist_zone = int(getattr(session, "zone", 0) or 0)
    session.persist_instance_id = int(getattr(session, "instance_id", 0) or 0)
    session.persist_x = float(position.x)
    session.persist_y = float(position.y)
    session.persist_z = float(position.z)
    session.persist_orientation = float(position.orientation)
    if POSITION_DEBUG_ENABLED:
        Logger.debug(
            "[POS_DEBUG] capture player=%s pos=%s",
            int(getattr(session, "char_guid", 0) or 0),
            format_position(position),
        )


def _remember_saved_position(session, now: float | None = None) -> None:
    if now is None:
        now = time.time()
    current_zone, current_instance_id, current_position = _current_position_snapshot(session)
    if current_position is None:
        return
    session.last_saved_map_id = int(current_position.map)
    session.last_saved_zone = int(current_zone)
    session.last_saved_instance_id = int(current_instance_id)
    session.last_saved_x = float(current_position.x)
    session.last_saved_y = float(current_position.y)
    session.last_saved_z = float(current_position.z)
    session.last_saved_orientation = float(current_position.orientation)
    session.last_position_save_at = float(now)
    session.position_dirty = False


def _save_session_position(session, *, reason: str, online: int | None = None, force: bool = False) -> bool:
    if not getattr(session, "char_guid", None) or not getattr(session, "realm_id", None):
        return False

    now = time.time()
    position_dirty = bool(getattr(session, "position_dirty", False))
    if not force and not position_dirty:
        return False
    if force and not position_dirty and online is not None:
        Logger.info(
            "[POS_SAVE] state-only player=%s reason=%s name=%s online=%s force=%s",
            int(session.char_guid),
            str(reason),
            str(getattr(session, "player_name", "") or ""),
            online,
            force,
        )
        return DatabaseConnection.save_character_online_state(
            int(session.char_guid),
            int(session.realm_id),
            online=online,
            logout_time=int(now) if online == 0 else None,
        )

    persist_position = normalize_position(
        Position(
            map=int(getattr(session, "persist_map_id", 0) or 0),
            x=float(getattr(session, "persist_x", 0.0) or 0.0),
            y=float(getattr(session, "persist_y", 0.0) or 0.0),
            z=float(getattr(session, "persist_z", 0.0) or 0.0),
            orientation=float(getattr(session, "persist_orientation", 0.0) or 0.0),
        ),
        safe_z=True,
    )
    if persist_position is None:
        Logger.warning(
            "[POS_SAVE] rejected player=%s reason=%s invalid persisted snapshot",
            int(session.char_guid),
            str(reason),
        )
        return False

    ok = save_player_position(
        int(session.char_guid),
        persist_position,
        str(reason),
        realm_id=int(session.realm_id),
        zone=int(getattr(session, "persist_zone", 0) or 0),
        instance_id=int(getattr(session, "persist_instance_id", 0) or 0),
        online=online,
        logout_time=int(now) if online == 0 else None,
        player_name=str(getattr(session, "player_name", "") or ""),
        debug=bool(POSITION_DEBUG_ENABLED),
    )
    if ok:
        _remember_saved_position(session, now)
    return ok


def _maybe_periodic_position_save(
    session,
    *,
    position_save_interval_seconds: float = _POSITION_SAVE_INTERVAL_SECONDS,
) -> bool:
    if not getattr(session, "position_dirty", False):
        return False
    now = time.time()
    last = float(getattr(session, "last_position_save_at", 0.0) or 0.0)
    if (now - last) < float(position_save_interval_seconds):
        return False
    saved_zone, saved_instance_id, saved_position = _saved_position_snapshot(session)
    current_zone, current_instance_id, current_position = _current_position_snapshot(session)
    if current_position is None:
        return False
    if not position_moved_enough(saved_position, current_position, threshold=POSITION_AUTOSAVE_DISTANCE_THRESHOLD):
        if POSITION_DEBUG_ENABLED:
            Logger.debug(
                "[POS_DEBUG] autosave skipped player=%s saved=%s current=%s zone=%s->%s instance=%s->%s",
                int(getattr(session, "char_guid", 0) or 0),
                format_position(saved_position),
                format_position(current_position),
                int(saved_zone),
                int(current_zone),
                int(saved_instance_id),
                int(current_instance_id),
            )
        return False
    return _save_session_position(session, reason="autosave", online=1, force=True)


@register("MSG_MOVE_START_FORWARD")
@register("MSG_MOVE_START_BACKWARD")
@register("MSG_MOVE_STOP")
@register("MSG_MOVE_HEARTBEAT")
@register("MSG_MOVE_START_TURN_LEFT")
@register("MSG_MOVE_START_TURN_RIGHT")
@register("MSG_MOVE_STOP_TURN")
@register("MSG_MOVE_FALL_LAND")
def handle_movement_packet(session, ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    opcode_name = str(ctx.name or f"0x{int(ctx.opcode):04X}")
    Logger.debug(f"[MOVE] opcode={opcode_name}")

    movement = parse_movement_info(session, opcode_name, ctx.payload, ctx.decoded)
    if movement is None:
        Logger.warning(
            f"[Movement] failed to parse {opcode_name} guid=0x{_player_guid(session):X} "
            f"payload_len={len(ctx.payload)}"
        )
        return 0, None

    x, y, z, orientation = movement
    if not _accept_movement_update(session, opcode_name, x, y, z, orientation):
        return 0, None

    normalized_orientation = _normalize_orientation(orientation)
    if normalized_orientation is None:
        log = Logger.debug if opcode_name == "MSG_MOVE_HEARTBEAT" else Logger.warning
        log(
            f"[Movement] ignoring implausible orientation from {opcode_name}: {orientation!r}; "
            "keeping previous facing"
        )
        normalized_orientation = float(getattr(session, "orientation", 0.0) or 0.0)

    session.x = float(x)
    session.y = float(y)
    session.z = float(z)
    session.orientation = float(normalized_orientation)
    if opcode_name == "MSG_MOVE_HEARTBEAT":
        _capture_persist_position_from_session(session)
        _mark_position_dirty(session)
        _maybe_periodic_position_save(session)

    Logger.debug(
        f"[MOVE] guid=0x{_player_guid(session):X} "
        f"pos=({session.x:.3f}, {session.y:.3f}, {session.z:.3f}) facing={session.orientation:.3f}"
    )
    return 0, None


@register("MSG_MOVE_SET_FACING")
def handle_msg_move_set_facing(session, ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    payload = bytes(ctx.payload or b"")
    if len(payload) < 4:
        Logger.warning("[Movement] MSG_MOVE_SET_FACING payload too short")
        return 0, None

    try:
        orientation = struct.unpack_from("<f", payload, len(payload) - 4)[0]
    except struct.error:
        Logger.warning("[Movement] MSG_MOVE_SET_FACING unpack failed")
        return 0, None

    normalized_orientation = _normalize_orientation(orientation)
    if normalized_orientation is None:
        Logger.warning(
            f"[Movement] ignoring implausible MSG_MOVE_SET_FACING orientation: {orientation!r}"
        )
        return 0, None

    session.orientation = float(normalized_orientation)
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    _maybe_periodic_position_save(session)

    Logger.debug(
        f"[MOVE] opcode=MSG_MOVE_SET_FACING guid=0x{_player_guid(session):X} "
        f"facing={session.orientation:.3f}"
    )
    return 0, None
