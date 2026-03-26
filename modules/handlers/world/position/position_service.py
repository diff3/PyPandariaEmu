#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any

from shared.Logger import Logger

POSITION_DEBUG_ENABLED = False
POSITION_ROUND_DIGITS = 4
POSITION_ORIENTATION_DIGITS = 6
POSITION_MAX_ABS_XY = 100000.0
POSITION_MAX_ABS_Z = 20000.0
POSITION_SUSPICIOUS_DELTA = 100.0
POSITION_SUSPICIOUS_Z_DELTA = 20.0
POSITION_AUTOSAVE_DISTANCE_THRESHOLD = 1.0
_POSITION_HISTORY_LIMIT = 128
_POSITION_HISTORY: dict[int, list[dict[str, Any]]] = {}


@dataclass(frozen=True)
class Position:
    map: int
    x: float
    y: float
    z: float
    orientation: float


@dataclass(frozen=True)
class PositionDelta:
    dx: float
    dy: float
    dz: float
    orientation_delta: float
    distance_2d: float
    distance_3d: float


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except Exception:
        return int(default)


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or 0.0)
    except Exception:
        return float(default)


def position_from_session(session: Any) -> Position:
    return Position(
        map=_coerce_int(getattr(session, "map_id", 0), 0),
        x=_coerce_float(getattr(session, "x", 0.0), 0.0),
        y=_coerce_float(getattr(session, "y", 0.0), 0.0),
        z=_coerce_float(getattr(session, "z", 0.0), 0.0),
        orientation=_coerce_float(getattr(session, "orientation", 0.0), 0.0),
    )


def position_from_row(row: Any) -> Position:
    return Position(
        map=_coerce_int(getattr(row, "map", 0), 0),
        x=_coerce_float(getattr(row, "position_x", 0.0), 0.0),
        y=_coerce_float(getattr(row, "position_y", 0.0), 0.0),
        z=_coerce_float(getattr(row, "position_z", 0.0), 0.0),
        orientation=_coerce_float(getattr(row, "orientation", 0.0), 0.0),
    )


def correct_z_if_invalid(pos: Position) -> Position:
    clamped_z = max(-POSITION_MAX_ABS_Z, min(POSITION_MAX_ABS_Z, float(pos.z)))
    return Position(
        map=int(pos.map),
        x=float(pos.x),
        y=float(pos.y),
        z=float(clamped_z),
        orientation=float(pos.orientation),
    )


def normalize_position(pos: Position, *, safe_z: bool = False) -> Position | None:
    try:
        normalized = Position(
            map=int(pos.map),
            x=float(pos.x),
            y=float(pos.y),
            z=float(pos.z),
            orientation=float(pos.orientation),
        )
    except Exception:
        return None

    if safe_z:
        normalized = correct_z_if_invalid(normalized)

    if not all(math.isfinite(value) for value in (normalized.x, normalized.y, normalized.z, normalized.orientation)):
        return None
    if abs(normalized.x) > POSITION_MAX_ABS_XY or abs(normalized.y) > POSITION_MAX_ABS_XY:
        return None
    if abs(normalized.z) > POSITION_MAX_ABS_Z:
        return None

    orientation = math.fmod(float(normalized.orientation), math.tau)
    if orientation < 0.0:
        orientation += math.tau

    return Position(
        map=int(normalized.map),
        x=round(float(normalized.x), POSITION_ROUND_DIGITS),
        y=round(float(normalized.y), POSITION_ROUND_DIGITS),
        z=round(float(normalized.z), POSITION_ROUND_DIGITS),
        orientation=round(float(orientation), POSITION_ORIENTATION_DIGITS),
    )


def format_position(pos: Position | None) -> str:
    if pos is None:
        return "(none)"
    return (
        f"(map={int(pos.map)} x={float(pos.x):.4f} y={float(pos.y):.4f} "
        f"z={float(pos.z):.4f} o={float(pos.orientation):.6f})"
    )


def position_delta(old: Position | None, new: Position) -> PositionDelta:
    if old is None:
        return PositionDelta(
            dx=0.0,
            dy=0.0,
            dz=0.0,
            orientation_delta=0.0,
            distance_2d=0.0,
            distance_3d=0.0,
        )

    dx = float(new.x) - float(old.x)
    dy = float(new.y) - float(old.y)
    dz = float(new.z) - float(old.z)
    direct_delta = abs(float(new.orientation) - float(old.orientation))
    orientation_delta = min(direct_delta, abs((math.tau - direct_delta) % math.tau))
    distance_2d = math.hypot(dx, dy)
    distance_3d = math.sqrt((dx * dx) + (dy * dy) + (dz * dz))
    return PositionDelta(
        dx=dx,
        dy=dy,
        dz=dz,
        orientation_delta=orientation_delta,
        distance_2d=distance_2d,
        distance_3d=distance_3d,
    )


def position_moved_enough(old: Position | None, new: Position, *, threshold: float = POSITION_AUTOSAVE_DISTANCE_THRESHOLD) -> bool:
    if old is None:
        return True
    if int(old.map) != int(new.map):
        return True
    delta = position_delta(old, new)
    return float(delta.distance_3d) >= float(threshold)


def _record_position_history(player_id: int, reason: str, old: Position | None, new: Position, delta: PositionDelta) -> None:
    history = _POSITION_HISTORY.setdefault(int(player_id), [])
    history.append(
        {
            "at": time.time(),
            "reason": str(reason),
            "old": old,
            "new": new,
            "delta": delta,
        }
    )
    if len(history) > _POSITION_HISTORY_LIMIT:
        del history[:-_POSITION_HISTORY_LIMIT]


def get_position_history(player_id: int) -> list[dict[str, Any]]:
    return list(_POSITION_HISTORY.get(int(player_id), []))


def _default_db_api():
    from server.modules.database.DatabaseConnection import DatabaseConnection

    return DatabaseConnection


def save_player_position(
    player_id: int,
    pos: Position,
    reason: str,
    *,
    realm_id: int,
    zone: int | None = None,
    instance_id: int | None = None,
    online: int | None = None,
    logout_time: int | None = None,
    player_name: str = "",
    debug: bool = False,
    db_api: Any | None = None,
) -> bool:
    db = db_api or _default_db_api()
    normalized = normalize_position(pos)
    if normalized is None:
        Logger.warning(
            "[POS_SAVE] rejected player=%s reason=%s invalid=%s",
            int(player_id),
            str(reason),
            format_position(pos),
        )
        if online is not None:
            return bool(
                db.save_character_online_state(
                    int(player_id),
                    int(realm_id),
                    online=int(online),
                    logout_time=logout_time,
                )
            )
        return False

    row = db.get_character(int(player_id), int(realm_id))
    if row is None:
        Logger.warning("[POS_SAVE] missing player=%s realm=%s reason=%s", int(player_id), int(realm_id), str(reason))
        return False

    old = normalize_position(position_from_row(row), safe_z=True)
    current_zone = int(zone if zone is not None else getattr(row, "zone", 0) or 0)
    current_instance_id = int(instance_id if instance_id is not None else getattr(row, "instance_id", 0) or 0)
    delta = position_delta(old, normalized)

    if old is not None and (
        float(delta.distance_3d) > POSITION_SUSPICIOUS_DELTA or abs(float(delta.dz)) > POSITION_SUSPICIOUS_Z_DELTA
    ):
        Logger.warning(
            "[POS_SAVE][SUSPECT] player=%s reason=%s delta3=%.4f dz=%.4f old=%s new=%s",
            int(player_id),
            str(reason),
            float(delta.distance_3d),
            float(delta.dz),
            format_position(old),
            format_position(normalized),
        )

    Logger.info(
        "[POS_SAVE] player=%s reason=%s name=%s old=%s new=%s delta=(dx=%.4f dy=%.4f dz=%.4f do=%.6f d3=%.4f)",
        int(player_id),
        str(reason),
        str(player_name or ""),
        format_position(old),
        format_position(normalized),
        float(delta.dx),
        float(delta.dy),
        float(delta.dz),
        float(delta.orientation_delta),
        float(delta.distance_3d),
    )

    if debug or POSITION_DEBUG_ENABLED:
        _record_position_history(int(player_id), str(reason), old, normalized, delta)
        Logger.debug(
            "[POS_DEBUG] player=%s reason=%s history=%s",
            int(player_id),
            str(reason),
            len(_POSITION_HISTORY.get(int(player_id), [])),
        )

    return bool(
        db.save_character_position(
            int(player_id),
            int(realm_id),
            map_id=int(normalized.map),
            zone=int(current_zone),
            instance_id=int(current_instance_id),
            x=float(normalized.x),
            y=float(normalized.y),
            z=float(normalized.z),
            orientation=float(normalized.orientation),
            online=online,
            logout_time=logout_time,
        )
    )
