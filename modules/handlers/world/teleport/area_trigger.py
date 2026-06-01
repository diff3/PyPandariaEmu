#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.dbc import read_dbc
from server.modules.handlers.world.teleport.map_transfer import (
    TeleportDestination,
    apply_map_transfer,
)


_AREA_TRIGGER_DBC_FMT = "nifffxxxfffffxxx"
_MAP_DBC_FMT = "nxixxsixxixiffxiiii"
_AREA_TRIGGER_SAFE_DELTA = 5.0
_AREA_TRIGGER_WORLD_MOVEMENT_SAFE_DELTA = 4.0
_AREA_TRIGGER_INSTANCE_MOVEMENT_SAFE_DELTA = 1.0
_AREA_TRIGGER_DEFAULT_RADIUS = 5.0
_AREA_TRIGGER_REENTRY_COOLDOWN_SECONDS = 1.0
_AREA_TRIGGER_MAX_SEGMENT_SCAN_DISTANCE = 120.0
_AREA_TRIGGER_RETURN_BLOCK_SECONDS = 8.0
_AREA_TRIGGER_MISS_LOG_RADIUS = 14.0
_AREA_TRIGGER_MISS_LOG_INTERVAL_SECONDS = 1.5
_INSTANCEABLE_MAP_TYPES = {1, 2, 3, 4, 5}


@dataclass(frozen=True)
class AreaTriggerDefinition:
    trigger_id: int
    map_id: int
    x: float
    y: float
    z: float
    radius: float
    box_x: float
    box_y: float
    box_z: float
    box_orientation: float


_DBC_CACHE: dict[int, AreaTriggerDefinition] | None = None
_TELEPORT_TRIGGER_CACHE: dict[int, dict[str, Any]] | None = None
_MAP_TYPE_CACHE: dict[int, int] | None = None


def _load_area_trigger_dbc() -> dict[int, AreaTriggerDefinition]:
    dbc_root = get_dbc_root()
    if dbc_root is None:
        return {}

    path = Path(dbc_root) / "AreaTrigger.dbc"
    if not path.is_file():
        Logger.warning("[AREATRIGGER] AreaTrigger.dbc missing path=%s", path)
        return {}

    try:
        rows = read_dbc(path, _AREA_TRIGGER_DBC_FMT)
    except Exception as exc:
        Logger.warning("[AREATRIGGER] AreaTrigger.dbc load failed path=%s err=%s", path, exc)
        return {}

    definitions: dict[int, AreaTriggerDefinition] = {}
    for row in rows:
        try:
            definition = AreaTriggerDefinition(
                trigger_id=int(row[0]),
                map_id=int(row[1]),
                x=float(row[2]),
                y=float(row[3]),
                z=float(row[4]),
                radius=float(row[5]),
                box_x=float(row[6]),
                box_y=float(row[7]),
                box_z=float(row[8]),
                box_orientation=float(row[9]),
            )
        except Exception:
            continue
        definitions[int(definition.trigger_id)] = definition

    Logger.info("[AREATRIGGER] loaded %s DBC definitions", len(definitions))
    return definitions


def _area_trigger_definitions() -> dict[int, AreaTriggerDefinition]:
    global _DBC_CACHE
    if _DBC_CACHE is None:
        _DBC_CACHE = _load_area_trigger_dbc()
    return _DBC_CACHE


def _teleport_trigger_rows() -> dict[int, dict[str, Any]]:
    global _TELEPORT_TRIGGER_CACHE
    if _TELEPORT_TRIGGER_CACHE is None:
        rows = DatabaseConnection.get_areatrigger_teleports()
        _TELEPORT_TRIGGER_CACHE = {
            int(row.get("id", 0) or 0): dict(row)
            for row in rows
            if int(row.get("id", 0) or 0) > 0
        }
        Logger.info("[AREATRIGGER] loaded %s teleport rows", len(_TELEPORT_TRIGGER_CACHE))
    return _TELEPORT_TRIGGER_CACHE


def _load_map_types() -> dict[int, int]:
    dbc_root = get_dbc_root()
    if dbc_root is None:
        return {}

    path = Path(dbc_root) / "Map.dbc"
    if not path.is_file():
        Logger.warning("[AREATRIGGER] Map.dbc missing path=%s", path)
        return {}

    try:
        rows = read_dbc(path, _MAP_DBC_FMT)
    except Exception as exc:
        Logger.warning("[AREATRIGGER] Map.dbc load failed path=%s err=%s", path, exc)
        return {}

    map_types: dict[int, int] = {}
    for row in rows:
        try:
            map_types[int(row[0])] = int(row[1])
        except Exception:
            continue

    Logger.info("[AREATRIGGER] loaded %s Map.dbc map types", len(map_types))
    return map_types


def _map_types() -> dict[int, int]:
    global _MAP_TYPE_CACHE
    if _MAP_TYPE_CACHE is None:
        _MAP_TYPE_CACHE = _load_map_types()
    return _MAP_TYPE_CACHE


def _map_is_instanceable(map_id: int) -> bool:
    map_type = _map_types().get(int(map_id))
    return map_type in _INSTANCEABLE_MAP_TYPES


def clear_area_trigger_caches() -> None:
    global _DBC_CACHE, _TELEPORT_TRIGGER_CACHE, _MAP_TYPE_CACHE
    _DBC_CACHE = None
    _TELEPORT_TRIGGER_CACHE = None
    _MAP_TYPE_CACHE = None


def _distance_sq_3d(
    ax: float,
    ay: float,
    az: float,
    bx: float,
    by: float,
    bz: float,
) -> float:
    dx = float(ax) - float(bx)
    dy = float(ay) - float(by)
    dz = float(az) - float(bz)
    return (dx * dx) + (dy * dy) + (dz * dz)


def _point_inside_trigger(
    definition: AreaTriggerDefinition,
    x: float,
    y: float,
    z: float,
    *,
    padding: float = _AREA_TRIGGER_SAFE_DELTA,
) -> bool:
    if float(definition.radius) > 0.0:
        radius = float(definition.radius) + float(padding)
        return _distance_sq_3d(x, y, z, definition.x, definition.y, definition.z) <= (radius * radius)

    rotation = (math.tau - float(definition.box_orientation))
    sin_value = math.sin(rotation)
    cos_value = math.cos(rotation)
    player_box_dist_x = float(x) - float(definition.x)
    player_box_dist_y = float(y) - float(definition.y)
    rotated_x = float(definition.x) + (player_box_dist_x * cos_value) - (player_box_dist_y * sin_value)
    rotated_y = float(definition.y) + (player_box_dist_y * cos_value) + (player_box_dist_x * sin_value)
    dx = rotated_x - float(definition.x)
    dy = rotated_y - float(definition.y)
    dz = float(z) - float(definition.z)
    return (
        abs(dx) <= (float(definition.box_x) * 0.5) + float(padding)
        and abs(dy) <= (float(definition.box_y) * 0.5) + float(padding)
        and abs(dz) <= (float(definition.box_z) * 0.5) + float(padding)
    )


def _segment_distance_sq_to_point(
    start: tuple[float, float, float],
    end: tuple[float, float, float],
    point: tuple[float, float, float],
) -> float:
    sx, sy, sz = start
    ex, ey, ez = end
    px, py, pz = point
    vx = ex - sx
    vy = ey - sy
    vz = ez - sz
    length_sq = (vx * vx) + (vy * vy) + (vz * vz)
    if length_sq <= 0.000001:
        return _distance_sq_3d(sx, sy, sz, px, py, pz)

    t = (((px - sx) * vx) + ((py - sy) * vy) + ((pz - sz) * vz)) / length_sq
    t = max(0.0, min(1.0, t))
    cx = sx + (vx * t)
    cy = sy + (vy * t)
    cz = sz + (vz * t)
    return _distance_sq_3d(cx, cy, cz, px, py, pz)


def _segment_crosses_trigger(
    definition: AreaTriggerDefinition,
    start: tuple[float, float, float],
    end: tuple[float, float, float],
    *,
    padding: float = _AREA_TRIGGER_SAFE_DELTA,
) -> bool:
    start_inside = _point_inside_trigger(definition, *start, padding=padding)
    end_inside = _point_inside_trigger(definition, *end, padding=padding)
    if start_inside and end_inside:
        return False
    if end_inside:
        return True
    if start_inside:
        return False

    if float(definition.radius) > 0.0:
        radius = float(definition.radius) + float(padding)
    else:
        radius = (
            max(float(definition.box_x), float(definition.box_y), float(definition.box_z), _AREA_TRIGGER_DEFAULT_RADIUS)
            * 0.5
        ) + float(padding)

    return _segment_distance_sq_to_point(
        start,
        end,
        (float(definition.x), float(definition.y), float(definition.z)),
    ) <= (radius * radius)


def _definition_for_trigger(trigger_id: int) -> AreaTriggerDefinition | None:
    return _area_trigger_definitions().get(int(trigger_id))


def _find_nearby_teleport_mapping(
    trigger_id: int,
    definition: AreaTriggerDefinition,
) -> tuple[int, dict[str, Any]] | None:
    # TODO: remove this fallback once the 5.4.8 areatrigger_teleport import is
    # verified to cover every client trigger id used by AreaTrigger.dbc.
    definitions = _area_trigger_definitions()
    teleport_rows = _teleport_trigger_rows()
    best_id = 0
    best_row: dict[str, Any] | None = None
    best_distance_sq = math.inf

    for candidate_id, row in teleport_rows.items():
        candidate_id = int(candidate_id)
        if candidate_id == int(trigger_id):
            continue

        candidate = definitions.get(candidate_id)
        if candidate is None or int(candidate.map_id) != int(definition.map_id):
            continue

        candidate_radius = max(
            float(candidate.radius),
            float(definition.radius),
            float(candidate.box_x) * 0.5,
            float(candidate.box_y) * 0.5,
            float(candidate.box_z) * 0.5,
            float(definition.box_x) * 0.5,
            float(definition.box_y) * 0.5,
            float(definition.box_z) * 0.5,
            _AREA_TRIGGER_DEFAULT_RADIUS,
        ) + _AREA_TRIGGER_SAFE_DELTA
        distance_sq = _distance_sq_3d(
            definition.x,
            definition.y,
            definition.z,
            candidate.x,
            candidate.y,
            candidate.z,
        )
        if distance_sq <= (candidate_radius * candidate_radius) and distance_sq < best_distance_sq:
            best_id = candidate_id
            best_row = row
            best_distance_sq = distance_sq

    if best_row is None:
        return None

    Logger.info(
        "[AREATRIGGER] mapping_fallback original=%s fallback=%s distance=%.3f",
        int(trigger_id),
        int(best_id),
        math.sqrt(best_distance_sq),
    )
    return best_id, best_row


def _destination_from_row(trigger_id: int, row: dict[str, Any]) -> TeleportDestination | None:
    try:
        return TeleportDestination(
            map_id=int(row["target_map"]),
            x=float(row["target_position_x"]),
            y=float(row["target_position_y"]),
            z=float(row["target_position_z"]),
            orientation=float(row.get("target_orientation", 0.0) or 0.0),
            name=f"areatrigger:{int(trigger_id)}",
        )
    except Exception as exc:
        Logger.warning("[AREATRIGGER] invalid teleport row id=%s row=%r err=%s", int(trigger_id), row, exc)
        return None


def _recently_triggered(session, trigger_id: int) -> bool:
    now = time.monotonic()
    recent = getattr(session, "_recent_areatriggers", None)
    if not isinstance(recent, dict):
        recent = {}
        setattr(session, "_recent_areatriggers", recent)

    previous = float(recent.get(int(trigger_id), 0.0) or 0.0)
    if previous > 0.0 and (now - previous) < _AREA_TRIGGER_REENTRY_COOLDOWN_SECONDS:
        Logger.info(
            "[AREATRIGGER] cooldown id=%s elapsed=%.3f",
            int(trigger_id),
            float(now - previous),
        )
        return True

    recent[int(trigger_id)] = now
    return False


def _block_immediate_return(session, source_map_id: int, destination: TeleportDestination) -> None:
    if int(destination.map_id) == int(source_map_id):
        return

    setattr(session, "_area_trigger_return_block_map", int(source_map_id))
    setattr(
        session,
        "_area_trigger_return_block_until",
        time.monotonic() + _AREA_TRIGGER_RETURN_BLOCK_SECONDS,
    )


def _return_blocked(session, row: dict[str, Any], trigger_id: int) -> bool:
    blocked_until = float(getattr(session, "_area_trigger_return_block_until", 0.0) or 0.0)
    if blocked_until <= time.monotonic():
        return False

    blocked_map_id = int(getattr(session, "_area_trigger_return_block_map", -1) or -1)
    try:
        target_map_id = int(row["target_map"])
    except Exception:
        return False

    if target_map_id != blocked_map_id:
        return False

    Logger.info(
        "[AREATRIGGER] crossing skipped id=%s reason=return_block target_map=%s remaining=%.3f",
        int(trigger_id),
        int(target_map_id),
        blocked_until - time.monotonic(),
    )
    return True


def _movement_scan_padding_for_transition(
    current_map_id: int,
    row: dict[str, Any],
) -> float:
    try:
        target_map_id = int(row["target_map"])
    except Exception:
        return _AREA_TRIGGER_WORLD_MOVEMENT_SAFE_DELTA

    if _map_is_instanceable(current_map_id) or _map_is_instanceable(target_map_id):
        return _AREA_TRIGGER_INSTANCE_MOVEMENT_SAFE_DELTA

    return _AREA_TRIGGER_WORLD_MOVEMENT_SAFE_DELTA


def _movement_activation_radius(definition: AreaTriggerDefinition, padding: float) -> float:
    if float(definition.radius) > 0.0:
        return float(definition.radius) + float(padding)

    return (
        max(
            float(definition.box_x),
            float(definition.box_y),
            float(definition.box_z),
            _AREA_TRIGGER_DEFAULT_RADIUS,
        )
        * 0.5
    ) + float(padding)


def _log_nearby_movement_miss(
    session,
    current_map_id: int,
    start: tuple[float, float, float],
    end: tuple[float, float, float],
    teleport_rows: dict[int, dict[str, Any]],
    definitions: dict[int, AreaTriggerDefinition],
) -> None:
    now = time.monotonic()
    next_log = float(getattr(session, "_area_trigger_next_miss_log", 0.0) or 0.0)
    if next_log > now:
        return

    nearest: tuple[float, int, float, float, int] | None = None
    for trigger_id, row in teleport_rows.items():
        definition = definitions.get(int(trigger_id))
        if definition is None or int(definition.map_id) != current_map_id:
            continue

        padding = _movement_scan_padding_for_transition(current_map_id, row)
        activation_radius = _movement_activation_radius(definition, padding)
        distance = math.sqrt(
            _segment_distance_sq_to_point(
                start,
                end,
                (definition.x, definition.y, definition.z),
            )
        )
        if distance > activation_radius + _AREA_TRIGGER_MISS_LOG_RADIUS:
            continue

        target_map = int(row.get("target_map", 0) or 0)
        candidate = (distance, int(trigger_id), activation_radius, padding, target_map)
        if nearest is None or candidate[0] < nearest[0]:
            nearest = candidate

    if nearest is None:
        return

    setattr(session, "_area_trigger_next_miss_log", now + _AREA_TRIGGER_MISS_LOG_INTERVAL_SECONDS)
    distance, trigger_id, activation_radius, padding, target_map = nearest
    Logger.info(
        "[AREATRIGGER] movement near_miss id=%s map=%s target_map=%s distance=%.3f activation_radius=%.3f padding=%.3f start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f)",
        int(trigger_id),
        int(current_map_id),
        int(target_map),
        float(distance),
        float(activation_radius),
        float(padding),
        start[0],
        start[1],
        start[2],
        end[0],
        end[1],
        end[2],
    )


def activate_area_trigger(
    session,
    trigger_id: int,
    *,
    source: str,
    crossed: bool = False,
) -> list[tuple[str, bytes]] | None:
    current_map_id = int(getattr(session, "map_id", 0) or 0)
    px = float(getattr(session, "x", 0.0) or 0.0)
    py = float(getattr(session, "y", 0.0) or 0.0)
    pz = float(getattr(session, "z", 0.0) or 0.0)

    Logger.info(
        "[AREATRIGGER] enter id=%s source=%s map=%s pos=(%.3f %.3f %.3f) crossed=%s",
        int(trigger_id),
        str(source),
        current_map_id,
        px,
        py,
        pz,
        int(crossed),
    )

    if bool(getattr(session, "taxi_in_flight", False) or getattr(session, "is_on_taxi", False)):
        Logger.info("[AREATRIGGER] failed id=%s reason=in_flight", int(trigger_id))
        return []

    definition = _definition_for_trigger(int(trigger_id))
    if definition is not None:
        if int(definition.map_id) != current_map_id:
            Logger.info(
                "[AREATRIGGER] failed id=%s reason=map_mismatch trigger_map=%s player_map=%s",
                int(trigger_id),
                int(definition.map_id),
                current_map_id,
            )
            return []
        if not crossed and not _point_inside_trigger(definition, px, py, pz):
            Logger.info("[AREATRIGGER] failed id=%s reason=outside_bounds", int(trigger_id))
            return []

    activation_id = int(trigger_id)
    row = DatabaseConnection.get_areatrigger_teleport(activation_id)
    if not row and definition is not None:
        fallback = _find_nearby_teleport_mapping(activation_id, definition)
        if fallback is not None:
            activation_id, row = fallback

    if not row:
        Logger.info("[AREATRIGGER] failed id=%s reason=no_teleport_mapping", int(trigger_id))
        return None

    if _recently_triggered(session, activation_id):
        return []

    destination = _destination_from_row(activation_id, row)
    if destination is None:
        return []

    _block_immediate_return(session, current_map_id, destination)
    responses = apply_map_transfer(session, destination, reason="areatrigger")
    Logger.info(
        "[AREATRIGGER] transition id=%s map=%s pos=(%.3f %.3f %.3f %.6f) responses=%s",
        activation_id,
        int(destination.map_id),
        float(destination.x),
        float(destination.y),
        float(destination.z),
        float(destination.orientation),
        len(responses),
    )
    return responses


def check_movement_segment_for_area_triggers(
    session,
    start: tuple[float, float, float],
    end: tuple[float, float, float],
) -> list[tuple[str, bytes]] | None:
    if bool(getattr(session, "near_teleport_pending", False) or getattr(session, "teleport_pending", False)):
        return None

    suppressed_until = float(getattr(session, "_area_trigger_suppressed_until", 0.0) or 0.0)
    if suppressed_until > time.monotonic():
        Logger.info(
            "[AREATRIGGER] crossing skipped reason=post_teleport_suppression remaining=%.3f",
            suppressed_until - time.monotonic(),
        )
        return None

    current_map_id = int(getattr(session, "map_id", 0) or 0)
    segment_length_sq = _distance_sq_3d(*start, *end)
    if segment_length_sq <= 0.000001:
        return None
    if segment_length_sq > (_AREA_TRIGGER_MAX_SEGMENT_SCAN_DISTANCE * _AREA_TRIGGER_MAX_SEGMENT_SCAN_DISTANCE):
        Logger.info(
            "[AREATRIGGER] crossing skipped reason=segment_too_long distance=%.3f",
            math.sqrt(segment_length_sq),
        )
        return None

    teleport_rows = _teleport_trigger_rows()
    if not teleport_rows:
        return None

    definitions = _area_trigger_definitions()
    if not definitions:
        return None

    candidates: list[AreaTriggerDefinition] = []
    for trigger_id, row in teleport_rows.items():
        definition = definitions.get(int(trigger_id))
        if definition is None or int(definition.map_id) != current_map_id:
            continue
        if _return_blocked(session, row, int(trigger_id)):
            continue
        movement_padding = _movement_scan_padding_for_transition(current_map_id, row)
        if _point_inside_trigger(
            definition,
            *start,
            padding=movement_padding,
        ) and not _point_inside_trigger(
            definition,
            *end,
            padding=movement_padding,
        ):
            Logger.info(
                "[AREATRIGGER] movement exit id=%s start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f)",
                int(definition.trigger_id),
                start[0],
                start[1],
                start[2],
                end[0],
                end[1],
                end[2],
            )
            continue
        if _segment_crosses_trigger(
            definition,
            start,
            end,
            padding=movement_padding,
        ):
            Logger.info(
                "[AREATRIGGER] movement candidate id=%s padding=%.3f source_map=%s target_map=%s",
                int(definition.trigger_id),
                float(movement_padding),
                current_map_id,
                int(row.get("target_map", 0) or 0),
            )
            candidates.append(definition)

    if not candidates:
        _log_nearby_movement_miss(
            session,
            current_map_id,
            start,
            end,
            teleport_rows,
            definitions,
        )
        return None

    candidates.sort(
        key=lambda definition: _segment_distance_sq_to_point(
            start,
            end,
            (definition.x, definition.y, definition.z),
        )
    )
    chosen = candidates[0]
    Logger.info(
        "[AREATRIGGER] movement crossing id=%s start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f)",
        int(chosen.trigger_id),
        start[0],
        start[1],
        start[2],
        end[0],
        end[1],
        end[2],
    )
    return activate_area_trigger(session, int(chosen.trigger_id), source="movement", crossed=True)
