#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
from typing import Any

from server.modules.database.DatabaseConnection import DatabaseConnection

DEEPRUN_MAP_ID = 369
DEEPRUN_DISPLAY_ID = 3831
DEEPRUN_TYPE = 11
DEEPRUN_ENTRIES = frozenset({176080, 176081, 176082, 176083, 176084, 176085})

DEEPRUN_MIN_X = -9.1809
DEEPRUN_MIN_Y = -5.6808
DEEPRUN_MAX_X = 9.1809
DEEPRUN_MAX_Y = 5.6808
DEEPRUN_MAX_Z = 0.5114

DEEPRUN_XY_EPSILON = 0.2
DEEPRUN_Z_MIN_DELTA = 3.0
DEEPRUN_Z_MAX_DELTA = 1.5
DEEPRUN_QUERY_RADIUS = 32.0
DEEPRUN_QUERY_LIMIT = 16


def is_deeprun_tram_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    return (
        int(entry.get("map_id", entry.get("map", 0)) or 0) == DEEPRUN_MAP_ID
        and int(entry.get("entry", 0) or 0) in DEEPRUN_ENTRIES
        and int(entry.get("display_id", entry.get("displayId", 0)) or 0) == DEEPRUN_DISPLAY_ID
        and int(entry.get("type", 0) or 0) == DEEPRUN_TYPE
    )


def _entry_scale(entry: dict[str, Any]) -> float:
    scale = float(entry.get("size", 1.0) or 1.0)
    return scale if scale > 0.0 else 1.0


def _local_xy(entry: dict[str, Any], world_x: float, world_y: float) -> tuple[float, float]:
    origin_x = float(entry.get("x", 0.0) or 0.0)
    origin_y = float(entry.get("y", 0.0) or 0.0)
    orientation = float(entry.get("orientation", 0.0) or 0.0)

    delta_x = float(world_x) - origin_x
    delta_y = float(world_y) - origin_y

    cos_yaw = math.cos(orientation)
    sin_yaw = math.sin(orientation)
    local_x = (delta_x * cos_yaw) + (delta_y * sin_yaw)
    local_y = (-delta_x * sin_yaw) + (delta_y * cos_yaw)
    return local_x, local_y


def point_inside_deeprun_wagon(
    entry: dict[str, Any] | None,
    world_x: float,
    world_y: float,
    *,
    epsilon: float = DEEPRUN_XY_EPSILON,
) -> bool:
    if not is_deeprun_tram_entry(entry):
        return False

    scale = _entry_scale(entry)
    local_x, local_y = _local_xy(entry, world_x, world_y)

    min_x = DEEPRUN_MIN_X * scale - float(epsilon)
    max_x = DEEPRUN_MAX_X * scale + float(epsilon)
    min_y = DEEPRUN_MIN_Y * scale - float(epsilon)
    max_y = DEEPRUN_MAX_Y * scale + float(epsilon)
    return min_x <= local_x <= max_x and min_y <= local_y <= max_y


def deeprun_surface_z(entry: dict[str, Any] | None) -> float | None:
    if not is_deeprun_tram_entry(entry):
        return None
    return float(entry.get("z", 0.0) or 0.0) + (DEEPRUN_MAX_Z * _entry_scale(entry))


def clamp_deeprun_player_z(
    *,
    map_id: int,
    world_x: float,
    world_y: float,
    world_z: float,
) -> tuple[bool, float]:
    if int(map_id or 0) != DEEPRUN_MAP_ID:
        return False, float(world_z)

    candidates = DatabaseConnection.get_gameobjects_near(
        DEEPRUN_MAP_ID,
        float(world_x),
        float(world_y),
        radius=DEEPRUN_QUERY_RADIUS,
        limit=DEEPRUN_QUERY_LIMIT,
    )
    for entry in candidates:
        if not point_inside_deeprun_wagon(entry, world_x, world_y):
            continue
        surface_z = deeprun_surface_z(entry)
        if surface_z is None:
            continue
        if float(surface_z) - DEEPRUN_Z_MIN_DELTA <= float(world_z) <= float(surface_z) + DEEPRUN_Z_MAX_DELTA:
            return True, float(surface_z)
    return False, float(world_z)
