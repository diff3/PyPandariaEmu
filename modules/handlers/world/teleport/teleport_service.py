#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import difflib
from math import sqrt
from typing import Any

try:
    from sqlalchemy import text
except ImportError:
    def text(sql: str) -> str:
        return sql

from shared.Logger import Logger

TELEPORTS: dict[str, dict[str, Any]] = {}


def _normalize_name(name: str) -> str:
    return str(name or "").strip().lower()


def _row_value(row: Any, attr: str, index: int) -> Any:
    if hasattr(row, attr):
        return getattr(row, attr)
    return row[index]


def _build_entry(name: str, map_id: int, x: float, y: float, z: float, orientation: float) -> dict[str, Any]:
    return {
        "name": str(name),
        "map": int(map_id),
        "x": float(x),
        "y": float(y),
        "z": float(z),
        "o": float(orientation),
    }


def load_teleports(db) -> None:
    rows = db.execute(
        text(
            """
            SELECT name, map, position_x, position_y, position_z, orientation
            FROM game_tele
            """
        )
    ).fetchall()

    TELEPORTS.clear()
    for row in rows:
        name = str(_row_value(row, "name", 0) or "").strip()
        if not name:
            continue
        TELEPORTS[_normalize_name(name)] = _build_entry(
            name=name,
            map_id=_row_value(row, "map", 1),
            x=_row_value(row, "position_x", 2),
            y=_row_value(row, "position_y", 3),
            z=_row_value(row, "position_z", 4),
            orientation=_row_value(row, "orientation", 5),
        )

    Logger.info("[Teleport] Loaded %s teleports", len(TELEPORTS))


def find_teleport(name: str):
    normalized = _normalize_name(name)
    if not normalized:
        return None

    if normalized in TELEPORTS:
        return TELEPORTS[normalized]

    for key in TELEPORTS:
        if key.startswith(normalized):
            return TELEPORTS[key]

    matches = difflib.get_close_matches(normalized, TELEPORTS.keys(), n=1, cutoff=0.7)
    if matches:
        return TELEPORTS[matches[0]]
    return None


def search_teleports(name: str) -> list[str]:
    normalized = _normalize_name(name)
    if not normalized:
        return []

    prefix_matches = [entry["name"] for key, entry in sorted(TELEPORTS.items()) if key.startswith(normalized)]
    if prefix_matches:
        return prefix_matches[:5]

    matches = difflib.get_close_matches(normalized, TELEPORTS.keys(), n=5, cutoff=0.5)
    return [TELEPORTS[key]["name"] for key in matches]


def distance_2d(x1, y1, x2, y2):
    return sqrt((x1 - x2) ** 2 + (y1 - y2) ** 2)


def nearest_teleport(map_id: int, x: float, y: float):
    closest = None
    closest_distance = None

    for entry in TELEPORTS.values():
        if int(entry["map"]) != int(map_id):
            continue
        distance = distance_2d(float(entry["x"]), float(entry["y"]), float(x), float(y))
        if closest is None or distance < float(closest_distance):
            closest = entry
            closest_distance = distance

    return closest


def add_teleport(db, name: str, map_id: int, x: float, y: float, z: float, orientation: float):
    original_name = str(name or "").strip()
    normalized = _normalize_name(original_name)
    if not normalized:
        raise ValueError("teleport name is required")

    try:
        db.execute(
            text("DELETE FROM game_tele WHERE LOWER(name) = :name"),
            {"name": normalized},
        )
        db.execute(
            text(
                """
                INSERT INTO game_tele (name, map, position_x, position_y, position_z, orientation)
                VALUES (:name, :map_id, :x, :y, :z, :orientation)
                """
            ),
            {
                "name": original_name,
                "map_id": int(map_id),
                "x": float(x),
                "y": float(y),
                "z": float(z),
                "orientation": float(orientation),
            },
        )
        db.commit()
    except Exception:
        rollback = getattr(db, "rollback", None)
        if callable(rollback):
            rollback()
        raise

    entry = _build_entry(original_name, map_id, x, y, z, orientation)
    TELEPORTS[normalized] = entry
    Logger.info("[Teleport] Added %s", original_name)
    return entry


def remove_teleport(db, name: str) -> bool:
    normalized = _normalize_name(name)
    if not normalized:
        return False

    try:
        db.execute(
            text("DELETE FROM game_tele WHERE LOWER(name) = :name"),
            {"name": normalized},
        )
        db.commit()
    except Exception:
        rollback = getattr(db, "rollback", None)
        if callable(rollback):
            rollback()
        raise
    removed = TELEPORTS.pop(normalized, None)
    if removed is not None:
        Logger.info("[Teleport] Removed %s", removed["name"])
        return True
    Logger.info("[Teleport] Remove requested for missing teleport=%s", normalized)
    return False
