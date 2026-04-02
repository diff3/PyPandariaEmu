from __future__ import annotations

from typing import Optional

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.dbc import read_dbc

_WORLD_MAP_AREAS: Optional[list[tuple[int, int, float, float, float, float, int]]] = None
_AREA_PARENTS: Optional[dict[int, int]] = None


def _load_world_map_areas() -> list[tuple[int, int, float, float, float, float, int]]:
    global _WORLD_MAP_AREAS
    if _WORLD_MAP_AREAS is not None:
        return _WORLD_MAP_AREAS

    _WORLD_MAP_AREAS = []
    dbc_root = get_dbc_root()
    path = dbc_root / "WorldMapArea.dbc"
    if not path.exists():
        Logger.warning("[WorldMapArea] missing")
        return _WORLD_MAP_AREAS

    try:
        rows = read_dbc(path, "xidxffffixxxxx")
    except Exception as exc:
        Logger.warning(f"[WorldMapArea] failed: {exc}")
        return _WORLD_MAP_AREAS

    for map_id, area_id, y1, y2, x1, x2, virtual_map_id in rows:
        _WORLD_MAP_AREAS.append(
            (
                int(map_id),
                int(area_id),
                float(x1),
                float(x2),
                float(y1),
                float(y2),
                int(virtual_map_id),
            )
        )

    return _WORLD_MAP_AREAS


def _load_area_parents() -> dict[int, int]:
    global _AREA_PARENTS
    if _AREA_PARENTS is not None:
        return _AREA_PARENTS

    _AREA_PARENTS = {}
    dbc_root = get_dbc_root()
    path = dbc_root / "AreaTable.dbc"
    if not path.exists():
        Logger.warning("[AreaTable] missing")
        return _AREA_PARENTS

    try:
        rows = read_dbc(path, "iiinixxxxxxxisiiiiifxxxxxxxxxx")
    except Exception as exc:
        Logger.warning(f"[AreaTable] failed: {exc}")
        return _AREA_PARENTS

    for row in rows:
        if len(row) < 3:
            continue
        area_id = int(row[0] or 0)
        parent_area_id = int(row[2] or 0)
        if area_id > 0:
            _AREA_PARENTS[area_id] = parent_area_id

    return _AREA_PARENTS


def _bbox_area(x1: float, x2: float, y1: float, y2: float) -> float:
    return abs(float(x2) - float(x1)) * abs(float(y2) - float(y1))


def _resolve_parent_zone(area_id: int) -> int:
    parents = _load_area_parents()
    current = int(area_id or 0)
    seen: set[int] = set()
    while current > 0 and current not in seen:
        seen.add(current)
        parent = int(parents.get(current, 0) or 0)
        if parent <= 0:
            return current
        current = parent
    return int(area_id or 0)


def resolve_zone_from_position(map_id: int, x: float, y: float) -> int:
    matches: list[tuple[float, int]] = []
    for candidate_map_id, area_id, x1, x2, y1, y2, _virtual_map_id in _load_world_map_areas():
        if candidate_map_id != int(map_id):
            continue
        if int(area_id) <= 0:
            continue
        if min(x1, x2) <= float(x) <= max(x1, x2) and min(y1, y2) <= float(y) <= max(y1, y2):
            matches.append((_bbox_area(x1, x2, y1, y2), int(area_id)))

    if not matches:
        return 0

    matches.sort(key=lambda item: (float(item[0]), int(item[1])))
    return _resolve_parent_zone(int(matches[0][1]))
