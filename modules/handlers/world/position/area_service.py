from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root, get_maps_root
from server.modules.dbc import read_dbc

_WORLD_MAP_AREAS: Optional[list[tuple[int, int, float, float, float, float, int]]] = None
_AREA_ASSIGNMENTS: Optional[dict[tuple[int, int, int], tuple[int, ...]]] = None
_AREA_ASSIGNMENT_CENTERS: Optional[dict[tuple[int, int], tuple[float, float]]] = None
_AREA_PARENTS: Optional[dict[int, int]] = None
_AREA_MAP_IDS: Optional[dict[int, int]] = None
_AREA_FLAGS: Optional[dict[int, int]] = None
_MAP_AREA_CACHE: dict[tuple[int, int, int], Optional[tuple[int, Optional[tuple[int, ...]]]]] = {}
_MAPS_ROOT_LOGGED = False
_ADT_TILE_SIZE = 533.3333333333334
_MAP_FILE_HEADER_SIZE = struct.calcsize("<4s4s4sIIIIIIII")
_MAP_AREA_HEADER_SIZE = struct.calcsize("<4sHH")
_MAP_AREA_NO_AREA = 0x0001

# Some sandbox/internal locations are valid AreaTable zones but are not covered
# by WorldMapArea bounding boxes. Keep these overrides narrow so normal zone
# resolution continues to come from DBC data.
_EXPLICIT_ZONE_AREAS: tuple[tuple[int, int, float, float, float, float], ...] = (
    # GM Island, Kalimdor. game_tele GMIsland: map=1 x=16226.2 y=16257.0.
    (1, 876, 15900.0, 16600.0, 15900.0, 16600.0),
)


def _resolve_explicit_zone_area(map_id: int, x: float, y: float) -> int:
    for candidate_map_id, area_id, x1, x2, y1, y2 in _EXPLICIT_ZONE_AREAS:
        if int(candidate_map_id) != int(map_id):
            continue
        if min(x1, x2) <= float(x) <= max(x1, x2) and min(y1, y2) <= float(y) <= max(y1, y2):
            return _resolve_parent_zone(int(area_id))
    return 0


def _resolve_explicit_area(map_id: int, x: float, y: float) -> int:
    for candidate_map_id, area_id, x1, x2, y1, y2 in _EXPLICIT_ZONE_AREAS:
        if int(candidate_map_id) != int(map_id):
            continue
        if min(x1, x2) <= float(x) <= max(x1, x2) and min(y1, y2) <= float(y) <= max(y1, y2):
            return int(area_id)
    return 0


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


def _tile_center(tile_y: int, tile_x: int) -> tuple[float, float]:
    return (
        (32.0 - (float(tile_x) + 0.5)) * _ADT_TILE_SIZE,
        (32.0 - (float(tile_y) + 0.5)) * _ADT_TILE_SIZE,
    )


def _load_area_assignments() -> dict[tuple[int, int, int], tuple[int, ...]]:
    global _AREA_ASSIGNMENTS, _AREA_ASSIGNMENT_CENTERS
    if _AREA_ASSIGNMENTS is not None:
        return _AREA_ASSIGNMENTS

    assignments: dict[tuple[int, int, int], list[int]] = {}
    centers: dict[tuple[int, int], list[tuple[float, float]]] = {}
    dbc_root = get_dbc_root()
    path = dbc_root / "AreaAssignment.dbc"
    if not path.exists():
        Logger.warning("[AreaAssignment] missing")
        _AREA_ASSIGNMENTS = {}
        _AREA_ASSIGNMENT_CENTERS = {}
        return _AREA_ASSIGNMENTS

    try:
        rows = read_dbc(path, "niiii")
    except Exception as exc:
        Logger.warning(f"[AreaAssignment] failed: {exc}")
        _AREA_ASSIGNMENTS = {}
        _AREA_ASSIGNMENT_CENTERS = {}
        return _AREA_ASSIGNMENTS

    for _entry_id, map_id, area_id, tile_y, tile_x in rows:
        if int(area_id or 0) <= 0:
            continue
        key = (int(map_id or 0), int(tile_y or 0), int(tile_x or 0))
        area_key = (int(map_id or 0), int(area_id or 0))
        assignments.setdefault(key, []).append(int(area_id))
        centers.setdefault(area_key, []).append(_tile_center(int(tile_y or 0), int(tile_x or 0)))

    _AREA_ASSIGNMENTS = {
        key: tuple(dict.fromkeys(area_ids))
        for key, area_ids in assignments.items()
    }
    _AREA_ASSIGNMENT_CENTERS = {
        key: (
            sum(x for x, _y in points) / len(points),
            sum(y for _x, y in points) / len(points),
        )
        for key, points in centers.items()
        if points
    }

    return _AREA_ASSIGNMENTS


def _load_area_parents() -> dict[int, int]:
    global _AREA_PARENTS, _AREA_MAP_IDS, _AREA_FLAGS
    if _AREA_PARENTS is not None:
        return _AREA_PARENTS

    _AREA_PARENTS = {}
    _AREA_MAP_IDS = {}
    _AREA_FLAGS = {}
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
        area_map_id = int(row[1] or 0)
        parent_area_id = int(row[2] or 0)
        if area_id > 0:
            _AREA_PARENTS[area_id] = parent_area_id
            _AREA_MAP_IDS[area_id] = area_map_id
            _AREA_FLAGS[area_id] = int(row[4] or 0) if len(row) > 4 else 0

    return _AREA_PARENTS


def area_flags(area_id: int) -> int:
    """Return AreaTable flags from the same metadata used by area resolution."""
    _load_area_parents()
    return int((_AREA_FLAGS or {}).get(int(area_id), 0) or 0)


def _area_belongs_to_map(area_id: int, map_id: int) -> bool:
    _load_area_parents()
    area_maps = _AREA_MAP_IDS or {}
    area_map_id = area_maps.get(int(area_id))
    return area_map_id is None or int(area_map_id) < 0 or int(area_map_id) == int(map_id)


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


def _adt_tile_from_position(x: float, y: float) -> tuple[int, int]:
    tile_y = int(32.0 - (float(y) / _ADT_TILE_SIZE))
    tile_x = int(32.0 - (float(x) / _ADT_TILE_SIZE))
    return tile_y, tile_x


def _grid_from_position(x: float, y: float) -> tuple[int, int]:
    return (
        int(32.0 - (float(x) / _ADT_TILE_SIZE)),
        int(32.0 - (float(y) / _ADT_TILE_SIZE)),
    )


def _map_file_path(map_id: int, grid_x: int, grid_y: int) -> Optional[Path]:
    global _MAPS_ROOT_LOGGED

    maps_root = get_maps_root()
    if maps_root is None:
        if not _MAPS_ROOT_LOGGED:
            Logger.warning("[AreaResolver] maps_path missing; using DBC area fallback")
            _MAPS_ROOT_LOGGED = True
        return None

    filename = f"{int(map_id):04d}_{int(grid_x):02d}_{int(grid_y):02d}.map"
    direct_path = maps_root / filename
    if direct_path.exists():
        return direct_path

    nested_path = maps_root / "maps" / filename
    if nested_path.exists():
        return nested_path

    return None


def _load_map_area_grid(map_id: int, grid_x: int, grid_y: int) -> Optional[tuple[int, Optional[tuple[int, ...]]]]:
    key = (int(map_id), int(grid_x), int(grid_y))
    if key in _MAP_AREA_CACHE:
        return _MAP_AREA_CACHE[key]

    path = _map_file_path(int(map_id), int(grid_x), int(grid_y))
    if path is None:
        _MAP_AREA_CACHE[key] = None
        return None

    try:
        data = path.read_bytes()
        if len(data) < _MAP_FILE_HEADER_SIZE:
            _MAP_AREA_CACHE[key] = None
            return None

        (
            map_magic,
            version_magic,
            _build_magic,
            area_map_offset,
            _area_map_size,
            _height_map_offset,
            _height_map_size,
            _liquid_map_offset,
            _liquid_map_size,
            _holes_offset,
            _holes_size,
        ) = struct.unpack_from("<4s4s4sIIIIIIII", data, 0)

        if map_magic != b"MAPS" or version_magic not in (b"v1.8", b"v1.4"):
            Logger.warning("[AreaResolver] incompatible map file %s version=%r", path, version_magic)
            _MAP_AREA_CACHE[key] = None
            return None

        if int(area_map_offset) <= 0 or int(area_map_offset) + _MAP_AREA_HEADER_SIZE > len(data):
            _MAP_AREA_CACHE[key] = None
            return None

        fourcc, flags, grid_area = struct.unpack_from("<4sHH", data, int(area_map_offset))
        if fourcc != b"AREA":
            _MAP_AREA_CACHE[key] = None
            return None

        area_map: Optional[tuple[int, ...]] = None
        if not (int(flags) & _MAP_AREA_NO_AREA):
            offset = int(area_map_offset) + _MAP_AREA_HEADER_SIZE
            size = 16 * 16 * 2
            if offset + size > len(data):
                _MAP_AREA_CACHE[key] = None
                return None
            area_map = tuple(int(value) for value in struct.unpack_from("<256H", data, offset))

        _MAP_AREA_CACHE[key] = (int(grid_area), area_map)
    except Exception as exc:
        Logger.warning("[AreaResolver] failed loading map area %s: %s", path, exc)
        _MAP_AREA_CACHE[key] = None

    return _MAP_AREA_CACHE[key]


def _resolve_map_file_area(map_id: int, x: float, y: float) -> int:
    grid_x, grid_y = _grid_from_position(float(x), float(y))
    area_grid = _load_map_area_grid(int(map_id), int(grid_x), int(grid_y))
    if area_grid is None:
        return 0

    grid_area, area_map = area_grid
    if area_map is None:
        return int(grid_area)

    local_x = int(16.0 * (32.0 - float(x) / _ADT_TILE_SIZE)) & 15
    local_y = int(16.0 * (32.0 - float(y) / _ADT_TILE_SIZE)) & 15
    index = local_x * 16 + local_y
    if not 0 <= index < len(area_map):
        return int(grid_area)
    return int(area_map[index])


def _resolve_area_assignment(map_id: int, x: float, y: float) -> int:
    tile_y, tile_x = _adt_tile_from_position(float(x), float(y))
    area_ids = _load_area_assignments().get((int(map_id), tile_y, tile_x), ())
    if not area_ids:
        return 0
    if len(area_ids) == 1:
        return int(area_ids[0])

    centers = _AREA_ASSIGNMENT_CENTERS or {}
    candidates: list[tuple[float, int]] = []
    for area_id in area_ids:
        center = centers.get((int(map_id), int(area_id)))
        if center is None:
            continue
        center_x, center_y = center
        distance = (float(x) - center_x) ** 2 + (float(y) - center_y) ** 2
        candidates.append((float(distance), int(area_id)))

    if not candidates:
        return int(area_ids[0])

    candidates.sort(key=lambda item: (item[0], item[1]))
    return int(candidates[0][1])


def resolve_zone_from_position(map_id: int, x: float, y: float) -> int:
    area_id = resolve_area_from_position(int(map_id), float(x), float(y))
    if area_id <= 0:
        return 0
    return _resolve_parent_zone(int(area_id))


def resolve_area_from_position(map_id: int, x: float, y: float) -> int:
    explicit_area = _resolve_explicit_area(int(map_id), float(x), float(y))
    if explicit_area > 0:
        return int(explicit_area)

    map_file_area = _resolve_map_file_area(int(map_id), float(x), float(y))
    if map_file_area > 0 and _area_belongs_to_map(map_file_area, int(map_id)):
        return int(map_file_area)

    assigned_area = _resolve_area_assignment(int(map_id), float(x), float(y))
    if assigned_area > 0:
        return int(assigned_area)

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
    return int(matches[0][1])
