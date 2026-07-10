from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
from typing import Iterable, Mapping

from server.modules.dbc import read_dbc
from shared.Logger import Logger

from .bounds import DisplayBounds, OrientedBounds, build_oriented_bounds

GAMEOBJECT_TYPE_DOOR = 0
GAMEOBJECT_TYPE_BUTTON = 1
GAMEOBJECT_TYPE_CHEST = 3
GAMEOBJECT_TYPE_GENERIC = 5
GAMEOBJECT_TYPE_CHAIR = 7
GAMEOBJECT_TYPE_SPELL_FOCUS = 8
GAMEOBJECT_TYPE_GOOBER = 10
GAMEOBJECT_TYPE_TRANSPORT = 11
GAMEOBJECT_TYPE_MAP_OBJECT = 14
GAMEOBJECT_TYPE_MO_TRANSPORT = 15
GAMEOBJECT_TYPE_DESTRUCTIBLE_BUILDING = 33
GAMEOBJECT_TYPE_TRAPDOOR = 35

# These types commonly describe authored solid scenery. Tiny ambiguous models are
# filtered separately; transports and chairs are deliberately never considered.
SOLID_TYPES = frozenset({0, 1, 3, 5, 8, 10, 14, 33, 35})
GO_STATE_READY = 1
GO_FLAG_DAMAGED = 0x0200
GO_FLAG_DESTROYED = 0x0400
_GRID_SIZE = 32.0
_MIN_PLANAR_EXTENT = 0.30
_MIN_HEIGHT = 0.50
_SOLID_NAME_TOKENS = ("crate", "barrel", "door", "gate", "wall", "platform", "bridge", "barricade")
_SOLID_BUTTON_NAME_TOKENS = ("severed head",)
_DECORATIVE_NAME_TOKENS = ("sign", "banner", "poster", "painting", "chair", "stool")
_DISPLAY_INFO_FORMAT = "isxxxxxxxxxxffffffxxx"
_START_INSIDE_ESCAPE_EPSILON = 0.001


@dataclass(frozen=True)
class GameObjectCollision:
    map_id: int
    guid: int
    entry: int
    display_id: int
    bounds: OrientedBounds
    name: str = ""


def load_display_bounds(path: str | Path | None = None) -> dict[int, DisplayBounds]:
    if path is None:
        path = Path(__file__).resolve().parents[5] / "data/client/dbc/GameObjectDisplayInfo.dbc"
    result: dict[int, DisplayBounds] = {}
    for row in read_dbc(path, _DISPLAY_INFO_FORMAT):
        bounds = DisplayBounds(tuple(float(v) for v in row[2:5]), tuple(float(v) for v in row[5:8]))
        if bounds.valid():
            result[int(row[0])] = bounds
    return result


def gameobject_eligibility_reason(entry: Mapping, bounds: DisplayBounds | None) -> tuple[bool, str]:
    go_type = int(entry.get("type", -1) or 0)
    if go_type not in SOLID_TYPES or go_type in (GAMEOBJECT_TYPE_CHAIR, GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT):
        return False, f"ineligible_type:{go_type}"
    if bounds is None or not bounds.valid():
        return False, "missing_or_invalid_bounds"
    if int(entry.get("flags", 0) or 0) & (GO_FLAG_DAMAGED | GO_FLAG_DESTROYED):
        return False, "damaged_or_destroyed"
    if int(entry.get("state", GO_STATE_READY) or 0) not in (0, 1, 2):
        return False, f"unsupported_state:{int(entry.get('state', GO_STATE_READY) or 0)}"
    # A ready door/trapdoor is closed. Active variants are visually open and
    # must not retain their closed collision volume.
    if go_type in (GAMEOBJECT_TYPE_DOOR, GAMEOBJECT_TYPE_TRAPDOOR) and int(entry.get("state", GO_STATE_READY)) != GO_STATE_READY:
        return False, f"open_door_state:{int(entry.get('state', GO_STATE_READY) or 0)}"
    scale = float(entry.get("size", 1.0) or 1.0)
    dimensions = tuple((bounds.maximum[i] - bounds.minimum[i]) * scale for i in range(3))
    if max(dimensions[0], dimensions[1]) < _MIN_PLANAR_EXTENT or dimensions[2] < _MIN_HEIGHT:
        return False, "below_min_dimensions"
    name = str(entry.get("name", "") or "").lower()
    if any(token in name for token in _DECORATIVE_NAME_TOKENS):
        return False, "decorative_name_token"
    if go_type == GAMEOBJECT_TYPE_BUTTON:
        if max(dimensions) >= 1.5 and any(token in name for token in _SOLID_BUTTON_NAME_TOKENS):
            return True, "eligible_button"
        return False, "non_solid_button"
    if go_type in (GAMEOBJECT_TYPE_GENERIC, GAMEOBJECT_TYPE_SPELL_FOCUS, GAMEOBJECT_TYPE_GOOBER):
        if max(dimensions) >= 1.5 or any(token in name for token in _SOLID_NAME_TOKENS):
            return True, "eligible_generic"
        return False, "generic_too_small"
    return True, "eligible"


def gameobject_is_eligible(entry: Mapping, bounds: DisplayBounds | None) -> bool:
    return gameobject_eligibility_reason(entry, bounds)[0]


class GameObjectCollisionIndex:
    def __init__(self) -> None:
        self._cells: dict[int, dict[tuple[int, int], list[GameObjectCollision]]] = {}
        self._objects: list[GameObjectCollision] = []

    def clear(self) -> None:
        self._cells.clear()
        self._objects.clear()

    def register(self, collision: GameObjectCollision) -> None:
        self._objects.append(collision)
        min_x, min_y, max_x, max_y = collision.bounds.world_aabb()
        cells = self._cells.setdefault(collision.map_id, {})
        for cell_x in range(math.floor(min_x / _GRID_SIZE), math.floor(max_x / _GRID_SIZE) + 1):
            for cell_y in range(math.floor(min_y / _GRID_SIZE), math.floor(max_y / _GRID_SIZE) + 1):
                cells.setdefault((cell_x, cell_y), []).append(collision)

    def nearby_segment(self, map_id: int, start, end) -> Iterable[GameObjectCollision]:
        cells = self._cells.get(int(map_id), {})
        min_x, max_x = sorted((float(start[0]), float(end[0])))
        min_y, max_y = sorted((float(start[1]), float(end[1])))
        seen: set[int] = set()
        for cell_x in range(math.floor(min_x / _GRID_SIZE), math.floor(max_x / _GRID_SIZE) + 1):
            for cell_y in range(math.floor(min_y / _GRID_SIZE), math.floor(max_y / _GRID_SIZE) + 1):
                for collision in cells.get((cell_x, cell_y), ()):
                    marker = id(collision)
                    if marker not in seen:
                        seen.add(marker)
                        yield collision

    def nearby_point(
        self,
        map_id: int,
        point: tuple[float, float, float],
        *,
        radius: float,
    ) -> Iterable[GameObjectCollision]:
        cells = self._cells.get(int(map_id), {})
        radius = max(0.0, float(radius))
        x = float(point[0])
        y = float(point[1])
        min_x = x - radius
        max_x = x + radius
        min_y = y - radius
        max_y = y + radius
        seen: set[int] = set()
        for cell_x in range(math.floor(min_x / _GRID_SIZE), math.floor(max_x / _GRID_SIZE) + 1):
            for cell_y in range(math.floor(min_y / _GRID_SIZE), math.floor(max_y / _GRID_SIZE) + 1):
                for collision in cells.get((cell_x, cell_y), ()):
                    marker = id(collision)
                    if marker in seen:
                        continue
                    seen.add(marker)
                    aabb_min_x, aabb_min_y, aabb_max_x, aabb_max_y = collision.bounds.world_aabb()
                    if aabb_max_x < min_x or aabb_min_x > max_x or aabb_max_y < min_y or aabb_min_y > max_y:
                        continue
                    yield collision

    def get(self, map_id: int, guid: int) -> GameObjectCollision | None:
        for collision in self._objects:
            if collision.map_id == int(map_id) and collision.guid == int(guid):
                return collision
        return None

    def nearby_segment_list(self, map_id: int, start, end) -> list[GameObjectCollision]:
        return list(self.nearby_segment(map_id, start, end))

    def blocked(self, map_id: int, start, end) -> GameObjectCollision | None:
        from server.modules.handlers.world.feature_config import gameobject_collision_debug_enabled

        debug_enabled = gameobject_collision_debug_enabled()
        candidates = self.nearby_segment_list(map_id, start, end)
        if debug_enabled:
            Logger.info(
                "[GOCollision] candidates map=%s start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f) count=%s",
                int(map_id),
                float(start[0]),
                float(start[1]),
                float(start[2]),
                float(end[0]),
                float(end[1]),
                float(end[2]),
                len(candidates),
            )
        for collision in candidates:
            # Never trap a player whose prior authoritative position already lies
            # inside an approximate box (login, spawn, or coarse model bounds).
            start_inside = collision.bounds.contains(start)
            end_inside = collision.bounds.contains(end)
            if start_inside:
                start_fraction = collision.bounds.containment_fraction(start)
                end_fraction = collision.bounds.containment_fraction(end)
                if debug_enabled:
                    Logger.info(
                        "[GOCollision] skip guid=%s entry=%s name=%s reason=start_inside "
                        "start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f) "
                        "end_inside=%s start_fraction=%.4f end_fraction=%.4f",
                        collision.guid,
                        collision.entry,
                        collision.name,
                        float(start[0]),
                        float(start[1]),
                        float(start[2]),
                        float(end[0]),
                        float(end[1]),
                        float(end[2]),
                        "yes" if end_inside else "no",
                        float(start_fraction),
                        float(end_fraction),
                    )
                # Always allow a movement that exits the volume so approximate
                # bounds can be escaped without trapping the player.
                if not end_inside:
                    continue
                # Inside -> inside movement is only allowed when it clearly
                # moves outward toward the boundary. This keeps the failsafe
                # escape path while preventing free traversal through a solid
                # object once the server already believes the player is inside.
                if end_fraction > start_fraction + _START_INSIDE_ESCAPE_EPSILON:
                    continue
                if debug_enabled:
                    Logger.info(
                        "[GOCollision] consider map=%s guid=%s entry=%s name=%s "
                        "result=block_start_inside_inside",
                        int(map_id),
                        collision.guid,
                        collision.entry,
                        collision.name,
                    )
                return collision
            segment_hit = collision.bounds.intersects_segment(start, end)
            if debug_enabled:
                Logger.info(
                    "[GOCollision] consider map=%s guid=%s entry=%s name=%s end_inside=%s segment_hit=%s",
                    int(map_id),
                    collision.guid,
                    collision.entry,
                    collision.name,
                    "yes" if end_inside else "no",
                    "yes" if segment_hit else "no",
                )
            if end_inside or segment_hit:
                if debug_enabled:
                    Logger.info(
                        "[GOCollision] hit map=%s guid=%s entry=%s name=%s reason=%s",
                        int(map_id),
                        collision.guid,
                        collision.entry,
                        collision.name,
                        "end_inside" if end_inside else "segment_intersection",
                    )
                return collision
        if debug_enabled:
            Logger.info(
                "[GOCollision] no_hit map=%s start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f)",
                int(map_id),
                float(start[0]),
                float(start[1]),
                float(start[2]),
                float(end[0]),
                float(end[1]),
                float(end[2]),
            )
        return None

    def __len__(self) -> int:
        return len(self._objects)


gameobject_collision_index = GameObjectCollisionIndex()


def clear_gameobject_collision_index() -> None:
    gameobject_collision_index.clear()


def build_gameobject_collision_index(entries_by_map: Mapping[int, Iterable[Mapping]]) -> int:
    gameobject_collision_index.clear()
    bounds_by_display = load_display_bounds()
    from server.modules.handlers.world.feature_config import gameobject_collision_debug_enabled

    for map_id, entries in entries_by_map.items():
        for entry in entries:
            display_id = int(entry.get("display_id", 0) or 0)
            display_bounds = bounds_by_display.get(display_id)
            eligible, reason = gameobject_eligibility_reason(entry, display_bounds)
            if not eligible:
                if gameobject_collision_debug_enabled():
                    Logger.info(
                        "[GOCollision] exclude map=%s guid=%s entry=%s display=%s type=%s name=%s reason=%s",
                        int(map_id),
                        int(entry.get("guid", 0) or 0),
                        int(entry.get("entry", 0) or 0),
                        display_id,
                        int(entry.get("type", 0) or 0),
                        str(entry.get("name", "") or ""),
                        reason,
                    )
                continue
            bounds = build_oriented_bounds(
                display_bounds,
                position=(float(entry.get("x", 0.0)), float(entry.get("y", 0.0)), float(entry.get("z", 0.0))),
                orientation=float(entry.get("orientation", 0.0) or 0.0),
                scale=float(entry.get("size", 1.0) or 1.0),
            )
            if bounds is None:
                if gameobject_collision_debug_enabled():
                    Logger.info(
                        "[GOCollision] exclude map=%s guid=%s entry=%s display=%s type=%s name=%s reason=failed_bounds_build",
                        int(map_id),
                        int(entry.get("guid", 0) or 0),
                        int(entry.get("entry", 0) or 0),
                        display_id,
                        int(entry.get("type", 0) or 0),
                        str(entry.get("name", "") or ""),
                    )
                continue
            collision = GameObjectCollision(
                int(map_id),
                int(entry.get("guid", 0) or 0),
                int(entry.get("entry", 0) or 0),
                display_id,
                bounds,
                str(entry.get("name", "") or ""),
            )
            gameobject_collision_index.register(collision)
            if gameobject_collision_debug_enabled():
                Logger.info(
                    "[GOCollision] register map=%s guid=%s entry=%s display=%s name=%s",
                    collision.map_id,
                    collision.guid,
                    collision.entry,
                    collision.display_id,
                    collision.name,
                )
    registered = len(gameobject_collision_index)
    if gameobject_collision_debug_enabled():
        Logger.info(
            "[GOCollision] build complete registered=%s maps=%s display_bounds=%s",
            registered,
            len(gameobject_collision_index._cells),
            len(bounds_by_display),
        )
    return registered
