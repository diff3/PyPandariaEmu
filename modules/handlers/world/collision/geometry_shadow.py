from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Any

from shared.Logger import Logger

from .gameobject_collision import GameObjectCollision


@dataclass(frozen=True)
class GeometryShadowComparison:
    old_hit: bool
    old_collision: GameObjectCollision | None
    old_resolved_end: tuple[float, float, float]
    new_hit: bool
    new_resolved_end: tuple[float, float, float]
    new_fraction: float | None
    new_hit_position: tuple[float, float, float] | None
    new_hit_normal: tuple[float, float, float] | None
    new_mesh_name: str | None
    new_instance_id: int | None
    delta: float
    agreed: bool


@dataclass
class ManualTrophyMissDiagnosticsStats:
    total_old_hit_new_miss: int = 0
    total_segment_length: float = 0.0
    total_segment_to_world_aabb_distance: float = 0.0
    misses_without_world_aabb_entry: int = 0
    misses_entered_local_aabb_without_triangle_hit: int = 0

    def clear(self) -> None:
        self.total_old_hit_new_miss = 0
        self.total_segment_length = 0.0
        self.total_segment_to_world_aabb_distance = 0.0
        self.misses_without_world_aabb_entry = 0
        self.misses_entered_local_aabb_without_triangle_hit = 0

    def average_segment_length(self) -> float:
        if self.total_old_hit_new_miss <= 0:
            return 0.0
        return float(self.total_segment_length) / float(self.total_old_hit_new_miss)

    def average_segment_to_world_aabb_distance(self) -> float:
        if self.total_old_hit_new_miss <= 0:
            return 0.0
        return float(self.total_segment_to_world_aabb_distance) / float(self.total_old_hit_new_miss)


@dataclass
class GeometryShadowStats:
    authoritative_mode: str = "legacy"
    comparisons: int = 0
    agreements: int = 0
    disagreements: int = 0
    old_hit_new_hit: int = 0
    old_hit_new_miss: int = 0
    old_miss_new_hit: int = 0
    old_miss_new_miss: int = 0
    total_delta: float = 0.0
    max_delta: float = 0.0
    legacy_hits: int = 0
    shadow_hits: int = 0
    legacy_only: int = 0
    shadow_only: int = 0
    both_hit: int = 0
    both_miss: int = 0
    _event_counts: dict[tuple[Any, ...], int] = field(default_factory=dict, repr=False)

    def clear(self) -> None:
        self.authoritative_mode = "legacy"
        self.comparisons = 0
        self.agreements = 0
        self.disagreements = 0
        self.old_hit_new_hit = 0
        self.old_hit_new_miss = 0
        self.old_miss_new_hit = 0
        self.old_miss_new_miss = 0
        self.total_delta = 0.0
        self.max_delta = 0.0
        self.legacy_hits = 0
        self.shadow_hits = 0
        self.legacy_only = 0
        self.shadow_only = 0
        self.both_hit = 0
        self.both_miss = 0
        self._event_counts.clear()

    def average_delta(self) -> float:
        if self.comparisons <= 0:
            return 0.0
        return float(self.total_delta) / float(self.comparisons)

    def snapshot(self) -> dict[str, float | int | str]:
        return {
            "authoritative_mode": str(self.authoritative_mode),
            "comparisons": int(self.comparisons),
            "agreements": int(self.agreements),
            "disagreements": int(self.disagreements),
            "old_hit_new_hit": int(self.old_hit_new_hit),
            "old_hit_new_miss": int(self.old_hit_new_miss),
            "old_miss_new_hit": int(self.old_miss_new_hit),
            "old_miss_new_miss": int(self.old_miss_new_miss),
            "average_delta": float(self.average_delta()),
            "max_delta": float(self.max_delta),
            "legacy_hits": int(self.legacy_hits),
            "shadow_hits": int(self.shadow_hits),
            "legacy_only": int(self.legacy_only),
            "shadow_only": int(self.shadow_only),
            "both_hit": int(self.both_hit),
            "both_miss": int(self.both_miss),
        }


geometry_shadow_stats = GeometryShadowStats()
manual_trophy_miss_diagnostics_stats = ManualTrophyMissDiagnosticsStats()

_mesh_cache: dict[tuple[float, float, float], object] = {}
_world_cache = None
_world_cache_signature: tuple[int, int, int, int] | None = None
_display_bounds_cache: dict[int, object] | None = None
_manual_mesh_logged: set[tuple[int, int]] = set()


def log_geometry_shadow_initialization() -> None:
    from server.modules.handlers.world.feature_config import (
        GAMEOBJECT_COLLISION_MODE_LEGACY,
        GAMEOBJECT_COLLISION_MODE_SHADOW_AUTHORITATIVE,
        experimental_geometry_shadow_enabled,
        gameobject_collision_debug_enabled,
        gameobject_collision_mode,
    )

    mode = gameobject_collision_mode()
    enabled = mode != GAMEOBJECT_COLLISION_MODE_LEGACY
    experimental_enabled = bool(experimental_geometry_shadow_enabled())
    shadow_authoritative = mode == GAMEOBJECT_COLLISION_MODE_SHADOW_AUTHORITATIVE
    debug_enabled = bool(gameobject_collision_debug_enabled())
    Logger.info(
        "[GeometryShadow] ExperimentalGeometryShadow=%s",
        "true" if experimental_enabled else "false",
    )
    Logger.info("[GeometryShadow] GameObjectCollisionMode=%s", mode)
    Logger.info(
        "[GeometryShadow] Legacy collision authoritative=%s",
        "false" if shadow_authoritative else "true",
    )
    Logger.info(
        "[GeometryShadow] Geometry Shadow authoritative=%s",
        "true" if shadow_authoritative else "false",
    )
    Logger.info("[GeometryShadow] initialized enabled=%s", "true" if enabled else "false")
    Logger.info(
        "[GeometryShadow] startup shadow=%s debug=%s authoritative_mode=%s",
        "true" if enabled else "false",
        "true" if debug_enabled else "false",
        mode,
    )


def clear_geometry_shadow_stats() -> None:
    geometry_shadow_stats.clear()
    manual_trophy_miss_diagnostics_stats.clear()


def get_geometry_shadow_stats() -> dict[str, float | int | str]:
    from server.modules.handlers.world.feature_config import gameobject_collision_mode

    geometry_shadow_stats.authoritative_mode = gameobject_collision_mode()
    return geometry_shadow_stats.snapshot()


def format_geometry_shadow_stats_lines() -> list[str]:
    stats = get_geometry_shadow_stats()
    lines = [
        "[GeometryShadow] statistics",
        f"authoritative_mode={stats['authoritative_mode']}",
        f"comparisons={int(stats['comparisons'])} agreements={int(stats['agreements'])} disagreements={int(stats['disagreements'])}",
        (
            "old_hit_new_hit="
            f"{int(stats['old_hit_new_hit'])} old_hit_new_miss={int(stats['old_hit_new_miss'])} "
            f"old_miss_new_hit={int(stats['old_miss_new_hit'])} old_miss_new_miss={int(stats['old_miss_new_miss'])}"
        ),
        f"average_delta={float(stats['average_delta']):.4f}m max_delta={float(stats['max_delta']):.4f}m",
        (
            f"legacy_hits={int(stats['legacy_hits'])} shadow_hits={int(stats['shadow_hits'])} "
            f"legacy_only={int(stats['legacy_only'])} shadow_only={int(stats['shadow_only'])} "
            f"both_hit={int(stats['both_hit'])} both_miss={int(stats['both_miss'])}"
        ),
    ]
    if manual_trophy_miss_diagnostics_stats.total_old_hit_new_miss > 0:
        lines.append(
            "[GeometryShadow] manual_trophy_old_hit_new_miss "
            f"total={int(manual_trophy_miss_diagnostics_stats.total_old_hit_new_miss)} "
            f"average_segment_length={float(manual_trophy_miss_diagnostics_stats.average_segment_length()):.4f}m "
            "average_segment_to_world_aabb_distance="
            f"{float(manual_trophy_miss_diagnostics_stats.average_segment_to_world_aabb_distance()):.4f}m"
        )
        lines.append(
            "[GeometryShadow] manual_trophy_old_hit_new_miss "
            f"misses_without_world_aabb_entry={int(manual_trophy_miss_diagnostics_stats.misses_without_world_aabb_entry)} "
            "misses_entered_local_aabb_without_triangle_hit="
            f"{int(manual_trophy_miss_diagnostics_stats.misses_entered_local_aabb_without_triangle_hit)}"
        )
    return lines


def run_geometry_shadow_comparison(
    session,
    opcode_name: str,
    *,
    map_id: int,
    start: tuple[float, float, float],
    end: tuple[float, float, float],
    old_collision: GameObjectCollision | None,
    old_resolved_end: tuple[float, float, float],
    authoritative_mode: str = "shadow_compare",
) -> GeometryShadowComparison:
    from server.modules.handlers.world.collision.geometry import Vec3, resolve_segment
    from server.modules.handlers.world.feature_config import (
        gameobject_collision_debug_enabled,
        geometry_contact_separation_epsilon,
    )

    Logger.info(
        "[GeometryShadow] movement_hook player=%s opcode=%s map=%s start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f)",
        int(getattr(session, "char_guid", 0) or 0),
        opcode_name,
        int(map_id),
        float(start[0]),
        float(start[1]),
        float(start[2]),
        float(end[0]),
        float(end[1]),
        float(end[2]),
    )
    shadow_world = _get_or_build_shadow_world()
    Logger.info("[GeometryShadow] querying world geometry")
    start_vec = Vec3(float(start[0]), float(start[1]), float(start[2]))
    end_vec = Vec3(float(end[0]), float(end[1]), float(end[2]))
    separation_epsilon = float(geometry_contact_separation_epsilon())
    result = resolve_segment(
        start_vec,
        end_vec,
        shadow_world,
        contact_epsilon=separation_epsilon,
    )
    Logger.info(
        "[GeometryShadow] query complete hit=%s",
        "true" if result.hit is not None else "false",
    )
    if result.hit is not None and gameobject_collision_debug_enabled():
        separation_distance = (result.resolved_end - result.hit.position).length()
        Logger.info(
            "[GeometryShadow] contact_resolution hit=(%.6f %.6f %.6f) "
            "normal=(%.6f %.6f %.6f) epsilon=%.6f corrected=(%.6f %.6f %.6f) "
            "separation_distance=%.6f",
            float(result.hit.position.x),
            float(result.hit.position.y),
            float(result.hit.position.z),
            float(result.hit.normal.x),
            float(result.hit.normal.y),
            float(result.hit.normal.z),
            separation_epsilon,
            float(result.resolved_end.x),
            float(result.resolved_end.y),
            float(result.resolved_end.z),
            float(separation_distance),
        )

    old_hit = old_collision is not None
    new_hit = result.hit is not None
    old_resolved = (
        float(old_resolved_end[0]),
        float(old_resolved_end[1]),
        float(old_resolved_end[2]),
    )
    new_resolved = (
        float(result.resolved_end.x),
        float(result.resolved_end.y),
        float(result.resolved_end.z),
    )
    delta = math.dist(old_resolved, new_resolved)
    comparison = GeometryShadowComparison(
        old_hit=old_hit,
        old_collision=old_collision,
        old_resolved_end=old_resolved,
        new_hit=new_hit,
        new_resolved_end=new_resolved,
        new_fraction=(None if result.hit is None else float(result.fraction)),
        new_hit_position=(
            None
            if result.hit_position is None
            else (
                float(result.hit_position.x),
                float(result.hit_position.y),
                float(result.hit_position.z),
            )
        ),
        new_hit_normal=(
            None
            if result.hit_normal is None
            else (
                float(result.hit_normal.x),
                float(result.hit_normal.y),
                float(result.hit_normal.z),
            )
        ),
        new_mesh_name=str(getattr(getattr(result.hit, "mesh", None), "name", "") or "") or None,
        new_instance_id=(
            None
            if getattr(result.hit, "instance", None) is None
            else int(getattr(result.hit.instance, "instance_id", 0) or 0)
        ),
        delta=float(delta),
        agreed=bool(old_hit == new_hit),
    )

    Logger.info("[GeometryShadow] comparison_ready old=%s new=%s", "hit" if old_hit else "miss", "hit" if new_hit else "miss")
    _record_comparison(comparison, authoritative_mode=authoritative_mode)
    _maybe_log_comparison(
        session,
        opcode_name,
        int(map_id),
        start,
        end,
        comparison,
        verbose=bool(gameobject_collision_debug_enabled()),
    )
    _maybe_log_manual_trophy_miss_diagnostics(
        session,
        opcode_name,
        map_id=int(map_id),
        start=start,
        end=end,
        comparison=comparison,
        enabled=bool(gameobject_collision_debug_enabled()),
    )
    setattr(session, "_last_geometry_shadow_comparison", comparison)
    return comparison


def build_manual_trophy_authoritative_contact_probe(
    map_id: int,
    comparison: GeometryShadowComparison,
) -> dict[str, object] | None:
    """Build read-only containment diagnostics for the selected trophy mesh hit."""
    if (
        not bool(getattr(comparison, "new_hit", False))
        or int(getattr(comparison, "new_instance_id", 0) or 0) != 73357
        or str(getattr(comparison, "new_mesh_name", "") or "") != "manual_onyxia_trophy_5951"
        or getattr(comparison, "new_hit_position", None) is None
        or getattr(comparison, "new_hit_normal", None) is None
    ):
        return None

    from server.modules.handlers.world.collision import gameobject_collision_index
    from server.modules.handlers.world.collision.geometry import Vec3

    collision = gameobject_collision_index.get(int(map_id), 73357)
    if collision is None or int(collision.entry) != 179881 or int(collision.display_id) != 5951:
        return None
    world = _get_or_build_shadow_world()
    instance = next(
        (
            item
            for item in getattr(world, "instances", ())
            if int(getattr(item, "instance_id", 0) or 0) == 73357
            and str(getattr(getattr(item, "mesh", None), "name", "") or "")
            == "manual_onyxia_trophy_5951"
        ),
        None,
    )
    if instance is None:
        return None
    world_min, world_max = _world_aabb_for_instance(instance)
    corrected = Vec3(*comparison.new_resolved_end)
    inside_world_aabb = (
        float(world_min.x) <= corrected.x <= float(world_max.x)
        and float(world_min.y) <= corrected.y <= float(world_max.y)
        and float(world_min.z) <= corrected.z <= float(world_max.z)
    )
    return {
        "guid": 73357,
        "entry": 179881,
        "display_id": 5951,
        "mesh": "manual_onyxia_trophy_5951",
        "hit_position": tuple(float(value) for value in comparison.new_hit_position),
        "hit_normal": tuple(float(value) for value in comparison.new_hit_normal),
        "corrected_position": tuple(float(value) for value in comparison.new_resolved_end),
        "separation_distance": math.dist(
            comparison.new_hit_position,
            comparison.new_resolved_end,
        ),
        "corrected_inside_world_aabb": bool(inside_world_aabb),
        "corrected_inside_legacy_obb": bool(
            collision.bounds.contains(tuple(float(value) for value in comparison.new_resolved_end))
        ),
    }


def _record_comparison(
    comparison: GeometryShadowComparison,
    *,
    authoritative_mode: str = "shadow_compare",
) -> None:
    stats = geometry_shadow_stats
    stats.authoritative_mode = str(authoritative_mode)
    stats.comparisons += 1
    if comparison.agreed:
        stats.agreements += 1
    else:
        stats.disagreements += 1
    if comparison.old_hit and comparison.new_hit:
        stats.old_hit_new_hit += 1
        stats.both_hit += 1
    elif comparison.old_hit and not comparison.new_hit:
        stats.old_hit_new_miss += 1
        stats.legacy_only += 1
    elif (not comparison.old_hit) and comparison.new_hit:
        stats.old_miss_new_hit += 1
        stats.shadow_only += 1
    else:
        stats.old_miss_new_miss += 1
        stats.both_miss += 1
    if comparison.old_hit:
        stats.legacy_hits += 1
    if comparison.new_hit:
        stats.shadow_hits += 1
    stats.total_delta += float(comparison.delta)
    stats.max_delta = max(float(stats.max_delta), float(comparison.delta))
    Logger.info(
        "[GeometryShadow] authoritative_mode=%s comparisons=%s agreements=%s disagreements=%s old_hit_new_hit=%s "
        "old_hit_new_miss=%s old_miss_new_hit=%s old_miss_new_miss=%s average_delta=%.4f max_delta=%.4f",
        str(stats.authoritative_mode),
        int(stats.comparisons),
        int(stats.agreements),
        int(stats.disagreements),
        int(stats.old_hit_new_hit),
        int(stats.old_hit_new_miss),
        int(stats.old_miss_new_hit),
        int(stats.old_miss_new_miss),
        float(stats.average_delta()),
        float(stats.max_delta),
    )
    Logger.info(
        "[GeometryShadow] legacy_hits=%s shadow_hits=%s legacy_only=%s shadow_only=%s both_hit=%s both_miss=%s",
        int(stats.legacy_hits),
        int(stats.shadow_hits),
        int(stats.legacy_only),
        int(stats.shadow_only),
        int(stats.both_hit),
        int(stats.both_miss),
    )


def _maybe_log_comparison(
    session,
    opcode_name: str,
    map_id: int,
    start: tuple[float, float, float],
    end: tuple[float, float, float],
    comparison: GeometryShadowComparison,
    *,
    verbose: bool,
) -> None:
    event_key = (
        bool(comparison.old_hit),
        bool(comparison.new_hit),
        int(getattr(comparison.old_collision, "entry", 0) or 0),
        int(comparison.new_instance_id or 0),
        str(comparison.new_mesh_name or ""),
    )
    seen_count = geometry_shadow_stats._event_counts.get(event_key, 0) + 1
    geometry_shadow_stats._event_counts[event_key] = seen_count
    should_log = verbose or (not comparison.agreed) or float(comparison.delta) >= 0.25
    if not should_log:
        Logger.info("[GeometryShadow] agreement")
        return
    if not verbose and seen_count not in {1, 2, 3} and (seen_count % 25) != 0:
        Logger.info("[GeometryShadow] skipped reason=aggregated_duplicate count=%s", int(seen_count))
        return
    Logger.info("[GeometryShadow] %s", "agreement" if comparison.agreed else "disagreement")
    Logger.info(
        "[GeometryShadow] old=%s new=%s delta=%.3fm opcode=%s player=%s map=%s object=%s mesh=%s fraction=%s",
        "HIT" if comparison.old_hit else "MISS",
        "HIT" if comparison.new_hit else "MISS",
        float(comparison.delta),
        opcode_name,
        int(getattr(session, "char_guid", 0) or 0),
        int(map_id),
        (
            "none"
            if comparison.old_collision is None
            else f"{int(comparison.old_collision.entry)}:{int(comparison.old_collision.guid)}"
        ),
        str(comparison.new_mesh_name or "none"),
        "none" if comparison.new_fraction is None else f"{float(comparison.new_fraction):.4f}",
    )
    if verbose:
        Logger.info(
            "[GeometryShadow] segment start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f) "
            "new_hit_pos=%s new_hit_normal=%s resolved=(%.3f %.3f %.3f)",
            float(start[0]),
            float(start[1]),
            float(start[2]),
            float(end[0]),
            float(end[1]),
            float(end[2]),
            "none"
            if comparison.new_hit_position is None
            else "(%.3f %.3f %.3f)" % comparison.new_hit_position,
            "none"
            if comparison.new_hit_normal is None
            else "(%.3f %.3f %.3f)" % comparison.new_hit_normal,
            float(comparison.new_resolved_end[0]),
            float(comparison.new_resolved_end[1]),
            float(comparison.new_resolved_end[2]),
        )


def _maybe_log_manual_trophy_miss_diagnostics(
    session,
    opcode_name: str,
    *,
    map_id: int,
    start: tuple[float, float, float],
    end: tuple[float, float, float],
    comparison: GeometryShadowComparison,
    enabled: bool,
) -> None:
    trigger = _manual_trophy_miss_diagnostics_trigger(comparison, enabled=enabled)
    if trigger["candidate"]:
        Logger.info(
            "[GeometryShadow] trophy_trigger entered enabled=%s old_hit=%s new_hit=%s old_collision=%s entry=%s displayId=%s guid=%s",
            "true" if bool(trigger["enabled"]) else "false",
            "true" if bool(trigger["old_hit"]) else "false",
            "true" if bool(trigger["new_hit"]) else "false",
            "yes" if bool(trigger["has_old_collision"]) else "no",
            int(trigger["entry"]),
            int(trigger["display_id"]),
            int(trigger["guid"]),
        )
        Logger.info(
            "[GeometryShadow] trophy_trigger result=%s registry_match=%s mesh=%s reason=%s",
            "true" if bool(trigger["should_log"]) else "false",
            "true" if bool(trigger["manual_mesh_matches"]) else "false",
            str(trigger["manual_mesh_name"] or "none"),
            str(trigger["reason"]),
        )
    if not trigger["should_log"]:
        return
    collision = comparison.old_collision
    assert collision is not None

    diagnostics = _build_manual_trophy_miss_diagnostics(collision, start, end)
    if diagnostics is None:
        Logger.info("[GeometryShadow] trophy_miss_diagnostics skipped reason=diagnostic_context_unavailable")
        return

    stats = manual_trophy_miss_diagnostics_stats
    stats.total_old_hit_new_miss += 1
    stats.total_segment_length += float(diagnostics["segment_length"])
    stats.total_segment_to_world_aabb_distance += float(diagnostics["segment_to_world_aabb_distance"])
    if not diagnostics["world_aabb_intersected"]:
        stats.misses_without_world_aabb_entry += 1
    if diagnostics["local_aabb_intersected"] and diagnostics["nearest_hit_distance"] is None:
        stats.misses_entered_local_aabb_without_triangle_hit += 1

    Logger.info(
        "[GeometryShadow] trophy_miss opcode=%s player=%s map=%s guid=%s entry=%s displayId=%s mesh=%s "
        "start=(%.3f %.3f %.3f) end=(%.3f %.3f %.3f) segment_length=%.3f",
        opcode_name,
        int(getattr(session, "char_guid", 0) or 0),
        int(map_id),
        int(collision.guid),
        int(collision.entry),
        int(collision.display_id),
        str(diagnostics["mesh_name"]),
        float(start[0]),
        float(start[1]),
        float(start[2]),
        float(end[0]),
        float(end[1]),
        float(end[2]),
        float(diagnostics["segment_length"]),
    )
    Logger.info(
        "[GeometryShadow] trophy_miss legacy_obb center=%s extents=%s yaw=%.6f",
        _fmt_tuple(diagnostics["legacy_center"]),
        _fmt_tuple(diagnostics["legacy_extents"]),
        float(diagnostics["legacy_yaw"]),
    )
    Logger.info(
        "[GeometryShadow] trophy_miss transform translation=%s rotation_yaw=%.6f scale=%.6f",
        _fmt_tuple(diagnostics["translation"]),
        float(diagnostics["rotation_yaw"]),
        float(diagnostics["scale"]),
    )
    Logger.info(
        "[GeometryShadow] trophy_miss local_aabb min=%s max=%s world_aabb min=%s max=%s",
        _fmt_tuple(diagnostics["local_aabb_min"]),
        _fmt_tuple(diagnostics["local_aabb_max"]),
        _fmt_tuple(diagnostics["world_aabb_min"]),
        _fmt_tuple(diagnostics["world_aabb_max"]),
    )
    Logger.info(
        "[GeometryShadow] trophy_miss ray world_start=%s world_end=%s local_start=%s local_end=%s",
        _fmt_tuple(diagnostics["world_start"]),
        _fmt_tuple(diagnostics["world_end"]),
        _fmt_tuple(diagnostics["local_start"]),
        _fmt_tuple(diagnostics["local_end"]),
    )
    Logger.info(
        "[GeometryShadow] trophy_miss query world_aabb_intersected=%s local_aabb_intersected=%s "
        "triangle_tests_executed=%s triangle_tests=%s nearest_hit_distance=%s nearest_miss_distance=%s "
        "segment_to_world_aabb_distance=%s",
        "true" if diagnostics["world_aabb_intersected"] else "false",
        "true" if diagnostics["local_aabb_intersected"] else "false",
        "true" if int(diagnostics["triangle_tests"]) > 0 else "false",
        int(diagnostics["triangle_tests"]),
        "none" if diagnostics["nearest_hit_distance"] is None else f"{float(diagnostics['nearest_hit_distance']):.4f}",
        "none" if diagnostics["nearest_miss_distance"] is None else f"{float(diagnostics['nearest_miss_distance']):.4f}",
        f"{float(diagnostics['segment_to_world_aabb_distance']):.4f}",
    )
    Logger.info(
        "[GeometryShadow] trophy_miss bvh nearest_node_entry=%s nearest_node_min=%s nearest_node_max=%s",
        "none" if diagnostics["nearest_node_entry"] is None else f"{float(diagnostics['nearest_node_entry']):.4f}",
        "none" if diagnostics["nearest_node_min"] is None else _fmt_tuple(diagnostics["nearest_node_min"]),
        "none" if diagnostics["nearest_node_max"] is None else _fmt_tuple(diagnostics["nearest_node_max"]),
    )
    Logger.info(
        "[GeometryShadow] trophy_miss bvh_result stop_reason=%s root_intersected=%s root_entry=%s root_exit=%s",
        str(diagnostics["bvh_stop_reason"]),
        "true" if bool(diagnostics["bvh_root_intersected"]) else "false",
        (
            "none"
            if diagnostics["bvh_root_entry_fraction"] is None
            else f"{float(diagnostics['bvh_root_entry_fraction']):.4f}"
        ),
        (
            "none"
            if diagnostics["bvh_root_exit_fraction"] is None
            else f"{float(diagnostics['bvh_root_exit_fraction']):.4f}"
        ),
    )
    for index, event in enumerate(list(diagnostics["bvh_events"])):
        Logger.info(
            "[GeometryShadow] trophy_miss bvh_trace step=%s reason=%s node_index=%s child_a=%s child_b=%s "
            "node_min=%s node_max=%s entry=%s exit=%s leaf=%s first_triangle=%s triangle_count=%s",
            int(index),
            str(event["reason"]),
            int(event["node_index"]),
            "none" if event["child_left_index"] is None else int(event["child_left_index"]),
            "none" if event["child_right_index"] is None else int(event["child_right_index"]),
            _fmt_tuple(tuple(float(v) for v in event["node_min"])),
            _fmt_tuple(tuple(float(v) for v in event["node_max"])),
            "none" if event["entry_fraction"] is None else f"{float(event['entry_fraction']):.4f}",
            "none" if event["exit_fraction"] is None else f"{float(event['exit_fraction']):.4f}",
            "true" if bool(event["leaf"]) else "false",
            "none" if event["first_triangle"] is None else int(event["first_triangle"]),
            int(event["triangle_count"]),
        )


def _manual_trophy_miss_diagnostics_trigger(
    comparison: GeometryShadowComparison,
    *,
    enabled: bool,
) -> dict[str, object]:
    from server.modules.handlers.world.collision.geometry.manual_mesh_registry import get_manual_mesh_spec

    collision = comparison.old_collision
    entry = int(getattr(collision, "entry", 0) or 0)
    display_id = int(getattr(collision, "display_id", 0) or 0)
    guid = int(getattr(collision, "guid", 0) or 0)
    manual_spec = None if display_id <= 0 else get_manual_mesh_spec(display_id)
    manual_mesh_name = None if manual_spec is None else str(getattr(manual_spec, "mesh_name", "") or "") or None
    state = {
        "enabled": bool(enabled),
        "old_hit": bool(comparison.old_hit),
        "new_hit": bool(comparison.new_hit),
        "guid": guid,
        "entry": entry,
        "display_id": display_id,
        "manual_mesh_name": manual_mesh_name,
        "comparison_new_mesh_name": str(comparison.new_mesh_name or "") or None,
        "has_old_collision": collision is not None,
        "entry_matches": entry == 179881,
        "display_id_matches": display_id == 5951,
        "manual_mesh_matches": manual_mesh_name == "manual_onyxia_trophy_5951",
    }
    state["candidate"] = bool(
        state["old_hit"]
        or state["has_old_collision"]
        or state["entry_matches"]
        or state["display_id_matches"]
    )
    reason = "ok"
    if not state["enabled"]:
        reason = "debug_disabled"
    elif not state["has_old_collision"]:
        reason = "missing_old_collision"
    elif not state["old_hit"]:
        reason = "old_hit_false"
    elif state["new_hit"]:
        reason = "new_hit_true"
    elif not state["entry_matches"]:
        reason = "entry_mismatch"
    elif not state["display_id_matches"]:
        reason = "display_id_mismatch"
    elif not state["manual_mesh_matches"]:
        reason = "registry_mismatch"
    state["should_log"] = bool(
        state["enabled"]
        and state["has_old_collision"]
        and state["old_hit"]
        and (not state["new_hit"])
        and state["entry_matches"]
        and state["display_id_matches"]
        and state["manual_mesh_matches"]
    )
    state["reason"] = "ok" if state["should_log"] else reason
    return state


def _build_manual_trophy_miss_diagnostics(
    collision: GameObjectCollision,
    start: tuple[float, float, float],
    end: tuple[float, float, float],
) -> dict[str, object] | None:
    from server.modules.handlers.world.collision.geometry import MeshAccelerator, Vec3, WorldMeshInstance
    from server.modules.handlers.world.collision.geometry.intersections import intersect_segment_aabb
    from server.modules.handlers.world.collision.geometry.manual_mesh_registry import load_manual_mesh_for_display

    mesh = load_manual_mesh_for_display(int(collision.display_id or 0))
    transform = _manual_mesh_transform_for_collision(collision)
    if mesh is None or transform is None:
        return None

    accelerator = MeshAccelerator(mesh)
    instance = WorldMeshInstance(
        provider=accelerator,
        transform=transform,
        name=str(collision.name or f"go:{int(collision.entry)}"),
        instance_id=int(collision.guid),
    )
    world_min, world_max = _world_aabb_for_instance(instance)
    world_start = Vec3(float(start[0]), float(start[1]), float(start[2]))
    world_end = Vec3(float(end[0]), float(end[1]), float(end[2]))
    local_start = transform.world_to_local_position(world_start)
    local_end = transform.world_to_local_position(world_end)
    world_aabb_hit = intersect_segment_aabb(world_start, world_end, world_min, world_max)
    local_aabb_hit = intersect_segment_aabb(local_start, local_end, mesh.aabb_min, mesh.aabb_max)
    bvh_diag = _diagnose_manual_mesh_bvh(accelerator, local_start, local_end)
    segment_to_world_aabb_distance = _approx_segment_to_aabb_distance(world_start, world_end, world_min, world_max)
    return {
        "mesh_name": str(mesh.name or "manual_onyxia_trophy_5951"),
        "segment_length": float((world_end - world_start).length()),
        "legacy_center": tuple(float(v) for v in collision.bounds.center),
        "legacy_extents": tuple(float(v) for v in collision.bounds.half_extents),
        "legacy_yaw": float(collision.bounds.orientation),
        "translation": (float(transform.translation.x), float(transform.translation.y), float(transform.translation.z)),
        "rotation_yaw": float(transform.rotation_yaw),
        "scale": float(transform.scale),
        "local_aabb_min": (float(mesh.aabb_min.x), float(mesh.aabb_min.y), float(mesh.aabb_min.z)),
        "local_aabb_max": (float(mesh.aabb_max.x), float(mesh.aabb_max.y), float(mesh.aabb_max.z)),
        "world_aabb_min": (float(world_min.x), float(world_min.y), float(world_min.z)),
        "world_aabb_max": (float(world_max.x), float(world_max.y), float(world_max.z)),
        "world_start": (float(world_start.x), float(world_start.y), float(world_start.z)),
        "world_end": (float(world_end.x), float(world_end.y), float(world_end.z)),
        "local_start": (float(local_start.x), float(local_start.y), float(local_start.z)),
        "local_end": (float(local_end.x), float(local_end.y), float(local_end.z)),
        "world_aabb_intersected": bool(world_aabb_hit is not None),
        "local_aabb_intersected": bool(local_aabb_hit is not None),
        "triangle_tests": int(bvh_diag["triangle_tests"]),
        "nearest_hit_distance": bvh_diag["nearest_hit_distance"],
        "nearest_miss_distance": float(segment_to_world_aabb_distance),
        "segment_to_world_aabb_distance": float(segment_to_world_aabb_distance),
        "nearest_node_entry": bvh_diag["nearest_node_entry"],
        "nearest_node_min": bvh_diag["nearest_node_min"],
        "nearest_node_max": bvh_diag["nearest_node_max"],
        "bvh_stop_reason": str(bvh_diag["stop_reason"]),
        "bvh_root_intersected": bool(bvh_diag["root_intersected"]),
        "bvh_root_entry_fraction": bvh_diag["root_entry_fraction"],
        "bvh_root_exit_fraction": bvh_diag["root_exit_fraction"],
        "bvh_events": list(bvh_diag["events"]),
    }


def _diagnose_manual_mesh_bvh(accelerator, start_local, end_local) -> dict[str, object]:
    from server.modules.handlers.world.collision.geometry.bvh import BVHNode
    from server.modules.handlers.world.collision.geometry.intersections import (
        intersect_segment_aabb,
        intersect_segment_triangle,
    )

    root = getattr(getattr(accelerator, "bvh", None), "root", None)
    mesh = getattr(accelerator, "mesh", None)
    if root is None or mesh is None:
        return {
            "triangle_tests": 0,
            "nearest_hit_distance": None,
            "nearest_node_entry": None,
            "nearest_node_min": None,
            "nearest_node_max": None,
            "stop_reason": "root_miss",
            "root_intersected": False,
            "root_entry_fraction": None,
            "root_exit_fraction": None,
            "events": [],
        }

    node_indices: dict[int, int] = {}

    def _index_nodes(node: BVHNode | None) -> None:
        if node is None:
            return
        key = id(node)
        if key in node_indices:
            return
        node_indices[key] = len(node_indices)
        _index_nodes(node.left)
        _index_nodes(node.right)

    _index_nodes(root)

    root_hit = intersect_segment_aabb(start_local, end_local, root.minimum, root.maximum)
    if root_hit is None:
        return {
            "triangle_tests": 0,
            "nearest_hit_distance": None,
            "nearest_node_entry": None,
            "nearest_node_min": None,
            "nearest_node_max": None,
            "stop_reason": "root_miss",
            "root_intersected": False,
            "root_entry_fraction": None,
            "root_exit_fraction": None,
            "events": [
                {
                    "reason": "root_miss",
                    "node_index": int(node_indices.get(id(root), 0)),
                    "child_left_index": (
                        None if root.left is None else int(node_indices.get(id(root.left), -1))
                    ),
                    "child_right_index": (
                        None if root.right is None else int(node_indices.get(id(root.right), -1))
                    ),
                    "node_min": (float(root.minimum.x), float(root.minimum.y), float(root.minimum.z)),
                    "node_max": (float(root.maximum.x), float(root.maximum.y), float(root.maximum.z)),
                    "entry_fraction": None,
                    "exit_fraction": None,
                    "leaf": bool(root.is_leaf),
                    "first_triangle": (
                        None if not root.triangle_indices else int(root.triangle_indices[0])
                    ),
                    "triangle_count": int(len(root.triangle_indices)),
                }
            ],
        }

    best_hit_distance = None
    nearest_node_entry = None
    nearest_node_min = None
    nearest_node_max = None
    triangle_tests = 0
    stop_reason = "traversal_finished"
    events: list[dict[str, object]] = []
    stack: list[tuple[BVHNode, float]] = [(root, float(root_hit.entry_fraction))]

    while stack:
        node, node_entry = stack.pop()
        if nearest_node_entry is None or float(node_entry) < float(nearest_node_entry):
            nearest_node_entry = float(node_entry)
            nearest_node_min = (float(node.minimum.x), float(node.minimum.y), float(node.minimum.z))
            nearest_node_max = (float(node.maximum.x), float(node.maximum.y), float(node.maximum.z))
        current_hit = intersect_segment_aabb(start_local, end_local, node.minimum, node.maximum)
        entry_fraction = None if current_hit is None else float(current_hit.entry_fraction)
        exit_fraction = None if current_hit is None else float(current_hit.exit_fraction)
        node_index = int(node_indices.get(id(node), -1))
        left_index = None if node.left is None else int(node_indices.get(id(node.left), -1))
        right_index = None if node.right is None else int(node_indices.get(id(node.right), -1))
        first_triangle = None if not node.triangle_indices else int(node.triangle_indices[0])
        if node.is_leaf:
            if not node.triangle_indices:
                stop_reason = "empty_leaf"
                events.append(
                    {
                        "reason": "empty_leaf",
                        "node_index": node_index,
                        "child_left_index": left_index,
                        "child_right_index": right_index,
                        "node_min": (float(node.minimum.x), float(node.minimum.y), float(node.minimum.z)),
                        "node_max": (float(node.maximum.x), float(node.maximum.y), float(node.maximum.z)),
                        "entry_fraction": entry_fraction,
                        "exit_fraction": exit_fraction,
                        "leaf": True,
                        "first_triangle": first_triangle,
                        "triangle_count": 0,
                    }
                )
                continue
            events.append(
                {
                    "reason": "triangle_loop_entered",
                    "node_index": node_index,
                    "child_left_index": left_index,
                    "child_right_index": right_index,
                    "node_min": (float(node.minimum.x), float(node.minimum.y), float(node.minimum.z)),
                    "node_max": (float(node.maximum.x), float(node.maximum.y), float(node.maximum.z)),
                    "entry_fraction": entry_fraction,
                    "exit_fraction": exit_fraction,
                    "leaf": True,
                    "first_triangle": first_triangle,
                    "triangle_count": int(len(node.triangle_indices)),
                }
            )
            stop_reason = "triangle_loop_entered"
            for triangle_index in node.triangle_indices:
                triangle_tests += 1
                if triangle_index < 0 or triangle_index >= len(mesh.triangles):
                    stop_reason = "invalid_leaf"
                    events.append(
                        {
                            "reason": "invalid_leaf",
                            "node_index": node_index,
                            "child_left_index": left_index,
                            "child_right_index": right_index,
                            "node_min": (float(node.minimum.x), float(node.minimum.y), float(node.minimum.z)),
                            "node_max": (float(node.maximum.x), float(node.maximum.y), float(node.maximum.z)),
                            "entry_fraction": entry_fraction,
                            "exit_fraction": exit_fraction,
                            "leaf": True,
                            "first_triangle": first_triangle,
                            "triangle_count": int(len(node.triangle_indices)),
                        }
                    )
                    continue
                ia, ib, ic = mesh.triangles[triangle_index]
                hit = intersect_segment_triangle(
                    start_local,
                    end_local,
                    mesh.vertices[ia],
                    mesh.vertices[ib],
                    mesh.vertices[ic],
                    triangle_index=triangle_index,
                )
                if hit is None:
                    continue
                if best_hit_distance is None or float(hit.distance) < float(best_hit_distance):
                    best_hit_distance = float(hit.distance)
            continue

        child_entries: list[tuple[float, BVHNode]] = []
        child_results: list[tuple[str, BVHNode | None, object | None]] = []
        for child in (node.left, node.right):
            if child is None:
                child_results.append(("missing", None, None))
                continue
            child_hit = intersect_segment_aabb(start_local, end_local, child.minimum, child.maximum)
            child_results.append(("hit" if child_hit is not None else "miss", child, child_hit))
            if child_hit is None:
                continue
            child_entries.append((float(child_hit.entry_fraction), child))
        child_reason = "traversal_finished"
        if node.left is not None and node.right is not None:
            left_result = next((item for item in child_results if item[1] is node.left), None)
            right_result = next((item for item in child_results if item[1] is node.right), None)
            left_miss = left_result is not None and left_result[0] == "miss"
            right_miss = right_result is not None and right_result[0] == "miss"
            if left_miss and right_miss:
                child_reason = "traversal_finished"
            elif left_miss:
                child_reason = "child_a_miss"
            elif right_miss:
                child_reason = "child_b_miss"
        elif node.left is not None and not child_entries:
            child_reason = "child_a_miss"
        elif node.right is not None and not child_entries:
            child_reason = "child_b_miss"
        events.append(
            {
                "reason": child_reason if child_entries else "traversal_finished",
                "node_index": node_index,
                "child_left_index": left_index,
                "child_right_index": right_index,
                "node_min": (float(node.minimum.x), float(node.minimum.y), float(node.minimum.z)),
                "node_max": (float(node.maximum.x), float(node.maximum.y), float(node.maximum.z)),
                "entry_fraction": entry_fraction,
                "exit_fraction": exit_fraction,
                "leaf": False,
                "first_triangle": first_triangle,
                "triangle_count": int(len(node.triangle_indices)),
            }
        )
        child_entries.sort(key=lambda item: item[0], reverse=True)
        for child_entry, child in child_entries:
            stack.append((child, child_entry))
        if not child_entries:
            stop_reason = "traversal_finished"

    return {
        "triangle_tests": int(triangle_tests),
        "nearest_hit_distance": best_hit_distance,
        "nearest_node_entry": nearest_node_entry,
        "nearest_node_min": nearest_node_min,
        "nearest_node_max": nearest_node_max,
        "stop_reason": stop_reason if triangle_tests <= 0 else "triangle_loop_entered",
        "root_intersected": True,
        "root_entry_fraction": float(root_hit.entry_fraction),
        "root_exit_fraction": float(root_hit.exit_fraction),
        "events": events,
    }


def _world_aabb_for_instance(instance) -> tuple[object, object]:
    from server.modules.handlers.world.collision.geometry import Vec3

    mesh = instance.mesh
    corners = [
        instance.local_to_world(Vec3(x, y, z))
        for x in (mesh.aabb_min.x, mesh.aabb_max.x)
        for y in (mesh.aabb_min.y, mesh.aabb_max.y)
        for z in (mesh.aabb_min.z, mesh.aabb_max.z)
    ]
    minimum = Vec3(
        min(point.x for point in corners),
        min(point.y for point in corners),
        min(point.z for point in corners),
    )
    maximum = Vec3(
        max(point.x for point in corners),
        max(point.y for point in corners),
        max(point.z for point in corners),
    )
    return minimum, maximum


def _approx_segment_to_aabb_distance(start, end, minimum, maximum, *, samples: int = 33) -> float:
    if _point_to_aabb_distance(start, minimum, maximum) <= 1e-9 or _point_to_aabb_distance(end, minimum, maximum) <= 1e-9:
        return 0.0
    best = math.inf
    segment = end - start
    for index in range(max(2, int(samples))):
        t = float(index) / float(max(1, int(samples) - 1))
        point = start + (segment * t)
        best = min(best, _point_to_aabb_distance(point, minimum, maximum))
        if best <= 1e-9:
            return 0.0
    return float(best)


def _point_to_aabb_distance(point, minimum, maximum) -> float:
    dx = max(float(minimum.x) - float(point.x), 0.0, float(point.x) - float(maximum.x))
    dy = max(float(minimum.y) - float(point.y), 0.0, float(point.y) - float(maximum.y))
    dz = max(float(minimum.z) - float(point.z), 0.0, float(point.z) - float(maximum.z))
    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz))


def _fmt_tuple(values: tuple[float, float, float]) -> str:
    return "(%.3f %.3f %.3f)" % (float(values[0]), float(values[1]), float(values[2]))


def _get_or_build_shadow_world():
    global _world_cache, _world_cache_signature
    from server.modules.handlers.world.collision import gameobject_collision_index
    from server.modules.handlers.world.collision.geometry import WorldGeometryMap

    objects = list(getattr(gameobject_collision_index, "_objects", ()) or ())
    signature = _index_signature(objects)
    if _world_cache is not None and signature == _world_cache_signature:
        Logger.info("[GeometryShadow] world_geometry cache=hit objects=%s", int(len(objects)))
        return _world_cache
    Logger.info("[GeometryShadow] world_geometry cache=miss objects=%s", int(len(objects)))
    world = WorldGeometryMap()
    if not objects:
        Logger.info("[GeometryShadow] skipped reason=no_world_geometry")
    for collision in objects:
        world.add_instance(_collision_to_world_instance(collision))
    _world_cache = world
    _world_cache_signature = signature
    Logger.info("[GeometryShadow] world_geometry ready instances=%s", int(len(world.instances)))
    return world


def _index_signature(objects: list[GameObjectCollision]) -> tuple[int, int, int, int]:
    if not objects:
        return (0, 0, 0, 0)
    return (
        int(len(objects)),
        int(objects[0].guid),
        int(objects[-1].guid),
        int(sum(int(c.guid) for c in objects[:8]) % 2147483647),
    )


def _collision_to_world_instance(collision: GameObjectCollision):
    from server.modules.handlers.world.collision.geometry import MeshAccelerator, Transform, WorldMeshInstance
    from server.modules.handlers.world.collision.geometry.manual_mesh_registry import (
        get_manual_mesh_spec,
        load_manual_mesh_for_display,
    )

    display_id = int(collision.display_id or 0)
    manual_spec = get_manual_mesh_spec(display_id)
    manual_mesh = None
    transform = None
    if manual_spec is not None:
        manual_mesh = load_manual_mesh_for_display(display_id)
        transform = _manual_mesh_transform_for_collision(collision)
        if manual_mesh is not None and transform is not None:
            marker = (int(collision.guid), display_id)
            if marker not in _manual_mesh_logged:
                _manual_mesh_logged.add(marker)
                Logger.info(
                    "[GeometryShadow] using manual mesh displayId=%s mesh=%s guid=%s entry=%s",
                    display_id,
                    manual_spec.mesh_name,
                    int(collision.guid),
                    int(collision.entry),
                )
    mesh = manual_mesh if manual_mesh is not None and transform is not None else _box_mesh_for_half_extents(collision.bounds.half_extents)
    if transform is None:
        transform = Transform(
            translation=_tuple_to_vec3(collision.bounds.center),
            rotation_yaw=float(collision.bounds.orientation),
            scale=1.0,
        )
    return WorldMeshInstance(
        provider=MeshAccelerator(mesh),
        transform=transform,
        name=str(collision.name or f"go:{int(collision.entry)}"),
        instance_id=int(collision.guid),
    )


def _manual_mesh_transform_for_collision(collision: GameObjectCollision):
    from server.modules.handlers.world.collision.bounds import DisplayBounds
    from server.modules.handlers.world.collision.geometry import Transform

    display_bounds = _shadow_display_bounds_by_display().get(int(collision.display_id or 0))
    if not isinstance(display_bounds, DisplayBounds) or not display_bounds.valid():
        return None
    scale = _derive_uniform_scale(display_bounds, collision.bounds.half_extents)
    if scale is None:
        return None
    local_center = tuple(
        (float(display_bounds.minimum[index]) + float(display_bounds.maximum[index])) * 0.5
        for index in range(3)
    )
    origin = collision.bounds.world_point(
        (
            -local_center[0] * scale,
            -local_center[1] * scale,
            -local_center[2] * scale,
        )
    )
    return Transform(
        translation=_tuple_to_vec3(origin),
        rotation_yaw=float(collision.bounds.orientation),
        scale=float(scale),
    )


def _derive_uniform_scale(display_bounds, half_extents: tuple[float, float, float]) -> float | None:
    display_half_extents = tuple(
        (float(display_bounds.maximum[index]) - float(display_bounds.minimum[index])) * 0.5
        for index in range(3)
    )
    ratios = [
        float(half_extents[index]) / float(display_half_extents[index])
        for index in range(3)
        if float(display_half_extents[index]) > 1e-9
    ]
    if not ratios:
        return None
    return float(sum(ratios) / len(ratios))


def _shadow_display_bounds_by_display() -> dict[int, object]:
    global _display_bounds_cache
    if _display_bounds_cache is None:
        from server.modules.handlers.world.collision.gameobject_collision import load_display_bounds

        _display_bounds_cache = load_display_bounds()
    return _display_bounds_cache


def _box_mesh_for_half_extents(half_extents: tuple[float, float, float]):
    from server.modules.handlers.world.collision.geometry import TriangleMesh, Vec3

    key = tuple(round(float(value), 6) for value in half_extents)
    cached = _mesh_cache.get(key)
    if cached is not None:
        return cached
    hx, hy, hz = (float(half_extents[0]), float(half_extents[1]), float(half_extents[2]))
    vertices = [
        Vec3(-hx, -hy, -hz),
        Vec3(hx, -hy, -hz),
        Vec3(hx, hy, -hz),
        Vec3(-hx, hy, -hz),
        Vec3(-hx, -hy, hz),
        Vec3(hx, -hy, hz),
        Vec3(hx, hy, hz),
        Vec3(-hx, hy, hz),
    ]
    triangles = [
        (0, 1, 2), (0, 2, 3),
        (4, 6, 5), (4, 7, 6),
        (0, 4, 5), (0, 5, 1),
        (1, 5, 6), (1, 6, 2),
        (2, 6, 7), (2, 7, 3),
        (3, 7, 4), (3, 4, 0),
    ]
    mesh = TriangleMesh.from_vertices(vertices, triangles, name=f"obb_{key[0]:.3f}_{key[1]:.3f}_{key[2]:.3f}")
    _mesh_cache[key] = mesh
    return mesh


def _tuple_to_vec3(values: tuple[float, float, float]):
    from server.modules.handlers.world.collision.geometry import Vec3

    return Vec3(float(values[0]), float(values[1]), float(values[2]))
