from __future__ import annotations

from dataclasses import dataclass

from .raycast import GeometryHit
from .vector import Vec3
from .world_map import WorldGeometryMap

DEFAULT_CONTACT_EPSILON = 1e-5


@dataclass(frozen=True)
class MovementResult:
    hit: GeometryHit | None
    fraction: float
    start: Vec3
    requested_end: Vec3
    resolved_end: Vec3
    hit_position: Vec3 | None
    hit_normal: Vec3 | None
    remaining_distance: float
    remaining_vector: Vec3


def resolve_segment(
    start: Vec3,
    end: Vec3,
    world: WorldGeometryMap,
    *,
    contact_epsilon: float = DEFAULT_CONTACT_EPSILON,
) -> MovementResult:
    delta = end - start
    hit = world.raycast(start, end)

    if hit is None:
        return MovementResult(
            hit=None,
            fraction=1.0,
            start=start,
            requested_end=end,
            resolved_end=end,
            hit_position=None,
            hit_normal=None,
            remaining_distance=0.0,
            remaining_vector=Vec3(0.0, 0.0, 0.0),
        )

    epsilon_distance = max(DEFAULT_CONTACT_EPSILON, float(contact_epsilon))
    contact_normal = hit.normal.normalize()
    # Authored triangle winding is not guaranteed to face the mover.  Contact
    # separation must always be applied back toward the side the segment came
    # from; otherwise a valid hit can publish a point just inside the volume
    # and trap the next movement packet there.
    if contact_normal.dot(delta) > 0.0:
        contact_normal = contact_normal * -1.0
    resolved_end = hit.position + (contact_normal * epsilon_distance)
    remaining_vector = end - resolved_end

    return MovementResult(
        hit=hit,
        fraction=float(hit.fraction),
        start=start,
        requested_end=end,
        resolved_end=resolved_end,
        hit_position=hit.position,
        hit_normal=contact_normal,
        remaining_distance=remaining_vector.length(),
        remaining_vector=remaining_vector,
    )
