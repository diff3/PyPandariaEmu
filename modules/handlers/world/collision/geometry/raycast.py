from __future__ import annotations

from dataclasses import dataclass

from .vector import Vec3


@dataclass(frozen=True)
class GeometryHit:
    fraction: float
    distance: float
    position: Vec3
    normal: Vec3
    triangle_index: int | None = None
    mesh: object | None = None
    instance: object | None = None


def nearest_raycast_hit(hits: list[GeometryHit]) -> GeometryHit | None:
    if not hits:
        return None
    return min(hits, key=lambda hit: float(hit.fraction))
