from __future__ import annotations

from dataclasses import dataclass
import math

from .raycast import GeometryHit
from .vector import Vec3

_EPSILON = 1e-8


@dataclass(frozen=True)
class SegmentTriangleHit(GeometryHit):
    pass


@dataclass(frozen=True)
class SegmentAABBHit:
    entry_fraction: float
    exit_fraction: float


def intersect_segment_triangle(
    start: Vec3,
    end: Vec3,
    a: Vec3,
    b: Vec3,
    c: Vec3,
    *,
    triangle_index: int | None = None,
) -> SegmentTriangleHit | None:
    direction = end - start
    direction_length = direction.length()
    edge1 = b - a
    edge2 = c - a
    pvec = direction.cross(edge2)
    determinant = edge1.dot(pvec)
    scale = edge1.length() * edge2.length() * direction_length
    if scale <= 1e-30:
        return None
    if abs(determinant) <= (_EPSILON * scale):
        return None

    inv_det = 1.0 / determinant
    tvec = start - a
    u = tvec.dot(pvec) * inv_det
    if u < 0.0 or u > 1.0:
        return None

    qvec = tvec.cross(edge1)
    v = direction.dot(qvec) * inv_det
    if v < 0.0 or (u + v) > 1.0:
        return None

    t = edge2.dot(qvec) * inv_det
    if t < 0.0 or t > 1.0:
        return None

    normal = edge1.cross(edge2).normalize()
    return SegmentTriangleHit(
        fraction=float(t),
        distance=float(t) * float(direction_length),
        position=start + (direction * t),
        normal=normal,
        triangle_index=triangle_index,
    )


def intersect_segment_aabb(start: Vec3, end: Vec3, minimum: Vec3, maximum: Vec3) -> SegmentAABBHit | None:
    direction = end - start
    entry = 0.0
    exit = 1.0

    for axis in ("x", "y", "z"):
        origin = float(getattr(start, axis))
        delta = float(getattr(direction, axis))
        lower = float(getattr(minimum, axis))
        upper = float(getattr(maximum, axis))

        if abs(delta) <= _EPSILON:
            if origin < lower or origin > upper:
                return None
            continue

        first = (lower - origin) / delta
        second = (upper - origin) / delta
        if first > second:
            first, second = second, first

        entry = max(entry, first)
        exit = min(exit, second)
        if entry > exit:
            return None

    return SegmentAABBHit(entry_fraction=float(entry), exit_fraction=float(exit))
