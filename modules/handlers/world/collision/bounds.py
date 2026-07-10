from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class DisplayBounds:
    minimum: tuple[float, float, float]
    maximum: tuple[float, float, float]

    def valid(self) -> bool:
        values = self.minimum + self.maximum
        return all(math.isfinite(value) for value in values) and all(
            self.minimum[index] < self.maximum[index] for index in range(3)
        )


@dataclass(frozen=True)
class OrientedBounds:
    center: tuple[float, float, float]
    half_extents: tuple[float, float, float]
    orientation: float

    def _local(self, point: tuple[float, float, float]) -> tuple[float, float, float]:
        dx = float(point[0]) - self.center[0]
        dy = float(point[1]) - self.center[1]
        cosine = math.cos(self.orientation)
        sine = math.sin(self.orientation)
        return (
            (cosine * dx) + (sine * dy),
            (-sine * dx) + (cosine * dy),
            float(point[2]) - self.center[2],
        )

    def contains(self, point: tuple[float, float, float], padding: float = 0.0) -> bool:
        local = self._local(point)
        return all(
            abs(local[index]) <= self.half_extents[index] + float(padding)
            for index in range(3)
        )

    def containment_fraction(self, point: tuple[float, float, float]) -> float:
        local = self._local(point)
        fractions: list[float] = []
        for index in range(3):
            extent = float(self.half_extents[index])
            if extent <= 1e-9:
                return math.inf
            fractions.append(abs(local[index]) / extent)
        return max(fractions, default=math.inf)

    def world_point(self, local_point: tuple[float, float, float]) -> tuple[float, float, float]:
        cosine = math.cos(self.orientation)
        sine = math.sin(self.orientation)
        return (
            self.center[0] + (cosine * float(local_point[0])) - (sine * float(local_point[1])),
            self.center[1] + (sine * float(local_point[0])) + (cosine * float(local_point[1])),
            self.center[2] + float(local_point[2]),
        )

    def corners(self) -> tuple[tuple[float, float, float], ...]:
        hx, hy, hz = self.half_extents
        return tuple(
            self.world_point((sx * hx, sy * hy, sz * hz))
            for sx in (-1.0, 1.0)
            for sy in (-1.0, 1.0)
            for sz in (-1.0, 1.0)
        )

    def wireframe_points(
        self,
        *,
        target_spacing: float = 1.5,
        max_segments_per_edge: int = 8,
    ) -> tuple[tuple[float, float, float], ...]:
        hx, hy, hz = self.half_extents
        local_edges = (
            ((-hx, -hy, -hz), (hx, -hy, -hz)),
            ((-hx, hy, -hz), (hx, hy, -hz)),
            ((-hx, -hy, hz), (hx, -hy, hz)),
            ((-hx, hy, hz), (hx, hy, hz)),
            ((-hx, -hy, -hz), (-hx, hy, -hz)),
            ((hx, -hy, -hz), (hx, hy, -hz)),
            ((-hx, -hy, hz), (-hx, hy, hz)),
            ((hx, -hy, hz), (hx, hy, hz)),
            ((-hx, -hy, -hz), (-hx, -hy, hz)),
            ((hx, -hy, -hz), (hx, -hy, hz)),
            ((-hx, hy, -hz), (-hx, hy, hz)),
            ((hx, hy, -hz), (hx, hy, hz)),
        )
        unique: dict[tuple[float, float, float], tuple[float, float, float]] = {}
        spacing = max(0.25, float(target_spacing))
        max_segments = max(1, int(max_segments_per_edge))
        for start, end in local_edges:
            dx = float(end[0]) - float(start[0])
            dy = float(end[1]) - float(start[1])
            dz = float(end[2]) - float(start[2])
            edge_length = math.sqrt((dx * dx) + (dy * dy) + (dz * dz))
            segments = min(max_segments, max(1, int(math.ceil(edge_length / spacing))))
            for index in range(segments + 1):
                t = float(index) / float(segments)
                local_point = (
                    float(start[0]) + (dx * t),
                    float(start[1]) + (dy * t),
                    float(start[2]) + (dz * t),
                )
                point = self.world_point(local_point)
                key = tuple(round(float(value), 6) for value in point)
                unique.setdefault(key, point)
        return tuple(unique.values())

    def intersects_segment(
        self,
        start: tuple[float, float, float],
        end: tuple[float, float, float],
    ) -> bool:
        """Slab-test a world-space segment after rotating it into box space."""
        local_start = self._local(start)
        local_end = self._local(end)
        t_min, t_max = 0.0, 1.0
        for axis in range(3):
            delta = local_end[axis] - local_start[axis]
            extent = self.half_extents[axis]
            if abs(delta) < 1e-9:
                if abs(local_start[axis]) > extent:
                    return False
                continue
            first = (-extent - local_start[axis]) / delta
            second = (extent - local_start[axis]) / delta
            if first > second:
                first, second = second, first
            t_min = max(t_min, first)
            t_max = min(t_max, second)
            if t_min > t_max:
                return False
        return True

    def segment_intersection_fraction(
        self,
        start: tuple[float, float, float],
        end: tuple[float, float, float],
    ) -> float | None:
        """Return first segment fraction entering the box, or None on miss."""
        local_start = self._local(start)
        local_end = self._local(end)
        t_min, t_max = 0.0, 1.0
        for axis in range(3):
            delta = local_end[axis] - local_start[axis]
            extent = self.half_extents[axis]
            if abs(delta) < 1e-9:
                if abs(local_start[axis]) > extent:
                    return None
                continue
            first = (-extent - local_start[axis]) / delta
            second = (extent - local_start[axis]) / delta
            if first > second:
                first, second = second, first
            t_min = max(t_min, first)
            t_max = min(t_max, second)
            if t_min > t_max:
                return None
        return float(t_min)

    def world_aabb(self) -> tuple[float, float, float, float]:
        hx, hy, _ = self.half_extents
        cosine, sine = abs(math.cos(self.orientation)), abs(math.sin(self.orientation))
        world_hx = (cosine * hx) + (sine * hy)
        world_hy = (sine * hx) + (cosine * hy)
        return (
            self.center[0] - world_hx,
            self.center[1] - world_hy,
            self.center[0] + world_hx,
            self.center[1] + world_hy,
        )


def build_oriented_bounds(
    bounds: DisplayBounds,
    *,
    position: tuple[float, float, float],
    orientation: float,
    scale: float,
) -> OrientedBounds | None:
    if not bounds.valid() or not math.isfinite(scale) or scale <= 0.0:
        return None
    local_center = tuple(
        (bounds.minimum[index] + bounds.maximum[index]) * 0.5 * scale
        for index in range(3)
    )
    half_extents = tuple(
        (bounds.maximum[index] - bounds.minimum[index]) * 0.5 * scale
        for index in range(3)
    )
    cosine, sine = math.cos(orientation), math.sin(orientation)
    center = (
        float(position[0]) + (cosine * local_center[0]) - (sine * local_center[1]),
        float(position[1]) + (sine * local_center[0]) + (cosine * local_center[1]),
        float(position[2]) + local_center[2],
    )
    return OrientedBounds(center, half_extents, float(orientation))
