from __future__ import annotations

from dataclasses import dataclass

from .intersections import intersect_segment_aabb, intersect_segment_triangle
from .provider import GeometryProvider
from .raycast import GeometryHit, nearest_raycast_hit
from .vector import Vec3


@dataclass(frozen=True)
class TriangleMesh(GeometryProvider):
    vertices: tuple[Vec3, ...]
    triangles: tuple[tuple[int, int, int], ...]
    aabb_min: Vec3
    aabb_max: Vec3
    name: str = ""
    model_id: int | None = None

    @classmethod
    def from_vertices(
        cls,
        vertices: list[Vec3] | tuple[Vec3, ...],
        triangles: list[tuple[int, int, int]] | tuple[tuple[int, int, int], ...],
        *,
        name: str = "",
        model_id: int | None = None,
    ) -> "TriangleMesh":
        vertex_tuple = tuple(vertices)
        triangle_tuple = tuple(triangles)
        if not vertex_tuple:
            zero = Vec3(0.0, 0.0, 0.0)
            return cls(vertex_tuple, triangle_tuple, zero, zero, name=name, model_id=model_id)

        minimum = vertex_tuple[0]
        maximum = vertex_tuple[0]
        for vertex in vertex_tuple[1:]:
            minimum = minimum.min_components(vertex)
            maximum = maximum.max_components(vertex)
        return cls(vertex_tuple, triangle_tuple, minimum, maximum, name=name, model_id=model_id)

    def raycast_segment(self, start: Vec3, end: Vec3) -> GeometryHit | None:
        if intersect_segment_aabb(start, end, self.aabb_min, self.aabb_max) is None:
            return None

        hits: list[GeometryHit] = []
        for index, (ia, ib, ic) in enumerate(self.triangles):
            hit = intersect_segment_triangle(
                start,
                end,
                self.vertices[ia],
                self.vertices[ib],
                self.vertices[ic],
                triangle_index=index,
            )
            if hit is not None:
                hits.append(
                    GeometryHit(
                        fraction=hit.fraction,
                        distance=hit.distance,
                        position=hit.position,
                        normal=hit.normal,
                        triangle_index=hit.triangle_index,
                        mesh=self,
                        instance=None,
                    )
                )
        return nearest_raycast_hit(hits)
