from __future__ import annotations

from dataclasses import dataclass

from .intersections import intersect_segment_aabb, intersect_segment_triangle
from .mesh import TriangleMesh
from .raycast import GeometryHit
from .vector import Vec3


@dataclass(frozen=True)
class BVHNode:
    minimum: Vec3
    maximum: Vec3
    left: "BVHNode | None" = None
    right: "BVHNode | None" = None
    triangle_indices: tuple[int, ...] = ()

    @property
    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


@dataclass(frozen=True)
class MeshBVH:
    mesh: TriangleMesh
    root: BVHNode | None
    leaf_size: int = 4

    @classmethod
    def build(cls, mesh: TriangleMesh, *, leaf_size: int = 4) -> "MeshBVH":
        triangle_indices = tuple(range(len(mesh.triangles)))
        root = _build_node(mesh, triangle_indices, max(1, int(leaf_size)))
        return cls(mesh=mesh, root=root, leaf_size=max(1, int(leaf_size)))

    def raycast_segment(self, start: Vec3, end: Vec3) -> GeometryHit | None:
        if self.root is None:
            return None

        best_hit: GeometryHit | None = None
        stack: list[tuple[BVHNode, float]] = [(self.root, 0.0)]

        while stack:
            node, node_entry = stack.pop()
            if best_hit is not None and node_entry > float(best_hit.fraction):
                continue

            if node.is_leaf:
                for triangle_index in node.triangle_indices:
                    ia, ib, ic = self.mesh.triangles[triangle_index]
                    hit = intersect_segment_triangle(
                        start,
                        end,
                        self.mesh.vertices[ia],
                        self.mesh.vertices[ib],
                        self.mesh.vertices[ic],
                        triangle_index=triangle_index,
                    )
                    if hit is None:
                        continue
                    if best_hit is None or float(hit.fraction) < float(best_hit.fraction):
                        best_hit = GeometryHit(
                            fraction=hit.fraction,
                            distance=hit.distance,
                            position=hit.position,
                            normal=hit.normal,
                            triangle_index=hit.triangle_index,
                            mesh=self.mesh,
                            instance=None,
                        )
                continue

            child_entries: list[tuple[float, BVHNode]] = []
            for child in (node.left, node.right):
                if child is None:
                    continue
                child_hit = intersect_segment_aabb(start, end, child.minimum, child.maximum)
                if child_hit is None:
                    continue
                if best_hit is not None and float(child_hit.entry_fraction) > float(best_hit.fraction):
                    continue
                child_entries.append((float(child_hit.entry_fraction), child))

            child_entries.sort(key=lambda item: item[0], reverse=True)
            for child_entry, child in child_entries:
                stack.append((child, child_entry))

        return best_hit


def _build_node(mesh: TriangleMesh, triangle_indices: tuple[int, ...], leaf_size: int) -> BVHNode | None:
    if not triangle_indices:
        return None

    minimum, maximum = _triangle_bounds(mesh, triangle_indices)
    if len(triangle_indices) <= leaf_size:
        return BVHNode(minimum=minimum, maximum=maximum, triangle_indices=triangle_indices)

    axis = _longest_axis(minimum, maximum)
    sorted_indices = tuple(
        sorted(
            triangle_indices,
            key=lambda triangle_index: (_centroid_axis(mesh, triangle_index, axis), triangle_index),
        )
    )
    middle = len(sorted_indices) // 2
    left_indices = sorted_indices[:middle]
    right_indices = sorted_indices[middle:]

    if not left_indices or not right_indices:
        return BVHNode(minimum=minimum, maximum=maximum, triangle_indices=sorted_indices)

    return BVHNode(
        minimum=minimum,
        maximum=maximum,
        left=_build_node(mesh, left_indices, leaf_size),
        right=_build_node(mesh, right_indices, leaf_size),
        triangle_indices=(),
    )


def _triangle_bounds(mesh: TriangleMesh, triangle_indices: tuple[int, ...]) -> tuple[Vec3, Vec3]:
    first_triangle = mesh.triangles[triangle_indices[0]]
    first_vertex = mesh.vertices[first_triangle[0]]
    minimum = first_vertex
    maximum = first_vertex

    for triangle_index in triangle_indices:
        ia, ib, ic = mesh.triangles[triangle_index]
        for vertex in (mesh.vertices[ia], mesh.vertices[ib], mesh.vertices[ic]):
            minimum = minimum.min_components(vertex)
            maximum = maximum.max_components(vertex)
    return minimum, maximum


def _centroid_axis(mesh: TriangleMesh, triangle_index: int, axis: str) -> float:
    ia, ib, ic = mesh.triangles[triangle_index]
    a = mesh.vertices[ia]
    b = mesh.vertices[ib]
    c = mesh.vertices[ic]
    centroid = Vec3((a.x + b.x + c.x) / 3.0, (a.y + b.y + c.y) / 3.0, (a.z + b.z + c.z) / 3.0)
    return float(getattr(centroid, axis))


def _longest_axis(minimum: Vec3, maximum: Vec3) -> str:
    extent_x = maximum.x - minimum.x
    extent_y = maximum.y - minimum.y
    extent_z = maximum.z - minimum.z
    if extent_x >= extent_y and extent_x >= extent_z:
        return "x"
    if extent_y >= extent_z:
        return "y"
    return "z"
