from __future__ import annotations

from dataclasses import dataclass, field

from .bvh import MeshBVH
from .mesh import TriangleMesh
from .provider import GeometryProvider
from .raycast import GeometryHit
from .vector import Vec3


@dataclass(frozen=True)
class MeshAccelerator(GeometryProvider):
    mesh: TriangleMesh
    leaf_size: int = 4
    bvh: MeshBVH = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "bvh", MeshBVH.build(self.mesh, leaf_size=self.leaf_size))

    def raycast_segment(self, start: Vec3, end: Vec3) -> GeometryHit | None:
        return self.bvh.raycast_segment(start, end)
