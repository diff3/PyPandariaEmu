from __future__ import annotations

from dataclasses import dataclass

from .provider import GeometryProvider
from .raycast import GeometryHit
from .transform import Transform
from .vector import Vec3


@dataclass(frozen=True)
class WorldRaycastHit(GeometryHit):
    pass


@dataclass(frozen=True)
class WorldMeshInstance(GeometryProvider):
    provider: GeometryProvider
    transform: Transform
    name: str | None = None
    instance_id: int | None = None

    @property
    def mesh(self) -> object | None:
        return getattr(self.provider, "mesh", None)

    def local_to_world(self, point: Vec3) -> Vec3:
        return self.transform.local_to_world_position(point)

    def world_to_local(self, point: Vec3) -> Vec3:
        return self.transform.world_to_local_position(point)

    def raycast_segment(self, start_world: Vec3, end_world: Vec3) -> GeometryHit | None:
        start_local = self.transform.world_to_local_position(start_world)
        end_local = self.transform.world_to_local_position(end_world)
        hit = self.provider.raycast_segment(start_local, end_local)
        if hit is None:
            return None
        return WorldRaycastHit(
            fraction=float(hit.fraction),
            distance=float((end_world - start_world).length()) * float(hit.fraction),
            position=self.transform.local_to_world_position(hit.position),
            normal=self.transform.local_to_world_normal(hit.normal),
            triangle_index=hit.triangle_index,
            mesh=hit.mesh,
            instance=self,
        )
