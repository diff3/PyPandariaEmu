from __future__ import annotations

from dataclasses import dataclass, field

from .provider import GeometryProvider
from .raycast import GeometryHit, nearest_raycast_hit
from .vector import Vec3
from .world_mesh import WorldMeshInstance


@dataclass
class WorldGeometryMap(GeometryProvider):
    instances: list[WorldMeshInstance] = field(default_factory=list)

    def add_instance(self, instance: WorldMeshInstance) -> None:
        self.instances.append(instance)

    def remove_instance(self, instance: WorldMeshInstance) -> bool:
        try:
            self.instances.remove(instance)
        except ValueError:
            return False
        return True

    def raycast(self, start: Vec3, end: Vec3) -> GeometryHit | None:
        return self.raycast_segment(start, end)

    def raycast_segment(self, start: Vec3, end: Vec3) -> GeometryHit | None:
        hits: list[GeometryHit] = []
        for instance in self.instances:
            hit = instance.raycast_segment(start, end)
            if hit is not None:
                hits.append(hit)
        return nearest_raycast_hit(hits)
