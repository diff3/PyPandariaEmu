from __future__ import annotations

from dataclasses import dataclass

from .provider import GeometryProvider
from .raycast import GeometryHit
from .vector import Vec3


@dataclass(frozen=True)
class GeometryQuery:
    provider: GeometryProvider

    def raycast(self, start: Vec3, end: Vec3) -> GeometryHit | None:
        return self.provider.raycast_segment(start, end)
