from __future__ import annotations

from abc import ABC, abstractmethod

from .raycast import GeometryHit
from .vector import Vec3


class GeometryProvider(ABC):
    @abstractmethod
    def raycast_segment(self, start: Vec3, end: Vec3) -> GeometryHit | None:
        raise NotImplementedError
