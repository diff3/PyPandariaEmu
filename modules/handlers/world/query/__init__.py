"""Public world-query boundary for gameplay systems."""

from .service import WorldQuery
from .types import CollisionQueryResult, WorldPoint

__all__ = ["CollisionQueryResult", "WorldPoint", "WorldQuery"]

