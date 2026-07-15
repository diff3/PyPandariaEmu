"""Value types exchanged by the stateless world-query boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from server.modules.handlers.world.collision.gameobject_collision import GameObjectCollision

WorldPoint = tuple[float, float, float]


@dataclass(frozen=True)
class CollisionQueryResult:
    """Existing legacy GameObject collision answer plus query diagnostics."""

    collision: GameObjectCollision | None
    registered_objects: int

