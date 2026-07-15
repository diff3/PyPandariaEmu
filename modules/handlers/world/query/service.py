"""Canonical, stateless entry point for world geometry queries.

WorldQuery owns geometry questions and delegates to the existing backends.  It
does not own gameplay decisions: movement decides whether a hit rejects a
packet, teleports decide whether to correct a destination, and transports own
passenger attachment.

This first migration intentionally exposes only the collision queries already
used by gameplay.  Terrain, liquid, line-of-sight, and navigation backends will
join this boundary when those existing systems are migrated; this module must
not invent fallback geometry or change their behavior in advance.

No method accepts or reads WorldSession.  All query inputs are explicit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .types import CollisionQueryResult, WorldPoint

if TYPE_CHECKING:
    from server.modules.handlers.world.collision.gameobject_collision import GameObjectCollision
    from server.modules.handlers.world.collision.geometry_shadow import GeometryShadowComparison


class WorldQuery:
    """Namespace for stateless world geometry queries."""

    @staticmethod
    def registered_collision_objects() -> int:
        from server.modules.handlers.world.collision import gameobject_collision_index

        return len(gameobject_collision_index)

    @staticmethod
    def query_collision(
        *,
        map_id: int,
        start: WorldPoint,
        end: WorldPoint,
    ) -> CollisionQueryResult:
        from server.modules.handlers.world.collision import gameobject_collision_index

        collision = gameobject_collision_index.blocked(
            int(map_id),
            tuple(float(value) for value in start),
            tuple(float(value) for value in end),
        )
        return CollisionQueryResult(
            collision=collision,
            registered_objects=len(gameobject_collision_index),
        )

    @staticmethod
    def query_geometry_shadow(
        *,
        player_guid: int,
        opcode_name: str,
        map_id: int,
        start: WorldPoint,
        end: WorldPoint,
        legacy_collision: GameObjectCollision | None,
        legacy_resolved_end: WorldPoint,
        authoritative_mode: str,
    ) -> GeometryShadowComparison:
        from server.modules.handlers.world.collision.geometry_shadow import (
            run_geometry_shadow_comparison,
        )

        return run_geometry_shadow_comparison(
            player_guid=int(player_guid),
            opcode_name=str(opcode_name),
            map_id=int(map_id),
            start=tuple(float(value) for value in start),
            end=tuple(float(value) for value in end),
            old_collision=legacy_collision,
            old_resolved_end=tuple(float(value) for value in legacy_resolved_end),
            authoritative_mode=str(authoritative_mode),
        )

    @staticmethod
    def build_collision_contact_probe(
        *,
        map_id: int,
        comparison: GeometryShadowComparison,
    ) -> dict[str, object] | None:
        from server.modules.handlers.world.collision.geometry_shadow import (
            build_manual_trophy_authoritative_contact_probe,
        )

        return build_manual_trophy_authoritative_contact_probe(
            int(map_id),
            comparison,
        )
