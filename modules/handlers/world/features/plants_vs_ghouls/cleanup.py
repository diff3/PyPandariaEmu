from __future__ import annotations

from server.modules.handlers.world.features.plants_vs_ghouls import spawning


def clear_session_match_markers(session) -> None:
    session.plants_vs_ghouls_active = False
    session.plants_vs_ghouls_outcome = None


def build_cleanup_responses(session, world_guids: set[int]) -> list[tuple[str, bytes]]:
    return [
        spawning.build_creature_despawn_response(session, world_guid=int(world_guid))
        for world_guid in sorted(int(value) for value in set(world_guids))
        if int(world_guid) > 0
    ]
