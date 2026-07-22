#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Canonical publication service for accepted player movement."""

from __future__ import annotations

import time


class MovementPublisher:
    """Publish one authoritative Player movement snapshot to its observers."""

    def publish(self, source_session, *, force: bool = False) -> None:
        # Packet builders remain in the protocol/runtime module. This service
        # owns orchestration and cadence, not packet serialization.
        from server.modules.handlers.world.state import runtime
        from server.modules.handlers.world.player_visibility import (
            get_player_visibility_service,
        )

        if not runtime._is_session_in_world(source_session):
            return

        now = float(time.time())
        source_player = runtime.resolve_player_runtime(source_session)
        key = (
            int(source_player.map_id),
            int(source_player.character_guid),
            round(float(source_player.x), 5),
            round(float(source_player.y), 5),
            round(float(source_player.z), 5),
            round(float(source_player.orientation), 5),
        )
        last_key = getattr(source_session, "_multiplayer_last_broadcast_key", None)
        last_at = float(getattr(source_session, "_multiplayer_last_broadcast_at", 0.0) or 0.0)
        if not force and key == last_key and (now - last_at) < 0.02:
            return

        move_response = runtime._build_player_move_response(source_session)
        value_responses = [] if move_response is not None else runtime._build_player_value_update_responses(source_session)
        if move_response is None and not value_responses:
            return

        peers = [
            peer
            for peer in runtime.iter_in_world_sessions(map_id=int(source_player.map_id))
            if peer is not source_session
        ]
        visibility = get_player_visibility_service()
        from server.modules.handlers.world.player_diagnostics import log_player_event

        for peer in peers:
            result = visibility.reconcile_pair(
                source_session,
                peer,
                create=runtime._publish_player_create,
                remove=runtime._publish_player_remove,
            )
            if result.other_observes_source and not result.created_for_other:
                responses = [move_response] if move_response is not None else list(value_responses)
                log_player_event(
                    "movement_publish",
                    source_session,
                    observer_guid=int(runtime.resolve_player_runtime(peer).character_guid),
                    packets=[opcode for opcode, *_rest in responses],
                )
                runtime.dispatch_responses_to_sessions([peer], responses)

        source_session._multiplayer_last_broadcast_at = now
        source_session._multiplayer_last_broadcast_key = key
        source_session._multiplayer_removed = False


_MOVEMENT_PUBLISHER = MovementPublisher()


def get_movement_publisher() -> MovementPublisher:
    return _MOVEMENT_PUBLISHER
