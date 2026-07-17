from __future__ import annotations

from shared.Logger import Logger


class WorldRefreshService:
    """Orchestrate existing client world synchronization operations.

    This service deliberately owns no runtime state.  The individual position,
    visibility, object-streaming, transport, spell, and login services remain
    authoritative for their respective data and packet construction.
    """

    def refresh_player_world(
        self,
        session,
        *,
        context: str,
        synchronize_player_visibility: bool = False,
        stream_world_objects: bool = True,
        force_object_stream: bool = False,
        teleport_resync_reason: str | None = None,
        _object_streamer=None,
        _teleport_resync=None,
        _object_refresh=None,
        _visibility_sync=None,
    ) -> list[tuple[str, bytes]]:
        responses: list[tuple[str, bytes]] = []

        if synchronize_player_visibility:
            if _visibility_sync is None:
                from server.modules.handlers.world.state.runtime import sync_player_visibility

                _visibility_sync = sync_player_visibility
            _visibility_sync(session)

        if teleport_resync_reason is not None:
            # This remains a specialized gameplay step (including canonical
            # mount removal), while this service owns when it runs in refresh.
            if _teleport_resync is None:
                from server.modules.handlers.world.opcodes import movement

                _teleport_resync = movement._post_teleport_multiplayer_resync
            responses.extend(
                _teleport_resync(session, reason=teleport_resync_reason)
            )

        if stream_world_objects:
            if _object_refresh is not None:
                responses.extend(_object_refresh(session, context=context))
            else:
                responses.extend(
                    self._stream_world_objects(
                        session,
                        context=context,
                        force=force_object_stream,
                        object_streamer=_object_streamer,
                    )
                )

        # TODO: Route position/area publication here once their existing
        # transition-specific ordering can be preserved without a second path.
        # TODO: Route action-button and transport-specific publication here
        # when those packets have a reusable, transition-safe refresh builder.
        return responses

    def refresh_after_teleport(
        self,
        session,
        *,
        context: str,
        resync_multiplayer: bool = True,
        _object_streamer=None,
        _teleport_resync=None,
        _object_refresh=None,
        reset_object_tracking: bool = True,
    ) -> list[tuple[str, bytes]]:
        if reset_object_tracking:
            self._reset_world_object_tracking(session)
        return self.refresh_player_world(
            session,
            context=context,
            force_object_stream=True,
            teleport_resync_reason=context if resync_multiplayer else None,
            _object_streamer=_object_streamer,
            _teleport_resync=_teleport_resync,
            _object_refresh=_object_refresh,
        )

    @staticmethod
    def _reset_world_object_tracking(session) -> None:
        """Forget client objects invalidated by a same-map teleport.

        The client clears these objects while applying the teleport.  No
        OUT_OF_RANGE packets are needed; clearing only the server bookkeeping
        makes the following forced stream serialize destination CREATEs again.
        """
        session.loaded_gameobjects = set()
        session.loaded_gameobject_entries = {}
        session.loaded_transport_entries = {}
        session.loaded_npcs = set()
        session.npc_flags_by_guid = {}
        session.npc_entries_by_guid = {}
        session.last_gameobject_stream_at = 0.0
        session.last_npc_stream_at = 0.0

    def refresh_after_transport(
        self,
        session,
        *,
        context: str,
        resync_multiplayer: bool = True,
        _object_streamer=None,
        _teleport_resync=None,
        _object_refresh=None,
    ) -> list[tuple[str, bytes]]:
        return self.refresh_player_world(
            session,
            context=context,
            force_object_stream=True,
            teleport_resync_reason=context if resync_multiplayer else None,
            _object_streamer=_object_streamer,
            _teleport_resync=_teleport_resync,
            _object_refresh=_object_refresh,
        )

    def refresh_after_movement(
        self,
        session,
        *,
        context: str,
        _object_streamer=None,
        _object_refresh=None,
    ) -> list[tuple[str, bytes]]:
        """Run the normal throttled, incremental visibility pipeline."""
        return self.refresh_player_world(
            session,
            context=context,
            _object_streamer=_object_streamer,
            _object_refresh=_object_refresh,
        )

    def refresh_after_login(
        self,
        session,
        *,
        context: str,
        synchronize_player_visibility: bool = False,
        stream_world_objects: bool = True,
        force_object_stream: bool = True,
        _object_streamer=None,
        _visibility_sync=None,
        _object_refresh=None,
        _area_trigger_sync=None,
    ) -> list[tuple[str, bytes]]:
        # Login establishes a discontinuous world position rather than a
        # movement segment. Seed containment silently so the first real
        # movement cannot be mistaken for an AreaTrigger enter event.
        if _area_trigger_sync is None:
            from server.modules.handlers.world.teleport.area_trigger import (
                synchronize_area_trigger_state,
            )

            _area_trigger_sync = synchronize_area_trigger_state
        _area_trigger_sync(session)
        return self.refresh_player_world(
            session,
            context=context,
            synchronize_player_visibility=synchronize_player_visibility,
            stream_world_objects=stream_world_objects,
            force_object_stream=force_object_stream,
            _object_streamer=_object_streamer,
            _visibility_sync=_visibility_sync,
            _object_refresh=_object_refresh,
        )

    @staticmethod
    def _stream_world_objects(
        session,
        *,
        context: str,
        force: bool,
        object_streamer=None,
    ) -> list[tuple[str, bytes]]:
        # Object discovery remains implemented by the existing GameObject and
        # Creature streaming code.  Only its transition orchestration lives here.
        if object_streamer is None:
            from server.modules.handlers.world.opcodes import movement

            object_streamer = movement._maybe_stream_world_objects

        before_gameobjects = set(getattr(session, "loaded_gameobjects", set()) or set())
        before_npcs = set(getattr(session, "loaded_npcs", set()) or set())
        before_transports = set(
            (getattr(session, "loaded_transport_entries", {}) or {}).keys()
        )

        if force:
            session.last_gameobject_stream_at = 0.0
            session.last_npc_stream_at = 0.0
        if force:
            responses = object_streamer(
                session,
                transition_bootstrap=True,
            )
        else:
            responses = object_streamer(session)

        after_gameobjects = set(getattr(session, "loaded_gameobjects", set()) or set())
        after_npcs = set(getattr(session, "loaded_npcs", set()) or set())
        after_transports = set(
            (getattr(session, "loaded_transport_entries", {}) or {}).keys()
        )
        transports_sent = len(after_transports - before_transports)
        gameobjects_sent = len(
            (after_gameobjects - before_gameobjects) - after_transports
        )
        npcs_sent = len(after_npcs - before_npcs)

        log = Logger.info if force else Logger.debug
        log(
            "[WORLD_REFRESH] context=%s player_guid=%s map=%s "
            "pos=(%.3f,%.3f,%.3f) gameobjects_sent=%s npcs_sent=%s "
            "transports_sent=%s",
            str(context),
            int(
                getattr(session, "char_guid", 0)
                or getattr(session, "player_guid", 0)
                or 0
            ),
            int(getattr(session, "map_id", 0) or 0),
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
            int(gameobjects_sent),
            int(npcs_sent),
            int(transports_sent),
        )
        return list(responses)


_WORLD_REFRESH_SERVICE = WorldRefreshService()


def get_world_refresh_service() -> WorldRefreshService:
    return _WORLD_REFRESH_SERVICE
