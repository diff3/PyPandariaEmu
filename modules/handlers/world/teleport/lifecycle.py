from __future__ import annotations

import math
from dataclasses import dataclass

from shared.Logger import Logger
from server.modules.handlers.world.teleport.map_transfer import TeleportDestination
from server.modules.protocol.packet_batch import bind_packet_batch_to_current_transition


@dataclass(frozen=True)
class TeleportTransition:
    destination: TeleportDestination
    reason: str
    source_map_id: int
    same_map: bool
    keep_transport: bool = False
    same_map_resync: bool = True
    release_chair: bool = True


class TeleportLifecycle:
    """Canonical orchestration boundary for player teleports.

    Runtime state remains owned by the existing transition, position,
    transport, login, and visibility services.
    """

    def begin_transition(
        self,
        session,
        destination: TeleportDestination,
        *,
        reason: str,
        keep_transport: bool = False,
        same_map_resync: bool = True,
        release_chair: bool = True,
    ) -> TeleportTransition:
        values = (
            destination.x,
            destination.y,
            destination.z,
            destination.orientation,
        )
        if int(destination.map_id) < 0 or not all(math.isfinite(float(value)) for value in values):
            raise ValueError("invalid teleport destination")

        source_map_id = int(getattr(session, "map_id", 0) or 0)
        target = TeleportDestination(
            map_id=int(destination.map_id),
            x=float(destination.x),
            y=float(destination.y),
            z=float(destination.z),
            orientation=self._normalize_orientation(destination.orientation),
            name=str(destination.name or reason),
        )
        same_map = source_map_id == int(target.map_id)

        if not same_map:
            self._run_map_change_cleanup(session, int(target.map_id))

        session.teleport_destination = target.name or str(reason)
        if keep_transport and not same_map:
            generation = self.begin_owned_transition(
                session,
                owner="transport_worldport",
            )
            pending = getattr(session, "pending_transport_transfer", None)
            if isinstance(pending, dict):
                pending["world_transition_generation"] = generation

        return TeleportTransition(
            destination=target,
            reason=str(reason),
            source_map_id=source_map_id,
            same_map=same_map,
            keep_transport=bool(keep_transport),
            same_map_resync=bool(same_map_resync),
            release_chair=bool(release_chair),
        )

    @staticmethod
    def begin_owned_transition(session, *, owner: str) -> int:
        from server.modules.handlers.world.teleport import transition

        starters = {
            "ordinary_teleport": transition.begin_ordinary_teleport_transition,
            "transport_worldport": transition.begin_transport_worldport_transition,
            "taxi_worldport": transition.begin_taxi_worldport_transition,
        }
        try:
            starter = starters[str(owner)]
        except KeyError as exc:
            raise ValueError(f"unsupported teleport transition owner: {owner}") from exc
        return int(starter(session))

    def perform_transfer(
        self,
        session,
        transition: TeleportTransition,
    ) -> list[tuple[str, bytes]]:
        from server.modules.handlers.world.opcodes import chat as chat_handlers
        from server.modules.handlers.world.opcodes import movement as movement_handlers
        from server.modules.handlers.world.opcodes import spells as spells_handlers

        target = transition.destination
        responses: list[tuple[str, bytes]] = []

        if transition.release_chair:
            try:
                from server.modules.handlers.world.opcodes.entities import release_current_chair

                release_current_chair(session, reason="teleport")
            except Exception as exc:
                Logger.debug("[CHAIR] release on teleport failed: %s", exc)

        if not transition.keep_transport:
            self._prepare_ordinary_runtime(
                session,
                opcode_name=f"teleport:{transition.reason}",
            )

        if (
            bool(getattr(session, "is_mounted", False))
            or int(getattr(session, "mount_spell", 0) or 0)
            or int(getattr(session, "mount_display_id", 0) or 0)
        ):
            responses.extend(spells_handlers.dismount(session))

        if not transition.keep_transport and not transition.same_map:
            responses.extend(
                chat_handlers._clear_loaded_world_objects_for_teleport(
                    session,
                    movement_handlers,
                    map_id=transition.source_map_id,
                    send_out_of_range=False,
                )
            )
        if not transition.keep_transport:
            chat_handlers.force_player_visibility_destroy(
                session,
                reason="teleport-start",
                map_id=transition.source_map_id,
            )

        from server.modules.handlers.world.position.publication import publish_from_teleport

        publish_from_teleport(
            session,
            map_id=int(target.map_id),
            instance_id=0,
            x=float(target.x),
            y=float(target.y),
            z=float(target.z),
            orientation=float(target.orientation),
            synchronize_membership=not transition.keep_transport,
            resolve_area=True,
            capture_persistence=False,
        )
        state = movement_handlers._movement_state(session)
        state.flags = 0
        state.flags2 = 0
        movement_handlers._capture_persist_position_from_session(session)
        movement_handlers._mark_position_dirty(session)

        if transition.same_map:
            from server.modules.handlers.world.teleport.transition import mark_near_teleport_pending

            session.teleport_pending = False
            session.worldport_ack_pending = False
            if not mark_near_teleport_pending(session):
                session.near_teleport_pending = True
            transfer_packets = [
                ("SMSG_MOVE_TELEPORT", movement_handlers.build_same_map_teleport_payload(session))
            ]
            if transition.same_map_resync:
                transfer_packets = chat_handlers.apply_state_and_resync(
                    session,
                    transfer_packets,
                )
            return bind_packet_batch_to_current_transition(
                session,
                responses + transfer_packets,
            )

        session.teleport_pending = True
        session.worldport_ack_pending = True
        session.near_teleport_pending = False
        build_login_packet = getattr(chat_handlers, "build_login_packet", None)
        if build_login_packet is None:
            from server.modules.handlers.world.login.packets import build_login_packet

        transfer_packets = [
            (
                "SMSG_TRANSFER_PENDING",
                build_login_packet(
                    "SMSG_TRANSFER_PENDING",
                    type("Ctx", (), {"map_id": int(target.map_id)})(),
                ),
            ),
            (
                "SMSG_NEW_WORLD",
                build_login_packet(
                    "SMSG_NEW_WORLD",
                    type(
                        "Ctx",
                        (),
                        {
                            "map_id": int(target.map_id),
                            "x": float(target.x),
                            "y": float(target.y),
                            "z": float(target.z),
                            "orientation": float(target.orientation),
                        },
                    )(),
                ),
            ),
        ]
        return bind_packet_batch_to_current_transition(
            session,
            responses + transfer_packets,
        )

    def perform_owned_worldport(
        self,
        session,
        destination: TeleportDestination,
        *,
        reason: str,
        synchronize_membership: bool,
        resolve_area: bool,
        _attach_world=None,
    ) -> list[tuple[str, bytes]]:
        """Publish and serialize a worldport whose owner is already active."""
        target = TeleportDestination(
            map_id=int(destination.map_id),
            x=float(destination.x),
            y=float(destination.y),
            z=float(destination.z),
            orientation=self._normalize_orientation(destination.orientation),
            name=str(destination.name or reason),
        )
        session.teleport_pending = True
        session.worldport_ack_pending = True
        session.near_teleport_pending = False
        session.teleport_destination = target.name

        from server.modules.handlers.world.position.publication import publish_from_teleport

        publish_from_teleport(
            session,
            map_id=target.map_id,
            instance_id=int(getattr(session, "instance_id", 0) or 0),
            x=target.x,
            y=target.y,
            z=target.z,
            orientation=target.orientation,
            synchronize_membership=bool(synchronize_membership),
            resolve_area=bool(resolve_area),
            capture_persistence=False,
        )
        from server.modules.handlers.world.world_refresh import get_world_refresh_service

        get_world_refresh_service()._reset_world_object_tracking(session)
        if not synchronize_membership:
            if _attach_world is None:
                from server.modules.handlers.world.state.runtime import attach_session_to_world_state

                _attach_world = attach_session_to_world_state
            _attach_world(session, map_id=target.map_id)

        from server.modules.handlers.world.login.packets import build_login_packet

        ctx = type(
            "Ctx",
            (),
            {
                "map_id": target.map_id,
                "x": target.x,
                "y": target.y,
                "z": target.z,
                "orientation": target.orientation,
            },
        )()
        return bind_packet_batch_to_current_transition(
            session,
            [
                ("SMSG_TRANSFER_PENDING", build_login_packet("SMSG_TRANSFER_PENDING", ctx)),
                ("SMSG_NEW_WORLD", build_login_packet("SMSG_NEW_WORLD", ctx)),
            ],
        )

    def complete_transition(
        self,
        session,
        *,
        context: str,
        refresh: str | None = None,
        resync_multiplayer: bool = True,
        _object_refresh=None,
        _teleport_resync=None,
    ) -> list[tuple[str, bytes]]:
        from server.modules.handlers.world.teleport.transition import complete_world_transition

        complete_world_transition(session)
        if refresh is None:
            return []
        from server.modules.handlers.world.world_refresh import get_world_refresh_service

        service = get_world_refresh_service()
        if refresh == "teleport":
            return service.refresh_after_teleport(
                session,
                context=context,
                resync_multiplayer=resync_multiplayer,
                _object_refresh=_object_refresh,
                _teleport_resync=_teleport_resync,
            )
        if refresh == "transport":
            return service.refresh_after_transport(
                session,
                context=context,
                resync_multiplayer=resync_multiplayer,
                _object_refresh=_object_refresh,
                _teleport_resync=_teleport_resync,
            )
        if refresh == "deferred":
            session._worldport_destination_visibility_refresh_pending = True
            return []
        raise ValueError(f"unsupported teleport refresh mode: {refresh}")

    def teleport(
        self,
        session,
        destination: TeleportDestination,
        *,
        reason: str,
        keep_transport: bool = False,
        same_map_resync: bool = True,
        release_chair: bool = True,
    ) -> list[tuple[str, bytes]]:
        transition = self.begin_transition(
            session,
            destination,
            reason=reason,
            keep_transport=keep_transport,
            same_map_resync=same_map_resync,
            release_chair=release_chair,
        )
        return self.perform_transfer(session, transition)

    @staticmethod
    def _normalize_orientation(value: float) -> float:
        orientation = math.fmod(float(value), math.tau)
        return float(orientation + math.tau if orientation < 0.0 else orientation)

    @staticmethod
    def _run_map_change_cleanup(session, target_map_id: int) -> None:
        callbacks = (
            ("server.modules.handlers.world.features.plants_vs_ghouls", "get_plants_vs_ghouls_manager", "handle_map_change", (session, target_map_id)),
            ("server.modules.handlers.world.features.halfhill_farming", "get_halfhill_farm_manager", "clear_for_map_transfer", (session,)),
            ("server.modules.handlers.world.features.pet_battles", "get_pet_battle_manager", "handle_map_transfer", (session,)),
        )
        for module_name, getter_name, method_name, args in callbacks:
            try:
                module = __import__(module_name, fromlist=[getter_name])
                getattr(getattr(module, getter_name)(), method_name)(*args)
            except Exception as exc:
                Logger.warning("[TeleportLifecycle] map cleanup failed service=%s err=%s", getter_name, exc)

    def _prepare_ordinary_runtime(self, session, *, opcode_name: str) -> None:
        from server.modules.handlers.world.taxi_runtime import cancel_taxi_flight
        from server.modules.handlers.world.transport_runtime import clear_player_transport_state

        replacement_destination = getattr(session, "teleport_destination", None)
        self.begin_owned_transition(session, owner="ordinary_teleport")
        cancel_taxi_flight(session, "ordinary_teleport", send_updates=False)
        session.pending_taxi_transfer = None
        session.teleport_pending = False
        session.worldport_ack_pending = False
        session.near_teleport_pending = False
        session.teleport_destination = None
        clear_player_transport_state(
            session,
            reason="teleport",
            opcode_name=str(opcode_name),
        )
        session.teleport_destination = replacement_destination


_TELEPORT_LIFECYCLE = TeleportLifecycle()


def get_teleport_lifecycle() -> TeleportLifecycle:
    return _TELEPORT_LIFECYCLE
