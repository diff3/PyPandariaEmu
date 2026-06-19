#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import time
from dataclasses import dataclass

from shared.Logger import Logger


_POST_TRANSFER_AREA_TRIGGER_SUPPRESS_SECONDS = 2.0


@dataclass(frozen=True)
class TeleportDestination:
    map_id: int
    x: float
    y: float
    z: float
    orientation: float
    name: str = ""


def _normalize_orientation(value: float) -> float:
    orientation = math.fmod(float(value), math.tau)
    if orientation < 0.0:
        orientation += math.tau
    return float(orientation)


def _reset_movement_for_teleport(session, destination: TeleportDestination) -> None:
    try:
        from server.modules.handlers.world.opcodes import movement as movement_handlers

        state = movement_handlers._movement_state(session)
    except Exception:
        state = getattr(session, "movement_state", None)
        if state is None:
            return

    state.x = float(destination.x)
    state.y = float(destination.y)
    state.z = float(destination.z)
    state.orientation = float(destination.orientation)
    state.flags = 0
    state.flags2 = 0
    state.pitch = 0.0
    state.is_ascending = False
    state.is_descending = False
    state.transport_guid = 0
    state.transport_x = 0.0
    state.transport_y = 0.0
    state.transport_z = 0.0
    state.transport_o = 0.0
    state.has_fall_data = False
    state.has_fall_direction = False
    state.fall_time = 0
    state.fall_vertical_speed = 0.0
    state.fall_horizontal_speed = 0.0
    state.fall_sin_angle = 0.0
    state.fall_cos_angle = 0.0


def apply_map_transfer(
    session,
    destination: TeleportDestination,
    *,
    reason: str,
) -> list[tuple[str, bytes]]:
    target = TeleportDestination(
        map_id=int(destination.map_id),
        x=float(destination.x),
        y=float(destination.y),
        z=float(destination.z),
        orientation=_normalize_orientation(destination.orientation),
        name=str(destination.name or reason),
    )
    source_map = int(getattr(session, "map_id", 0) or 0)
    same_map = source_map == int(target.map_id)

    if not same_map:
        try:
            from server.modules.handlers.world.features.plants_vs_ghouls import (
                get_plants_vs_ghouls_manager,
            )

            get_plants_vs_ghouls_manager().handle_map_change(session, int(target.map_id))
        except Exception as exc:
            Logger.warning("[PvG] map-transfer cleanup failed: %s", exc)
        try:
            from server.modules.handlers.world.features.halfhill_farming import (
                get_halfhill_farm_manager,
            )

            get_halfhill_farm_manager().clear_for_map_transfer(session)
        except Exception as exc:
            Logger.warning("[HalfhillFarm] map-transfer cleanup failed: %s", exc)
        try:
            from server.modules.handlers.world.features.pet_battles import (
                get_pet_battle_manager,
            )

            get_pet_battle_manager().handle_map_transfer(session)
        except Exception as exc:
            Logger.warning("[PetBattle] map-transfer cleanup failed: %s", exc)

    session.teleport_destination = target.name or str(reason)
    session.near_teleport_pending = same_map
    session.teleport_pending = not same_map
    session.worldport_ack_pending = not same_map
    session._area_trigger_suppressed_until = (
        time.monotonic() + _POST_TRANSFER_AREA_TRIGGER_SUPPRESS_SECONDS
    )
    _reset_movement_for_teleport(session, target)

    # TODO: move chat command teleports onto this helper once the older command
    # path can be changed without altering its user-facing command feedback.
    from server.modules.handlers.world.opcodes import chat as chat_handlers

    responses = chat_handlers.apply_player_state_change(
        session,
        position=(target.x, target.y, target.z, target.orientation),
        map_id=target.map_id,
    )
    _reset_movement_for_teleport(session, target)

    Logger.info(
        "[MapTransfer] reason=%s destination=%s same_map=%s map=%s pos=(%.3f %.3f %.3f %.6f)",
        str(reason),
        str(target.name or "?"),
        int(same_map),
        int(target.map_id),
        float(target.x),
        float(target.y),
        float(target.z),
        float(target.orientation),
    )
    return list(responses or [])
