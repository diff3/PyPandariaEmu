#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
from dataclasses import dataclass

from shared.Logger import Logger
from server.modules.protocol.packet_batch import (
    bind_packet_batch_to_current_transition,
    preserve_packet_batch_metadata,
)




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


def _reset_movement_for_teleport(
    session,
    destination: TeleportDestination,
) -> None:
    try:
        from server.modules.handlers.world.opcodes import movement as movement_handlers

        state = movement_handlers._movement_state(session)
    except Exception:
        state = getattr(session, "movement_state", None)
        if state is None:
            return

    state.flags = 0
    state.flags2 = 0
    state.pitch = 0.0
    state.is_ascending = False
    state.is_descending = False
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
    keep_transport: bool = False,
    source_map_id: int | None = None,
    transport_entry: int | None = None,
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

    from server.modules.handlers.world.teleport.lifecycle import get_teleport_lifecycle

    responses = get_teleport_lifecycle().teleport(
        session,
        target,
        reason=reason,
        keep_transport=bool(keep_transport),
    )
    _reset_movement_for_teleport(session, target)
    from server.modules.handlers.world.teleport.area_trigger import (
        synchronize_area_trigger_state,
    )

    synchronize_area_trigger_state(session)
    if keep_transport and transport_entry is not None:
        from server.modules.handlers.world.login.packets import build_login_packet

        source_for_packet = source_map if source_map_id is None else int(source_map_id)
        transport_transfer_pending = (
            "SMSG_TRANSFER_PENDING",
            build_login_packet(
                "SMSG_TRANSFER_PENDING",
                type(
                    "Ctx",
                    (),
                    {
                        "map_id": int(target.map_id),
                        "has_transport": True,
                        "source_map_id": int(source_for_packet),
                        "transport_entry": int(transport_entry),
                    },
                )(),
            ),
        )
        replaced_responses = [
            (
                transport_transfer_pending
                if opcode == "SMSG_TRANSFER_PENDING"
                else (opcode, payload)
            )
            for opcode, payload in list(responses or [])
        ]
        responses = preserve_packet_batch_metadata(responses, replaced_responses)
        responses = bind_packet_batch_to_current_transition(session, responses)
        Logger.info(
            "[TransportWorldport] transfer_pending_transport "
            "dest_map=%s source_map=%s transport_entry=%s keep_transport=true",
            int(target.map_id),
            int(source_for_packet),
            int(transport_entry),
        )

    Logger.info(
        "[MapTransfer] reason=%s destination=%s same_map=%s map=%s "
        "pos=(%.3f %.3f %.3f %.6f) keep_transport=%s",
        str(reason),
        str(target.name or "?"),
        int(same_map),
        int(target.map_id),
        float(target.x),
        float(target.y),
        float(target.z),
        float(target.orientation),
        int(bool(keep_transport)),
    )
    return preserve_packet_batch_metadata(responses, responses)
