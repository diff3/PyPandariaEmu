#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Low-volume, event-based diagnostics for transport lifecycle transitions.

This module intentionally has no movement-tick or coordinate-update API.
Callers may report only discrete lifecycle and exceptional events.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from shared.Logger import Logger
from server.modules.handlers.world.feature_config import (
    transport_lifecycle_debug_enabled,
    transport_packet_debug_enabled,
)


class TransportDebugEvent(str, Enum):
    ARRIVED = "arrived"
    LEAVING = "leaving"
    BOUNDARY_REACHED = "boundary_reached"
    WORLDPORT_STARTED = "worldport_started"
    WORLDPORT_COMPLETED = "worldport_completed"
    PLAYER_ATTACHED = "player_attached"
    PLAYER_DETACHED = "player_detached"
    PASSENGER_TRANSFER_STARTED = "passenger_transfer_started"
    PASSENGER_TRANSFER_COMPLETED = "passenger_transfer_completed"
    WORLDPORT_REJECTED = "worldport_rejected"
    PASSENGER_TRANSFER_REJECTED = "passenger_transfer_rejected"
    PENDING_TRANSFER_TIMEOUT = "pending_transfer_timeout"
    UNEXPECTED_DETACH = "unexpected_detach"
    STALE_GENERATION_IGNORED = "stale_generation_ignored"
    PACKET_BATCH_DISCARDED = "packet_batch_discarded"
    LATE_ACK_IGNORED = "late_ack_ignored"
    BOOTSTRAP_SKIPPED = "bootstrap_skipped"
    BOOTSTRAP_REJECTED = "bootstrap_rejected"


def transport_location(*, map_id: int | None, node_index: int | None = None) -> str:
    """Return a stable location label without logging runtime coordinates."""
    map_label = "unknown" if map_id is None else str(int(map_id))
    if node_index is None:
        return f"map:{map_label}"
    return f"map:{map_label}/node:{int(node_index)}"


def log_transport_event(
    event: TransportDebugEvent,
    *,
    transport_guid: int = 0,
    entry: int = 0,
    player_guid: int = 0,
    transfer_id: str = "",
    location: str = "",
    source: str = "",
    destination: str = "",
    reason: str = "",
    participants: int | None = None,
    **details: Any,
) -> bool:
    """Emit one structured lifecycle record when Transport debug is enabled."""
    if not transport_lifecycle_debug_enabled():
        return False

    fields = [f"event={event.value}"]
    if transport_guid:
        fields.append(f"transport=0x{int(transport_guid) & 0xFFFFFFFFFFFFFFFF:016X}")
    if entry:
        fields.append(f"entry={int(entry)}")
    if player_guid:
        fields.append(f"player={int(player_guid)}")
    if transfer_id:
        fields.append(f"transfer_id={transfer_id}")
    if location:
        fields.append(f"location={location}")
    if source:
        fields.append(f"from={source}")
    if destination:
        fields.append(f"to={destination}")
    if participants is not None:
        fields.append(f"participants={int(participants)}")
    if reason:
        fields.append(f"reason={reason}")
    for key in sorted(details):
        value = details[key]
        if value is not None and value != "":
            fields.append(f"{key}={value}")
    Logger.info("[TransportLifecycle] %s", " ".join(fields))
    return True


def log_transport_packet_snapshot(
    session: Any,
    *,
    opcode: str,
    source_subsystem: str,
    batch_id: str,
    map_id: int,
    position: tuple[float, float, float, float] | None = None,
    transport_guid: int = 0,
    transport_offsets: tuple[float, float, float, float] | None = None,
    movement_flags: int = 0,
    object_guid: int = 0,
    object_map_context: int | None = None,
) -> bool:
    """Log one transition packet's semantic snapshot when explicitly enabled."""
    if not transport_packet_debug_enabled():
        return False

    generation = int(
        getattr(session, "world_transition_generation", 0) or 0
    )
    owner = str(getattr(session, "world_transition_owner", "") or "none")
    fields = [
        f"opcode={str(opcode)}",
        f"batch_id={str(batch_id)}",
        f"generation={generation}",
        f"owner={owner}",
        f"source={str(source_subsystem)}",
        f"map_id={int(map_id)}",
        f"transport_guid=0x{int(transport_guid) & 0xFFFFFFFFFFFFFFFF:016X}",
        f"movement_flags=0x{int(movement_flags) & 0xFFFFFFFF:08X}",
        f"object_guid=0x{int(object_guid) & 0xFFFFFFFFFFFFFFFF:016X}",
        "object_map_context=%s"
        % (
            "none"
            if object_map_context is None
            else str(int(object_map_context))
        ),
    ]
    if position is not None:
        fields.append(
            "position=(%.3f,%.3f,%.3f,%.6f)" % tuple(position)
        )
    if transport_offsets is not None:
        fields.append(
            "transport_offsets=(%.3f,%.3f,%.3f,%.6f)"
            % tuple(transport_offsets)
        )
    Logger.info("[TransportPacket] %s", " ".join(fields))
    return True
