#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import struct
import time
from typing import Any, Optional, Tuple

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitInterPreter, BitWriter
# from modules.handlers.world.opcodes.chat import _append_feedback_response
from shared.Logger import Logger
from server.modules.game.guid import CreatureGuid, GameObjectGuid, GuidHelper, MoTransportGuid
from server.modules.handlers.world.bootstrap.gameobjects import build_database_gameobject_responses
from server.modules.handlers.world.bootstrap.playerobjects import build_single_u32_update_object_payload
from server.modules.handlers.world.protocol.orientation import normalize_orientation as normalize_wire_orientation
from server.modules.handlers.world.runtime.gameobject_store import (
    resolve_gameobject_runtime,
)
from server.modules.handlers.world.runtime.player import Player
from server.modules.handlers.world.runtime.player_store import (
    sync_player_runtime_from_session,
)
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.achievement_service import discover_area
from server.modules.interpretation.utils import dsl_decode
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.position.position_service import (
    POSITION_AUTOSAVE_DISTANCE_THRESHOLD,
    POSITION_DEBUG_ENABLED,
    Position,
    format_position,
    normalize_position,
    position_from_session,
    position_moved_enough,
    save_player_position,
)
from server.modules.handlers.world.position.area_service import (
    resolve_area_from_position,
    resolve_zone_from_position,
)
from server.modules.handlers.world.state.runtime import (
    broadcast_player_state_update,
    build_same_map_teleport_self_resync_responses,
    dispatch_responses_to_sessions,
    force_bilateral_visibility_resync,
    is_player_world_active,
    refresh_region_weather,
)
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.handlers.world.transport_debug import (
    TransportDebugEvent,
    log_transport_event,
    transport_location,
)


def _transport_movement_debug_enabled() -> bool:
    try:
        from server.modules.handlers.world.feature_config import transport_movement_debug_enabled

        return bool(transport_movement_debug_enabled())
    except Exception:
        return False


def _transport_debug_log(message: str, *args) -> None:
    if not _transport_movement_debug_enabled():
        return
    Logger.info(message, *args)


def _transport_player_debug(
    session,
    stage: str,
    text: str,
    *,
    transfer_id: str | None = None,
) -> bool:
    try:
        from server.modules.handlers.world.transport_debug_messages import send_message

        return send_message(
            session,
            stage,
            text,
            transfer_id=transfer_id,
        )
    except Exception as exc:
        Logger.warning("[TransportDebug] message failed stage=%s error=%s", stage, str(exc))
        return False


def _clear_falling_state(state) -> None:
    state.has_fall_data = False
    state.fall_time = 0
    state.fall_vertical_speed = 0.0
    state.fall_horizontal_speed = 0.0
    state.fall_sin_angle = 0.0
    state.fall_cos_angle = 0.0
    state.flags &= ~_MOVEMENTFLAG_FALLING
    if hasattr(state, "is_ascending"):
        state.is_ascending = False
    if hasattr(state, "is_descending"):
        state.is_descending = False


def _verify_pending_boat_transfer_attachment(session, pending: dict[str, Any] | None) -> None:
    if not isinstance(pending, dict):
        return
    try:
        from server.modules.handlers.world.transport_runtime import (
            attach_transport_passenger,
            cached_transport_runtime_entry,
            is_cross_map_boat_entry,
            is_cross_map_zeppelin_entry,
            runtime_transport_state_for_guid,
            transport_passenger_attachment,
        )
    except Exception:
        return

    destination_entry = pending.get("destination_entry")
    is_boat = is_cross_map_boat_entry(
        destination_entry if isinstance(destination_entry, dict) else None
    )
    is_zeppelin = is_cross_map_zeppelin_entry(
        destination_entry if isinstance(destination_entry, dict) else None
    )
    if not (is_boat or is_zeppelin):
        return

    transfer_id = str(pending.get("transfer_id", "unknown") or "unknown")
    transport_kind = "boat" if is_boat else "zeppelin"
    if is_zeppelin and not is_boat:
        Logger.info(
            "[TransportTransferDiag] verify transfer_id=%s kind=%s return_reason=not_boat_verifier "
            "early_return=true runtime_attachment=unknown rebase=false",
            transfer_id,
            transport_kind,
        )
        return

    player_guid = int(getattr(session, "char_guid", 0) or 0)
    destination_guid = int(pending.get("destination_guid", 0) or 0)
    if player_guid <= 0 or destination_guid <= 0:
        Logger.info(
            "[TransportTransferDiag] verify transfer_id=%s kind=%s return_reason=invalid_identity "
            "early_return=true runtime_attachment=unknown rebase=false",
            transfer_id,
            transport_kind,
        )
        return

    Logger.info(
        "[TransportTransfer] verify player=%s transport=0x%016X",
        player_guid,
        destination_guid & 0xFFFFFFFFFFFFFFFF,
    )

    movement_state = getattr(session, "movement_state", None)
    runtime_attachment = transport_passenger_attachment(destination_guid, player_guid)
    if (
        movement_state is not None
        and bool(getattr(movement_state, "has_transport_data", False))
        and int(getattr(movement_state, "transport_guid", 0) or 0) == destination_guid
        and runtime_attachment is not None
    ):
        Logger.info("[TransportTransfer] verify success")
        Logger.info(
            "[TransportTransferDiag] verify transfer_id=%s kind=%s return_reason=already_attached "
            "early_return=true runtime_attachment=true rebase=false",
            transfer_id,
            transport_kind,
        )
        return

    Logger.info("[TransportTransfer] verify failed reattaching")

    local_x = float(
        getattr(runtime_attachment, "local_x", pending.get("local_x", 0.0))
        if runtime_attachment is not None
        else pending.get("local_x", 0.0)
    )
    local_y = float(
        getattr(runtime_attachment, "local_y", pending.get("local_y", 0.0))
        if runtime_attachment is not None
        else pending.get("local_y", 0.0)
    )
    local_z = float(
        getattr(runtime_attachment, "local_z", pending.get("local_z", 0.0))
        if runtime_attachment is not None
        else pending.get("local_z", 0.0)
    )
    local_o = float(
        getattr(runtime_attachment, "local_o", pending.get("local_o", 0.0))
        if runtime_attachment is not None
        else pending.get("local_o", 0.0)
    )

    runtime_state = runtime_transport_state_for_guid(destination_guid)
    if runtime_state is not None:
        transport_map = int(getattr(runtime_state, "map_id", pending.get("destination_map", 0)) or 0)
        transport_x = float(getattr(runtime_state, "x", 0.0) or 0.0)
        transport_y = float(getattr(runtime_state, "y", 0.0) or 0.0)
        transport_z = float(getattr(runtime_state, "z", 0.0) or 0.0)
        transport_o = float(getattr(runtime_state, "orientation", 0.0) or 0.0)
    else:
        entry = destination_entry if isinstance(destination_entry, dict) else {}
        transport_map = int(entry.get("map", entry.get("map_id", pending.get("destination_map", 0))) or 0)
        transport_x = float(entry.get("x", pending.get("base_x", 0.0)) or 0.0)
        transport_y = float(entry.get("y", pending.get("base_y", 0.0)) or 0.0)
        transport_z = float(entry.get("z", pending.get("base_z", 0.0)) or 0.0)
        transport_o = float(entry.get("orientation", pending.get("base_o", 0.0)) or 0.0)

    world_x = float(transport_x) + float(local_x)
    world_y = float(transport_y) + float(local_y)
    world_z = float(transport_z) + float(local_z)
    world_o = float(transport_o) + float(local_o)

    if runtime_attachment is None:
        attach_transport_passenger(
            destination_guid,
            player_guid,
            local_x=local_x,
            local_y=local_y,
            local_z=local_z,
            local_o=local_o,
            source_map=transport_map,
        )

    from server.modules.handlers.world.position.publication import (
        publish_absolute,
    )
    from server.modules.handlers.world.transport_runtime import (
        update_transport_passenger_offset,
    )

    update_transport_passenger_offset(
        session,
        destination_guid,
        local_x=local_x,
        local_y=local_y,
        local_z=local_z,
        local_o=local_o,
        transport_time=int(pending.get("route_phase", 0) or 0),
    )
    publish_absolute(
        session,
        map_id=int(transport_map),
        instance_id=int(getattr(session, "instance_id", 0) or 0),
        x=world_x,
        y=world_y,
        z=world_z,
        orientation=world_o,
        capture_persistence=True,
    )
    Logger.info(
        "[TransportTransferDiag] verify transfer_id=%s kind=%s return_reason=completed "
        "early_return=false runtime_attachment=%s runtime_transport=%s rebase=true "
        "rebased_world=(%.3f %.3f %.3f %.3f)",
        transfer_id,
        transport_kind,
        "true" if runtime_attachment is not None else "false",
        "true" if runtime_state is not None else "false",
        world_x,
        world_y,
        world_z,
        world_o,
    )
    session.transport_attach_state = "ATTACHED"
    session.transport_attach_source_map = int(transport_map)

    loaded_entries = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_entries, dict) and isinstance(destination_entry, dict):
        loaded_entries[destination_guid] = cached_transport_runtime_entry(session, dict(destination_entry))

    Logger.info("[TransportTransfer] verify success")


def _append_guid_byte_seq(payload: bytearray, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        value = raw_guid[index]
        if value:
            payload.append((value ^ 1) & 0xFF)


def _decode_guid_byte_seq(value: int) -> int:
    return (int(value) ^ 1) & 0xFF


def _guid_from_bytes(raw_guid: list[int]) -> int:
    value = 0
    for index, byte_value in enumerate(raw_guid[:8]):
        value |= (int(byte_value) & 0xFF) << (index * 8)
    return int(value) & 0xFFFFFFFFFFFFFFFF


_MOVEMENTFLAG_FORWARD = 0x00000001
_MOVEMENTFLAG_BACKWARD = 0x00000002
_MOVEMENTFLAG_STRAFE_LEFT = 0x00000004
_MOVEMENTFLAG_STRAFE_RIGHT = 0x00000008
_MOVEMENTFLAG_TURN_LEFT = 0x00000010
_MOVEMENTFLAG_TURN_RIGHT = 0x00000020
_MOVEMENTFLAG_LEFT = _MOVEMENTFLAG_TURN_LEFT
_MOVEMENTFLAG_RIGHT = _MOVEMENTFLAG_TURN_RIGHT
_MOVEMENTFLAG_FALLING = 0x00000800
_MOVEMENTFLAG_SWIMMING = 0x00100000
_MOVEMENTFLAG_ASCENDING = 0x00200000
_MOVEMENTFLAG_DESCENDING = 0x00400000
_MOVEMENTFLAG_CAN_FLY = 0x00800000
_MOVEMENTFLAG_FLYING = 0x01000000
_MOVEMENTFLAG_SPLINE_ELEVATION = 0x02000000
_MOVEMENTFLAG2_CIRCLE_RUN_SYNC = 0x00000800

_SKYFIRE_FLYING_MOVEMENT_OPCODES = frozenset({
    "MSG_MOVE_HEARTBEAT",
    "MSG_MOVE_START_ASCEND",
    "MSG_MOVE_STOP_ASCEND",
    "MSG_MOVE_START_DESCEND",
    "MSG_MOVE_STOP_DESCEND",
    "MSG_MOVE_SET_PITCH",
})

_SKYFIRE_MOVEMENT_HEARTBEAT_SEQUENCE = (
    "MSEPositionZ",
    "MSEPositionX",
    "MSEPositionY",
    "MSEForcesCount",
    "MSEHasMovementFlags",
    "MSEZeroBit",
    "MSEHasCounter",
    "MSEHasGuidByte3",
    "MSEHasGuidByte6",
    "MSEHasPitch",
    "MSEZeroBit",
    "MSEZeroBit",
    "MSEHasGuidByte7",
    "MSEHasGuidByte2",
    "MSEHasGuidByte4",
    "MSEHasMovementFlags2",
    "MSEHasOrientation",
    "MSEHasTimestamp",
    "MSEHasTransportData",
    "MSEHasFallData",
    "MSEHasGuidByte5",
    "MSEHasSplineElevation",
    "MSEHasGuidByte1",
    "MSEHasGuidByte0",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte7",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte1",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportGuidByte4",
    "MSEHasTransportTime2",
    "MSEMovementFlags",
    "MSEHasFallDirection",
    "MSEMovementFlags2",
    "MSEGuidByte2",
    "MSEGuidByte3",
    "MSEGuidByte6",
    "MSEGuidByte1",
    "MSEGuidByte4",
    "MSEGuidByte7",
    "MSEForces",
    "MSEGuidByte5",
    "MSEGuidByte0",
    "MSEFallSinAngle",
    "MSEFallCosAngle",
    "MSEFallHorizontalSpeed",
    "MSEFallVerticalSpeed",
    "MSEFallTime",
    "MSETransportGuidByte1",
    "MSETransportGuidByte3",
    "MSETransportGuidByte2",
    "MSETransportGuidByte0",
    "MSETransportTime3",
    "MSETransportSeat",
    "MSETransportGuidByte7",
    "MSETransportPositionX",
    "MSETransportGuidByte4",
    "MSETransportTime2",
    "MSETransportPositionY",
    "MSETransportGuidByte6",
    "MSETransportGuidByte5",
    "MSETransportPositionZ",
    "MSETransportTime",
    "MSETransportOrientation",
    "MSECounter",
    "MSEOrientation",
    "MSEPitch",
    "MSETimestamp",
    "MSESplineElevation",
)

_SKYFIRE_MOVEMENT_START_ASCEND_SEQUENCE = (
    "MSEPositionY",
    "MSEPositionX",
    "MSEPositionZ",
    "MSEHasOrientation",
    "MSEHasGuidByte3",
    "MSEHasTransportData",
    "MSEHasMovementFlags",
    "MSEZeroBit",
    "MSEHasGuidByte0",
    "MSEHasGuidByte4",
    "MSEHasTimestamp",
    "MSEHasGuidByte7",
    "MSEZeroBit",
    "MSEHasPitch",
    "MSEHasGuidByte5",
    "MSEHasMovementFlags2",
    "MSEZeroBit",
    "MSEHasGuidByte6",
    "MSEHasGuidByte2",
    "MSEHasCounter",
    "MSEForcesCount",
    "MSEHasGuidByte1",
    "MSEHasSplineElevation",
    "MSEHasFallData",
    "MSEHasTransportGuidByte4",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportTime2",
    "MSEHasTransportGuidByte1",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportGuidByte7",
    "MSEHasFallDirection",
    "MSEMovementFlags2",
    "MSEMovementFlags",
    "MSEGuidByte2",
    "MSEGuidByte5",
    "MSEForces",
    "MSEGuidByte1",
    "MSEGuidByte0",
    "MSEGuidByte4",
    "MSEGuidByte7",
    "MSEGuidByte6",
    "MSEGuidByte3",
    "MSEOrientation",
    "MSETimestamp",
    "MSETransportGuidByte3",
    "MSETransportTime",
    "MSETransportPositionY",
    "MSETransportOrientation",
    "MSETransportGuidByte6",
    "MSETransportTime3",
    "MSETransportPositionX",
    "MSETransportGuidByte2",
    "MSETransportTime2",
    "MSETransportGuidByte1",
    "MSETransportGuidByte7",
    "MSETransportPositionZ",
    "MSETransportSeat",
    "MSETransportGuidByte0",
    "MSETransportGuidByte4",
    "MSETransportGuidByte5",
    "MSESplineElevation",
    "MSEFallVerticalSpeed",
    "MSEFallSinAngle",
    "MSEFallCosAngle",
    "MSEFallHorizontalSpeed",
    "MSEFallTime",
    "MSEPitch",
    "MSECounter",
)

_SKYFIRE_MOVEMENT_START_DESCEND_SEQUENCE = (
    "MSEPositionX",
    "MSEPositionY",
    "MSEPositionZ",
    "MSEHasFallData",
    "MSEHasMovementFlags",
    "MSEHasGuidByte7",
    "MSEHasGuidByte0",
    "MSEHasGuidByte4",
    "MSEHasMovementFlags2",
    "MSEHasPitch",
    "MSEHasGuidByte6",
    "MSEHasGuidByte2",
    "MSEZeroBit",
    "MSEHasCounter",
    "MSEForcesCount",
    "MSEHasTransportData",
    "MSEHasOrientation",
    "MSEHasGuidByte1",
    "MSEZeroBit",
    "MSEZeroBit",
    "MSEHasGuidByte3",
    "MSEHasGuidByte5",
    "MSEHasSplineElevation",
    "MSEHasTimestamp",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte7",
    "MSEHasTransportTime2",
    "MSEHasTransportGuidByte1",
    "MSEHasTransportGuidByte4",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportGuidByte2",
    "MSEMovementFlags2",
    "MSEMovementFlags",
    "MSEHasFallDirection",
    "MSEGuidByte4",
    "MSEGuidByte7",
    "MSEGuidByte1",
    "MSEGuidByte3",
    "MSEForces",
    "MSEGuidByte2",
    "MSEGuidByte6",
    "MSEGuidByte0",
    "MSEGuidByte5",
    "MSETransportPositionX",
    "MSETransportGuidByte0",
    "MSETransportGuidByte3",
    "MSETransportGuidByte7",
    "MSETransportSeat",
    "MSETransportGuidByte5",
    "MSETransportGuidByte1",
    "MSETransportPositionY",
    "MSETransportTime3",
    "MSETransportTime",
    "MSETransportGuidByte4",
    "MSETransportTime2",
    "MSETransportOrientation",
    "MSETransportPositionZ",
    "MSETransportGuidByte2",
    "MSETransportGuidByte6",
    "MSEFallTime",
    "MSEFallCosAngle",
    "MSEFallHorizontalSpeed",
    "MSEFallSinAngle",
    "MSEFallVerticalSpeed",
    "MSEPitch",
    "MSECounter",
    "MSESplineElevation",
    "MSEOrientation",
    "MSETimestamp",
)

_SKYFIRE_MOVEMENT_STOP_ASCEND_SEQUENCE = (
    "MSEPositionZ",
    "MSEPositionX",
    "MSEPositionY",
    "MSEHasOrientation",
    "MSEHasGuidByte0",
    "MSEHasGuidByte3",
    "MSEHasGuidByte7",
    "MSEHasGuidByte2",
    "MSEHasGuidByte6",
    "MSEHasMovementFlags2",
    "MSEHasTimestamp",
    "MSEHasCounter",
    "MSEHasTransportData",
    "MSEHasPitch",
    "MSEZeroBit",
    "MSEZeroBit",
    "MSEHasGuidByte4",
    "MSEZeroBit",
    "MSEHasGuidByte5",
    "MSEForcesCount",
    "MSEHasFallData",
    "MSEHasMovementFlags",
    "MSEHasGuidByte1",
    "MSEHasSplineElevation",
    "MSEHasTransportTime2",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte4",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportGuidByte1",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte7",
    "MSEMovementFlags2",
    "MSEMovementFlags",
    "MSEHasFallDirection",
    "MSEGuidByte0",
    "MSEForces",
    "MSEGuidByte4",
    "MSEGuidByte5",
    "MSEGuidByte1",
    "MSEGuidByte7",
    "MSEGuidByte6",
    "MSEGuidByte3",
    "MSEGuidByte2",
    "MSETransportGuidByte5",
    "MSETransportPositionY",
    "MSETransportGuidByte4",
    "MSETransportGuidByte7",
    "MSETransportGuidByte1",
    "MSETransportGuidByte3",
    "MSETransportTime2",
    "MSETransportPositionX",
    "MSETransportOrientation",
    "MSETransportGuidByte0",
    "MSETransportGuidByte2",
    "MSETransportPositionZ",
    "MSETransportTime3",
    "MSETransportTime",
    "MSETransportSeat",
    "MSETransportGuidByte6",
    "MSEFallCosAngle",
    "MSEFallHorizontalSpeed",
    "MSEFallSinAngle",
    "MSEFallTime",
    "MSEFallVerticalSpeed",
    "MSETimestamp",
    "MSESplineElevation",
    "MSEPitch",
    "MSECounter",
    "MSEOrientation",
)

_SKYFIRE_MOVEMENT_START_FORWARD_SEQUENCE = (
    "MSEPositionZ",
    "MSEPositionX",
    "MSEPositionY",
    "MSEHasMovementFlags2",
    "MSEZeroBit",
    "MSEHasCounter",
    "MSEZeroBit",
    "MSEHasGuidByte0",
    "MSEHasOrientation",
    "MSEHasFallData",
    "MSEForcesCount",
    "MSEHasGuidByte4",
    "MSEHasGuidByte1",
    "MSEHasTimestamp",
    "MSEHasGuidByte7",
    "MSEHasPitch",
    "MSEHasTransportData",
    "MSEHasGuidByte5",
    "MSEHasMovementFlags",
    "MSEHasGuidByte3",
    "MSEHasSplineElevation",
    "MSEHasGuidByte2",
    "MSEHasGuidByte6",
    "MSEZeroBit",
    "MSEHasTransportGuidByte1",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte4",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte7",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportTime2",
    "MSEHasFallDirection",
    "MSEMovementFlags2",
    "MSEMovementFlags",
    "MSEGuidByte1",
    "MSEGuidByte6",
    "MSEGuidByte7",
    "MSEForces",
    "MSEGuidByte5",
    "MSEGuidByte0",
    "MSEGuidByte3",
    "MSEGuidByte2",
    "MSEGuidByte4",
    "MSETransportGuidByte3",
    "MSETransportGuidByte1",
    "MSETransportGuidByte6",
    "MSETransportPositionZ",
    "MSETransportGuidByte4",
    "MSETransportTime3",
    "MSETransportSeat",
    "MSETransportGuidByte7",
    "MSETransportOrientation",
    "MSETransportTime2",
    "MSETransportGuidByte5",
    "MSETransportGuidByte2",
    "MSETransportPositionX",
    "MSETransportGuidByte0",
    "MSETransportPositionY",
    "MSETransportTime",
    "MSEFallCosAngle",
    "MSEFallSinAngle",
    "MSEFallHorizontalSpeed",
    "MSEFallTime",
    "MSEFallVerticalSpeed",
    "MSETimestamp",
    "MSEPitch",
    "MSESplineElevation",
    "MSEOrientation",
    "MSECounter",
)

_SKYFIRE_MOVEMENT_START_BACKWARD_SEQUENCE = (
    "MSEPositionY",
    "MSEPositionZ",
    "MSEPositionX",
    "MSEHasTimestamp",
    "MSEHasOrientation",
    "MSEHasGuidByte7",
    "MSEHasGuidByte2",
    "MSEForcesCount",
    "MSEHasFallData",
    "MSEZeroBit",
    "MSEHasGuidByte5",
    "MSEHasGuidByte3",
    "MSEHasGuidByte6",
    "MSEHasSplineElevation",
    "MSEHasGuidByte4",
    "MSEHasTransportData",
    "MSEHasGuidByte0",
    "MSEHasMovementFlags",
    "MSEHasPitch",
    "MSEHasCounter",
    "MSEHasMovementFlags2",
    "MSEZeroBit",
    "MSEHasGuidByte1",
    "MSEZeroBit",
    "MSEHasTransportGuidByte1",
    "MSEHasTransportTime2",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte7",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportGuidByte4",
    "MSEMovementFlags2",
    "MSEMovementFlags",
    "MSEHasFallDirection",
    "MSEForces",
    "MSEGuidByte1",
    "MSEGuidByte3",
    "MSEGuidByte5",
    "MSEGuidByte2",
    "MSEGuidByte0",
    "MSEGuidByte4",
    "MSEGuidByte7",
    "MSEGuidByte6",
    "MSECounter",
    "MSETransportTime",
    "MSETransportGuidByte4",
    "MSETransportGuidByte1",
    "MSETransportGuidByte5",
    "MSETransportGuidByte3",
    "MSETransportGuidByte6",
    "MSETransportSeat",
    "MSETransportOrientation",
    "MSETransportPositionX",
    "MSETransportGuidByte0",
    "MSETransportPositionY",
    "MSETransportTime3",
    "MSETransportGuidByte7",
    "MSETransportTime2",
    "MSETransportPositionZ",
    "MSETransportGuidByte2",
    "MSEOrientation",
    "MSEFallTime",
    "MSEFallSinAngle",
    "MSEFallCosAngle",
    "MSEFallHorizontalSpeed",
    "MSEFallVerticalSpeed",
    "MSEPitch",
    "MSETimestamp",
    "MSESplineElevation",
)

_SKYFIRE_MOVEMENT_START_TURN_LEFT_SEQUENCE = (
    "MSEPositionZ",
    "MSEPositionX",
    "MSEPositionY",
    "MSEHasOrientation",
    "MSEHasGuidByte4",
    "MSEHasGuidByte5",
    "MSEZeroBit",
    "MSEHasTimestamp",
    "MSEZeroBit",
    "MSEZeroBit",
    "MSEHasCounter",
    "MSEHasGuidByte3",
    "MSEHasGuidByte1",
    "MSEHasMovementFlags2",
    "MSEHasMovementFlags",
    "MSEHasGuidByte0",
    "MSEHasGuidByte2",
    "MSEForcesCount",
    "MSEHasTransportData",
    "MSEHasGuidByte7",
    "MSEHasPitch",
    "MSEHasSplineElevation",
    "MSEHasFallData",
    "MSEHasGuidByte6",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte4",
    "MSEHasTransportGuidByte7",
    "MSEHasTransportTime2",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte1",
    "MSEMovementFlags",
    "MSEMovementFlags2",
    "MSEHasFallDirection",
    "MSEGuidByte7",
    "MSEGuidByte3",
    "MSEGuidByte6",
    "MSEGuidByte4",
    "MSEGuidByte1",
    "MSEForces",
    "MSEGuidByte5",
    "MSEGuidByte0",
    "MSEGuidByte2",
    "MSEFallTime",
    "MSEFallHorizontalSpeed",
    "MSEFallCosAngle",
    "MSEFallSinAngle",
    "MSEFallVerticalSpeed",
    "MSEPitch",
    "MSETransportPositionY",
    "MSETransportGuidByte3",
    "MSETransportPositionX",
    "MSETransportOrientation",
    "MSETransportGuidByte5",
    "MSETransportTime2",
    "MSETransportPositionZ",
    "MSETransportGuidByte2",
    "MSETransportGuidByte1",
    "MSETransportGuidByte7",
    "MSETransportGuidByte4",
    "MSETransportGuidByte0",
    "MSETransportTime3",
    "MSETransportSeat",
    "MSETransportGuidByte6",
    "MSETransportTime",
    "MSEOrientation",
    "MSESplineElevation",
    "MSECounter",
    "MSETimestamp",
)

_SKYFIRE_MOVEMENT_START_TURN_RIGHT_SEQUENCE = (
    "MSEPositionX",
    "MSEPositionZ",
    "MSEPositionY",
    "MSEZeroBit",
    "MSEZeroBit",
    "MSEHasGuidByte1",
    "MSEHasGuidByte0",
    "MSEHasMovementFlags",
    "MSEHasFallData",
    "MSEHasPitch",
    "MSEHasCounter",
    "MSEForcesCount",
    "MSEHasSplineElevation",
    "MSEHasMovementFlags2",
    "MSEHasOrientation",
    "MSEHasGuidByte2",
    "MSEHasTimestamp",
    "MSEHasGuidByte4",
    "MSEHasGuidByte6",
    "MSEHasGuidByte5",
    "MSEHasGuidByte3",
    "MSEZeroBit",
    "MSEHasTransportData",
    "MSEHasGuidByte7",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportTime2",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte7",
    "MSEHasTransportGuidByte4",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte1",
    "MSEMovementFlags",
    "MSEMovementFlags2",
    "MSEHasFallDirection",
    "MSEGuidByte5",
    "MSEGuidByte1",
    "MSEGuidByte3",
    "MSEGuidByte0",
    "MSEGuidByte4",
    "MSEGuidByte2",
    "MSEGuidByte6",
    "MSEForces",
    "MSEGuidByte7",
    "MSEFallSinAngle",
    "MSEFallHorizontalSpeed",
    "MSEFallCosAngle",
    "MSEFallVerticalSpeed",
    "MSEFallTime",
    "MSEPitch",
    "MSETransportTime3",
    "MSETransportGuidByte3",
    "MSETransportTime2",
    "MSETransportGuidByte7",
    "MSETransportGuidByte1",
    "MSETransportPositionX",
    "MSETransportSeat",
    "MSETransportGuidByte5",
    "MSETransportGuidByte4",
    "MSETransportGuidByte2",
    "MSETransportGuidByte0",
    "MSETransportPositionZ",
    "MSETransportTime",
    "MSETransportPositionY",
    "MSETransportGuidByte6",
    "MSETransportOrientation",
    "MSEOrientation",
    "MSETimestamp",
    "MSESplineElevation",
    "MSECounter",
)

_SKYFIRE_MOVEMENT_STOP_SEQUENCE = (
    "MSEPositionX",
    "MSEPositionY",
    "MSEPositionZ",
    "MSEHasGuidByte5",
    "MSEHasGuidByte2",
    "MSEHasFallData",
    "MSEHasGuidByte0",
    "MSEZeroBit",
    "MSEZeroBit",
    "MSEHasCounter",
    "MSEHasGuidByte1",
    "MSEForcesCount",
    "MSEHasPitch",
    "MSEHasGuidByte3",
    "MSEHasGuidByte4",
    "MSEHasTransportData",
    "MSEZeroBit",
    "MSEHasGuidByte6",
    "MSEHasMovementFlags",
    "MSEHasTimestamp",
    "MSEHasMovementFlags2",
    "MSEHasOrientation",
    "MSEHasSplineElevation",
    "MSEHasGuidByte7",
    "MSEHasTransportTime2",
    "MSEHasTransportGuidByte7",
    "MSEHasTransportGuidByte4",
    "MSEHasTransportGuidByte1",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportTime3",
    "MSEHasTransportGuidByte6",
    "MSEHasFallDirection",
    "MSEMovementFlags2",
    "MSEMovementFlags",
    "MSEGuidByte0",
    "MSEGuidByte3",
    "MSEForces",
    "MSEGuidByte6",
    "MSEGuidByte1",
    "MSEGuidByte4",
    "MSEGuidByte2",
    "MSEGuidByte5",
    "MSEGuidByte7",
    "MSEOrientation",
    "MSEFallVerticalSpeed",
    "MSEFallHorizontalSpeed",
    "MSEFallSinAngle",
    "MSEFallCosAngle",
    "MSEFallTime",
    "MSESplineElevation",
    "MSETransportPositionX",
    "MSETransportTime",
    "MSETransportGuidByte3",
    "MSETransportOrientation",
    "MSETransportPositionY",
    "MSETransportGuidByte2",
    "MSETransportGuidByte6",
    "MSETransportGuidByte7",
    "MSETransportGuidByte1",
    "MSETransportGuidByte4",
    "MSETransportTime3",
    "MSETransportGuidByte0",
    "MSETransportSeat",
    "MSETransportPositionZ",
    "MSETransportGuidByte5",
    "MSETransportTime2",
    "MSECounter",
    "MSEPitch",
    "MSETimestamp",
)

_SKYFIRE_MOVEMENT_STOP_TURN_SEQUENCE = (
    "MSEPositionX",
    "MSEPositionZ",
    "MSEPositionY",
    "MSEHasTransportData",
    "MSEForcesCount",
    "MSEZeroBit",
    "MSEHasGuidByte4",
    "MSEHasGuidByte5",
    "MSEHasCounter",
    "MSEHasGuidByte3",
    "MSEZeroBit",
    "MSEHasFallData",
    "MSEHasGuidByte0",
    "MSEHasGuidByte1",
    "MSEHasPitch",
    "MSEHasGuidByte6",
    "MSEHasMovementFlags",
    "MSEHasGuidByte2",
    "MSEZeroBit",
    "MSEHasMovementFlags2",
    "MSEHasSplineElevation",
    "MSEHasOrientation",
    "MSEHasGuidByte7",
    "MSEHasTimestamp",
    "MSEMovementFlags2",
    "MSEHasTransportGuidByte1",
    "MSEHasTransportTime3",
    "MSEHasTransportTime2",
    "MSEHasTransportGuidByte3",
    "MSEHasTransportGuidByte6",
    "MSEHasTransportGuidByte2",
    "MSEHasTransportGuidByte0",
    "MSEHasTransportGuidByte5",
    "MSEHasTransportGuidByte7",
    "MSEHasTransportGuidByte4",
    "MSEMovementFlags",
    "MSEHasFallDirection",
    "MSEGuidByte2",
    "MSEGuidByte3",
    "MSEGuidByte6",
    "MSEForces",
    "MSEGuidByte0",
    "MSEGuidByte5",
    "MSEGuidByte4",
    "MSEGuidByte7",
    "MSEGuidByte1",
    "MSETransportTime",
    "MSETransportTime3",
    "MSETransportSeat",
    "MSETransportPositionY",
    "MSETransportPositionX",
    "MSETransportTime2",
    "MSETransportGuidByte4",
    "MSETransportGuidByte3",
    "MSETransportOrientation",
    "MSETransportGuidByte0",
    "MSETransportPositionZ",
    "MSETransportGuidByte6",
    "MSETransportGuidByte7",
    "MSETransportGuidByte5",
    "MSETransportGuidByte1",
    "MSETransportGuidByte2",
    "MSEOrientation",
    "MSETimestamp",
    "MSEFallSinAngle",
    "MSEFallCosAngle",
    "MSEFallHorizontalSpeed",
    "MSEFallVerticalSpeed",
    "MSEFallTime",
    "MSECounter",
    "MSESplineElevation",
    "MSEPitch",
)

_SKYFIRE_FLYING_MOVEMENT_SEQUENCES = {
    "MSG_MOVE_HEARTBEAT": _SKYFIRE_MOVEMENT_HEARTBEAT_SEQUENCE,
    "MSG_MOVE_START_FORWARD": _SKYFIRE_MOVEMENT_START_FORWARD_SEQUENCE,
    "MSG_MOVE_START_BACKWARD": _SKYFIRE_MOVEMENT_START_BACKWARD_SEQUENCE,
    "MSG_MOVE_START_TURN_LEFT": _SKYFIRE_MOVEMENT_START_TURN_LEFT_SEQUENCE,
    "MSG_MOVE_START_TURN_RIGHT": _SKYFIRE_MOVEMENT_START_TURN_RIGHT_SEQUENCE,
    "MSG_MOVE_STOP": _SKYFIRE_MOVEMENT_STOP_SEQUENCE,
    "MSG_MOVE_STOP_TURN": _SKYFIRE_MOVEMENT_STOP_TURN_SEQUENCE,
    "MSG_MOVE_START_ASCEND": _SKYFIRE_MOVEMENT_START_ASCEND_SEQUENCE,
    "MSG_MOVE_STOP_ASCEND": _SKYFIRE_MOVEMENT_STOP_ASCEND_SEQUENCE,
    "MSG_MOVE_START_DESCEND": _SKYFIRE_MOVEMENT_START_DESCEND_SEQUENCE,
}

_SMSG_PLAYER_MOVE_JUMP_CONTROL_NO_DIRECTION = bytes.fromhex("8A0C0800000000")
_SMSG_PLAYER_MOVE_JUMP_CONTROL_WITH_DIRECTION = bytes.fromhex("8A4C0800000000")


def _movement_sync_guid(
    session,
    player: Player | None = None,
) -> int:
    if player is not None:
        return int(player.character_guid)
    return int(getattr(session, "char_guid", 0) or _player_guid(session) or 0)


def _movement_state(session):
    state = getattr(session, "movement_state", None)
    state_created = state is None
    if state is None:
        from server.session.world_session import MovementState

        state = MovementState()
        session.movement_state = state
    if state_created:
        from server.modules.handlers.world.position.publication import (
            publish_absolute,
        )

        publish_absolute(
            session,
            map_id=int(getattr(session, "map_id", 0) or 0),
            instance_id=int(getattr(session, "instance_id", 0) or 0),
            x=float(getattr(session, "x", 0.0) or 0.0),
            y=float(getattr(session, "y", 0.0) or 0.0),
            z=float(getattr(session, "z", 0.0) or 0.0),
            orientation=float(getattr(session, "orientation", 0.0) or 0.0),
        )
    previous_orientation = float(getattr(state, "orientation", getattr(session, "orientation", 0.0)) or 0.0)
    ensured_orientation = float(getattr(state, "orientation", getattr(session, "orientation", 0.0)) or 0.0)
    Logger.info(
        "[ORIENTATION_WRITE] writer=_movement_state target=movement_state.orientation "
        "reason=ensure_state_defaults old=%.6f new=%.6f player_attached_to_transport=%s "
        "session_pos=(%.3f %.3f %.3f) session_orientation=%.6f "
        "movement_pos=(%.3f %.3f %.3f) movement_orientation=%.6f "
        "transport_guid=0x%016X transport_offset=(%.3f %.3f %.3f) "
        "transport_orientation=%.6f attach_state=%s",
        float(previous_orientation),
        float(ensured_orientation),
        bool(
            int(getattr(state, "transport_guid", 0) or 0)
            or str(getattr(session, "transport_attach_state", "") or "") in {"ATTACHED", "TRANSFERRING"}
        ),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
        float(getattr(state, "x", 0.0) or 0.0),
        float(getattr(state, "y", 0.0) or 0.0),
        float(getattr(state, "z", 0.0) or 0.0),
        float(previous_orientation),
        int(getattr(state, "transport_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
        float(getattr(state, "transport_x", 0.0) or 0.0),
        float(getattr(state, "transport_y", 0.0) or 0.0),
        float(getattr(state, "transport_z", 0.0) or 0.0),
        float(getattr(state, "transport_orientation", 0.0) or 0.0),
        str(getattr(session, "transport_attach_state", "") or ""),
    )
    state.flags = int(getattr(state, "flags", 0) or 0)
    state.flags2 = int(getattr(state, "flags2", 0) or 0)
    state.timestamp_ms = int(getattr(state, "timestamp_ms", 0) or 0) & 0xFFFFFFFF
    state.client_timestamp_ms = int(getattr(state, "client_timestamp_ms", 0) or 0) & 0xFFFFFFFF
    state.server_movement_timestamp_ms = int(
        getattr(state, "server_movement_timestamp_ms", 0) or 0
    ) & 0xFFFFFFFF
    state.pitch = float(getattr(state, "pitch", 0.0) or 0.0)
    state.last_valid_orientation = float(
        getattr(
            state,
            "last_valid_orientation",
            getattr(session, "last_valid_orientation", getattr(session, "orientation", 0.0)),
        )
        or 0.0
    )
    if math.isclose(float(state.last_valid_orientation), 0.0, abs_tol=1e-6):
        session_orientation = _normalize_orientation(getattr(session, "orientation", None))
        if session_orientation is not None and not math.isclose(
            float(session_orientation),
            0.0,
            abs_tol=1e-6,
        ):
            state.last_valid_orientation = float(session_orientation)
    state.counter = int(getattr(state, "counter", 0) or 0) & 0xFFFFFFFF
    state.is_ascending = bool(getattr(state, "is_ascending", False))
    state.is_descending = bool(getattr(state, "is_descending", False))
    return state


def _wrap_pitch(value: float) -> float:
    wrapped = math.fmod(float(value) + math.pi, math.tau)
    if wrapped < 0.0:
        wrapped += math.tau
    return wrapped - math.pi


def _movement_is_flying(session) -> bool:
    state = getattr(session, "movement_state", None)
    state_flags = int(getattr(state, "flags", 0) or 0)
    if state_flags & _MOVEMENTFLAG_SWIMMING:
        return False
    return bool(
        getattr(session, "is_flying", False)
        or state_flags & _MOVEMENTFLAG_FLYING
    )


def _has_active_flying_mount(session) -> bool:
    """Return true while a restored mount should own flying state.

    Login restore can race with stale client fall packets.  Keep this check
    small and explicit so landing handling cannot accidentally confirm those.
    """
    state = getattr(session, "movement_state", None)
    state_flags = int(getattr(state, "flags", 0) or 0)
    if state_flags & _MOVEMENTFLAG_SWIMMING:
        return False
    return bool(getattr(session, "can_fly", False)) and int(getattr(session, "mount_spell", 0) or 0) > 0


def _movement_is_airborne(session) -> bool:
    state = _movement_state(session)
    state_flags = int(getattr(state, "flags", 0) or 0)
    return bool(state_flags & _MOVEMENTFLAG_FALLING or getattr(state, "has_fall_data", False))


def _read_u32(payload: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from("<I", payload, offset)[0], offset + 4


def _read_i8(payload: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from("<b", payload, offset)[0], offset + 1


def _read_f32(payload: bytes, offset: int) -> tuple[float, int]:
    return struct.unpack_from("<f", payload, offset)[0], offset + 4


def _byte_seq_present(flag_map: dict[str, bool], element: str) -> bool:
    if element.startswith("MSEGuidByte"):
        return bool(flag_map.get(f"MSEHasGuidByte{element[-1]}", False))
    if element.startswith("MSETransportGuidByte"):
        return bool(flag_map.get(f"MSEHasTransportGuidByte{element[-1]}", False))
    return True


def _read_skyfire_movement_bit_fields(
    payload: bytes,
    sequence: tuple[str, ...],
) -> tuple[dict[str, Any], int]:
    values: dict[str, Any] = {
        "hasMovementFlags": False,
        "hasMovementFlags2": False,
        "hasTimestamp": False,
        "hasOrientation": False,
        "hasTransportData": False,
        "hasTransportTime2": False,
        "hasTransportTime3": False,
        "hasTransportVehicleId": False,
        "hasPitch": False,
        "hasFallData": False,
        "hasFallDirection": False,
        "hasSplineElevation": False,
        "hasCounter": False,
        "forcesCount": 0,
        "flags": 0,
        "flags2": 0,
    }
    byte_pos = 0
    bit_pos = 0

    for element in sequence:
        if element.startswith("MSEHasGuidByte") or element.startswith("MSEHasTransportGuidByte"):
            if element.startswith("MSEHasTransportGuidByte") and not values["hasTransportData"]:
                continue
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values[element] = bool(bit)
            continue
        if element == "MSEHasMovementFlags":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasMovementFlags"] = not bool(bit)
            continue
        if element == "MSEHasMovementFlags2":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasMovementFlags2"] = not bool(bit)
            continue
        if element == "MSEHasTimestamp":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasTimestamp"] = not bool(bit)
            continue
        if element == "MSEHasOrientation":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasOrientation"] = not bool(bit)
            continue
        if element == "MSEHasTransportData":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasTransportData"] = bool(bit)
            continue
        if element == "MSEHasTransportTime2":
            if values["hasTransportData"]:
                bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
                values["hasTransportTime2"] = bool(bit)
            continue
        if element == "MSEHasTransportTime3":
            if values["hasTransportData"]:
                bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
                values["hasTransportTime3"] = bool(bit)
            continue
        if element == "MSEHasTransportVehicleId":
            if values["hasTransportData"]:
                bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
                values["hasTransportVehicleId"] = bool(bit)
            continue
        if element == "MSEHasPitch":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasPitch"] = not bool(bit)
            continue
        if element == "MSEHasFallData":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasFallData"] = bool(bit)
            continue
        if element == "MSEHasFallDirection":
            if values["hasFallData"]:
                bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
                values["hasFallDirection"] = bool(bit)
            continue
        if element == "MSEHasSplineElevation":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasSplineElevation"] = not bool(bit)
            continue
        if element == "MSEHasCounter":
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            values["hasCounter"] = not bool(bit)
            continue
        if element == "MSEForcesCount":
            count, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 22)
            values["forcesCount"] = int(count)
            continue
        if element == "MSEMovementFlags":
            if values["hasMovementFlags"]:
                flags, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 30)
                values["flags"] = int(flags)
            continue
        if element == "MSEMovementFlags2":
            if values["hasMovementFlags2"]:
                flags2, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 13)
                values["flags2"] = int(flags2)
            continue
        if element in {"MSEZeroBit", "MSEOneBit"}:
            _bit, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
            continue

    byte_offset = int(byte_pos + (1 if bit_pos else 0))
    return values, byte_offset


def _should_use_skyfire_flying_sequence(session, opcode_name: str) -> bool:
    if opcode_name in {
        "MSG_MOVE_START_FORWARD",
        "MSG_MOVE_START_BACKWARD",
        "MSG_MOVE_START_TURN_LEFT",
        "MSG_MOVE_START_TURN_RIGHT",
        "MSG_MOVE_STOP",
        "MSG_MOVE_STOP_TURN",
        "MSG_MOVE_START_ASCEND",
        "MSG_MOVE_STOP_ASCEND",
        "MSG_MOVE_START_DESCEND",
        "MSG_MOVE_STOP_DESCEND",
    }:
        return True
    if opcode_name != "MSG_MOVE_HEARTBEAT":
        return False
    if _movement_is_flying(session) or _movement_is_airborne(session):
        return True
    if int(getattr(_movement_state(session), "transport_guid", 0) or 0):
        return True
    return False


def _parse_skyfire_flying_movement_info(
    session,
    opcode_name: str,
    payload: bytes,
) -> Optional[dict[str, Any]]:
    if not _should_use_skyfire_flying_sequence(session, opcode_name):
        return None
    sequence = _SKYFIRE_FLYING_MOVEMENT_SEQUENCES.get(opcode_name)
    if sequence is None or not payload:
        return None

    try:
        flags: dict[str, Any] = {
            "hasMovementFlags": False,
            "hasMovementFlags2": False,
            "hasTimestamp": False,
            "hasOrientation": False,
            "hasTransportData": False,
            "hasTransportTime2": False,
            "hasTransportTime3": False,
            "hasTransportVehicleId": False,
            "hasPitch": False,
            "hasFallData": False,
            "hasFallDirection": False,
            "hasSplineElevation": False,
            "hasCounter": False,
            "forcesCount": 0,
            "flags": 0,
            "flags2": 0,
        }
        cursor = 0
        bit_pos = 0

        def _align_cursor() -> None:
            nonlocal cursor, bit_pos
            if bit_pos:
                cursor += 1
                bit_pos = 0

        def _read_bit_value() -> int:
            nonlocal cursor, bit_pos
            bit, cursor, bit_pos = BitInterPreter.read_bit(payload, cursor, bit_pos)
            return int(bit)

        def _read_bits_value(width: int) -> int:
            nonlocal cursor, bit_pos
            value, cursor, bit_pos = BitInterPreter.read_bits(payload, cursor, bit_pos, width)
            return int(value)

        parsed: dict[str, Any] = {
            "x": float(getattr(session, "x", 0.0) or 0.0),
            "y": float(getattr(session, "y", 0.0) or 0.0),
            "z": float(getattr(session, "z", 0.0) or 0.0),
            "orientation": float(getattr(session, "orientation", 0.0) or 0.0),
            "pitch": float(getattr(_movement_state(session), "pitch", 0.0) or 0.0),
            "flags": int(flags["flags"]),
            "flags2": int(flags["flags2"]),
            "timestamp": None,
            "has_fall_data": bool(flags["hasFallData"]),
            "has_fall_direction": bool(flags["hasFallDirection"]),
            "fall_time": 0,
            "fall_vertical_speed": 0.0,
            "fall_horizontal_speed": 0.0,
            "fall_sin_angle": 0.0,
            "fall_cos_angle": 0.0,
            "has_transport_data": False,
            "transport_guid": 0,
            "transport_x": 0.0,
            "transport_y": 0.0,
            "transport_z": 0.0,
            "transport_orientation": 0.0,
            "transport_time": 0,
            "transport_time2": 0,
            "transport_time3": 0,
            "transport_seat": -1,
            "transport_vehicle_id": 0,
            "parser_path": f"skyfire_sequence:{opcode_name}",
        }
        transport_guid_bytes = [0] * 8

        for element in sequence:
            if element.startswith("MSEHasGuidByte") or element.startswith("MSEHasTransportGuidByte"):
                if element.startswith("MSEHasTransportGuidByte") and not flags["hasTransportData"]:
                    continue
                flags[element] = bool(_read_bit_value())
                continue
            if element == "MSEHasMovementFlags":
                flags["hasMovementFlags"] = not bool(_read_bit_value())
                continue
            if element == "MSEHasMovementFlags2":
                flags["hasMovementFlags2"] = not bool(_read_bit_value())
                continue
            if element == "MSEHasTimestamp":
                flags["hasTimestamp"] = not bool(_read_bit_value())
                continue
            if element == "MSEHasOrientation":
                flags["hasOrientation"] = not bool(_read_bit_value())
                continue
            if element == "MSEHasTransportData":
                flags["hasTransportData"] = bool(_read_bit_value())
                continue
            if element == "MSEHasTransportTime2":
                if flags["hasTransportData"]:
                    flags["hasTransportTime2"] = bool(_read_bit_value())
                continue
            if element == "MSEHasTransportTime3":
                if flags["hasTransportData"]:
                    flags["hasTransportTime3"] = bool(_read_bit_value())
                continue
            if element == "MSEHasTransportVehicleId":
                if flags["hasTransportData"]:
                    flags["hasTransportVehicleId"] = bool(_read_bit_value())
                continue
            if element == "MSEHasPitch":
                flags["hasPitch"] = not bool(_read_bit_value())
                continue
            if element == "MSEHasFallData":
                flags["hasFallData"] = bool(_read_bit_value())
                continue
            if element == "MSEHasFallDirection":
                if flags["hasFallData"]:
                    flags["hasFallDirection"] = bool(_read_bit_value())
                continue
            if element == "MSEHasSplineElevation":
                flags["hasSplineElevation"] = not bool(_read_bit_value())
                continue
            if element == "MSEHasCounter":
                flags["hasCounter"] = not bool(_read_bit_value())
                continue
            if element == "MSEForcesCount":
                flags["forcesCount"] = _read_bits_value(22)
                continue
            if element == "MSEMovementFlags":
                if flags["hasMovementFlags"]:
                    flags["flags"] = _read_bits_value(30)
                continue
            if element == "MSEMovementFlags2":
                if flags["hasMovementFlags2"]:
                    flags["flags2"] = _read_bits_value(13)
                continue
            if element in {"MSEZeroBit", "MSEOneBit"}:
                _read_bit_value()
                continue

            _align_cursor()
            if element in {"MSEGuidByte0", "MSEGuidByte1", "MSEGuidByte2", "MSEGuidByte3", "MSEGuidByte4", "MSEGuidByte5", "MSEGuidByte6", "MSEGuidByte7"}:
                if _byte_seq_present(flags, element):
                    cursor += 1
                continue
            if element in {
                "MSETransportGuidByte0",
                "MSETransportGuidByte1",
                "MSETransportGuidByte2",
                "MSETransportGuidByte3",
                "MSETransportGuidByte4",
                "MSETransportGuidByte5",
                "MSETransportGuidByte6",
                "MSETransportGuidByte7",
            }:
                if flags["hasTransportData"] and _byte_seq_present(flags, element):
                    byte_index = int(element[-1])
                    transport_guid_bytes[byte_index] = _decode_guid_byte_seq(
                        payload[cursor]
                    )
                    cursor += 1
                continue
            if element == "MSEPositionX":
                parsed["x"], cursor = _read_f32(payload, cursor)
                continue
            if element == "MSEPositionY":
                parsed["y"], cursor = _read_f32(payload, cursor)
                continue
            if element == "MSEPositionZ":
                parsed["z"], cursor = _read_f32(payload, cursor)
                continue
            if element == "MSEOrientation":
                if flags["hasOrientation"]:
                    orientation, cursor = _read_f32(payload, cursor)
                    parsed["orientation"] = float(orientation)
                continue
            if element == "MSEPitch":
                if flags["hasPitch"]:
                    pitch, cursor = _read_f32(payload, cursor)
                    parsed["pitch"] = _wrap_pitch(pitch)
                continue
            if element == "MSETimestamp":
                if flags["hasTimestamp"]:
                    parsed["timestamp"], cursor = _read_u32(payload, cursor)
                continue
            if element == "MSEFallTime":
                if flags["hasFallData"]:
                    parsed["fall_time"], cursor = _read_u32(payload, cursor)
                continue
            if element == "MSEFallVerticalSpeed":
                if flags["hasFallData"]:
                    parsed["fall_vertical_speed"], cursor = _read_f32(payload, cursor)
                continue
            if element == "MSEFallCosAngle":
                if flags["hasFallData"] and flags["hasFallDirection"]:
                    parsed["fall_cos_angle"], cursor = _read_f32(payload, cursor)
                continue
            if element == "MSEFallSinAngle":
                if flags["hasFallData"] and flags["hasFallDirection"]:
                    parsed["fall_sin_angle"], cursor = _read_f32(payload, cursor)
                continue
            if element == "MSEFallHorizontalSpeed":
                if flags["hasFallData"] and flags["hasFallDirection"]:
                    parsed["fall_horizontal_speed"], cursor = _read_f32(payload, cursor)
                continue
            if element == "MSECounter":
                if flags["hasCounter"]:
                    _counter, cursor = _read_u32(payload, cursor)
                continue
            if element == "MSEForces":
                cursor += int(flags["forcesCount"]) * 4
                continue
            if element in {
                "MSETransportPositionX",
                "MSETransportPositionY",
                "MSETransportPositionZ",
                "MSETransportOrientation",
                "MSETransportTime",
                "MSETransportTime2",
                "MSETransportTime3",
                "MSESplineElevation",
                "MSETransportVehicleId",
            }:
                if element == "MSESplineElevation":
                    if flags["hasSplineElevation"]:
                        _spline, cursor = _read_f32(payload, cursor)
                elif flags["hasTransportData"]:
                    if element == "MSETransportOrientation":
                        value, cursor = _read_f32(payload, cursor)
                        parsed["transport_orientation"] = float(value)
                    elif element in {"MSETransportPositionX", "MSETransportPositionY", "MSETransportPositionZ"}:
                        value, cursor = _read_f32(payload, cursor)
                        if element == "MSETransportPositionX":
                            parsed["transport_x"] = float(value)
                        elif element == "MSETransportPositionY":
                            parsed["transport_y"] = float(value)
                        else:
                            parsed["transport_z"] = float(value)
                    elif element == "MSETransportTime":
                        value, cursor = _read_u32(payload, cursor)
                        parsed["transport_time"] = int(value)
                    elif element == "MSETransportTime2" and flags["hasTransportTime2"]:
                        value, cursor = _read_u32(payload, cursor)
                        parsed["transport_time2"] = int(value)
                    elif element == "MSETransportTime3" and flags["hasTransportTime3"]:
                        value, cursor = _read_u32(payload, cursor)
                        parsed["transport_time3"] = int(value)
                    elif element == "MSETransportVehicleId" and flags["hasTransportVehicleId"]:
                        value, cursor = _read_u32(payload, cursor)
                        parsed["transport_vehicle_id"] = int(value)
                continue
            if element == "MSETransportSeat":
                if flags["hasTransportData"]:
                    seat, cursor = _read_i8(payload, cursor)
                    parsed["transport_seat"] = int(seat)
                continue

        parsed["flags"] = int(flags["flags"])
        parsed["flags2"] = int(flags["flags2"])
        parsed["has_fall_data"] = bool(flags["hasFallData"])
        parsed["has_fall_direction"] = bool(flags["hasFallDirection"])
        parsed["has_transport_data"] = bool(flags["hasTransportData"])
        if parsed["has_transport_data"]:
            parsed["transport_guid"] = _guid_from_bytes(transport_guid_bytes)

        Logger.debug(
            "[FLY_PARSE] opcode=%s path=%s len=%u pos=(%.6f, %.6f, %.6f) "
            "orientation=%.6f pitch=%.6f flags=0x%X flags2=0x%X timestamp=%s fall=%s transport=%s",
            opcode_name,
            parsed["parser_path"],
            len(payload),
            float(parsed["x"]),
            float(parsed["y"]),
            float(parsed["z"]),
            float(parsed["orientation"]),
            float(parsed["pitch"]),
            int(parsed["flags"]),
            int(parsed["flags2"]),
            "None" if parsed["timestamp"] is None else int(parsed["timestamp"]),
            bool(parsed["has_fall_data"]),
            "yes" if parsed["has_transport_data"] else "no",
        )
        if parsed["has_transport_data"]:
            Logger.info(
                "[TRANSPORT_PARSE] opcode=%s tguid=0x%016X "
                "tpos=(%.3f %.3f %.3f) torient=%.3f "
                "time=%s time2=%s time3=%s seat=%s vehicle=%s "
                "world=(%.3f %.3f %.3f) flags=0x%X fall=%s",
                opcode_name,
                int(parsed["transport_guid"]) & 0xFFFFFFFFFFFFFFFF,
                float(parsed["transport_x"]),
                float(parsed["transport_y"]),
                float(parsed["transport_z"]),
                float(parsed["transport_orientation"]),
                int(parsed["transport_time"]),
                int(parsed["transport_time2"]),
                int(parsed["transport_time3"]),
                int(parsed["transport_seat"]),
                int(parsed["transport_vehicle_id"]),
                float(parsed["x"]),
                float(parsed["y"]),
                float(parsed["z"]),
                int(parsed["flags"]),
                bool(parsed["has_fall_data"]),
            )
        return parsed
    except (IndexError, struct.error):
        Logger.debug(
            "[FLY_PARSE] opcode=%s path=skyfire_sequence failed len=%u",
            opcode_name,
            len(payload),
        )
        return None


def _remember_valid_orientation(session, orientation: float | None) -> None:
    normalized = _normalize_orientation(orientation)
    if normalized is None or math.isclose(float(normalized), 0.0, abs_tol=1e-6):
        return
    state = _movement_state(session)
    state.last_valid_orientation = float(normalized)
    setattr(session, "last_valid_orientation", float(normalized))


def _last_known_valid_orientation(session) -> float | None:
    state = _movement_state(session)
    for value in (
        getattr(state, "last_valid_orientation", None),
        getattr(session, "last_valid_orientation", None),
    ):
        normalized = _normalize_orientation(value)
        if normalized is not None and not math.isclose(float(normalized), 0.0, abs_tol=1e-6):
            return float(normalized)
    return None


def _sync_session_from_movement_state(session) -> None:
    state = _movement_state(session)
    from server.modules.handlers.world.position.publication import (
        publish_from_movement,
    )

    _log_orientation_write(
        session,
        writer="_sync_session_from_movement_state",
        target="session.orientation",
        old_value=float(getattr(session, "orientation", 0.0) or 0.0),
        new_value=float(state.orientation),
        reason="sync_from_movement_state",
    )
    publish_from_movement(
        session,
        x=float(state.x),
        y=float(state.y),
        z=float(state.z),
        orientation=float(state.orientation),
    )
    _remember_valid_orientation(session, state.orientation)


def _player_attached_to_transport(session) -> bool:
    state = _movement_state(session)
    return bool(
        int(getattr(state, "transport_guid", 0) or 0)
        or str(getattr(session, "transport_attach_state", "") or "") in {"ATTACHED", "TRANSFERRING"}
    )


def _log_orientation_write(
    session,
    *,
    writer: str,
    target: str,
    old_value: float,
    new_value: float,
    reason: str,
) -> None:
    state = _movement_state(session)
    Logger.info(
        "[ORIENTATION_WRITE] writer=%s target=%s reason=%s "
        "old=%.6f new=%.6f player_attached_to_transport=%s "
        "session_pos=(%.3f %.3f %.3f) session_orientation=%.6f "
        "movement_pos=(%.3f %.3f %.3f) movement_orientation=%.6f "
        "transport_guid=0x%016X transport_offset=(%.3f %.3f %.3f) "
        "transport_orientation=%.6f attach_state=%s",
        str(writer),
        str(target),
        str(reason),
        float(old_value),
        float(new_value),
        bool(_player_attached_to_transport(session)),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
        float(getattr(state, "x", 0.0) or 0.0),
        float(getattr(state, "y", 0.0) or 0.0),
        float(getattr(state, "z", 0.0) or 0.0),
        float(getattr(state, "orientation", 0.0) or 0.0),
        int(getattr(state, "transport_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
        float(getattr(state, "transport_x", 0.0) or 0.0),
        float(getattr(state, "transport_y", 0.0) or 0.0),
        float(getattr(state, "transport_z", 0.0) or 0.0),
        float(getattr(state, "transport_orientation", 0.0) or 0.0),
        str(getattr(session, "transport_attach_state", "") or ""),
    )


def _store_transport_state_from_parsed(session, opcode_name: str, parsed: dict[str, Any]) -> None:
    state = _movement_state(session)
    previous_guid = int(getattr(state, "transport_guid", 0) or 0)
    parsed_has_transport = bool(parsed.get("has_transport_data"))
    parsed_transport_guid = int(parsed.get("transport_guid", 0) or 0)

    if previous_guid:
        try:
            from server.modules.handlers.world.transport_runtime import (
                detach_session_transport_passenger,
                validate_attached_passenger_geometry,
            )

            geometry_valid, geometry_reason, geometry = validate_attached_passenger_geometry(
                session,
                has_transport_data=parsed_has_transport,
                transport_guid=parsed_transport_guid,
                world_x=float(parsed.get("x", getattr(session, "x", 0.0)) or 0.0),
                world_y=float(parsed.get("y", getattr(session, "y", 0.0)) or 0.0),
                world_z=float(parsed.get("z", getattr(session, "z", 0.0)) or 0.0),
                local_x=float(parsed.get("transport_x", 0.0) or 0.0),
                local_y=float(parsed.get("transport_y", 0.0) or 0.0),
                local_z=float(parsed.get("transport_z", 0.0) or 0.0),
            )
            if not geometry_valid:
                Logger.info(
                    "[TransportDetach] geometric departure opcode=%s player=%s "
                    "transport=0x%016X reason=%s metrics=%s",
                    opcode_name,
                    int(getattr(session, "char_guid", 0) or 0),
                    previous_guid & 0xFFFFFFFFFFFFFFFF,
                    geometry_reason,
                    geometry,
                )
                detach_session_transport_passenger(
                    session,
                    opcode_name=opcode_name,
                    reason=f"geometric_departure:{geometry_reason}",
                    world_guid=previous_guid,
                )
                return
        except Exception as exc:
            Logger.warning(
                "[TransportAttach] geometric validation failed open err=%s",
                exc,
            )

    if (
        bool(getattr(session, "_worldporttest_active", False))
        and not bool(getattr(session, "_worldporttest_first_movement_logged", False))
    ):
        session._worldporttest_first_movement_logged = True
        Logger.info(
            "[WorldportTest] first_movement opcode=%s transport=%s",
            opcode_name,
            "yes" if bool(parsed.get("has_transport_data")) else "no",
        )

    if not bool(parsed.get("has_transport_data")):
        if previous_guid:
            if _has_active_transport_transition(session):
                session._transport_missing_metadata_guid = 0
                session._transport_missing_metadata_count = 0
                return
            try:
                from server.modules.handlers.world.transport_runtime import (
                    consume_movement_rebuild_transport_guard,
                )

                if consume_movement_rebuild_transport_guard(session, previous_guid):
                    session._transport_missing_metadata_guid = 0
                    session._transport_missing_metadata_count = 0
                    return
            except Exception as exc:
                Logger.warning(
                    "[TransportAttach] movement rebuild guard failed err=%s",
                    exc,
                )
            missing_guid = int(
                getattr(session, "_transport_missing_metadata_guid", 0) or 0
            )
            missing_count = int(
                getattr(session, "_transport_missing_metadata_count", 0) or 0
            )
            if missing_guid != previous_guid:
                missing_count = 0
            missing_count += 1
            session._transport_missing_metadata_guid = previous_guid
            session._transport_missing_metadata_count = missing_count
            if missing_count < _TRANSPORT_METADATA_MISSING_CONFIRMATION_PACKETS:
                return
            session._transport_missing_metadata_guid = 0
            session._transport_missing_metadata_count = 0
            try:
                from server.modules.handlers.world.transport_runtime import detach_session_transport_passenger

                detach_session_transport_passenger(
                    session,
                    opcode_name=opcode_name,
                    reason="client_clear",
                    world_guid=previous_guid,
                    clear_pending_transfer=not (
                        bool(getattr(session, "teleport_pending", False))
                        or bool(getattr(session, "worldport_ack_pending", False))
                    ),
                )
            except Exception as exc:
                Logger.warning("[TransportDetach] lifecycle notify failed err=%s", exc)
            _clear_stale_transport_transfer_pending(
                session,
                previous_guid,
                reason="client_clear",
            )
        if not previous_guid:
            state.has_transport_data = False
            state.transport_guid = 0
            state.transport_x = 0.0
            state.transport_y = 0.0
            state.transport_z = 0.0
            state.transport_orientation = 0.0
            state.transport_time = 0
            state.transport_time2 = 0
            state.transport_time3 = 0
            state.transport_seat = -1
            state.transport_vehicle_id = 0
        return

    transport_guid = int(parsed.get("transport_guid", 0) or 0)
    try:
        from server.modules.handlers.world.transport_runtime import (
            clear_movement_rebuild_transport_guard,
        )

        clear_movement_rebuild_transport_guard(session)
    except Exception:
        pass
    session._transport_missing_metadata_guid = 0
    session._transport_missing_metadata_count = 0
    if previous_guid != transport_guid:
        if previous_guid:
            try:
                from server.modules.handlers.world.transport_runtime import detach_session_transport_passenger

                detach_session_transport_passenger(
                    session,
                    reason="new_transport",
                    world_guid=previous_guid,
                    opcode_name=opcode_name,
                )
            except Exception as exc:
                Logger.warning("[TransportDetach] previous transport detach failed err=%s", exc)
        try:
            from server.modules.handlers.world.transport_runtime import can_attach_transport

            if not can_attach_transport(session, transport_guid):
                try:
                    from server.modules.handlers.world.transport_runtime import detach_session_transport_passenger

                    detach_session_transport_passenger(
                        session,
                        reason="attach_rejected",
                        world_guid=transport_guid,
                        opcode_name=opcode_name,
                    )
                except Exception:
                    state.has_transport_data = False
                    state.transport_guid = 0
                Logger.warning(
                    "[TransportAttach] rejected opcode=%s tguid=0x%016X player=%s",
                    opcode_name,
                    transport_guid & 0xFFFFFFFFFFFFFFFF,
                    int(getattr(session, "char_guid", 0) or 0),
                )
                return
        except Exception as exc:
            Logger.warning("[TransportAttach] lifecycle validation failed err=%s", exc)

    try:
        from server.modules.handlers.world.transport_runtime import (
            record_transport_attach,
            update_transport_passenger_offset,
        )

        publish_offset = (
            record_transport_attach
            if previous_guid != transport_guid
            else update_transport_passenger_offset
        )
        publish_offset(
            session,
            transport_guid,
            **({"opcode_name": opcode_name} if previous_guid != transport_guid else {}),
            local_x=float(parsed.get("transport_x", 0.0) or 0.0),
            local_y=float(parsed.get("transport_y", 0.0) or 0.0),
            local_z=float(parsed.get("transport_z", 0.0) or 0.0),
            local_o=float(parsed.get("transport_orientation", 0.0) or 0.0),
            transport_time=int(parsed.get("transport_time", 0) or 0),
            transport_time2=int(parsed.get("transport_time2", 0) or 0),
            transport_time3=int(parsed.get("transport_time3", 0) or 0),
            seat=int(parsed.get("transport_seat", -1)),
            vehicle_id=int(parsed.get("transport_vehicle_id", 0) or 0),
        )
    except Exception as exc:
        Logger.warning("[TransportAttach] lifecycle notify failed err=%s", exc)


def _log_transport_parse_unknown_preserve(session, opcode_name: str, transport_guid: int) -> None:
    _ = session, opcode_name, transport_guid


def _transport_entry_for_guid(session, transport_guid: int) -> dict[str, Any] | None:
    try:
        from server.modules.handlers.world.transport_runtime import authoritative_transport_entry_for_guid

        entry = authoritative_transport_entry_for_guid(int(transport_guid))
        if isinstance(entry, dict):
            return entry
    except Exception:
        pass

    loaded_transport_entries = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transport_entries, dict):
        entry = loaded_transport_entries.get(int(transport_guid))
        if isinstance(entry, dict):
            return entry

    return None


def _is_real_runtime_elevator_entry(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    try:
        from server.modules.handlers.world.feature_config import elevators_enabled

        if not elevators_enabled():
            return False
    except Exception:
        return False
    try:
        from server.modules.handlers.world.transport_runtime import (
            GAMEOBJECT_TYPE_TRANSPORT,
            is_runtime_transport_entry,
            is_thunder_bluff_elevator_entry,
        )
    except Exception:
        return False
    if is_thunder_bluff_elevator_entry(entry):
        return True
    return bool(
        int(entry.get("type", 0) or 0) == GAMEOBJECT_TYPE_TRANSPORT
        and is_runtime_transport_entry(entry)
    )


def _has_loaded_real_runtime_elevator(session) -> bool:
    loaded_transport_entries = getattr(session, "loaded_transport_entries", None)
    return bool(isinstance(loaded_transport_entries, dict) and any(
        _is_real_runtime_elevator_entry(entry)
        for entry in loaded_transport_entries.values()
        if isinstance(entry, dict)
    ))


def _clear_transport_state(session) -> None:
    state = _movement_state(session)
    state.has_transport_data = False
    state.transport_guid = 0
    state.transport_x = 0.0
    state.transport_y = 0.0
    state.transport_z = 0.0
    state.transport_orientation = 0.0
    state.transport_time = 0
    state.transport_time2 = 0
    state.transport_time3 = 0
    state.transport_seat = -1
    state.transport_vehicle_id = 0


def _clear_loaded_world_objects_for_transfer(session) -> list[tuple[str, bytes]]:
    map_id = int(getattr(session, "map_id", 0) or 0)
    responses: list[tuple[str, bytes]] = []
    loaded_sets = (
        getattr(session, "loaded_gameobjects", None),
        getattr(session, "loaded_npcs", None),
    )
    for loaded_guids in loaded_sets:
        if not isinstance(loaded_guids, set):
            continue
        for guid in sorted(int(value) for value in loaded_guids):
            if int(guid) <= 0:
                continue
            responses.append(
                (
                    "SMSG_UPDATE_OBJECT",
                    _build_out_of_range_update_object_payload(map_id=map_id, guid=int(guid)),
                )
            )
        loaded_guids.clear()
    loaded_transport_entries = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transport_entries, dict):
        loaded_transport_entries.clear()
    loaded_gameobject_entries = getattr(session, "loaded_gameobject_entries", None)
    if isinstance(loaded_gameobject_entries, dict):
        loaded_gameobject_entries.clear()
    return responses


def _pending_transport_transfer_matches(
    session,
    transport_guid: int,
) -> bool:
    pending = getattr(session, "pending_transport_transfer", None)
    if not isinstance(pending, dict):
        return True
    source_guid = int(pending.get("source_guid", 0) or 0)
    destination_guid = int(pending.get("destination_guid", 0) or 0)
    return int(transport_guid) in {source_guid, destination_guid}


def _clear_stale_transport_transfer_pending(
    session,
    transport_guid: int,
    *,
    reason: str,
) -> bool:
    if not bool(getattr(session, "transport_transfer_pending", False)):
        return False
    if bool(getattr(session, "teleport_pending", False)):
        return False
    if bool(getattr(session, "worldport_ack_pending", False)):
        return False
    if not _pending_transport_transfer_matches(session, int(transport_guid)):
        return False

    Logger.info(
        "[TRANSPORT_TRANSFER_STATE_CLEAR] reason=%s transport_guid=0x%016X "
        "player_guid=%s pending=%s",
        str(reason),
        int(transport_guid) & 0xFFFFFFFFFFFFFFFF,
        int(getattr(session, "char_guid", 0) or 0),
        getattr(session, "pending_transport_transfer", None),
    )
    session.transport_transfer_pending = False
    session.pending_transport_transfer = None
    return True


def _disabled_legacy_transport_route_transfer_impl(
    session,
    opcode_name: str,
    forced_destination_map: int | None = None,
) -> list[tuple[str, bytes]]:
    state = _movement_state(session)
    transport_guid = int(getattr(state, "transport_guid", 0) or 0)
    Logger.info(
        "[TransportBoundary] legacy_transfer_initiator_suppressed "
        "source=movement opcode=%s player=%s transport_guid=0x%016X "
        "forced_destination_map=%s",
        str(opcode_name),
        int(getattr(session, "char_guid", 0) or 0),
        transport_guid & 0xFFFFFFFFFFFFFFFF,
        "none" if forced_destination_map is None else int(forced_destination_map),
    )
    return []
    state = _movement_state(session)
    transport_guid = int(getattr(state, "transport_guid", 0) or 0)

    if transport_guid <= 0:
        return []
    if bool(getattr(session, "transport_transfer_pending", False)):
        if _clear_stale_transport_transfer_pending(
            session,
            transport_guid,
            reason="stale_pending",
        ):
            pass
        else:
            return []
    if _is_teleporting(session):
        return []

    entry = _transport_entry_for_guid(session, transport_guid)
    if not isinstance(entry, dict):
        return []

    try:
        from server.modules.handlers.world.transport_runtime import (
            cached_transport_runtime_entry,
            ensure_linked_transport_destination_entry,
            is_cross_map_boat_entry,
            is_cross_map_zeppelin_entry,
            linked_transport_world_guid,
            runtime_transport_state_for_guid,
            transport_transfer_destination_map_for_guid,
        )
        from server.modules.handlers.world.movements.manager import get_movement_manager
    except Exception as exc:
        Logger.warning("[TransportTransfer] runtime unavailable err=%s", exc)
        return []

    runtime_state = runtime_transport_state_for_guid(transport_guid)
    if runtime_state is None:
        moved_entry = cached_transport_runtime_entry(session, entry)
        runtime_state = runtime_transport_state_for_guid(transport_guid)
        if runtime_state is None:
            return []
        entry = moved_entry

    source_map = int(getattr(session, "map_id", 0) or 0)
    if forced_destination_map is not None:
        destination = int(forced_destination_map)
    else:
        destination = transport_transfer_destination_map_for_guid(transport_guid)
    if destination is None:
        return []
    destination_map = int(destination)
    if destination_map == source_map:
        return []

    canonical_world_db_transfer = bool(getattr(runtime_state, "world_db_transport", False))
    if canonical_world_db_transfer:
        destination_guid = int(getattr(runtime_state, "guid", transport_guid) or transport_guid)
    else:
        destination_guid = int(linked_transport_world_guid(entry, map_id=destination_map))
    transfer_check_id = (
        f"check-{int(transport_guid)}-"
        f"{int(getattr(runtime_state, 'path_progress_ms', 0) or 0)}"
    )
    passenger_membership = bool(
        int(getattr(session, "char_guid", 0) or 0)
        in (getattr(runtime_state, "passengers", None) or {})
    )
    logically_attached = bool(
        getattr(session, "player_attached_to_transport", False)
        or str(getattr(session, "transport_attach_state", "") or "") == "ATTACHED"
    )
    passenger_transfer = get_movement_manager().begin_passenger_transfer(
        int(transport_guid),
        int(destination_guid),
        int(getattr(session, "char_guid", 0) or 0),
        target_map_id=int(destination_map),
    )
    if passenger_transfer is None:
        Logger.warning(
            "[TransportTransfer] passenger transfer rejected player=%s transport=0x%016X",
            int(getattr(session, "char_guid", 0) or 0),
            transport_guid & 0xFFFFFFFFFFFFFFFF,
        )
        _transport_player_debug(
            session,
            "abort",
            "[Transport] ABORT reason=passenger_transfer_rejected",
            transfer_id=transfer_check_id,
        )
        return []
    local_x = float(passenger_transfer.local_x)
    local_y = float(passenger_transfer.local_y)
    local_z = float(passenger_transfer.local_z)
    local_o = float(passenger_transfer.local_o)
    if canonical_world_db_transfer:
        destination_entry = dict(entry)
        destination_entry["world_guid"] = int(destination_guid)
        destination_entry["map"] = int(destination_map)
        destination_entry["map_id"] = int(destination_map)
        destination_entry["home_map"] = int(destination_map)
    else:
        destination_entry = ensure_linked_transport_destination_entry(
            entry,
            destination_map=destination_map,
            source_state=runtime_state,
        )
    destination_entry = cached_transport_runtime_entry(session, destination_entry)
    destination_base_source = "route_node_fallback"
    if (
        canonical_world_db_transfer
        and int(
            getattr(runtime_state, "map_id")
            if getattr(runtime_state, "map_id", None) is not None
            else -1
        ) == int(destination_map)
    ):
        destination_base_source = "runtime_state"
        destination_x = float(getattr(runtime_state, "x", 0.0) or 0.0)
        destination_y = float(getattr(runtime_state, "y", 0.0) or 0.0)
        destination_z = float(getattr(runtime_state, "z", 0.0) or 0.0)
        destination_o = float(getattr(runtime_state, "orientation", 0.0) or 0.0)
        destination_entry["map"] = int(destination_map)
        destination_entry["map_id"] = int(destination_map)
        destination_entry["x"] = destination_x
        destination_entry["y"] = destination_y
        destination_entry["z"] = destination_z
        destination_entry["orientation"] = destination_o
    else:
        destination_node = _transport_route_node_for_map(runtime_state, destination_map)
        if destination_node is not None:
            destination_x = float(getattr(destination_node, "x", 0.0) or 0.0)
            destination_y = float(getattr(destination_node, "y", 0.0) or 0.0)
            destination_z = float(getattr(destination_node, "z", 0.0) or 0.0)
            destination_o = float(getattr(runtime_state, "orientation", 0.0) or 0.0)
            destination_entry["map"] = int(destination_map)
            destination_entry["map_id"] = int(destination_map)
            destination_entry["x"] = destination_x
            destination_entry["y"] = destination_y
            destination_entry["z"] = destination_z
            destination_entry["orientation"] = destination_o
        elif int(destination_entry.get("map", destination_map)) == destination_map:
            destination_x = float(destination_entry.get("x", getattr(runtime_state, "x", 0.0)) or 0.0)
            destination_y = float(destination_entry.get("y", getattr(runtime_state, "y", 0.0)) or 0.0)
            destination_z = float(destination_entry.get("z", getattr(runtime_state, "z", 0.0)) or 0.0)
            destination_o = float(destination_entry.get("orientation", getattr(runtime_state, "orientation", 0.0)) or 0.0)
        else:
            destination_x = float(getattr(runtime_state, "x", 0.0) or 0.0)
            destination_y = float(getattr(runtime_state, "y", 0.0) or 0.0)
            destination_z = float(getattr(runtime_state, "z", 0.0) or 0.0)
            destination_o = float(getattr(runtime_state, "orientation", 0.0) or 0.0)
            destination_entry["map"] = int(destination_map)
            destination_entry["map_id"] = int(destination_map)
            destination_entry["x"] = destination_x
            destination_entry["y"] = destination_y
            destination_entry["z"] = destination_z
            destination_entry["orientation"] = destination_o

    player_x = destination_x + local_x
    player_y = destination_y + local_y
    player_z = destination_z + local_z
    player_o = destination_o + local_o
    source_player_x = float(getattr(session, "x", 0.0) or 0.0)
    source_player_y = float(getattr(session, "y", 0.0) or 0.0)
    source_player_z = float(getattr(session, "z", 0.0) or 0.0)
    source_player_o = float(getattr(session, "orientation", 0.0) or 0.0)
    transfer_id = (
        f"{int(getattr(session, 'char_guid', 0) or 0)}-"
        f"{int(time.monotonic() * 1000.0)}"
    )
    session.transport_debug_transfer_id = transfer_id
    is_boat = is_cross_map_boat_entry(destination_entry)
    is_zeppelin = is_cross_map_zeppelin_entry(destination_entry)
    transport_kind = "boat" if is_boat else "zeppelin" if is_zeppelin else "other"
    diagnostic_transport = bool(is_boat or is_zeppelin)

    session.transport_transfer_pending = True
    session.teleport_pending = True
    session.worldport_ack_pending = True
    session.near_teleport_pending = False
    session.teleport_destination = (
        f"transport:{int(entry.get('entry', 0) or 0)}:"
        f"{source_map}->{destination_map}"
    )
    session.pending_transport_transfer = {
        "transfer_id": transfer_id,
        "source_guid": int(transport_guid),
        "destination_guid": int(destination_guid),
        "source_map": int(source_map),
        "destination_map": int(destination_map),
        "node_index": int(getattr(runtime_state, "node_index", 0) or 0),
        "route_phase": int(getattr(runtime_state, "path_progress_ms", 0) or 0),
        "local_x": local_x,
        "local_y": local_y,
        "local_z": local_z,
        "local_o": local_o,
        "base_source": str(destination_base_source),
        "base_x": float(destination_x),
        "base_y": float(destination_y),
        "base_z": float(destination_z),
        "base_o": float(destination_o),
        "final_x": float(player_x),
        "final_y": float(player_y),
        "final_z": float(player_z),
        "final_o": float(player_o),
        "destination_entry": dict(destination_entry),
    }
    if diagnostic_transport:
        Logger.info(
            "[TransportTransferDiag] start transfer_id=%s kind=%s source_guid=0x%016X "
            "destination_guid=0x%016X source_map=%s destination_map=%s "
            "player_world=(%.3f %.3f %.3f %.3f) local_offset=(%.3f %.3f %.3f %.3f) "
            "transport_world=(%.3f %.3f %.3f %.3f) snapshot_world=(%.3f %.3f %.3f %.3f) "
            "snapshot_base_source=%s",
            transfer_id,
            transport_kind,
            transport_guid & 0xFFFFFFFFFFFFFFFF,
            destination_guid & 0xFFFFFFFFFFFFFFFF,
            source_map,
            destination_map,
            source_player_x,
            source_player_y,
            source_player_z,
            source_player_o,
            local_x,
            local_y,
            local_z,
            local_o,
            float(getattr(runtime_state, "x", 0.0) or 0.0),
            float(getattr(runtime_state, "y", 0.0) or 0.0),
            float(getattr(runtime_state, "z", 0.0) or 0.0),
            float(getattr(runtime_state, "orientation", 0.0) or 0.0),
            player_x,
            player_y,
            player_z,
            player_o,
            destination_base_source,
        )
        Logger.info(
            "[TransportTransfer] transfer_begin transfer_id=%s transport_guid=0x%016X "
            "player=%s route_phase=%s",
            transfer_id,
            destination_guid & 0xFFFFFFFFFFFFFFFF,
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(runtime_state, "path_progress_ms", 0) or 0),
        )
    try:
        from server.modules.handlers.world.transport_runtime import record_transport_detach

        record_transport_detach(
            session,
            transport_guid,
            opcode_name=opcode_name,
            reason="transfer",
        )
    except Exception as exc:
        Logger.warning("[TransportTransfer] source lifecycle detach failed err=%s", exc)
    session.transport_attach_state = "TRANSFERRING"

    from server.modules.handlers.world.position.publication import (
        publish_absolute,
    )

    publish_absolute(
        session,
        map_id=int(destination_map),
        instance_id=int(getattr(session, "instance_id", 0) or 0),
        x=float(player_x),
        y=float(player_y),
        z=float(player_z),
        orientation=float(player_o),
    )
    # During the cross-map handoff there is intentionally no destination-side
    # PassengerAttachment yet; this is transition snapshot data, not a live
    # local-offset publication.
    state.has_transport_data = True
    state.transport_guid = int(destination_guid)
    state.transport_x = local_x
    state.transport_y = local_y
    state.transport_z = local_z
    state.transport_orientation = local_o
    state.transport_time = int(getattr(runtime_state, "path_progress_ms", 0) or 0) & 0xFFFFFFFF
    state.transport_time2 = int(getattr(state, "transport_time2", 0) or 0) & 0xFFFFFFFF
    state.transport_time3 = int(getattr(state, "transport_time3", 0) or 0) & 0xFFFFFFFF
    _log_orientation_write(
        session,
        writer="_maybe_start_transport_route_transfer",
        target="movement_state.orientation",
        old_value=float(getattr(state, "orientation", 0.0) or 0.0),
        new_value=float(player_o),
        reason="route_transition_begin_worldport",
    )

    Logger.info(
        "[TransportTransfer] begin transport=0x%016X node=%s source_map=%s dest_map=%s",
        transport_guid & 0xFFFFFFFFFFFFFFFF,
        int(getattr(runtime_state, "node_index", 0) or 0),
        source_map,
        destination_map,
    )
    Logger.info(
        "[TransportTransfer] passenger saved player=%s local=(%.3f %.3f %.3f %.3f) "
        "dest_transport=0x%016X route_phase=%s",
        int(getattr(session, "char_guid", 0) or 0),
        local_x,
        local_y,
        local_z,
        local_o,
        destination_guid & 0xFFFFFFFFFFFFFFFF,
        int(getattr(runtime_state, "path_progress_ms", 0) or 0),
    )
    Logger.info(
        "[TRANSPORT_PASSENGER] player=%s transport=0x%016X relative_x=%.3f "
        "relative_y=%.3f relative_z=%.3f relative_o=%.3f reattached=false map_transition=%s->%s",
        int(getattr(session, "char_guid", 0) or 0),
        destination_guid & 0xFFFFFFFFFFFFFFFF,
        local_x,
        local_y,
        local_z,
        local_o,
        source_map,
        destination_map,
    )
    Logger.info(
        "[TransportTransfer] worldport player=%s map=%s pos=(%.2f %.2f %.2f %.2f)",
        int(getattr(session, "char_guid", 0) or 0),
        destination_map,
        player_x,
        player_y,
        player_z,
        player_o,
    )
    Logger.info(
        "[TransportTransfer] pre_worldport_transport_state "
        "attached=%s runtime_passenger=%s has_transport_data=%s "
        "transport_guid=0x%016X offset=(%.3f %.3f %.3f %.6f)",
        bool(_player_attached_to_transport(session)),
        bool(passenger_membership),
        bool(getattr(state, "has_transport_data", False)),
        int(getattr(state, "transport_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
        float(getattr(state, "transport_x", 0.0) or 0.0),
        float(getattr(state, "transport_y", 0.0) or 0.0),
        float(getattr(state, "transport_z", 0.0) or 0.0),
        float(getattr(state, "transport_orientation", 0.0) or 0.0),
    )
    if diagnostic_transport:
        Logger.info(
            "[TransportTransferDiag] before_new_world transfer_id=%s kind=%s "
            "world=(%.3f %.3f %.3f %.3f) position_source=snapshot base_source=%s",
            transfer_id,
            transport_kind,
            player_x,
            player_y,
            player_z,
            player_o,
            (
                "runtime_transport"
                if destination_base_source == "runtime_state"
                else "fallback"
            ),
        )
    from server.modules.handlers.world.teleport.map_transfer import (
        TeleportDestination,
        apply_map_transfer,
    )

    responses = apply_map_transfer(
        session,
        TeleportDestination(
            map_id=int(destination_map),
            x=float(player_x),
            y=float(player_y),
            z=float(player_z),
            orientation=float(player_o),
            name=(
                f"transport:{int(entry.get('entry', 0) or 0)}:"
                f"{source_map}->{destination_map}"
            ),
        ),
        reason="transport",
        keep_transport=True,
        source_map_id=int(source_map),
        transport_entry=int(entry.get("entry", 0) or 0),
    )
    return responses


def _transport_route_node_for_map(runtime_state, map_id: int):
    route = getattr(runtime_state, "route", ()) or ()
    for node in route:
        if int(getattr(node, "map_id", -1)) == int(map_id):
            return node
    return None


def _transfer_local_value(passenger_transfer, pending: dict, name: str) -> float:
    return float(getattr(passenger_transfer, str(name), pending.get(str(name), 0.0)) or 0.0)


def _log_transport_worldport_ack_diagnostics(session, pending: dict[str, Any] | None) -> None:
    if not isinstance(pending, dict):
        return
    destination_entry = pending.get("destination_entry")
    if not isinstance(destination_entry, dict):
        return
    try:
        from server.modules.handlers.world.transport_runtime import (
            is_cross_map_boat_entry,
            is_cross_map_zeppelin_entry,
            runtime_transport_state_for_guid,
        )
    except Exception:
        return
    is_boat = is_cross_map_boat_entry(destination_entry)
    is_zeppelin = is_cross_map_zeppelin_entry(destination_entry)
    if not (is_boat or is_zeppelin):
        return

    destination_guid = int(pending.get("destination_guid", 0) or 0)
    runtime_state = runtime_transport_state_for_guid(destination_guid)
    local_x = float(pending.get("local_x", 0.0) or 0.0)
    local_y = float(pending.get("local_y", 0.0) or 0.0)
    local_z = float(pending.get("local_z", 0.0) or 0.0)
    local_o = float(pending.get("local_o", 0.0) or 0.0)
    current = (
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )
    if runtime_state is not None:
        runtime_position = (
            float(getattr(runtime_state, "x", 0.0) or 0.0),
            float(getattr(runtime_state, "y", 0.0) or 0.0),
            float(getattr(runtime_state, "z", 0.0) or 0.0),
            float(getattr(runtime_state, "orientation", 0.0) or 0.0),
        )
        calculated = (
            runtime_position[0] + local_x,
            runtime_position[1] + local_y,
            runtime_position[2] + local_z,
            runtime_position[3] + local_o,
        )
        delta = math.dist(current[:3], calculated[:3])
    else:
        runtime_position = (0.0, 0.0, 0.0, 0.0)
        calculated = (
            float(pending.get("final_x", current[0]) or current[0]),
            float(pending.get("final_y", current[1]) or current[1]),
            float(pending.get("final_z", current[2]) or current[2]),
            float(pending.get("final_o", current[3]) or current[3]),
        )
        delta = math.dist(current[:3], calculated[:3])

    Logger.info(
        "[TransportTransferDiag] worldport_ack transfer_id=%s kind=%s "
        "destination_guid=0x%016X runtime_found=%s runtime_world=(%.3f %.3f %.3f) "
        "runtime_orientation=%.3f local_offset=(%.3f %.3f %.3f %.3f) "
        "current_world=(%.3f %.3f %.3f %.3f) calculated_world=(%.3f %.3f %.3f %.3f) "
        "world_delta=%.3f",
        str(pending.get("transfer_id", "unknown") or "unknown"),
        "boat" if is_boat else "zeppelin",
        destination_guid & 0xFFFFFFFFFFFFFFFF,
        "true" if runtime_state is not None else "false",
        runtime_position[0],
        runtime_position[1],
        runtime_position[2],
        runtime_position[3],
        local_x,
        local_y,
        local_z,
        local_o,
        *current,
        *calculated,
        delta,
    )
    Logger.info(
        "[TransportTransfer] worldport_ack transfer_id=%s transport_guid=0x%016X "
        "transport_found=%s retry=0",
        str(pending.get("transfer_id", "unknown") or "unknown"),
        destination_guid & 0xFFFFFFFFFFFFFFFF,
        "true" if runtime_state is not None else "false",
    )
    if runtime_state is None:
        Logger.info(
            "[TransportTransfer] fallback transfer_id=%s transport_guid=0x%016X "
            "reason=transport_not_found",
            str(pending.get("transfer_id", "unknown") or "unknown"),
            destination_guid & 0xFFFFFFFFFFFFFFFF,
        )


def _maybe_start_transport_route_transfer(
    session,
    opcode_name: str,
    forced_destination_map: int | None = None,
) -> list[tuple[str, bytes]]:
    state = _movement_state(session)
    transport_guid = int(getattr(state, "transport_guid", 0) or 0)
    Logger.info(
        "[TransportBoundary] legacy_transfer_initiator_suppressed "
        "source=movement opcode=%s player=%s transport_guid=0x%016X "
        "forced_destination_map=%s",
        str(opcode_name),
        int(getattr(session, "char_guid", 0) or 0),
        transport_guid & 0xFFFFFFFFFFFFFFFF,
        "none" if forced_destination_map is None else int(forced_destination_map),
    )
    return []


def complete_pending_transport_transfer(session) -> bool:
    """Complete the current transport-owned worldport, if one is pending.

    Destination bootstrap is the canonical completion boundary.  The worldport
    ACK handler also calls this helper as a compatibility path, so completion
    must remain safe when bootstrap has already retired the transfer.
    """
    pending = getattr(session, "pending_transport_transfer", None)
    if not isinstance(pending, dict):
        session.pending_transport_transfer = None
        session.transport_transfer_pending = False
        return False

    from server.modules.handlers.world.teleport.transition import (
        pending_transition_is_current,
    )

    if not pending_transition_is_current(session, pending):
        log_transport_event(
            TransportDebugEvent.STALE_GENERATION_IGNORED,
            transport_guid=int(pending.get("destination_guid", 0) or 0),
            player_guid=int(getattr(session, "char_guid", 0) or 0),
            transfer_id=str(pending.get("transfer_id", "") or ""),
            reason=(
                f"pending:{pending.get('world_transition_generation')} "
                f"current:{int(getattr(session, 'world_transition_generation', 0) or 0)}"
            ),
        )
        _transport_debug_log(
            "[TeleportTransition] ignoring superseded transport completion "
            "pending_generation=%s current_generation=%s",
            pending.get("world_transition_generation"),
            int(getattr(session, "world_transition_generation", 0) or 0),
        )
        session.pending_transport_transfer = None
        session.transport_transfer_pending = False
        return False

    state = _movement_state(session)
    destination_guid = int(pending.get("destination_guid", 0) or 0)
    destination_entry = pending.get("destination_entry")
    if destination_guid > 0:
        state.has_transport_data = True
        state.transport_guid = destination_guid
        state.transport_x = _transfer_local_value(None, pending, "local_x")
        state.transport_y = _transfer_local_value(None, pending, "local_y")
        state.transport_z = _transfer_local_value(None, pending, "local_z")
        state.transport_orientation = _transfer_local_value(None, pending, "local_o")
        loaded = getattr(session, "loaded_transport_entries", None)
        if not isinstance(loaded, dict):
            loaded = {}
            session.loaded_transport_entries = loaded
        if isinstance(destination_entry, dict):
            loaded[destination_guid] = dict(destination_entry)
        session.transport_attach_state = "ATTACHED"
        session.transport_attached_guid = destination_guid
        session.transport_attach_source_map = int(
            pending.get("destination_map", getattr(session, "map_id", 0)) or 0
        )
        _transport_debug_log(
            "[TransportBoundary] transfer_complete_preserve_attachment player=%s "
            "transport=0x%016X "
            "local=(%.3f %.3f %.3f %.3f)",
            int(getattr(session, "char_guid", 0) or 0),
            destination_guid & 0xFFFFFFFFFFFFFFFF,
            float(state.transport_x),
            float(state.transport_y),
            float(state.transport_z),
            float(state.transport_orientation),
        )
    _transport_debug_log(
        "[TransportBoundary] completed player=%s source_map=%s dest_map=%s "
        "node=%s route_phase=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(pending.get("source_map", 0) or 0),
        int(pending.get("destination_map", 0) or 0),
        int(pending.get("node_index", 0) or 0),
        int(pending.get("route_phase", 0) or 0),
    )
    try:
        from server.modules.handlers.world.transport_runtime import (
            finalize_transport_boundary_event,
        )

        finalize_transport_boundary_event(pending, outcome="completed")
    except Exception as exc:
        Logger.warning(
            "[TransportBoundary] completion finalization failed error=%s",
            str(exc),
        )
    session.pending_transport_transfer = None
    session.transport_transfer_pending = False
    if destination_guid > 0:
        event_fields = {
            "transport_guid": destination_guid,
            "player_guid": int(getattr(session, "char_guid", 0) or 0),
            "transfer_id": str(pending.get("transfer_id", "") or ""),
            "destination": transport_location(
                map_id=int(pending.get("destination_map", getattr(session, "map_id", 0)) or 0)
            ),
        }
        log_transport_event(
            TransportDebugEvent.PASSENGER_TRANSFER_COMPLETED,
            **event_fields,
        )
        log_transport_event(
            TransportDebugEvent.WORLDPORT_COMPLETED,
            **event_fields,
        )
    _transport_debug_log(
        "[TransportTransfer] transfer_state_cleared transfer_id=%s player=%s",
        str(pending.get("transfer_id", "unknown") or "unknown"),
        int(getattr(session, "char_guid", 0) or 0),
    )
    return True


def _complete_pending_transport_transfer(session) -> bool:
    """Compatibility alias for existing internal callers and tests."""
    return complete_pending_transport_transfer(session)


def _disabled_legacy_queue_pending_transport_transfer_post_bootstrap(session) -> bool:
    """Queue optional boat/zeppelin reattachment without mutating transfer state."""
    if isinstance(getattr(session, "pending_transport_transfer", None), dict):
        Logger.info(
            "[TransportBoundary] post_bootstrap_reattach_not_queued "
            "reason=boundary_lifecycle player=%s",
            int(getattr(session, "char_guid", 0) or 0),
        )
    return False
    pending = getattr(session, "pending_transport_transfer", None)
    if not isinstance(pending, dict):
        return False
    destination_entry = pending.get("destination_entry")
    if not isinstance(destination_entry, dict):
        return False
    try:
        from server.modules.handlers.world.transport_runtime import (
            is_cross_map_boat_entry,
            is_cross_map_zeppelin_entry,
        )
    except Exception:
        return False
    if not (
        is_cross_map_boat_entry(destination_entry)
        or is_cross_map_zeppelin_entry(destination_entry)
    ):
        return False

    transfer_id = str(pending.get("transfer_id", "unknown") or "unknown")
    destination_guid = int(pending.get("destination_guid", 0) or 0)
    session.post_bootstrap_transport_reattach_request = {
        "transfer_id": transfer_id,
        "destination_guid": destination_guid,
    }
    Logger.info(
        "[TransportTransfer] post_bootstrap_reattach_queued transfer_id=%s "
        "transport_guid=0x%016X",
        transfer_id,
        destination_guid & 0xFFFFFFFFFFFFFFFF,
    )
    return True


def _disabled_legacy_complete_queued_post_bootstrap_transport_reattach(
    session,
) -> list[tuple[str, bytes]]:
    """Run a queued boat/zeppelin reattach after bootstrap packets were sent."""
    if isinstance(getattr(session, "post_bootstrap_transport_reattach_request", None), dict):
        Logger.info(
            "[TransportBoundary] post_bootstrap_reattach_suppressed "
            "reason=boundary_lifecycle player=%s",
            int(getattr(session, "char_guid", 0) or 0),
        )
        session.post_bootstrap_transport_reattach_request = None
    return []
    request = getattr(session, "post_bootstrap_transport_reattach_request", None)
    if not isinstance(request, dict):
        return []
    session.post_bootstrap_transport_reattach_request = None

    transfer_id = str(request.get("transfer_id", "unknown") or "unknown")
    destination_guid = int(request.get("destination_guid", 0) or 0)
    debug_responses: list[tuple[str, bytes]] = []

    def add_debug(stage: str, text: str) -> None:
        try:
            from server.modules.handlers.world.transport_debug_messages import build_message

            response = build_message(
                session,
                stage,
                text,
                transfer_id=transfer_id,
            )
            if response is not None:
                debug_responses.append(response)
        except Exception as exc:
            Logger.warning("[TransportDebug] response failed stage=%s error=%s", stage, str(exc))
    Logger.info(
        "[TransportTransfer] post_bootstrap_reattach_attempt transfer_id=%s "
        "transport_guid=0x%016X",
        transfer_id,
        destination_guid & 0xFFFFFFFFFFFFFFFF,
    )

    pending = getattr(session, "pending_transport_transfer", None)
    if not isinstance(pending, dict):
        Logger.warning(
            "[TransportTransfer] post_bootstrap_reattach_failed transfer_id=%s "
            "transport_guid=0x%016X reason=pending_missing",
            transfer_id,
            destination_guid & 0xFFFFFFFFFFFFFFFF,
        )
        add_debug(
            "reattach",
            "[Transport] REATTACH guid=0x%016X success=no" % (destination_guid & 0xFFFFFFFFFFFFFFFF),
        )
        return debug_responses
    if (
        str(pending.get("transfer_id", "unknown") or "unknown") != transfer_id
        or int(pending.get("destination_guid", 0) or 0) != destination_guid
    ):
        Logger.warning(
            "[TransportTransfer] post_bootstrap_reattach_failed transfer_id=%s "
            "transport_guid=0x%016X reason=pending_changed",
            transfer_id,
            destination_guid & 0xFFFFFFFFFFFFFFFF,
        )
        add_debug(
            "reattach",
            "[Transport] REATTACH guid=0x%016X success=no" % (destination_guid & 0xFFFFFFFFFFFFFFFF),
        )
        return debug_responses

    try:
        from server.modules.handlers.world.transport_runtime import (
            current_runtime_transport_state_for_guid,
        )

        runtime_state = current_runtime_transport_state_for_guid(destination_guid)
    except Exception as exc:
        runtime_state = None
        runtime_error = str(exc)
    else:
        runtime_error = ""

    if runtime_state is None:
        Logger.warning(
            "[TransportTransfer] post_bootstrap_reattach_failed transfer_id=%s "
            "transport_guid=0x%016X reason=transport_not_found error=%s",
            transfer_id,
            destination_guid & 0xFFFFFFFFFFFFFFFF,
            runtime_error,
        )
        session.pending_transport_transfer = None
        session.transport_transfer_pending = False
        add_debug(
            "boat_lookup",
            "[Transport] BOAT NOT FOUND guid=0x%016X" % (destination_guid & 0xFFFFFFFFFFFFFFFF),
        )
        add_debug(
            "reattach",
            "[Transport] REATTACH guid=0x%016X success=no" % (destination_guid & 0xFFFFFFFFFFFFFFFF),
        )
        return debug_responses

    distance = math.sqrt(
        (float(getattr(session, "x", 0.0) or 0.0) - float(getattr(runtime_state, "x", 0.0) or 0.0)) ** 2
        + (float(getattr(session, "y", 0.0) or 0.0) - float(getattr(runtime_state, "y", 0.0) or 0.0)) ** 2
        + (float(getattr(session, "z", 0.0) or 0.0) - float(getattr(runtime_state, "z", 0.0) or 0.0)) ** 2
    )
    add_debug(
        "boat_lookup",
        "[Transport] BOAT FOUND guid=0x%016X distance=%.3f runtime=(%.3f,%.3f,%.3f)"
        % (
            destination_guid & 0xFFFFFFFFFFFFFFFF,
            distance,
            float(getattr(runtime_state, "x", 0.0) or 0.0),
            float(getattr(runtime_state, "y", 0.0) or 0.0),
            float(getattr(runtime_state, "z", 0.0) or 0.0),
        ),
    )
    add_debug(
        "player_sync",
        "[Transport] PLAYER SYNC player=(%.3f,%.3f,%.3f) boat=(%.3f,%.3f,%.3f) distance=%.3f"
        % (
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
            float(getattr(runtime_state, "x", 0.0) or 0.0),
            float(getattr(runtime_state, "y", 0.0) or 0.0),
            float(getattr(runtime_state, "z", 0.0) or 0.0),
            distance,
        ),
    )

    try:
        complete_pending_transport_transfer(session)
        responses = resync_movement(session)
    except Exception as exc:
        Logger.warning(
            "[TransportTransfer] post_bootstrap_reattach_failed transfer_id=%s "
            "transport_guid=0x%016X reason=exception error=%s",
            transfer_id,
            destination_guid & 0xFFFFFFFFFFFFFFFF,
            str(exc),
        )
        session.pending_transport_transfer = None
        session.transport_transfer_pending = False
        add_debug(
            "reattach",
            "[Transport] REATTACH guid=0x%016X success=no" % (destination_guid & 0xFFFFFFFFFFFFFFFF),
        )
        return debug_responses

    Logger.info(
        "[TransportTransfer] post_bootstrap_reattach_success transfer_id=%s "
        "transport_guid=0x%016X packets=%s",
        transfer_id,
        destination_guid & 0xFFFFFFFFFFFFFFFF,
        len(responses),
    )
    add_debug(
        "reattach",
        "[Transport] REATTACH guid=0x%016X success=yes" % (destination_guid & 0xFFFFFFFFFFFFFFFF),
    )
    return debug_responses + responses


def queue_pending_transport_transfer_post_bootstrap(session) -> bool:
    """Boundary lifecycle does not queue late transport reattach work."""
    if isinstance(getattr(session, "pending_transport_transfer", None), dict):
        Logger.info(
            "[TransportBoundary] post_bootstrap_reattach_not_queued "
            "reason=boundary_lifecycle player=%s",
            int(getattr(session, "char_guid", 0) or 0),
        )
    return False


def complete_queued_post_bootstrap_transport_reattach(
    session,
) -> list[tuple[str, bytes]]:
    """Boundary lifecycle suppresses late transport reattach/resync packets."""
    if isinstance(getattr(session, "post_bootstrap_transport_reattach_request", None), dict):
        Logger.info(
            "[TransportBoundary] post_bootstrap_reattach_suppressed "
            "reason=boundary_lifecycle player=%s",
            int(getattr(session, "char_guid", 0) or 0),
        )
        session.post_bootstrap_transport_reattach_request = None
    return []


def _movement_flags_for_sync(session) -> int:
    return int(_movement_state(session).flags)


def _movement_flags_for_outbound_sync(session, state=None) -> int:
    if state is None:
        state = _movement_state(session)

    flags = int(getattr(state, "flags", 0) or 0)
    can_fly = bool(getattr(session, "can_fly", False))
    is_flying = bool(getattr(session, "is_flying", False))

    if can_fly:
        flags |= _MOVEMENTFLAG_CAN_FLY
    else:
        flags &= ~_MOVEMENTFLAG_CAN_FLY

    if is_flying:
        flags |= _MOVEMENTFLAG_FLYING
    else:
        flags &= ~_MOVEMENTFLAG_FLYING

    if bool(getattr(state, "is_ascending", False)):
        flags |= _MOVEMENTFLAG_ASCENDING
        flags &= ~_MOVEMENTFLAG_DESCENDING
    elif bool(getattr(state, "is_descending", False)):
        flags |= _MOVEMENTFLAG_DESCENDING
        flags &= ~_MOVEMENTFLAG_ASCENDING
    else:
        flags &= ~(_MOVEMENTFLAG_ASCENDING | _MOVEMENTFLAG_DESCENDING)

    return int(flags)


def _movement_timestamp_ms(session) -> int:
    state = _movement_state(session)
    existing = int(getattr(state, "timestamp_ms", 0) or 0)
    now_ms = int(time.time() * 1000.0) & 0xFFFFFFFF
    if existing <= 0:
        state.timestamp_ms = now_ms
        return now_ms
    if now_ms <= existing:
        now_ms = (existing + 1) & 0xFFFFFFFF
    state.timestamp_ms = now_ms
    return now_ms


def _outbound_movement_timestamp_ms(session) -> int:
    state = _movement_state(session)
    override = getattr(session, "_taxi_movement_timestamp_override_ms", None)
    if override is not None:
        timestamp = int(override) & 0xFFFFFFFF
        state.server_movement_timestamp_ms = timestamp
        return timestamp

    existing = int(getattr(state, "server_movement_timestamp_ms", 0) or 0)
    now_ms = int(time.time() * 1000.0) & 0xFFFFFFFF
    if existing <= 0:
        state.server_movement_timestamp_ms = now_ms
        return now_ms
    if now_ms <= existing:
        now_ms = (existing + 1) & 0xFFFFFFFF
    state.server_movement_timestamp_ms = now_ms
    return now_ms


def _has_valid_fall_direction(state) -> bool:
    horizontal_speed = float(getattr(state, "fall_horizontal_speed", 0.0) or 0.0)
    sin_angle = float(getattr(state, "fall_sin_angle", 0.0) or 0.0)
    cos_angle = float(getattr(state, "fall_cos_angle", 0.0) or 0.0)
    if not all(math.isfinite(value) for value in (horizontal_speed, sin_angle, cos_angle)):
        return False
    return abs(horizontal_speed) > 1e-5 and abs(sin_angle) <= 1.001 and abs(cos_angle) <= 1.001


def build_smsg_player_move_payload_old(
    session,
    player: Player | None = None,
) -> bytes | None:
    state = _movement_state(session)
    guid_value = _movement_sync_guid(session, player)
    if guid_value <= 0:
        return None

    raw_guid = int(guid_value).to_bytes(8, "little", signed=False)
    move_flags = _movement_flags_for_outbound_sync(session, state)
    move_flags2 = int(state.flags2)
    timestamp = _outbound_movement_timestamp_ms(session)
    x = float(player.x) if player is not None else float(state.x)
    y = float(player.y) if player is not None else float(state.y)
    z = float(player.z) if player is not None else float(state.z)
    orientation = (
        float(player.orientation)
        if player is not None
        else float(state.orientation)
    )
    # Keep outbound SMSG_PLAYER_MOVE on the simpler low-guid layout that gave
    # the best visual sync so far in the sandbox. The stricter SkyFire-like
    # rewrite made the client ignore live movement again.
    has_fall_data = False
    has_fall_direction = False

    bits = BitWriter()
    bits.write_bits(1, 1)  # MSEHasPitch -> !hasPitch
    bits.write_bits(1 if raw_guid[2] else 0, 1)
    bits.write_bits(0, 1)  # MSEZeroBit
    bits.write_bits(0, 1)  # MSEZeroBit
    bits.write_bits(1 if raw_guid[0] else 0, 1)
    bits.write_bits(0, 1)  # MSEHasOrientation -> !hasOrientation
    bits.write_bits(0 if has_fall_data else 1, 1)  # MSEHasFallData -> !hasFallData
    bits.write_bits(1, 1)  # MSEHasCounter -> !counter
    bits.write_bits(1 if raw_guid[3] else 0, 1)
    bits.write_bits(0 if has_fall_direction else 1, 1)  # MSEHasFallDirection -> !hasFallDirection
    bits.write_bits(1, 1)  # MSEHasTransportData -> !hasTransportData
    bits.write_bits(1 if raw_guid[4] else 0, 1)
    bits.write_bits(1, 1)  # MSEHasSplineElevation -> !hasSplineElevation
    bits.write_bits(0 if move_flags else 1, 1)  # MSEHasMovementFlags -> !hasMovementFlags
    bits.write_bits(0, 1)  # MSEZeroBit
    if move_flags:
        bits.write_bits(int(move_flags), 30)
    bits.write_bits(0 if move_flags2 else 1, 1)  # MSEHasMovementFlags2 -> !hasMovementFlags2
    bits.write_bits(1 if raw_guid[7] else 0, 1)
    bits.write_bits(1 if raw_guid[1] else 0, 1)
    bits.write_bits(0, 1)  # MSEHasTimestamp -> !hasTimestamp
    if move_flags2:
        bits.write_bits(int(move_flags2), 13)
    bits.write_bits(1 if raw_guid[5] else 0, 1)
    bits.write_bits(0, 22)  # MSEForcesCount
    bits.write_bits(1 if raw_guid[6] else 0, 1)

    payload = bytearray(bits.getvalue())
    payload.extend(struct.pack("<f", y))  # MSEPositionY
    _append_guid_byte_seq(payload, raw_guid, (5, 1))
    payload.extend(struct.pack("<f", z))  # MSEPositionZ
    payload.extend(struct.pack("<I", timestamp))  # MSETimestamp
    payload.extend(struct.pack("<f", normalize_wire_orientation(orientation)))  # MSEOrientation
    _append_guid_byte_seq(payload, raw_guid, (3,))
    _append_guid_byte_seq(payload, raw_guid, (0, 2, 6))
    payload.extend(struct.pack("<f", x))  # MSEPositionX
    _append_guid_byte_seq(payload, raw_guid, (4, 7))
    return bytes(payload)


def build_smsg_player_move_payload_stable_old(
    session,
    player: Player | None = None,
) -> bytes | None:
    state = _movement_state(session)
    guid_value = _movement_sync_guid(session, player)
    if guid_value <= 0:
        return None

    raw_guid = int(guid_value).to_bytes(8, "little", signed=False)
    timestamp = _outbound_movement_timestamp_ms(session)
    x = float(player.x) if player is not None else float(state.x)
    y = float(player.y) if player is not None else float(state.y)
    z = float(player.z) if player is not None else float(state.z)
    orientation = (
        float(player.orientation)
        if player is not None
        else float(state.orientation)
    )
    has_fall_data = bool(getattr(state, "has_fall_data", False))
    fall_time = int(getattr(state, "fall_time", 0) or 0) & 0xFFFFFFFF
    fall_vertical_speed = float(getattr(state, "fall_vertical_speed", 0.0) or 0.0)
    if has_fall_data:
        has_fall_direction = _has_valid_fall_direction(state)
        payload = bytearray(
            _SMSG_PLAYER_MOVE_JUMP_CONTROL_WITH_DIRECTION
            if has_fall_direction
            else _SMSG_PLAYER_MOVE_JUMP_CONTROL_NO_DIRECTION
        )
        payload.extend(struct.pack("<f", y))
        payload.extend(struct.pack("<f", z))
        payload.extend(struct.pack("<I", timestamp))
        payload.extend(struct.pack("<f", normalize_wire_orientation(orientation)))
        if has_fall_direction:
            payload.extend(struct.pack("<f", float(state.fall_sin_angle)))
            payload.extend(struct.pack("<f", float(state.fall_horizontal_speed)))
            payload.extend(struct.pack("<f", float(state.fall_cos_angle)))
            payload.extend(struct.pack("<I", fall_time))
            payload.extend(struct.pack("<f", fall_vertical_speed))
        else:
            payload.extend(struct.pack("<f", fall_vertical_speed))
            payload.extend(struct.pack("<I", fall_time))
        payload.append((raw_guid[0] ^ 1) & 0xFF)
        payload.extend(struct.pack("<I", int(getattr(state, "counter", 0) or 0) & 0xFFFFFFFF))
        payload.extend(struct.pack("<f", x))
        state.counter = (int(getattr(state, "counter", 0) or 0) + 1) & 0xFFFFFFFF
        return bytes(payload)

    move_flags = _movement_flags_for_outbound_sync(session, state)
    move_flags2 = int(state.flags2)
    # Facing 0.0 is a valid orientation. Omitting it makes the normal
    # SMSG_PLAYER_MOVE layout flip between two binary shapes as players rotate
    # through zero, which causes remote drift/correction artifacts.
    has_orientation = True
    has_counter = int(getattr(state, "counter", 0) or 0) != 0
    transport_guid = int(getattr(state, "transport_guid", 0) or 0)
    has_transport_data = bool(
        getattr(state, "has_transport_data", False) and transport_guid
    )
    transport_raw_guid = transport_guid.to_bytes(8, "little", signed=False)
    has_transport_time2 = bool(int(getattr(state, "transport_time2", 0) or 0))
    has_transport_time3 = bool(int(getattr(state, "transport_time3", 0) or 0))

    bits = BitWriter()
    bits.write_bits(1, 1)  # MSEHasPitch -> !hasPitch
    bits.write_bits(1 if raw_guid[2] else 0, 1)
    bits.write_bits(0, 1)  # MSEZeroBit
    bits.write_bits(0, 1)  # MSEZeroBit
    bits.write_bits(1 if raw_guid[0] else 0, 1)
    bits.write_bits(0 if has_orientation else 1, 1)  # MSEHasOrientation -> !hasOrientation
    bits.write_bits(0 if has_fall_data else 0, 1)  # MSEHasFallData; keep no-fall stable byte-for-byte.
    bits.write_bits(0 if has_counter else 1, 1)  # MSEHasCounter -> !counter
    bits.write_bits(1 if raw_guid[3] else 0, 1)
    bits.write_bits(1 if has_transport_data else 0, 1)  # MSEHasTransportData
    bits.write_bits(1 if raw_guid[4] else 0, 1)
    if has_transport_data:
        for index in (5, 4, 7, 2, 6):
            bits.write_bits(1 if transport_raw_guid[index] else 0, 1)
        bits.write_bits(1 if has_transport_time2 else 0, 1)
        for index in (3, 1):
            bits.write_bits(1 if transport_raw_guid[index] else 0, 1)
        bits.write_bits(1 if has_transport_time3 else 0, 1)
        bits.write_bits(1 if transport_raw_guid[0] else 0, 1)
    bits.write_bits(1, 1)  # MSEHasSplineElevation -> !hasSplineElevation
    bits.write_bits(0 if move_flags else 1, 1)  # MSEHasMovementFlags -> !hasMovementFlags
    bits.write_bits(0, 1)  # MSEZeroBit
    if move_flags:
        bits.write_bits(int(move_flags), 30)
    bits.write_bits(0 if move_flags2 else 1, 1)  # MSEHasMovementFlags2 -> !hasMovementFlags2
    bits.write_bits(1 if raw_guid[7] else 0, 1)
    bits.write_bits(1 if raw_guid[1] else 0, 1)
    bits.write_bits(0 if timestamp else 1, 1)  # MSEHasTimestamp -> !hasTimestamp
    if move_flags2:
        bits.write_bits(int(move_flags2), 13)
    bits.write_bits(1 if raw_guid[5] else 0, 1)
    bits.write_bits(0, 22)  # MSEForcesCount
    bits.write_bits(1 if raw_guid[6] else 0, 1)

    payload = bytearray(bits.getvalue())
    payload.extend(struct.pack("<f", y))  # MSEPositionY
    if has_transport_data:
        if transport_raw_guid[7]:
            payload.append((transport_raw_guid[7] ^ 1) & 0xFF)
        if has_transport_time2:
            payload.extend(struct.pack("<I", int(state.transport_time2) & 0xFFFFFFFF))
        payload.extend(struct.pack("<f", float(state.transport_x)))
        if transport_raw_guid[5]:
            payload.append((transport_raw_guid[5] ^ 1) & 0xFF)
        payload.extend(struct.pack("<b", int(getattr(state, "transport_seat", -1))))
        for index in (2, 0, 3):
            if transport_raw_guid[index]:
                payload.append((transport_raw_guid[index] ^ 1) & 0xFF)
        payload.extend(struct.pack("<I", int(getattr(state, "transport_time", 0) or 0) & 0xFFFFFFFF))
        if transport_raw_guid[4]:
            payload.append((transport_raw_guid[4] ^ 1) & 0xFF)
        payload.extend(struct.pack("<f", float(state.transport_z)))
        if transport_raw_guid[1]:
            payload.append((transport_raw_guid[1] ^ 1) & 0xFF)
        payload.extend(struct.pack("<f", float(state.transport_y)))
        payload.extend(
            struct.pack(
                "<f",
                normalize_wire_orientation(float(state.transport_orientation)),
            )
        )
        if transport_raw_guid[6]:
            payload.append((transport_raw_guid[6] ^ 1) & 0xFF)
        if has_transport_time3:
            payload.extend(struct.pack("<I", int(state.transport_time3) & 0xFFFFFFFF))
    if raw_guid[5]:
        payload.append((raw_guid[5] ^ 1) & 0xFF)  # MSEGuidByte5
    if raw_guid[1]:
        payload.append((raw_guid[1] ^ 1) & 0xFF)  # MSEGuidByte1
    payload.extend(struct.pack("<f", z))  # MSEPositionZ
    if timestamp:
        payload.extend(struct.pack("<I", timestamp))  # MSETimestamp
    if has_orientation:
        payload.extend(struct.pack("<f", normalize_wire_orientation(orientation)))  # MSEOrientation
    if has_fall_data:
        payload.extend(struct.pack("<f", fall_vertical_speed))  # MSEJumpVerticalSpeed
        payload.extend(struct.pack("<I", fall_time))  # MSEFallTime
    if raw_guid[3]:
        payload.append((raw_guid[3] ^ 1) & 0xFF)  # MSEGuidByte3
    if raw_guid[0]:
        payload.append((raw_guid[0] ^ 1) & 0xFF)  # MSEGuidByte0
    if raw_guid[2]:
        payload.append((raw_guid[2] ^ 1) & 0xFF)  # MSEGuidByte2
    if raw_guid[6]:
        payload.append((raw_guid[6] ^ 1) & 0xFF)  # MSEGuidByte6
    if has_counter:
        payload.extend(struct.pack("<I", int(state.counter) & 0xFFFFFFFF))  # MSECounter
    payload.extend(struct.pack("<f", x))  # MSEPositionX
    if raw_guid[4]:
        payload.append((raw_guid[4] ^ 1) & 0xFF)  # MSEGuidByte4
    if raw_guid[7]:
        payload.append((raw_guid[7] ^ 1) & 0xFF)  # MSEGuidByte7

    state.counter = (int(getattr(state, "counter", 0) or 0) + 1) & 0xFFFFFFFF
    return bytes(payload)


def build_smsg_player_move_payload(
    session,
    player: Player | None = None,
) -> bytes | None:
    return build_smsg_player_move_payload_stable_old(session, player)


def _build_run_speed_refresh_response(session) -> tuple[str, bytes] | None:
    _sync_session_from_movement_state(session)
    payload = build_smsg_player_move_payload(session)
    if not payload:
        return None
    return ("SMSG_PLAYER_MOVE", payload)


def resync_movement(session) -> list[tuple[str, bytes]]:
    # Speed changes apply more reliably after a fresh move packet.
    response = _build_run_speed_refresh_response(session)
    if response is None:
        return []
    return [response]


def _next_speed_change_counter(session) -> int:
    state = _movement_state(session)
    counter = int(getattr(state, "counter", 0) or 0) & 0xFFFFFFFF
    state.counter = (counter + 2) & 0xFFFFFFFF
    return counter


def build_move_set_speed_payload(session, opcode_name: str, speed: float) -> bytes:
    guid_value = int(_movement_sync_guid(session) or 0)
    raw_guid = guid_value.to_bytes(8, "little", signed=False)
    counter = _next_speed_change_counter(session)
    low_guid_xor = (raw_guid[0] ^ 1) & 0xFF
    realm_guid_xor = (raw_guid[4] ^ 1) & 0xFF

    opcode_name = str(opcode_name or "").strip().upper()

    if opcode_name == "SMSG_MOVE_SET_WALK_SPEED":
        encoded = EncoderHandler.encode_packet(
            opcode_name,
            {
                "control_0": 0x44,
                "counter": counter,
                "speed": float(speed),
                "low_guid_xor": low_guid_xor,
                "realm_guid_xor": realm_guid_xor,
            },
        )
        Logger.debug(
            "[SPEED_PACKET] opcode=%s size=%s guid=0x%X speed=%.3f hex=%s",
            opcode_name,
            len(encoded),
            guid_value,
            float(speed),
            encoded.hex().upper(),
        )
        return encoded

    if opcode_name == "SMSG_MOVE_SET_RUN_SPEED":
        encoded = EncoderHandler.encode_packet(
            opcode_name,
            {
                "control_0": 0x41,
                "counter": counter,
                "realm_guid_xor": realm_guid_xor,
                "low_guid_xor": low_guid_xor,
                "speed": float(speed),
            },
        )
        Logger.debug(
            "[SPEED_PACKET] opcode=%s size=%s guid=0x%X speed=%.3f hex=%s",
            opcode_name,
            len(encoded),
            guid_value,
            float(speed),
            encoded.hex().upper(),
        )
        return encoded

    if opcode_name == "SMSG_MOVE_SET_SWIM_SPEED":
        encoded = EncoderHandler.encode_packet(
            opcode_name,
            {
                "control_0": 0x48,
                "counter": counter,
                "speed": float(speed),
                "realm_guid_xor": realm_guid_xor,
                "low_guid_xor": low_guid_xor,
            },
        )
        Logger.debug(
            "[SPEED_PACKET] opcode=%s size=%s guid=0x%X speed=%.3f hex=%s",
            opcode_name,
            len(encoded),
            guid_value,
            float(speed),
            encoded.hex().upper(),
        )
        return encoded

    if opcode_name == "SMSG_MOVE_SET_FLIGHT_SPEED":
        encoded = EncoderHandler.encode_packet(
            opcode_name,
            {
                "speed": float(speed),
                "counter": counter,
                "control_0": 0x24,
                "low_guid_xor": low_guid_xor,
                "realm_guid_xor": realm_guid_xor,
            },
        )
        Logger.debug(
            "[SPEED_PACKET] opcode=%s size=%s guid=0x%X speed=%.3f hex=%s",
            opcode_name,
            len(encoded),
            guid_value,
            float(speed),
            encoded.hex().upper(),
        )
        return encoded

    raise ValueError(f"Unsupported move-set speed opcode: {opcode_name}")


def build_move_set_run_speed_payload(session) -> bytes:
    return build_move_set_speed_payload(
        session,
        "SMSG_MOVE_SET_RUN_SPEED",
        float(getattr(session, "run_speed", 7.0) or 7.0),
    )


def build_move_set_flight_speed_payload(session) -> bytes:
    return build_move_set_speed_payload(
        session,
        "SMSG_MOVE_SET_FLIGHT_SPEED",
        float(getattr(session, "fly_speed", 7.0) or 7.0),
    )


def _flying_speed_enter_response(session, was_flying: bool) -> tuple[str, bytes] | None:
    is_flying = bool(getattr(session, "is_flying", False))
    if was_flying or not is_flying:
        return None
    run_speed = float(getattr(session, "run_speed", 7.0) or 7.0)
    session.fly_speed = float(run_speed) * 3.2
    Logger.debug(
        "[FLIGHT_SPEED] enter guid=0x%X run=%.3f fly=%.3f",
        _player_guid(session),
        float(run_speed),
        float(session.fly_speed),
    )
    return ("SMSG_MOVE_SET_FLIGHT_SPEED", build_move_set_flight_speed_payload(session))


def _landing_speed_restore_response(session) -> tuple[str, bytes]:
    Logger.debug(
        "[FLIGHT_SPEED] land guid=0x%X run=%.3f",
        _player_guid(session),
        float(getattr(session, "run_speed", 7.0) or 7.0),
    )
    return ("SMSG_MOVE_SET_RUN_SPEED", build_move_set_run_speed_payload(session))


def build_move_set_can_fly_payload(session, enabled: bool) -> bytes:
    guid_value = int(_movement_sync_guid(session) or 0)
    raw_guid = guid_value.to_bytes(8, "little", signed=False)
    low_guid_xor = (raw_guid[0] ^ 1) & 0xFF
    realm_guid_xor = (raw_guid[4] ^ 1) & 0xFF

    if enabled:
        opcode_name = "SMSG_MOVE_SET_CAN_FLY"
        encoded = EncoderHandler.encode_packet(
            opcode_name,
            {
                "control_0": 0x14,
                "control_1": 0x13,
                "low_guid_xor": low_guid_xor,
                "realm_guid_xor": realm_guid_xor,
            },
        )
    else:
        opcode_name = "SMSG_MOVE_UNSET_CAN_FLY"
        encoded = EncoderHandler.encode_packet(
            opcode_name,
            {
                "control_0": 0x24,
                "realm_guid_xor": realm_guid_xor,
                "control_2": 0x69,
                "low_guid_xor": low_guid_xor,
            },
        )

    Logger.debug(
        "[FLY_PACKET] opcode=%s size=%s guid=0x%X hex=%s",
        opcode_name,
        len(encoded),
        guid_value,
        encoded.hex().upper(),
    )
    return encoded


def build_same_map_teleport_payload(session) -> bytes:
    state = _movement_state(session)
    counter = int(getattr(state, "counter", 0) or 0) & 0xFFFFFFFF
    guid_low = int(_player_guid(session) or 0) & 0xFF

    # Pandaria 5.4.8 focus captures show the same-map teleport payload as:
    # fixed 3-byte prefix, z/y/x, counter, one low-guid byte, orientation.
    payload = bytearray(b"\x90\x00\x06")
    payload.extend(struct.pack("<f", float(getattr(session, "z", 0.0) or 0.0)))
    payload.extend(struct.pack("<f", float(getattr(session, "y", 0.0) or 0.0)))
    payload.extend(struct.pack("<f", float(getattr(session, "x", 0.0) or 0.0)))
    payload.extend(struct.pack("<I", counter))
    payload.append((guid_low ^ 1) & 0xFF)
    payload.extend(struct.pack("<f", normalize_wire_orientation(getattr(session, "orientation", 0.0) or 0.0)))

    state.counter = (counter + 1) & 0xFFFFFFFF
    return bytes(payload)


def _is_teleporting(session) -> bool:
    return bool(
        getattr(session, "near_teleport_pending", False)
        or getattr(session, "worldport_ack_pending", False)
        or getattr(session, "teleport_pending", False)
    )


def _has_active_transport_transition(session) -> bool:
    return bool(
        getattr(session, "transport_transfer_pending", False)
        or isinstance(getattr(session, "pending_transport_transfer", None), dict)
        or str(getattr(session, "world_transition_owner", "") or "")
        == "transport_worldport"
    )


def _maybe_clear_stale_near_teleport_pending_on_movement(session, opcode_name: str) -> None:
    if not bool(getattr(session, "near_teleport_pending", False)):
        return
    if bool(getattr(session, "worldport_ack_pending", False)):
        return
    if bool(getattr(session, "teleport_pending", False)):
        return
    if not all(
        math.isfinite(float(getattr(session, attr, 0.0) or 0.0))
        for attr in ("x", "y", "z", "orientation")
    ):
        return
    session.near_teleport_pending = False
    Logger.info(
        "[TELEPORT_STATE_CLEAR] reason=movement_resumed opcode=%s player=%s "
        "map=%s pos=(%.3f %.3f %.3f %.3f)",
        str(opcode_name),
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "map_id", 0) or 0),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )


def _consume_pending_teleport_on_movement(session, opcode_name: str) -> None:
    # Movement must stay usable during teleport. Pending state is cleared only
    # after accepted movement proves a same-map teleport has resumed normally.
    if not _is_teleporting(session):
        return
    Logger.debug("[Teleport] movement resumed on %s while teleport ack is pending", str(opcode_name))


def _complete_owned_near_teleport_from_movement(
    session,
    opcode_name: str,
) -> tuple[bool, list[tuple[str, bytes]]]:
    """Complete a current near teleport before the normal gameplay gate.

    The triggering movement is deliberately consumed.  It exists only as the
    client signal that the same-map teleport completed; later movement packets
    resume through the ordinary movement path.
    """
    from server.modules.handlers.world.teleport.transition import current_near_teleport_is_owned

    if not bool(getattr(session, "near_teleport_pending", False)):
        return False, []
    if (
        int(getattr(session, "near_teleport_generation", 0) or 0) <= 0
        and str(getattr(session, "world_transition_owner", "") or "")
        != "ordinary_teleport"
    ):
        return False, []
    if not current_near_teleport_is_owned(session):
        Logger.info(
            "[Teleport] near movement fallback rejected opcode=%s player=%s "
            "near_generation=%s current_generation=%s owner=%s",
            str(opcode_name),
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "near_teleport_generation", 0) or 0),
            int(getattr(session, "world_transition_generation", 0) or 0),
            str(getattr(session, "world_transition_owner", "") or "none"),
        )
        return True, []

    destination = str(getattr(session, "teleport_destination", "") or "?")
    session.near_teleport_pending = False
    session.worldport_ack_pending = False
    from server.modules.handlers.world.teleport.lifecycle import get_teleport_lifecycle

    responses = get_teleport_lifecycle().complete_transition(
        session,
        context="near-teleport-movement-fallback",
        refresh="teleport",
        resync_multiplayer=False,
        _object_refresh=stream_world_objects_after_teleport,
    )
    session.teleport_destination = None
    Logger.info(
        "[Teleport] near movement fallback completed opcode=%s player=%s "
        "destination=%s packets=%s",
        str(opcode_name),
        int(getattr(session, "char_guid", 0) or 0),
        destination,
        len(responses),
    )
    return True, responses


def _player_movement_debug_enabled() -> bool:
    try:
        from server.modules.handlers.world.feature_config import player_movement_debug_enabled

        return bool(player_movement_debug_enabled())
    except Exception:
        return False


def _movement_debug_log(session, message: str, *args) -> None:
    if not _player_movement_debug_enabled():
        return
    Logger.info(message, *args)


_MAX_MOVEMENT_POSITION_DELTA = 200.0
_MAX_MOVEMENT_Z_DELTA = 100.0
_STALE_MOVEMENT_TIMESTAMP_REJECT_MS = 10000
_POSITION_SAVE_INTERVAL_SECONDS = 30.0
_STATIONARY_EPSILON = 0.01
_SIM_TURN_RATE_RAD_PER_SEC = math.pi
_GAMEOBJECT_STREAM_LOAD_RADIUS = 120.0
_GAMEOBJECT_STREAM_UNLOAD_RADIUS = 150.0
_GAMEOBJECT_STREAM_INTERVAL_SECONDS = 0.5
_NPC_STREAM_UNLOAD_RADIUS = 150.0
_NPC_STREAM_INTERVAL_SECONDS = 0.5
_TRANSPORT_METADATA_MISSING_CONFIRMATION_PACKETS = 2
def _player_guid(session) -> int:
    return int(getattr(session, "world_guid", 0) or getattr(session, "player_guid", 0) or 0)


def _visible_peer_targets(session) -> list:
    state = getattr(session, "global_state", None)
    if state is None:
        return []

    source_guid = int(getattr(session, "char_guid", 0) or 0)
    map_id = int(getattr(session, "map_id", 0) or 0)
    targets = []
    for target in list(getattr(state, "sessions", set()) or ()):
        if target is session:
            continue
        if int(getattr(target, "map_id", 0) or 0) != map_id:
            continue
        if not callable(getattr(target, "send_response", None)):
            continue
        visible_guids = getattr(target, "visible_guids", set()) or set()
        if source_guid not in visible_guids:
            continue
        targets.append(target)
    return targets


def _broadcast_same_map(session, responses) -> None:
    state = getattr(session, "global_state", None)
    map_id = int(getattr(session, "map_id", 0) or 0)
    for target in list(getattr(state, "sessions", set()) or ()):
        sender = getattr(target, "send_response", None)
        if not callable(sender):
            continue
        if int(getattr(target, "map_id", 0) or 0) != map_id:
            continue
        sender(list(responses))


def _build_out_of_range_update_object_payload(*, map_id: int, guid: int) -> bytes:
    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
    payload += struct.pack("<B", 3)
    payload += struct.pack("<I", 1)
    payload += GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)
    return bytes(payload)


def _stream_nearby_gameobjects(session) -> list[tuple[str, bytes]]:
    if not bool(getattr(session, "gameobjects_visible", True)):
        return []

    map_id = int(getattr(session, "map_id", 0) or 0)
    # Map 0 is valid. Only negative ids mean "no world map".
    if map_id < 0:
        return []

    loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    if not isinstance(loaded_gameobjects, set):
        loaded_gameobjects = set()
        session.loaded_gameobjects = loaded_gameobjects

    realm_id = int(getattr(session, "realm_id", 1) or 1)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)

    responses = list(
        build_database_gameobject_responses(
            session,
            loaded_guids=loaded_gameobjects,
            discovery_context="proximity_stream",
        )
    )

    keep_entries = DatabaseConnection.get_gameobjects_near(
        map_id,
        x,
        y,
        radius=_GAMEOBJECT_STREAM_UNLOAD_RADIUS,
        limit=400,
    )
    keep_guids = set()
    from server.modules.handlers.world.transport_runtime import prepare_runtime_transport_entry

    for entry in keep_entries:
        entry = prepare_runtime_transport_entry(entry)
        if int(entry.get("type", 0) or 0) == 15 or bool(entry.get("use_transport_guid")):
            runtime_guid = int(
                MoTransportGuid.from_spawn_guid(int(entry.get("guid", 0) or 0))
            )
        else:
            runtime_guid = int(
                GameObjectGuid.from_spawn_guid(
                    int(entry.get("guid", 0) or 0),
                    realm_id,
                )
            )
        runtime_object = resolve_gameobject_runtime(
            entry,
            runtime_guid=runtime_guid,
        )
        keep_guids.add(int(runtime_object.runtime_guid))
    try:
        from server.modules.handlers.world.transport_runtime import synthetic_transport_entries_near

        keep_guids.update(
            int(entry.get("world_guid", 0) or 0)
            for entry in synthetic_transport_entries_near(session, context="proximity_keep")
            if int(entry.get("world_guid", 0) or 0) > 0
        )
    except Exception as exc:
        Logger.warning("[WorldTransport] synthetic keep lookup failed err=%s", exc)

    stale_guids = sorted(int(guid) for guid in loaded_gameobjects if int(guid) not in keep_guids)
    loaded_transport_entries = getattr(session, "loaded_transport_entries", None)
    for guid in stale_guids:
        Logger.debug("[GO_STREAM] despawn guid=0x%X", int(guid))
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                _build_out_of_range_update_object_payload(map_id=map_id, guid=int(guid)),
            )
        )
        loaded_gameobjects.discard(int(guid))
        loaded_gameobject_entries = getattr(session, "loaded_gameobject_entries", None)
        if isinstance(loaded_gameobject_entries, dict):
            loaded_gameobject_entries.pop(int(guid), None)
        if isinstance(loaded_transport_entries, dict):
            loaded_transport_entries.pop(int(guid), None)

    return responses


def _maybe_stream_gameobjects(session) -> list[tuple[str, bytes]]:
    now = float(time.monotonic())
    last_stream_at = float(getattr(session, "last_gameobject_stream_at", 0.0) or 0.0)
    if now - last_stream_at < _GAMEOBJECT_STREAM_INTERVAL_SECONDS:
        return []
    session.last_gameobject_stream_at = now
    responses = _stream_nearby_gameobjects(session)
    if responses:
        Logger.debug("[GO_STREAM] responses=%s", len(responses))
    return responses


def _stream_nearby_npcs(session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.feature_config import npcs_enabled

    if not npcs_enabled():
        return []
    if not bool(getattr(session, "npcs_visible", False)):
        return []
    if not bool(getattr(session, "npc_auto_stream", False)):
        return []

    map_id = int(getattr(session, "map_id", 0) or 0)
    if map_id < 0:
        return []

    loaded_npcs = getattr(session, "loaded_npcs", None)
    if not isinstance(loaded_npcs, set):
        loaded_npcs = set()
        session.loaded_npcs = loaded_npcs

    from server.modules.handlers.world.bootstrap.creatures import build_database_creature_responses

    realm_id = int(getattr(session, "realm_id", 1) or 1)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    responses = list(build_database_creature_responses(session, loaded_guids=loaded_npcs))

    keep_entries = DatabaseConnection.get_creatures_near(
        map_id,
        x,
        y,
        radius=_NPC_STREAM_UNLOAD_RADIUS,
        limit=400,
    )
    keep_guids = {
        int(CreatureGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), realm_id))
        for entry in keep_entries
    }

    stale_guids = sorted(int(guid) for guid in loaded_npcs if int(guid) not in keep_guids)
    for guid in stale_guids:
        Logger.debug("[NPC_STREAM] despawn guid=0x%X", int(guid))
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                _build_out_of_range_update_object_payload(map_id=map_id, guid=int(guid)),
            )
        )
        loaded_npcs.discard(int(guid))

    return responses


def _maybe_stream_npcs(session) -> list[tuple[str, bytes]]:
    if not bool(getattr(session, "npc_auto_stream", False)):
        return []

    now = float(time.monotonic())
    last_stream_at = float(getattr(session, "last_npc_stream_at", 0.0) or 0.0)
    if now - last_stream_at < _NPC_STREAM_INTERVAL_SECONDS:
        return []
    session.last_npc_stream_at = now
    responses = _stream_nearby_npcs(session)
    if responses:
        Logger.debug("[NPC_STREAM] responses=%s", len(responses))
    return responses


def _maybe_stream_world_objects(
    session,
    *,
    transition_bootstrap: bool = False,
) -> list[tuple[str, bytes]]:
    if not transition_bootstrap and not is_player_world_active(session):
        return []
    responses = []
    responses.extend(_maybe_stream_gameobjects(session))
    responses.extend(_maybe_stream_npcs(session))
    return responses


def stream_world_objects_after_teleport(
    session,
    *,
    context: str,
) -> list[tuple[str, bytes]]:
    """Compatibility entry point; new transitions use WorldRefreshService."""
    from server.modules.handlers.world.world_refresh import get_world_refresh_service

    return get_world_refresh_service().refresh_player_world(
        session,
        context=context,
        force_object_stream=True,
        _object_streamer=_maybe_stream_world_objects,
    )


def _refresh_after_movement(session, *, context: str) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.world_refresh import get_world_refresh_service

    return get_world_refresh_service().refresh_after_movement(
        session,
        context=context,
        _object_streamer=_maybe_stream_world_objects,
    )


def _maybe_move_companion_pet(session) -> list[tuple[str, bytes]]:
    if int(getattr(session, "summoned_companion_world_guid", 0) or 0) <= 0:
        return []
    from server.modules.handlers.world.opcodes.pets import build_companion_follow_responses

    return build_companion_follow_responses(session)


_COMPANION_FOLLOW_TRIGGER_OPCODES = {
    "MSG_MOVE_HEARTBEAT",
    "MSG_MOVE_START_FORWARD",
    "MSG_MOVE_START_BACKWARD",
    "MSG_MOVE_START_STRAFE_LEFT",
    "MSG_MOVE_START_STRAFE_RIGHT",
    "MSG_MOVE_STOP_STRAFE",
    "MSG_MOVE_STOP",
    "MSG_MOVE_JUMP",
    "MSG_MOVE_FALL_LAND",
}


def _maybe_move_companion_pet_for_opcode(session, opcode_name: str) -> list[tuple[str, bytes]]:
    if str(opcode_name) not in _COMPANION_FOLLOW_TRIGGER_OPCODES:
        return []
    return _maybe_move_companion_pet(session)


_CHAIR_CANCEL_MOVEMENT_OPCODES = {
    "MSG_MOVE_START_FORWARD",
    "MSG_MOVE_START_BACKWARD",
    "MSG_MOVE_START_STRAFE_LEFT",
    "MSG_MOVE_START_STRAFE_RIGHT",
    "MSG_MOVE_JUMP",
    "MSG_MOVE_FALL_LAND",
    "MSG_MOVE_START_ASCEND",
    "MSG_MOVE_START_DESCEND",
}


def _clear_dance_emote_state_on_move(session, opcode_name: str | None = None) -> None:
    responses = []

    if int(getattr(session, "player_stand_state", 0) or 0) != 0:
        current_chair = int(getattr(session, "current_chair", 0) or 0)
        should_clear = current_chair <= 0 or str(opcode_name or "") in _CHAIR_CANCEL_MOVEMENT_OPCODES
        if should_clear:
            try:
                from server.modules.handlers.world.opcodes.entities import release_current_chair
                release_current_chair(session, reason="movement")
            except Exception as exc:
                Logger.debug("[CHAIR] release on movement failed: %s", exc)
            setattr(session, "player_stand_state", 0)
            responses.append(
                (
                    "SMSG_UPDATE_OBJECT",
                    build_single_u32_update_object_payload(
                        map_id=int(getattr(session, "map_id", 0) or 0),
                        guid=int(getattr(session, "char_guid", 0) or _player_guid(session) or 0),
                        field_index=0x4C,
                        value=0,
                    ),
                )
            )

    if int(getattr(session, "npc_emote_state", 0) or 0) == 10:
        setattr(session, "npc_emote_state", 0)
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                build_single_u32_update_object_payload(
                    map_id=int(getattr(session, "map_id", 0) or 0),
                    guid=int(getattr(session, "char_guid", 0) or _player_guid(session) or 0),
                    field_index=0x59,
                    value=0,
                ),
            )
        )

    if responses:
        _broadcast_same_map(session, responses)


def _resolve_live_position_source(session):
    region = getattr(session, "region", None)
    if region is None:
        return session

    expected_world_guid = int(getattr(session, "world_guid", 0) or 0)
    expected_char_guid = int(getattr(session, "char_guid", 0) or 0)

    for player in list(getattr(region, "players", ()) or ()):
        if expected_world_guid and int(getattr(player, "world_guid", 0) or 0) == expected_world_guid:
            return player
        if expected_char_guid and int(getattr(player, "char_guid", 0) or 0) == expected_char_guid:
            return player

    return session


def _coerce_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_movement_from_decoded(session, decoded: dict[str, Any]) -> Optional[tuple[float, float, float, float]]:
    if not decoded:
        return None

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)

    x = _coerce_float(decoded.get("x"))
    if x is None:
        x = _coerce_float(decoded.get("position_x"))

    y = _coerce_float(decoded.get("y"))
    if y is None:
        y = _coerce_float(decoded.get("position_y"))

    z = _coerce_float(decoded.get("z"))
    if z is None:
        z = _coerce_float(decoded.get("position_z"))

    orientation = _coerce_float(decoded.get("facing"))
    if orientation is None:
        orientation = _coerce_float(decoded.get("orientation"))

    if orientation is None:
        return None

    if x is None:
        x = current_x
    if y is None:
        y = current_y
    if z is None:
        z = current_z

    if None not in (x, y, z):
        return (x, y, z, orientation)
    return None


def _simulated_ground_speed(session, move_dir: float) -> float:
    if float(move_dir) < 0.0:
        return float(getattr(session, "run_back_speed", 4.5) or 4.5)
    return float(getattr(session, "run_speed", 7.0) or 7.0)


def _score_movement_candidate(
    session,
    x: float,
    y: float,
    z: float,
    orientation: float,
) -> float:
    if not all(math.isfinite(value) for value in (x, y, z, orientation)):
        return float("inf")
    if abs(x) > 100000 or abs(y) > 100000 or abs(z) > 100000:
        return float("inf")
    if abs(orientation) > (math.pi * 8):
        return float("inf")

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)
    current_o = float(getattr(session, "orientation", 0.0) or 0.0)

    score = abs(x - current_x) + abs(y - current_y) + abs(z - current_z)
    score += min(abs(orientation - current_o), math.tau)
    return score


def _normalize_orientation(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        orientation = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(orientation):
        return None
    if abs(orientation) > (math.pi * 4):
        return None
    orientation = math.fmod(orientation, math.tau)
    if orientation < 0.0:
        orientation += math.tau
    return orientation


def _orientation_from_xy_delta(
    previous_x: float,
    previous_y: float,
    current_x: float,
    current_y: float,
    *,
    minimum_planar_delta: float = 0.05,
) -> float | None:
    dx = float(current_x) - float(previous_x)
    dy = float(current_y) - float(previous_y)
    if not math.isfinite(dx) or not math.isfinite(dy):
        return None
    if math.hypot(dx, dy) < float(minimum_planar_delta):
        return None
    return _normalize_orientation(math.atan2(dy, dx))


def _is_effectively_stationary(
    session,
    x: float,
    y: float,
    z: float,
    *,
    current_x: float | None = None,
    current_y: float | None = None,
    current_z: float | None = None,
    epsilon: float = _STATIONARY_EPSILON,
) -> bool:
    if current_x is None:
        current_x = float(getattr(session, "x", 0.0) or 0.0)
    if current_y is None:
        current_y = float(getattr(session, "y", 0.0) or 0.0)
    if current_z is None:
        current_z = float(getattr(session, "z", 0.0) or 0.0)
    return (
        abs(float(x) - current_x) <= float(epsilon)
        and abs(float(y) - current_y) <= float(epsilon)
        and abs(float(z) - current_z) <= float(epsilon)
    )


def _apply_movement_flags(state, opcode_name: str) -> None:
    previous_flags = int(getattr(state, "flags", 0) or 0)
    flags = int(previous_flags)
    flags2 = int(getattr(state, "flags2", 0) or 0)
    if opcode_name == "MSG_MOVE_START_FORWARD":
        flags |= _MOVEMENTFLAG_FORWARD
        flags &= ~_MOVEMENTFLAG_BACKWARD
    elif opcode_name == "MSG_MOVE_START_BACKWARD":
        flags |= _MOVEMENTFLAG_BACKWARD
        flags &= ~_MOVEMENTFLAG_FORWARD
    elif opcode_name == "MSG_MOVE_STOP":
        flags &= ~(_MOVEMENTFLAG_FORWARD | _MOVEMENTFLAG_BACKWARD)
    elif opcode_name == "MSG_MOVE_START_STRAFE_LEFT":
        flags |= _MOVEMENTFLAG_STRAFE_LEFT
        flags &= ~_MOVEMENTFLAG_STRAFE_RIGHT
    elif opcode_name == "MSG_MOVE_START_STRAFE_RIGHT":
        flags |= _MOVEMENTFLAG_STRAFE_RIGHT
        flags &= ~_MOVEMENTFLAG_STRAFE_LEFT
    elif opcode_name == "MSG_MOVE_STOP_STRAFE":
        flags &= ~(_MOVEMENTFLAG_STRAFE_LEFT | _MOVEMENTFLAG_STRAFE_RIGHT)
    elif opcode_name == "MSG_MOVE_START_TURN_LEFT":
        flags |= _MOVEMENTFLAG_TURN_LEFT
        flags &= ~_MOVEMENTFLAG_TURN_RIGHT
    elif opcode_name == "MSG_MOVE_START_TURN_RIGHT":
        flags |= _MOVEMENTFLAG_TURN_RIGHT
        flags &= ~_MOVEMENTFLAG_TURN_LEFT
    elif opcode_name == "MSG_MOVE_STOP_TURN":
        flags &= ~(_MOVEMENTFLAG_TURN_LEFT | _MOVEMENTFLAG_TURN_RIGHT)
    elif opcode_name == "MSG_MOVE_JUMP":
        flags |= _MOVEMENTFLAG_FALLING
        flags &= ~_MOVEMENTFLAG_SWIMMING
    elif opcode_name == "MSG_MOVE_FALL_LAND":
        flags &= ~_MOVEMENTFLAG_FALLING
        flags &= ~(
            _MOVEMENTFLAG_FLYING
            | _MOVEMENTFLAG_ASCENDING
            | _MOVEMENTFLAG_DESCENDING
        )
        state.is_ascending = False
        state.is_descending = False
    elif opcode_name == "MSG_MOVE_START_SWIM":
        flags |= _MOVEMENTFLAG_SWIMMING
        flags &= ~(
            _MOVEMENTFLAG_FALLING
            | _MOVEMENTFLAG_FLYING
            | _MOVEMENTFLAG_ASCENDING
            | _MOVEMENTFLAG_DESCENDING
        )
        state.has_fall_data = False
        state.fall_time = 0
        state.fall_vertical_speed = 0.0
        state.fall_horizontal_speed = 0.0
        state.fall_sin_angle = 0.0
        state.fall_cos_angle = 0.0
        state.is_ascending = False
        state.is_descending = False
    elif opcode_name == "MSG_MOVE_STOP_SWIM":
        flags &= ~_MOVEMENTFLAG_SWIMMING
    elif opcode_name == "MSG_MOVE_START_ASCEND":
        if flags & _MOVEMENTFLAG_SWIMMING:
            state.is_ascending = True
            state.is_descending = False
            flags |= _MOVEMENTFLAG_ASCENDING
            flags &= ~(
                _MOVEMENTFLAG_FLYING
                | _MOVEMENTFLAG_DESCENDING
            )
        elif flags & _MOVEMENTFLAG_CAN_FLY:
            state.is_ascending = True
            state.is_descending = False
            flags |= _MOVEMENTFLAG_ASCENDING
            flags &= ~_MOVEMENTFLAG_DESCENDING
            flags |= _MOVEMENTFLAG_FLYING
            flags &= ~_MOVEMENTFLAG_SPLINE_ELEVATION
        else:
            state.is_ascending = False
            state.is_descending = False
            flags &= ~(
                _MOVEMENTFLAG_FLYING
                | _MOVEMENTFLAG_ASCENDING
                | _MOVEMENTFLAG_DESCENDING
            )
    elif opcode_name == "MSG_MOVE_STOP_ASCEND":
        state.is_ascending = False
        flags &= ~_MOVEMENTFLAG_ASCENDING
    elif opcode_name == "MSG_MOVE_START_DESCEND":
        if flags & _MOVEMENTFLAG_SWIMMING:
            state.is_descending = True
            state.is_ascending = False
            flags |= _MOVEMENTFLAG_DESCENDING
            flags &= ~(
                _MOVEMENTFLAG_FLYING
                | _MOVEMENTFLAG_ASCENDING
            )
        elif flags & _MOVEMENTFLAG_CAN_FLY:
            state.is_descending = True
            state.is_ascending = False
            flags |= _MOVEMENTFLAG_FLYING | _MOVEMENTFLAG_DESCENDING
            flags &= ~(_MOVEMENTFLAG_ASCENDING | _MOVEMENTFLAG_SPLINE_ELEVATION)
        else:
            state.is_descending = False
            state.is_ascending = False
            flags &= ~(
                _MOVEMENTFLAG_FLYING
                | _MOVEMENTFLAG_ASCENDING
                | _MOVEMENTFLAG_DESCENDING
            )
    elif opcode_name == "MSG_MOVE_STOP_DESCEND":
        state.is_descending = False
        flags &= ~_MOVEMENTFLAG_DESCENDING
    if (
        flags & _MOVEMENTFLAG_FORWARD
        and flags & (_MOVEMENTFLAG_TURN_LEFT | _MOVEMENTFLAG_TURN_RIGHT)
    ):
        flags2 |= _MOVEMENTFLAG2_CIRCLE_RUN_SYNC
    else:
        flags2 &= ~_MOVEMENTFLAG2_CIRCLE_RUN_SYNC
    state.flags = int(flags)
    state.flags2 = int(flags2)
    if opcode_name in {
        "MSG_MOVE_START_FORWARD",
        "MSG_MOVE_START_BACKWARD",
        "MSG_MOVE_START_TURN_LEFT",
        "MSG_MOVE_START_TURN_RIGHT",
        "MSG_MOVE_STOP_TURN",
        "MSG_MOVE_HEARTBEAT",
        "MSG_MOVE_STOP",
    }:
        Logger.debug(
            "[MOVE_FLAGS] opcode=%s previous=0x%X new=0x%X",
            opcode_name,
            previous_flags,
            int(flags),
        )


def _clear_jump_fall_state(state) -> bool:
    previous_flags = int(getattr(state, "flags", 0) or 0)
    previous_has_fall_data = bool(getattr(state, "has_fall_data", False))
    previous_fall_values = (
        int(getattr(state, "fall_time", 0) or 0),
        float(getattr(state, "fall_vertical_speed", 0.0) or 0.0),
        float(getattr(state, "fall_horizontal_speed", 0.0) or 0.0),
        float(getattr(state, "fall_sin_angle", 0.0) or 0.0),
        float(getattr(state, "fall_cos_angle", 0.0) or 0.0),
    )

    state.flags = previous_flags & ~_MOVEMENTFLAG_FALLING
    state.has_fall_data = False
    state.fall_time = 0
    state.fall_vertical_speed = 0.0
    state.fall_horizontal_speed = 0.0
    state.fall_sin_angle = 0.0
    state.fall_cos_angle = 0.0

    return (
        previous_has_fall_data
        or bool(previous_flags & _MOVEMENTFLAG_FALLING)
        or any(value != 0 for value in previous_fall_values)
    )


def _clear_strafe_state(state) -> bool:
    previous_flags = int(getattr(state, "flags", 0) or 0)
    state.flags = previous_flags & ~(_MOVEMENTFLAG_STRAFE_LEFT | _MOVEMENTFLAG_STRAFE_RIGHT)
    return int(state.flags) != previous_flags


def _apply_post_parse_movement_cleanup(
    session,
    state,
    opcode_name: str,
) -> None:
    flags_before = int(getattr(state, "flags", 0) or 0)
    flags_after = int(flags_before)

    if opcode_name == "MSG_MOVE_STOP":
        flags_after &= ~(_MOVEMENTFLAG_FORWARD | _MOVEMENTFLAG_BACKWARD)
    elif opcode_name == "MSG_MOVE_STOP_STRAFE":
        flags_after &= ~(_MOVEMENTFLAG_STRAFE_LEFT | _MOVEMENTFLAG_STRAFE_RIGHT)
    elif opcode_name == "MSG_MOVE_STOP_TURN":
        flags_after &= ~(_MOVEMENTFLAG_TURN_LEFT | _MOVEMENTFLAG_TURN_RIGHT)
    elif opcode_name == "MSG_MOVE_FALL_LAND":
        flags_after &= ~_MOVEMENTFLAG_FALLING

    if flags_after != flags_before:
        state.flags = int(flags_after)
        if opcode_name == "MSG_MOVE_FALL_LAND":
            state.has_fall_data = False
            state.fall_time = 0
            state.fall_vertical_speed = 0.0
            state.fall_horizontal_speed = 0.0
            state.fall_sin_angle = 0.0
            state.fall_cos_angle = 0.0

    if flags_after != flags_before or opcode_name in {
        "MSG_MOVE_STOP",
        "MSG_MOVE_FALL_LAND",
        "MSG_MOVE_STOP_STRAFE",
        "MSG_MOVE_STOP_TURN",
    }:
        Logger.debug(
            "[MOVE_CLEANUP] opcode=%s flags_before=0x%X flags_after=0x%X "
            "pos=(%.3f %.3f %.3f)",
            opcode_name,
            flags_before,
            flags_after,
            float(getattr(state, "x", 0.0) or 0.0),
            float(getattr(state, "y", 0.0) or 0.0),
            float(getattr(state, "z", 0.0) or 0.0),
        )


def _apply_early_movement_cleanup(session, opcode_name: str) -> None:
    if opcode_name not in {
        "MSG_MOVE_FALL_LAND",
        "MSG_MOVE_START_FORWARD",
        "MSG_MOVE_STOP_STRAFE",
    }:
        return

    state = _movement_state(session)
    if opcode_name == "MSG_MOVE_FALL_LAND":
        if _clear_jump_fall_state(state):
            Logger.debug("[LAND_RESET] cleared fall state")
    elif opcode_name == "MSG_MOVE_START_FORWARD":
        has_fall_state = (
            bool(getattr(state, "has_fall_data", False))
            or bool(int(getattr(state, "flags", 0) or 0) & _MOVEMENTFLAG_FALLING)
        )
        if has_fall_state:
            if _clear_jump_fall_state(state):
                Logger.debug(
                    "[POST_JUMP_RESET] opcode=%s cleared fall state flags=0x%X",
                    opcode_name,
                    int(getattr(state, "flags", 0) or 0),
                )
    elif opcode_name == "MSG_MOVE_STOP_STRAFE":
        if _clear_strafe_state(state):
            Logger.debug("[STOP_STRAFE_RESET] cleared strafe flags")


def _extract_packet_timestamp(opcode_name: str, payload: bytes) -> int | None:
    if opcode_name == "MSG_MOVE_HEARTBEAT" and len(payload) >= 32:
        return int.from_bytes(payload[-4:], "little", signed=False)
    if opcode_name == "MSG_MOVE_START_FORWARD" and len(payload) >= 28:
        return int.from_bytes(payload[24:28], "little", signed=False)
    if opcode_name == "MSG_MOVE_START_BACKWARD" and len(payload) >= 28:
        return int.from_bytes(payload[-4:], "little", signed=False)
    if opcode_name == "MSG_MOVE_STOP" and len(payload) >= 28:
        return int.from_bytes(payload[-4:], "little", signed=False)
    if opcode_name in {"MSG_MOVE_START_STRAFE_LEFT", "MSG_MOVE_START_STRAFE_RIGHT", "MSG_MOVE_STOP_STRAFE"} and len(payload) >= 24:
        return int.from_bytes(payload[-4:], "little", signed=False)
    if opcode_name == "MSG_MOVE_JUMP" and len(payload) >= 52:
        return int.from_bytes(payload[-4:], "little", signed=False)
    if opcode_name == "MSG_MOVE_FALL_LAND" and len(payload) >= 28:
        return int.from_bytes(payload[-4:], "little", signed=False)
    if opcode_name in {"MSG_MOVE_START_TURN_LEFT", "MSG_MOVE_START_TURN_RIGHT", "MSG_MOVE_STOP_TURN"} and len(payload) >= 24:
        return int.from_bytes(payload[-4:], "little", signed=False)
    return None


def _extract_jump_fall_data(payload: bytes) -> dict[str, float | int] | None:
    if len(payload) < 36:
        return None

    try:
        vertical_speed = struct.unpack_from("<f", payload, 24)[0]
        sin_angle = struct.unpack_from("<f", payload, 28)[0]
        cos_angle = struct.unpack_from("<f", payload, 32)[0]
        horizontal_speed = struct.unpack_from("<f", payload, 36)[0] if len(payload) >= 40 else 0.0
    except struct.error:
        return None

    if not all(math.isfinite(value) for value in (vertical_speed, sin_angle, cos_angle, horizontal_speed)):
        return None

    return {
        "fall_time": 0,
        "fall_vertical_speed": float(vertical_speed),
        "fall_horizontal_speed": float(horizontal_speed) if abs(float(horizontal_speed)) > 1e-5 else 0.0,
        "fall_sin_angle": float(sin_angle),
        "fall_cos_angle": float(cos_angle),
    }


def _extract_pitch_from_payload(payload: bytes) -> float | None:
    if len(payload) < 4:
        return None
    try:
        pitch = struct.unpack_from("<f", payload, len(payload) - 4)[0]
    except struct.error:
        return None
    if not math.isfinite(pitch):
        return None
    return _wrap_pitch(float(pitch))


def _is_stale_client_timestamp(current_timestamp_ms: int, incoming_timestamp_ms: int) -> bool:
    current = int(current_timestamp_ms or 0) & 0xFFFFFFFF
    incoming = int(incoming_timestamp_ms or 0) & 0xFFFFFFFF
    if current <= 0 or incoming <= 0:
        return False
    if incoming >= current:
        return False
    delta = current - incoming
    if delta >= 60000:
        return False
    return delta > _STALE_MOVEMENT_TIMESTAMP_REJECT_MS


def _store_client_movement_timestamp(state, incoming_timestamp_ms: int | None) -> None:
    if incoming_timestamp_ms is None:
        existing = int(getattr(state, "timestamp_ms", 0) or 0) & 0xFFFFFFFF
        now_ms = int(time.time() * 1000.0) & 0xFFFFFFFF
        if existing > 0 and now_ms <= existing:
            now_ms = (existing + 1) & 0xFFFFFFFF
        state.timestamp_ms = now_ms
        return

    incoming = int(incoming_timestamp_ms) & 0xFFFFFFFF
    state.client_timestamp_ms = incoming
    current = int(getattr(state, "timestamp_ms", 0) or 0) & 0xFFFFFFFF
    if current <= 0 or incoming >= current:
        state.timestamp_ms = incoming
        return

    # TODO: replace this soft monotonic clamp with a Trinity/SkyFire-style
    # client-time-delay model once all movement opcodes expose MovementInfo.time
    # through one parser path. For now, never let small packet reordering move
    # server-side movement time backwards.
    state.timestamp_ms = (current + 1) & 0xFFFFFFFF


def _extract_movement_from_payload(session, payload: bytes) -> Optional[tuple[float, float, float, float]]:
    if len(payload) < 16:
        return None

    best: Optional[tuple[float, float, float, float]] = None
    best_score = float("inf")
    for offset in range(0, len(payload) - 15):
        try:
            x, y, z, orientation = struct.unpack_from("<ffff", payload, offset)
        except struct.error:
            continue

        score = _score_movement_candidate(session, x, y, z, orientation)
        if score < best_score:
            best = (x, y, z, orientation)
            best_score = score

    return best


def _extract_skyfire_movement_from_payload(
    session,
    opcode_name: str,
    payload: bytes,
) -> Optional[tuple[float, float, float, float]]:
    parsed = _parse_skyfire_flying_movement_info(session, opcode_name, payload)
    if parsed is not None:
        return (
            float(parsed["x"]),
            float(parsed["y"]),
            float(parsed["z"]),
            float(parsed["orientation"]),
        )

    if opcode_name in _SKYFIRE_FLYING_MOVEMENT_SEQUENCES and len(payload) < 28:
        return None

    if len(payload) < 12:
        return None

    try:
        first, second, third = struct.unpack_from("<fff", payload, 0)
    except struct.error:
        return None

    orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    previous_orientation = _normalize_orientation(
        float(getattr(session, "orientation", 0.0) or 0.0)
    )
    is_flying_session = _movement_is_flying(session)

    def _orientation_debug_candidates(offsets: tuple[int, ...]) -> list[tuple[int, float, float | None]]:
        candidates: list[tuple[int, float, float | None]] = []
        for offset in offsets:
            try:
                candidate = struct.unpack_from("<f", payload, offset)[0]
            except struct.error:
                continue
            candidates.append((int(offset), float(candidate), _normalize_orientation(candidate)))
        return candidates

    def _select_orientation_from_offsets(
        offsets: tuple[int, ...],
        *,
        prefer_nonzero: bool = False,
        avoid_tau_alias: bool = False,
    ) -> tuple[float, int | None, list[tuple[int, float, float | None]]]:
        zeroish_epsilon = 0.01
        flying_zeroish_epsilon = 0.1 if is_flying_session else zeroish_epsilon
        candidates = _orientation_debug_candidates(offsets)
        valid = [
            (offset, raw_value, normalized)
            for offset, raw_value, normalized in candidates
            if normalized is not None
        ]
        if not valid:
            return float(orientation), None, candidates

        nonzero_valid = [
            item
            for item in valid
            if not math.isclose(float(item[2]), 0.0, abs_tol=flying_zeroish_epsilon)
            and not math.isclose(float(item[2]), math.tau, abs_tol=flying_zeroish_epsilon)
        ]
        if (
            prefer_nonzero
            and previous_orientation is not None
            and not math.isclose(float(previous_orientation), 0.0, abs_tol=flying_zeroish_epsilon)
            and nonzero_valid
        ):
            valid = nonzero_valid
        elif avoid_tau_alias and nonzero_valid:
            valid = nonzero_valid
        elif (
            prefer_nonzero
            and previous_orientation is not None
            and not math.isclose(float(previous_orientation), 0.0, abs_tol=flying_zeroish_epsilon)
        ):
            return float(previous_orientation), None, candidates

        selected_offset, _raw_value, selected_orientation = valid[0]
        return float(selected_orientation), int(selected_offset), candidates

    def _log_flying_parse(
        selected_offset: int | None,
        parsed_x: float,
        parsed_y: float,
        parsed_z: float,
        parsed_orientation: float,
        candidates: list[tuple[int, float, float | None]],
    ) -> None:
        if opcode_name not in {
            "MSG_MOVE_HEARTBEAT",
            "MSG_MOVE_START_ASCEND",
            "MSG_MOVE_STOP_ASCEND",
            "MSG_MOVE_SET_PITCH",
        }:
            return
        candidate_parts = [
            f"{offset}:{raw_value:.6f}->{normalized!r}"
            for offset, raw_value, normalized in candidates
        ]
        Logger.debug(
            "[FLY_PARSE] opcode=%s len=%s first3=(%.6f, %.6f, %.6f) candidates=[%s] accepted=%s parsed=(%.6f, %.6f, %.6f, %.6f)",
            opcode_name,
            len(payload),
            float(first),
            float(second),
            float(third),
            ", ".join(candidate_parts),
            "None" if selected_offset is None else int(selected_offset),
            float(parsed_x),
            float(parsed_y),
            float(parsed_z),
            float(parsed_orientation),
        )

    if opcode_name == "MSG_MOVE_HEARTBEAT":
        # SkyFire 5.4.8 MovementHeartBeat starts with PositionZ, PositionX, PositionY.
        z, x, y = first, second, third
        selected_offset = None
        candidates: list[tuple[int, float, float | None]] = []
        if is_flying_session and len(payload) == 30:
            orientation, selected_offset, candidates = _select_orientation_from_offsets(
                (23, 24, 20, 27, 28, 31),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
        elif is_flying_session and len(payload) == 31:
            orientation, selected_offset, candidates = _select_orientation_from_offsets(
                (23, 24, 20, 27, 28, 31),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
        elif is_flying_session and len(payload) >= 35:
            orientation, selected_offset, candidates = _select_orientation_from_offsets(
                (23, 24, 20, 27, 28, 31, 43),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
        elif len(payload) >= 51:
            orientation, selected_offset, candidates = _select_orientation_from_offsets((43,))
        elif len(payload) >= 32:
            orientation, selected_offset, candidates = _select_orientation_from_offsets((24,))
        parsed = (float(x), float(y), float(z), float(orientation))
        if is_flying_session:
            _log_flying_parse(selected_offset, *parsed, candidates)
        return parsed

    if opcode_name == "MSG_MOVE_SET_PITCH":
        # SkyFire 5.4.8 MovementSetPitch starts with PositionZ, PositionX, PositionY.
        z, x, y = first, second, third
        orientation, selected_offset, candidates = _select_orientation_from_offsets(
            (24, 20, 23, 27, 28, 31, 25),
            prefer_nonzero=True,
            avoid_tau_alias=True,
        )
        parsed = (float(x), float(y), float(z), float(orientation))
        _log_flying_parse(selected_offset, *parsed, candidates)
        return parsed

    if opcode_name == "MSG_MOVE_START_FORWARD":
        # SkyFire 5.4.8 MovementStartForward starts with PositionZ, PositionX, PositionY.
        z, x, y = first, second, third
        if len(payload) >= 32:
            try:
                candidate = struct.unpack_from("<f", payload, 28)[0]
                normalized = _normalize_orientation(candidate)
                if normalized is not None:
                    orientation = float(normalized)
            except struct.error:
                pass
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_START_ASCEND":
        layout_candidates = (
            (float(first), float(second), float(third)),
            (float(second), float(third), float(first)),
            (float(second), float(first), float(third)),
        )
        best_layout = layout_candidates[0]
        best_score = float("inf")
        for candidate_x, candidate_y, candidate_z in layout_candidates:
            score = _score_movement_candidate(
                session,
                candidate_x,
                candidate_y,
                candidate_z,
                previous_orientation
                if previous_orientation is not None
                else float(orientation),
            )
            if score < best_score:
                best_score = score
                best_layout = (candidate_x, candidate_y, candidate_z)

        orientation, selected_offset, candidates = _select_orientation_from_offsets(
            (25, 28, 23, 24, 31, 20, 27),
            prefer_nonzero=True,
            avoid_tau_alias=True,
        )
        parsed = (
            float(best_layout[0]),
            float(best_layout[1]),
            float(best_layout[2]),
            float(orientation),
        )
        _log_flying_parse(selected_offset, *parsed, candidates)
        return parsed

    if opcode_name == "MSG_MOVE_START_BACKWARD":
        # SkyFire 5.4.8 MovementStartBackward starts with PositionY, PositionZ, PositionX.
        y, z, x = first, second, third
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_STOP":
        # SkyFire 5.4.8 MovementStop starts with PositionX, PositionY, PositionZ.
        x, y, z = first, second, third
        if is_flying_session:
            orientation, _selected_offset, _candidates = _select_orientation_from_offsets(
                (24, 20, 23, 27, 28, 31, 25),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
            return (float(x), float(y), float(z), float(orientation))
        orientation_offsets = ()
        if len(payload) >= 51:
            # Jump/fall STOP variants carry extra control fields. The known
            # captures do not place facing at the simple ground offsets.
            orientation_offsets = ()
        elif len(payload) >= 32:
            orientation_offsets = (24,)
        elif len(payload) >= 28:
            orientation_offsets = (20,)
        for offset in orientation_offsets:
            try:
                candidate = struct.unpack_from("<f", payload, offset)[0]
            except struct.error:
                continue
            normalized = _normalize_orientation(candidate)
            if normalized is not None:
                orientation = float(normalized)
                break
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_STOP_ASCEND":
        # Captured STOP_ASCEND packets match heartbeat order: PositionZ,
        # PositionX, PositionY. Keeping this exact avoids broad float scanning.
        z, x, y = first, second, third
        if len(payload) == 35:
            orientation, selected_offset, candidates = _select_orientation_from_offsets(
                (31, 23, 24, 28, 20, 27),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
        else:
            orientation, selected_offset, candidates = _select_orientation_from_offsets(
                (27, 23),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
        parsed = (float(x), float(y), float(z), float(orientation))
        _log_flying_parse(selected_offset, *parsed, candidates)
        return parsed

    if opcode_name == "MSG_MOVE_START_STRAFE_LEFT":
        # SkyFire 5.4.8 MovementStartStrafeLeft starts with PositionY, PositionZ, PositionX.
        y, z, x = first, second, third
        if len(payload) >= 32:
            try:
                candidate = struct.unpack_from("<f", payload, 28)[0]
                normalized = _normalize_orientation(candidate)
                if normalized is not None:
                    orientation = float(normalized)
            except struct.error:
                pass
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_START_STRAFE_RIGHT":
        # SkyFire 5.4.8 MovementStartStrafeRight starts with PositionY, PositionX, PositionZ.
        y, x, z = first, second, third
        if len(payload) >= 32:
            try:
                candidate = struct.unpack_from("<f", payload, 28)[0]
                normalized = _normalize_orientation(candidate)
                if normalized is not None:
                    orientation = float(normalized)
            except struct.error:
                pass
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_STOP_STRAFE":
        # SkyFire 5.4.8 MovementStopStrafe starts with PositionZ, PositionX, PositionY.
        z, x, y = first, second, third
        if len(payload) >= 24:
            try:
                candidate = struct.unpack_from("<f", payload, 20)[0]
                normalized = _normalize_orientation(candidate)
                if normalized is not None:
                    previous_normalized = _normalize_orientation(
                        float(getattr(session, "orientation", 0.0) or 0.0)
                    )
                    if (
                        math.isclose(float(normalized), 0.0, abs_tol=1e-6)
                        and previous_normalized is not None
                        and not math.isclose(float(previous_normalized), 0.0, abs_tol=1e-6)
                    ):
                        Logger.debug(
                            "[STOP_ORIENTATION_GUARD] opcode=%s preserved previous=%.3f parsed=0.000",
                            opcode_name,
                            float(previous_normalized),
                        )
                    else:
                        orientation = float(normalized)
            except struct.error:
                pass
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_START_TURN_RIGHT":
        # SkyFire 5.4.8 MovementStartTurnRight starts with PositionX, PositionZ, PositionY.
        x, z, y = first, second, third
        if is_flying_session:
            orientation, _selected_offset, _candidates = _select_orientation_from_offsets(
                (24, 20, 23, 27, 28, 31, 25),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
        elif len(payload) >= 28:
            try:
                candidate = struct.unpack_from("<f", payload, 24)[0]
                normalized = _normalize_orientation(candidate)
                if normalized is not None:
                    orientation = float(normalized)
            except struct.error:
                pass
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_START_TURN_LEFT":
        # SkyFire 5.4.8 MovementStartTurnLeft starts with PositionZ, PositionX, PositionY.
        z, x, y = first, second, third
        if is_flying_session:
            orientation, _selected_offset, _candidates = _select_orientation_from_offsets(
                (24, 20, 23, 27, 28, 31, 25),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
        elif len(payload) >= 28:
            try:
                candidate = struct.unpack_from("<f", payload, 24)[0]
                normalized = _normalize_orientation(candidate)
                if normalized is not None:
                    orientation = float(normalized)
            except struct.error:
                pass
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_STOP_TURN":
        # SkyFire 5.4.8 MovementStopTurn starts with PositionX, PositionZ, PositionY.
        x, z, y = first, second, third
        orientation_offsets = ()
        if is_flying_session:
            orientation, _selected_offset, _candidates = _select_orientation_from_offsets(
                (24, 20, 23, 27, 28, 31, 25),
                prefer_nonzero=True,
                avoid_tau_alias=True,
            )
            return (float(x), float(y), float(z), float(orientation))
        if len(payload) >= 32:
            orientation_offsets = (24, 20)
        elif len(payload) >= 24:
            orientation_offsets = (20,)
        for offset in orientation_offsets:
            try:
                candidate = struct.unpack_from("<f", payload, offset)[0]
            except struct.error:
                continue
            normalized = _normalize_orientation(candidate)
            if normalized is not None:
                orientation = float(normalized)
                break
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_JUMP":
        # SkyFire 5.4.8 MovementJump starts with PositionY, PositionX, PositionZ.
        y, x, z = first, second, third
        if len(payload) >= 48:
            try:
                candidate = struct.unpack_from("<f", payload, 44)[0]
                normalized = _normalize_orientation(candidate)
                if normalized is not None:
                    orientation = float(normalized)
            except struct.error:
                pass
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_FALL_LAND":
        # SkyFire 5.4.8 MovementFallLand starts with PositionY, PositionZ, PositionX.
        y, z, x = first, second, third
        orientation_offsets = ()
        if len(payload) >= 40:
            orientation_offsets = (36,)
        elif len(payload) >= 36:
            orientation_offsets = (32,)
        elif len(payload) >= 28:
            orientation_offsets = (24,)
        for offset in orientation_offsets:
            try:
                candidate = struct.unpack_from("<f", payload, offset)[0]
            except struct.error:
                continue
            normalized = _normalize_orientation(candidate)
            if normalized is not None:
                orientation = float(normalized)
                break
        return (float(x), float(y), float(z), float(orientation))

    return None


def _accept_movement_update(
    session,
    opcode_name: str,
    x: float,
    y: float,
    z: float,
    orientation: float,
) -> bool:
    session._last_movement_rejection = None
    if not all(math.isfinite(value) for value in (x, y, z)):
        session._last_movement_rejection = "nonfinite_position"
        _movement_debug_log(
            session,
            "MOVE_DEBUG guid=Player-%s opcode=%s rejection=nonfinite_position",
            int(getattr(session, "char_guid", 0) or 0),
            opcode_name,
        )
        return False

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)
    if current_x == 0.0 and current_y == 0.0 and current_z == 0.0:
        return True

    planar_delta = math.hypot(x - current_x, y - current_y)
    vertical_delta = abs(z - current_z)
    if planar_delta > _MAX_MOVEMENT_POSITION_DELTA or vertical_delta > _MAX_MOVEMENT_Z_DELTA:
        session._last_movement_rejection = "implausible_delta"
        log = Logger.debug if opcode_name in {"MSG_MOVE_FALL_LAND", "MSG_MOVE_HEARTBEAT"} else Logger.warning
        log(
            f"[Movement] ignoring implausible {opcode_name} update "
            f"dx={x - current_x:.3f} dy={y - current_y:.3f} dz={z - current_z:.3f}"
        )
        _movement_debug_log(
            session,
            "MOVE_DEBUG guid=Player-%s opcode=%s dx=%.3f dy=%.3f dz=%.3f "
            "correction=false rejection=implausible_delta",
            int(getattr(session, "char_guid", 0) or 0),
            opcode_name,
            float(x - current_x),
            float(y - current_y),
            float(z - current_z),
        )
        return False
    return True


def parse_movement_info(
    session,
    opcode_name: str,
    payload: bytes,
    decoded: dict[str, Any] | None = None,
) -> Optional[tuple[float, float, float, float]]:
    decoded = decoded or {}

    exact_movement = _extract_skyfire_movement_from_payload(session, opcode_name, payload)
    if exact_movement is not None:
        return exact_movement

    movement = _extract_movement_from_decoded(session, decoded)
    if movement is not None:
        return movement

    # Start/stop movement opcodes are state transitions. Treating arbitrary float
    # windows in those payloads as live coordinates has caused z=0 snaps, which
    # in turn makes nearby players disappear client-side. Only heartbeat/fall/jump
    # should move the authoritative position.
    if opcode_name in {
        "MSG_MOVE_FALL_LAND",
        "MSG_MOVE_JUMP",
    }:
        movement = _extract_movement_from_payload(session, payload)
        if movement is not None:
            x, y, z, _ignored_orientation = movement
            return (
                float(x),
                float(y),
                float(z),
                float(getattr(session, "orientation", 0.0) or 0.0),
            )

    # Only HEARTBEAT gets the permissive full fallback, including facing.
    if opcode_name != "MSG_MOVE_HEARTBEAT":
        return None

    if opcode_name == "MSG_MOVE_HEARTBEAT":
        decoded = dsl_decode("MSG_MOVE_HEARTBEAT", payload, silent=True)
        movement = _extract_movement_from_decoded(session, decoded)
        if movement is not None:
            return movement

    return _extract_movement_from_payload(session, payload)


def _record_movement_packet_state(session, opcode_name: str, payload: bytes) -> None:
    state = _movement_state(session)
    parsed_flying = _parse_skyfire_flying_movement_info(session, opcode_name, payload)
    if parsed_flying is not None:
        state.flags = int(parsed_flying["flags"])
        state.flags2 = int(parsed_flying["flags2"])
        state.pitch = float(parsed_flying["pitch"])
        state.has_fall_data = bool(parsed_flying["has_fall_data"])
        state.fall_time = int(parsed_flying["fall_time"])
        state.fall_vertical_speed = float(parsed_flying["fall_vertical_speed"])
        state.fall_horizontal_speed = float(parsed_flying["fall_horizontal_speed"])
        state.fall_sin_angle = float(parsed_flying["fall_sin_angle"])
        state.fall_cos_angle = float(parsed_flying["fall_cos_angle"])
        state.is_ascending = bool(int(state.flags) & _MOVEMENTFLAG_ASCENDING)
        state.is_descending = bool(int(state.flags) & _MOVEMENTFLAG_DESCENDING)
        _store_transport_state_from_parsed(session, opcode_name, parsed_flying)
        _store_client_movement_timestamp(state, parsed_flying["timestamp"])
        Logger.debug(
            "[MOVE_FLAGS] opcode=%s parser=%s authoritative flags=0x%X flags2=0x%X "
            "pitch=%.6f orientation=%.6f",
            opcode_name,
            parsed_flying["parser_path"],
            int(state.flags),
            int(state.flags2),
            float(state.pitch),
            float(parsed_flying["orientation"]),
        )
    else:
        _apply_movement_flags(state, opcode_name)
        previous_guid = int(getattr(state, "transport_guid", 0) or 0)
        previous_attached_guid = int(getattr(session, "transport_attached_guid", 0) or 0)
        unknown_transport_guid = previous_guid or previous_attached_guid
        if unknown_transport_guid:
            _log_transport_parse_unknown_preserve(
                session,
                opcode_name,
                unknown_transport_guid,
            )
        else:
            state.has_transport_data = False
            state.transport_guid = 0
    if opcode_name == "MSG_MOVE_JUMP":
        fall_data = _extract_jump_fall_data(payload)
        if fall_data is not None:
            state.has_fall_data = True
            state.fall_time = int(fall_data["fall_time"])
            state.fall_vertical_speed = float(fall_data["fall_vertical_speed"])
            state.fall_horizontal_speed = float(fall_data["fall_horizontal_speed"])
            state.fall_sin_angle = float(fall_data["fall_sin_angle"])
            state.fall_cos_angle = float(fall_data["fall_cos_angle"])
    elif opcode_name == "MSG_MOVE_FALL_LAND":
        _clear_jump_fall_state(state)
    elif opcode_name == "MSG_MOVE_START_SWIM":
        setattr(session, "is_flying", False)
    elif opcode_name == "MSG_MOVE_SET_PITCH":
        pitch = _extract_pitch_from_payload(payload)
        if pitch is not None:
            state.pitch = float(pitch)
            Logger.debug(
                "[MOVE_PITCH] opcode=%s pitch=%.6f",
                opcode_name,
                float(state.pitch),
            )
    if parsed_flying is None:
        timestamp = _extract_packet_timestamp(opcode_name, payload)
        _store_client_movement_timestamp(state, timestamp)
    # Keep the same-map teleport counter in step with accepted client movement.
    state.counter = (int(getattr(state, "counter", 0) or 0) + 1) & 0xFFFFFFFF
    return None


def _store_authoritative_movement(session, opcode_name: str, payload: bytes, movement: tuple[float, float, float, float] | None) -> None:
    state = _movement_state(session)
    _apply_early_movement_cleanup(session, opcode_name)
    parsed_flying = _parse_skyfire_flying_movement_info(session, opcode_name, payload)
    incoming_timestamp = parsed_flying["timestamp"] if parsed_flying is not None else _extract_packet_timestamp(opcode_name, payload)
    if incoming_timestamp is not None and _is_stale_client_timestamp(state.timestamp_ms, incoming_timestamp):
        Logger.debug(
            "[Movement] ignoring stale %s timestamp current=%u incoming=%u "
            "outbound=%u flags=0x%X orientation=%.6f fall=%s",
            opcode_name,
            int(state.timestamp_ms),
            int(incoming_timestamp),
            int(getattr(state, "server_movement_timestamp_ms", 0) or 0),
            int(getattr(state, "flags", 0) or 0),
            float(getattr(state, "orientation", 0.0) or 0.0),
            bool(getattr(state, "has_fall_data", False)),
        )
        _movement_debug_log(
            session,
            "MOVE_DEBUG guid=Player-%s opcode=%s client_ts=%u server_ts=%u "
            "correction=false rejection=stale_timestamp",
            int(getattr(session, "char_guid", 0) or 0),
            opcode_name,
            int(incoming_timestamp) & 0xFFFFFFFF,
            int(getattr(state, "timestamp_ms", 0) or 0) & 0xFFFFFFFF,
        )
        return False
    previous_timestamp = int(getattr(state, "timestamp_ms", 0) or 0) & 0xFFFFFFFF
    older_movement_packet = False
    if incoming_timestamp is not None and previous_timestamp > 0:
        incoming = int(incoming_timestamp) & 0xFFFFFFFF
        if incoming < previous_timestamp and (previous_timestamp - incoming) < 60000:
            older_movement_packet = True
            _movement_debug_log(
                session,
                "MOVE_DEBUG guid=Player-%s opcode=%s client_ts=%u server_ts=%u "
                "timestamp_backstep_ms=%u correction=false rejection=false",
                int(getattr(session, "char_guid", 0) or 0),
                opcode_name,
                int(incoming),
                int(previous_timestamp),
                int(previous_timestamp - incoming),
            )
    _record_movement_packet_state(session, opcode_name, payload)
    _apply_post_parse_movement_cleanup(session, state, opcode_name)
    active_flying_mount = _has_active_flying_mount(session)
    if opcode_name == "MSG_MOVE_FALL_LAND":
        setattr(session, "is_flying", False)
        state.is_ascending = False
        state.is_descending = False
        state.flags &= ~(
            _MOVEMENTFLAG_FLYING
            | _MOVEMENTFLAG_ASCENDING
            | _MOVEMENTFLAG_DESCENDING
            | _MOVEMENTFLAG_FALLING
        )
        state.has_fall_data = False
        state.fall_time = 0
        state.fall_vertical_speed = 0.0
        state.fall_horizontal_speed = 0.0
        state.fall_sin_angle = 0.0
        state.fall_cos_angle = 0.0
        state.pitch = 0.0
    elif opcode_name == "MSG_MOVE_START_SWIM":
        setattr(session, "is_flying", False)
        state.is_ascending = False
        state.is_descending = False
        state.flags &= ~(
            _MOVEMENTFLAG_FALLING
            | _MOVEMENTFLAG_FLYING
            | _MOVEMENTFLAG_ASCENDING
            | _MOVEMENTFLAG_DESCENDING
        )
        state.flags |= _MOVEMENTFLAG_SWIMMING
    elif opcode_name in {"MSG_MOVE_START_ASCEND", "MSG_MOVE_START_DESCEND"}:
        current_flags = int(getattr(state, "flags", 0) or 0)
        swimming_vertical = bool(current_flags & _MOVEMENTFLAG_SWIMMING)
        can_enter_flight = bool(
            current_flags & _MOVEMENTFLAG_CAN_FLY and not swimming_vertical
        )
        setattr(session, "is_flying", can_enter_flight)
        if swimming_vertical:
            state.flags &= ~_MOVEMENTFLAG_FLYING
        elif can_enter_flight:
            state.flags |= _MOVEMENTFLAG_FLYING
        else:
            state.is_ascending = False
            state.is_descending = False
            state.flags &= ~(
                _MOVEMENTFLAG_FLYING
                | _MOVEMENTFLAG_ASCENDING
                | _MOVEMENTFLAG_DESCENDING
            )
    elif active_flying_mount and int(getattr(state, "flags", 0) or 0) & (
        _MOVEMENTFLAG_FLYING | _MOVEMENTFLAG_ASCENDING | _MOVEMENTFLAG_DESCENDING
    ):
        if int(getattr(state, "flags", 0) or 0) & _MOVEMENTFLAG_FALLING or bool(getattr(state, "has_fall_data", False)):
            Logger.info(
                "[Movement] converting fall-state to flying mount state opcode=%s guid=0x%X flags=0x%X",
                opcode_name,
                _player_guid(session),
                int(getattr(state, "flags", 0) or 0),
            )
        state.has_fall_data = False
        state.fall_time = 0
        state.fall_vertical_speed = 0.0
        state.fall_horizontal_speed = 0.0
        state.fall_sin_angle = 0.0
        state.fall_cos_angle = 0.0
        state.flags |= _MOVEMENTFLAG_CAN_FLY | _MOVEMENTFLAG_FLYING
        state.flags &= ~_MOVEMENTFLAG_FALLING
        setattr(session, "is_flying", True)
    current_flags = int(getattr(state, "flags", 0) or 0)
    if opcode_name == "MSG_MOVE_STOP" and current_flags & (
        _MOVEMENTFLAG_TURN_LEFT | _MOVEMENTFLAG_TURN_RIGHT
    ):
        Logger.debug(
            "[Movement] STOP left active turn flags=0x%X timestamp=%u outbound=%u",
            current_flags,
            int(getattr(state, "timestamp_ms", 0) or 0),
            int(getattr(state, "server_movement_timestamp_ms", 0) or 0),
        )
    if movement is not None and not older_movement_packet:
        x, y, z, orientation = movement
        _log_orientation_write(
            session,
            writer="_store_authoritative_movement",
            target="movement_state.orientation",
            old_value=float(getattr(state, "orientation", 0.0) or 0.0),
            new_value=float(orientation),
            reason=str(opcode_name),
        )
        from server.modules.handlers.world.position.publication import (
            publish_from_movement,
        )

        publish_from_movement(
            session,
            x=float(x),
            y=float(y),
            z=float(z),
            orientation=float(orientation),
        )
    else:
        _sync_session_from_movement_state(session)
    return True


def _current_position_snapshot(session) -> tuple[int, int, Position | None]:
    position = normalize_position(
        Position(
            map=int(getattr(session, "persist_map_id", 0) or 0),
            x=float(getattr(session, "persist_x", 0.0) or 0.0),
            y=float(getattr(session, "persist_y", 0.0) or 0.0),
            z=float(getattr(session, "persist_z", 0.0) or 0.0),
            orientation=float(getattr(session, "persist_orientation", 0.0) or 0.0),
        ),
        safe_z=True,
    )
    return (
        int(getattr(session, "persist_zone", 0) or 0),
        int(getattr(session, "persist_instance_id", 0) or 0),
        position,
    )


def _saved_position_snapshot(session) -> tuple[int, int, Position | None]:
    position = normalize_position(
        Position(
            map=int(getattr(session, "last_saved_map_id", 0) or 0),
            x=float(getattr(session, "last_saved_x", 0.0) or 0.0),
            y=float(getattr(session, "last_saved_y", 0.0) or 0.0),
            z=float(getattr(session, "last_saved_z", 0.0) or 0.0),
            orientation=float(getattr(session, "last_saved_orientation", 0.0) or 0.0),
        ),
        safe_z=True,
    )
    return (
        int(getattr(session, "last_saved_zone", 0) or 0),
        int(getattr(session, "last_saved_instance_id", 0) or 0),
        position,
    )


def _mark_position_dirty(session) -> None:
    session.position_dirty = _current_position_snapshot(session) != _saved_position_snapshot(session)


def _capture_persist_position_from_session(session) -> None:
    source = _resolve_live_position_source(session)
    raw_position = position_from_session(source)
    position = normalize_position(raw_position, safe_z=True)
    if position is None:
        Logger.warning(
            "[POS_SAVE] invalid live position player=%s raw=%s",
            int(getattr(session, "char_guid", 0) or 0),
            format_position(raw_position),
        )
        return
    from server.modules.handlers.world.position.publication import publish_absolute

    publish_absolute(
        session,
        map_id=int(position.map),
        instance_id=int(getattr(session, "instance_id", 0) or 0),
        x=float(position.x),
        y=float(position.y),
        z=float(position.z),
        orientation=float(position.orientation),
        resolve_area=True,
        capture_persistence=True,
    )
    if POSITION_DEBUG_ENABLED:
        Logger.debug(
            "[POS_DEBUG] capture player=%s pos=%s source=%s",
            int(getattr(session, "char_guid", 0) or 0),
            format_position(position),
            type(source).__name__,
        )


def _maybe_refresh_weather_for_zone_change(
    session,
    previous_zone: int,
) -> list[tuple[str, bytes]]:
    current_zone = int(getattr(session, "zone", 0) or 0)
    if current_zone <= 0 or current_zone == int(previous_zone):
        return []

    if not bool(refresh_region_weather(session)):
        return []

    payload = build_login_packet(
        "SMSG_WEATHER",
        type("Ctx", (), dict(getattr(session, "weather", {}) or {}))(),
    )
    if payload is None:
        return []

    Logger.info(
        "[Weather] zone change player=%s zone=%s weather=%s density=%.2f",
        int(getattr(session, "char_guid", 0) or 0),
        int(current_zone),
        int(dict(getattr(session, "weather", {}) or {}).get("weather_type", 0) or 0),
        float(dict(getattr(session, "weather", {}) or {}).get("density", 0.0) or 0.0),
    )
    return [("SMSG_WEATHER", payload)]


def _build_current_weather_response(
    session,
    *,
    reason: str,
) -> list[tuple[str, bytes]]:
    if getattr(session, "region", None) is None or getattr(session, "global_state", None) is None:
        return []

    refresh_region_weather(session)
    weather = dict(getattr(session, "weather", {}) or {})
    payload = build_login_packet(
        "SMSG_WEATHER",
        type("Ctx", (), weather)(),
    )
    if payload is None:
        return []

    Logger.info(
        "[Weather] teleport refresh player=%s reason=%s zone=%s weather=%s density=%.2f",
        int(getattr(session, "char_guid", 0) or 0),
        str(reason),
        int(getattr(session, "zone", 0) or 0),
        int(weather.get("weather_type", 0) or 0),
        float(weather.get("density", 0.0) or 0.0),
    )
    return [("SMSG_WEATHER", payload)]


def _remember_saved_position(session, now: float | None = None) -> None:
    if now is None:
        now = time.time()
    current_zone, current_instance_id, current_position = _current_position_snapshot(session)
    if current_position is None:
        return
    session.last_saved_map_id = int(current_position.map)
    session.last_saved_zone = int(current_zone)
    session.last_saved_instance_id = int(current_instance_id)
    session.last_saved_x = float(current_position.x)
    session.last_saved_y = float(current_position.y)
    session.last_saved_z = float(current_position.z)
    session.last_saved_orientation = float(current_position.orientation)
    session.last_position_save_at = float(now)
    session.position_dirty = False


def _save_session_position(session, *, reason: str, online: int | None = None, force: bool = False) -> bool:
    if not getattr(session, "char_guid", None) or not getattr(session, "realm_id", None):
        return False
    if (
        str(reason) not in {"disconnect", "logout"}
        and not is_player_world_active(session)
    ):
        Logger.debug(
            "[POS_SAVE] suspended player=%s reason=%s transition_owner=%s generation=%s",
            int(getattr(session, "char_guid", 0) or 0),
            str(reason),
            str(getattr(session, "world_transition_owner", "") or ""),
            int(getattr(session, "world_transition_generation", 0) or 0),
        )
        return False

    if str(getattr(session, "transport_attach_state", "") or "") == "ATTACHED":
        Logger.info(
            "[POS_SAVE] attached position preserved player=%s reason=%s",
            int(getattr(session, "char_guid", 0) or 0),
            str(reason),
        )
        if online is None:
            return False
        now = time.time()
        return DatabaseConnection.save_character_online_state(
            int(session.char_guid),
            int(session.realm_id),
            online=int(online),
            logout_time=int(now) if int(online) == 0 else None,
        )

    now = time.time()
    position_dirty = bool(getattr(session, "position_dirty", False))
    if not force and not position_dirty:
        return False
    if force and not position_dirty and online is not None:
        Logger.info(
            "[POS_SAVE] state-only player=%s reason=%s name=%s online=%s force=%s",
            int(session.char_guid),
            str(reason),
            str(getattr(session, "player_name", "") or ""),
            online,
            force,
        )
        return DatabaseConnection.save_character_online_state(
            int(session.char_guid),
            int(session.realm_id),
            online=online,
            logout_time=int(now) if online == 0 else None,
        )

    persist_position = normalize_position(
        Position(
            map=int(getattr(session, "persist_map_id", 0) or 0),
            x=float(getattr(session, "persist_x", 0.0) or 0.0),
            y=float(getattr(session, "persist_y", 0.0) or 0.0),
            z=float(getattr(session, "persist_z", 0.0) or 0.0),
            orientation=float(getattr(session, "persist_orientation", 0.0) or 0.0),
        ),
        safe_z=True,
    )
    if persist_position is None:
        Logger.warning(
            "[POS_SAVE] rejected player=%s reason=%s invalid persisted snapshot",
            int(session.char_guid),
            str(reason),
        )
        return False

    ok = save_player_position(
        int(session.char_guid),
        persist_position,
        str(reason),
        realm_id=int(session.realm_id),
        zone=int(getattr(session, "persist_zone", 0) or 0),
        instance_id=int(getattr(session, "persist_instance_id", 0) or 0),
        online=online,
        logout_time=int(now) if online == 0 else None,
        player_name=str(getattr(session, "player_name", "") or ""),
        debug=bool(POSITION_DEBUG_ENABLED),
    )
    if ok:
        _remember_saved_position(session, now)
    return ok


def _save_current_position_like_command(
    session,
    *,
    reason: str,
    online: int | None = None,
    force: bool = True,
) -> bool:
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    return _save_session_position(session, reason=str(reason), online=online, force=force)


def _maybe_discover_current_area(session) -> list[tuple[str, bytes]]:
    if not is_player_world_active(session):
        return []
    try:
        area_id = int(
            getattr(session, "current_area", 0)
            or getattr(session, "zone", 0)
            or getattr(session, "persist_zone", 0)
            or 0
        )
        previous_area_check = int(getattr(session, "last_explore_area_check", 0) or 0)
        if area_id != previous_area_check:
            session.last_explore_area_check = area_id
            discovered_areas = getattr(session, "discovered_areas", {}) or {}
            Logger.info(
                "[Explore] area check player=%s map=%s area=%s zone=%s known=%s "
                "pos=(%.2f %.2f %.2f)",
                int(getattr(session, "char_guid", 0) or 0),
                int(getattr(session, "persist_map_id", 0) or 0),
                area_id,
                int(getattr(session, "zone", 0) or 0),
                bool(area_id in discovered_areas),
                float(getattr(session, "persist_x", 0.0) or 0.0),
                float(getattr(session, "persist_y", 0.0) or 0.0),
                float(getattr(session, "persist_z", 0.0) or 0.0),
            )
        responses = discover_area(session, area_id)
        from server.modules.handlers.world.mount.restrictions import enforce_active_mount_legality
        responses.extend(enforce_active_mount_legality(session))
        if responses:
            Logger.info(
                "[Explore] discovery responses area=%s count=%s player=%s",
                area_id,
                len(responses),
                int(getattr(session, "char_guid", 0) or 0),
            )
        return responses
    except Exception as exc:
        Logger.error(
            "[Explore] discovery failed player=%s area=%s err=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "zone", 0) or 0),
            exc,
        )
        return []


def _maybe_periodic_position_save(
    session,
    *,
    position_save_interval_seconds: float = _POSITION_SAVE_INTERVAL_SECONDS,
) -> bool:
    if not is_player_world_active(session):
        return False
    if not getattr(session, "position_dirty", False):
        return False
    now = time.time()
    last = float(getattr(session, "last_position_save_at", 0.0) or 0.0)
    if (now - last) < float(position_save_interval_seconds):
        return False
    saved_zone, saved_instance_id, saved_position = _saved_position_snapshot(session)
    current_zone, current_instance_id, current_position = _current_position_snapshot(session)
    if current_position is None:
        return False
    if not position_moved_enough(saved_position, current_position, threshold=POSITION_AUTOSAVE_DISTANCE_THRESHOLD):
        if POSITION_DEBUG_ENABLED:
            Logger.debug(
                "[POS_DEBUG] autosave skipped player=%s saved=%s current=%s zone=%s->%s instance=%s->%s",
                int(getattr(session, "char_guid", 0) or 0),
                format_position(saved_position),
                format_position(current_position),
                int(saved_zone),
                int(current_zone),
                int(saved_instance_id),
                int(current_instance_id),
            )
        return False
    return _save_session_position(session, reason="autosave", online=1, force=True)



@register("MSG_MOVE_START_FORWARD")
@register("MSG_MOVE_START_BACKWARD")
@register("MSG_MOVE_START_STRAFE_LEFT")
@register("MSG_MOVE_START_STRAFE_RIGHT")
@register("MSG_MOVE_STOP_STRAFE")
@register("MSG_MOVE_STOP")
@register("MSG_MOVE_HEARTBEAT")
@register("MSG_MOVE_JUMP")
@register("MSG_MOVE_START_SWIM")
@register("MSG_MOVE_STOP_SWIM")
@register("MSG_MOVE_START_ASCEND")
@register("MSG_MOVE_STOP_ASCEND")
@register("MSG_MOVE_START_DESCEND")
@register("MSG_MOVE_STOP_DESCEND")
@register("MSG_MOVE_SET_PITCH")
@register("MSG_MOVE_START_TURN_LEFT")
@register("MSG_MOVE_START_TURN_RIGHT")
@register("MSG_MOVE_STOP_TURN")
@register("MSG_MOVE_FALL_LAND")
def handle_movement_packet(session, ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    opcode_name = str(ctx.name or f"0x{int(ctx.opcode):04X}")
    server_receive_ts = int(time.time() * 1000.0) & 0xFFFFFFFF
    Logger.debug(f"[MOVE] opcode={opcode_name}")
    starting_x = float(getattr(session, "x", 0.0) or 0.0)
    starting_y = float(getattr(session, "y", 0.0) or 0.0)
    starting_z = float(getattr(session, "z", 0.0) or 0.0)
    starting_o = float(getattr(session, "orientation", 0.0) or 0.0)
    _consume_pending_teleport_on_movement(session, opcode_name)
    near_fallback_handled, near_fallback_responses = (
        _complete_owned_near_teleport_from_movement(session, opcode_name)
    )
    if near_fallback_handled:
        return 0, near_fallback_responses or None
    if not is_player_world_active(session):
        Logger.debug(
            "[Movement] suspended opcode=%s player=%s transition_owner=%s generation=%s",
            opcode_name,
            int(getattr(session, "char_guid", 0) or 0),
            str(getattr(session, "world_transition_owner", "") or ""),
            int(getattr(session, "world_transition_generation", 0) or 0),
        )
        return 0, None
    _clear_dance_emote_state_on_move(session, opcode_name)
    _apply_early_movement_cleanup(session, opcode_name)
    movement_responses: list[tuple[str, bytes]] = []
    was_flying = _movement_is_flying(session)

    movement = parse_movement_info(session, opcode_name, ctx.payload, ctx.decoded)
    if movement is None:
        if opcode_name in {
            "MSG_MOVE_START_FORWARD",
            "MSG_MOVE_START_BACKWARD",
            "MSG_MOVE_START_STRAFE_LEFT",
            "MSG_MOVE_START_STRAFE_RIGHT",
            "MSG_MOVE_STOP_STRAFE",
            "MSG_MOVE_STOP",
            "MSG_MOVE_START_SWIM",
            "MSG_MOVE_STOP_SWIM",
            "MSG_MOVE_START_ASCEND",
            "MSG_MOVE_STOP_ASCEND",
            "MSG_MOVE_START_DESCEND",
            "MSG_MOVE_STOP_DESCEND",
            "MSG_MOVE_START_TURN_LEFT",
            "MSG_MOVE_START_TURN_RIGHT",
            "MSG_MOVE_STOP_TURN",
        }:
            if not _store_authoritative_movement(session, opcode_name, ctx.payload, None):
                return 0, None
            state = _movement_state(session)
            client_timestamp = int(getattr(state, "client_timestamp_ms", 0) or 0) & 0xFFFFFFFF
            _movement_debug_log(
                session,
                "MOVE_DEBUG guid=Player-%s opcode=%s client_ts=%s server_ts=%u "
                "dx=0.000 dy=0.000 dz=0.000 delta=0.000 correction=false "
                "rejected=false state_only=true flags=0x%X",
                int(getattr(session, "char_guid", 0) or 0),
                opcode_name,
                "none" if client_timestamp <= 0 else str(client_timestamp),
                int(server_receive_ts),
                int(getattr(state, "flags", 0) or 0),
            )
            broadcast_player_state_update(session, force=True)
            Logger.debug(
                "[Movement] state-only %s guid=0x%X pos=(%.3f, %.3f, %.3f) facing=%.3f flags=0x%X",
                opcode_name,
                _player_guid(session),
                float(getattr(session, "x", 0.0) or 0.0),
                float(getattr(session, "y", 0.0) or 0.0),
                float(getattr(session, "z", 0.0) or 0.0),
                float(getattr(session, "orientation", 0.0) or 0.0),
                int(_movement_state(session).flags),
            )
            stream_responses = _refresh_after_movement(
                session,
                context=f"movement:{opcode_name}",
            )
            companion_responses = _maybe_move_companion_pet_for_opcode(session, opcode_name)
            responses = []
            enter_response = _flying_speed_enter_response(session, was_flying)
            if enter_response is not None:
                responses.append(enter_response)
            if stream_responses:
                responses.extend(stream_responses)
            if companion_responses:
                responses.extend(companion_responses)
            return 0, (responses or None)
        Logger.warning(
            f"[Movement] failed to parse {opcode_name} guid=0x{_player_guid(session):X} "
            f"payload_len={len(ctx.payload)}"
        )
        return 0, None

    x, y, z, orientation = movement
    previous_x = float(getattr(session, "x", 0.0) or 0.0)
    previous_y = float(getattr(session, "y", 0.0) or 0.0)
    previous_z = float(getattr(session, "z", 0.0) or 0.0)
    previous_orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    previous_normalized_orientation = _normalize_orientation(previous_orientation)
    state = _movement_state(session)
    if not _accept_movement_update(session, opcode_name, x, y, z, orientation):
        return 0, None

    adjusted_movement = (x, y, z, orientation)

    if not _store_authoritative_movement(session, opcode_name, ctx.payload, adjusted_movement):
        return 0, None
    enter_response = _flying_speed_enter_response(session, was_flying)
    if enter_response is not None:
        movement_responses.append(enter_response)
    if opcode_name == "MSG_MOVE_FALL_LAND" and was_flying and not _has_active_flying_mount(session):
        movement_responses.append(_landing_speed_restore_response(session))

    is_flying_movement = _movement_is_flying(session)
    normalized_orientation = _normalize_orientation(orientation)
    if normalized_orientation is None:
        if is_flying_movement:
            Logger.debug(
                f"[Movement] ignoring invalid flying orientation from {opcode_name}: {orientation!r}"
            )
            return 0, None
        log = Logger.debug if opcode_name == "MSG_MOVE_HEARTBEAT" else Logger.warning
        log(
            f"[Movement] ignoring implausible orientation from {opcode_name}: {orientation!r}; "
            "keeping previous facing"
        )
        normalized_orientation = (
            float(previous_normalized_orientation)
            if previous_normalized_orientation is not None
            else 0.0
        )
    orientation_accepted = True
    if is_flying_movement:
        orientation_accepted = True
    elif opcode_name == "MSG_MOVE_HEARTBEAT":
        if previous_normalized_orientation is not None:
            state = _movement_state(session)
            movement_flags = int(getattr(state, "flags", 0) or 0)
            is_turning = bool(
                movement_flags
                & (_MOVEMENTFLAG_TURN_LEFT | _MOVEMENTFLAG_TURN_RIGHT)
            )
            is_airborne = bool(
                movement_flags & _MOVEMENTFLAG_FALLING
                or bool(getattr(state, "has_fall_data", False))
            )
            if is_turning:
                Logger.debug(
                    "[Movement] accepting turning %s orientation %.6f -> %.6f",
                    opcode_name,
                    float(previous_normalized_orientation),
                    float(normalized_orientation),
                )
            elif is_airborne:
                Logger.debug(
                    "[Movement] accepting airborne %s orientation %.6f -> %.6f",
                    opcode_name,
                    float(previous_normalized_orientation),
                    float(normalized_orientation),
                )
            elif _is_effectively_stationary(
                session,
                x,
                y,
                z,
                current_x=previous_x,
                current_y=previous_y,
                current_z=previous_z,
            ):
                if not math.isclose(
                    float(normalized_orientation),
                    float(previous_normalized_orientation),
                    abs_tol=1e-4,
                ):
                    Logger.debug(
                        "[Movement] ignoring stationary %s orientation override %.6f -> %.6f",
                        opcode_name,
                        float(previous_normalized_orientation),
                        float(normalized_orientation),
                    )
            else:
                Logger.debug(
                    "[Movement] ignoring %s orientation override %.6f -> %.6f",
                    opcode_name,
                    float(previous_normalized_orientation),
                    float(normalized_orientation),
                )
            orientation_accepted = bool(is_turning or is_airborne or is_flying_movement)
            if not orientation_accepted:
                previous_is_zero = math.isclose(
                    float(previous_normalized_orientation),
                    0.0,
                    abs_tol=1e-6,
                )
                incoming_is_nonzero = not math.isclose(
                    float(normalized_orientation),
                    0.0,
                    abs_tol=1e-6,
                )
                if previous_is_zero and incoming_is_nonzero:
                    recovered_orientation = _last_known_valid_orientation(session)
                    if recovered_orientation is None:
                        recovered_orientation = float(normalized_orientation)
                    Logger.debug(
                        "[Movement] recovering %s orientation %.6f -> %.6f",
                        opcode_name,
                        float(previous_normalized_orientation),
                        float(recovered_orientation),
                    )
                    normalized_orientation = float(recovered_orientation)
                else:
                    normalized_orientation = float(previous_normalized_orientation)
    state = _movement_state(session)
    movement_flags = int(getattr(state, "flags", 0) or 0)
    is_turning = bool(movement_flags & (_MOVEMENTFLAG_TURN_LEFT | _MOVEMENTFLAG_TURN_RIGHT))
    is_airborne = bool(
        movement_flags & _MOVEMENTFLAG_FALLING
        or bool(getattr(state, "has_fall_data", False))
    )
    Logger.debug(
        "[ORIENTATION_ACCEPT] opcode=%s is_flying=%s is_turning=%s old=%.6f new=%.6f accepted=%s",
        opcode_name,
        bool(is_flying_movement),
        bool(is_turning),
        float(previous_orientation),
        float(normalized_orientation),
        bool(orientation_accepted),
    )

    if is_flying_movement:
        session.pitch = float(getattr(state, "pitch", 0.0) or 0.0)
        _log_orientation_write(
            session,
            writer="handle_movement_packet",
            target="movement_state.orientation",
            old_value=float(getattr(state, "orientation", 0.0) or 0.0),
            new_value=float(normalized_orientation),
            reason=f"{opcode_name}:flying",
        )
        from server.modules.handlers.world.position.publication import (
            publish_from_movement,
        )

        publish_from_movement(
            session,
            x=float(x),
            y=float(y),
            z=float(z),
            orientation=float(normalized_orientation),
        )
        _remember_valid_orientation(session, state.orientation)
        _log_orientation_write(
            session,
            writer="handle_movement_packet",
            target="session.orientation",
            old_value=float(getattr(session, "orientation", 0.0) or 0.0),
            new_value=float(state.orientation),
            reason=f"{opcode_name}:flying",
        )
        Logger.debug(
            "[FLY_PITCH] pitch=%.6f z=%.6f flags=0x%X",
            float(session.pitch),
            float(session.z),
            int(getattr(state, "flags", 0) or 0),
        )
    else:
        _log_orientation_write(
            session,
            writer="handle_movement_packet",
            target="movement_state.orientation",
            old_value=float(getattr(state, "orientation", 0.0) or 0.0),
            new_value=float(normalized_orientation),
            reason=str(opcode_name),
        )
        from server.modules.handlers.world.position.publication import (
            publish_from_movement,
        )

        publish_from_movement(
            session,
            x=float(x),
            y=float(y),
            z=float(z),
            orientation=float(normalized_orientation),
        )
        _remember_valid_orientation(session, state.orientation)
    client_timestamp = int(getattr(state, "client_timestamp_ms", 0) or 0) & 0xFFFFFFFF
    movement_delta = math.sqrt(
        ((float(session.x) - previous_x) ** 2)
        + ((float(session.y) - previous_y) ** 2)
        + ((float(session.z) - previous_z) ** 2)
    )
    _movement_debug_log(
        session,
        "MOVE_DEBUG guid=Player-%s opcode=%s client_ts=%s server_ts=%u "
        "dx=%.3f dy=%.3f dz=%.3f delta=%.3f correction=false rejected=false "
        "flags=0x%X",
        int(getattr(session, "char_guid", 0) or 0),
        opcode_name,
        "none" if client_timestamp <= 0 else str(client_timestamp),
        int(server_receive_ts),
        float(session.x) - previous_x,
        float(session.y) - previous_y,
        float(session.z) - previous_z,
        float(movement_delta),
        int(getattr(state, "flags", 0) or 0),
    )
    previous_zone_for_weather = int(getattr(session, "zone", 0) or 0)
    _capture_persist_position_from_session(session)
    movement_responses.extend(
        _maybe_refresh_weather_for_zone_change(session, previous_zone_for_weather)
    )
    _mark_position_dirty(session)
    discovery_responses = _maybe_discover_current_area(session)
    if discovery_responses:
        movement_responses.extend(discovery_responses)
    _maybe_clear_stale_near_teleport_pending_on_movement(session, opcode_name)
    if opcode_name == "MSG_MOVE_HEARTBEAT":
        _maybe_periodic_position_save(session)
    try:
        from server.modules.handlers.world.teleport.area_trigger import (
            check_movement_segment_for_area_triggers,
        )

        area_trigger_responses = check_movement_segment_for_area_triggers(
            session,
            (float(previous_x), float(previous_y), float(previous_z)),
            (float(session.x), float(session.y), float(session.z)),
        )
    except Exception as exc:
        Logger.debug("[AREATRIGGER] movement check failed: %s", exc)
        area_trigger_responses = None
    if area_trigger_responses:
        movement_responses.extend(area_trigger_responses)
        return 0, movement_responses
    force_broadcast = opcode_name in {
        "MSG_MOVE_HEARTBEAT",
        "MSG_MOVE_JUMP",
        "MSG_MOVE_START_ASCEND",
        "MSG_MOVE_STOP_ASCEND",
        "MSG_MOVE_START_DESCEND",
        "MSG_MOVE_STOP_DESCEND",
        "MSG_MOVE_SET_PITCH",
        "MSG_MOVE_FALL_LAND",
    }
    if opcode_name == "MSG_MOVE_JUMP":
        Logger.debug(
            "[JUMP_BROADCAST] opcode=%s fall_time=%s force=%s",
            opcode_name,
            int(getattr(state, "fall_time", 0) or 0),
            bool(force_broadcast),
        )
    broadcast_player_state_update(session, force=force_broadcast)

    Logger.debug(
        f"[MOVE] guid=0x{_player_guid(session):X} "
        f"pos=({session.x:.3f}, {session.y:.3f}, {session.z:.3f}) facing={session.orientation:.3f}"
    )
    stream_responses = _refresh_after_movement(
        session,
        context=f"movement:{opcode_name}",
    )
    if stream_responses:
        movement_responses.extend(stream_responses)
    companion_responses = _maybe_move_companion_pet_for_opcode(session, opcode_name)
    if companion_responses:
        movement_responses.extend(companion_responses)
    return 0, (movement_responses or None)


@register("MSG_MOVE_SET_FACING")
def handle_msg_move_set_facing(session, ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    _consume_pending_teleport_on_movement(session, "MSG_MOVE_SET_FACING")
    if not is_player_world_active(session):
        return 0, None
    payload = bytes(ctx.payload or b"")
    if len(payload) < 4:
        Logger.warning("[Movement] MSG_MOVE_SET_FACING payload too short")
        return 0, None
    _clear_dance_emote_state_on_move(session, "MSG_MOVE_SET_FACING")

    try:
        orientation = struct.unpack_from("<f", payload, len(payload) - 4)[0]
    except struct.error:
        Logger.warning("[Movement] MSG_MOVE_SET_FACING unpack failed")
        return 0, None

    normalized_orientation = _normalize_orientation(orientation)
    if normalized_orientation is None:
        Logger.warning(
            f"[Movement] ignoring implausible MSG_MOVE_SET_FACING orientation: {orientation!r}"
        )
        return 0, None

    state = _movement_state(session)
    _log_orientation_write(
        session,
        writer="handle_msg_move_set_facing",
        target="movement_state.orientation",
        old_value=float(getattr(state, "orientation", 0.0) or 0.0),
        new_value=float(normalized_orientation),
        reason="MSG_MOVE_SET_FACING",
    )
    from server.modules.handlers.world.position.publication import (
        publish_from_movement,
    )

    publish_from_movement(
        session,
        x=float(state.x),
        y=float(state.y),
        z=float(state.z),
        orientation=float(normalized_orientation),
    )
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    discovery_responses = _maybe_discover_current_area(session)
    _maybe_periodic_position_save(session)

    Logger.debug(
        f"[MOVE] opcode=MSG_MOVE_SET_FACING guid=0x{_player_guid(session):X} "
        f"facing={session.orientation:.3f}"
    )
    broadcast_player_state_update(session, force=True)
    stream_responses = _refresh_after_movement(
        session,
        context="movement:MSG_MOVE_SET_FACING",
    )
    responses = []
    responses.extend(discovery_responses)
    responses.extend(stream_responses)
    return 0, (responses or None)


def _post_teleport_multiplayer_resync(
    session,
    *,
    reason: str,
) -> list[tuple[str, bytes]]:
    """Rebuild live peer state after teleport ACK using existing runtime paths."""
    if not (
        bool(getattr(session, "is_mounted", False))
        or int(getattr(session, "mount_spell", 0) or 0)
        or int(getattr(session, "mount_display_id", 0) or 0)
    ):
        broadcast_player_state_update(session, force=True)
        force_bilateral_visibility_resync(session, reason=reason)
        return []

    try:
        from server.modules.handlers.world.opcodes import spells as spells_handlers
    except Exception as exc:
        Logger.warning("[Teleport] mount resync unavailable reason=%s err=%s", reason, exc)
        return []

    responses = list(spells_handlers.dismount(session))
    move_payload = build_smsg_player_move_payload(session)
    if move_payload is not None:
        responses.append(("SMSG_PLAYER_MOVE", move_payload))

    broadcast_player_state_update(session, force=True)
    force_bilateral_visibility_resync(session, reason=reason)
    Logger.info(
        "[Teleport] post-ack dismount player=%s reason=%s",
        int(getattr(session, "char_guid", 0) or 0),
        str(reason),
    )
    return responses


@register("CMSG_MOVE_TELEPORT_ACK")
def handle_move_teleport_ack(session, _ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    Logger.info(
        "[Teleport] ack opcode=CMSG_MOVE_TELEPORT_ACK pending_before=(near=%s world=%s teleport=%s) "
        "destination=%s player=%s",
        bool(getattr(session, "near_teleport_pending", False)),
        bool(getattr(session, "worldport_ack_pending", False)),
        bool(getattr(session, "teleport_pending", False)),
        str(getattr(session, "teleport_destination", "") or "?"),
        int(getattr(session, "char_guid", 0) or 0),
    )
    if not bool(getattr(session, "near_teleport_pending", False)):
        Logger.debug("[Teleport] ignoring unexpected CMSG_MOVE_TELEPORT_ACK")
        return 0, [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload("[Teleport] unexpected near-teleport ack ignored"))]

    from server.modules.handlers.world.teleport.transition import (
        current_near_teleport_is_owned,
    )

    if (
        str(getattr(session, "world_transition_owner", "") or "")
        == "ordinary_teleport"
        and not current_near_teleport_is_owned(session)
    ):
        Logger.info(
            "[Teleport] stale near-teleport ACK ignored player=%s "
            "near_generation=%s current_generation=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "near_teleport_generation", 0) or 0),
            int(getattr(session, "world_transition_generation", 0) or 0),
        )
        return 0, None

    destination = str(getattr(session, "teleport_destination", "") or "?")
    session.near_teleport_pending = False
    session.worldport_ack_pending = False
    fixspeed_pending = bool(getattr(session, "fixspeed_pending", False))
    session.fixspeed_pending = False
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    _save_session_position(session, reason="near-teleport", online=1, force=True)
    from server.modules.handlers.world.teleport.lifecycle import get_teleport_lifecycle

    world_refresh_responses = get_teleport_lifecycle().complete_transition(
        session,
        context="near-teleport-ack",
        refresh="teleport",
        _teleport_resync=_post_teleport_multiplayer_resync,
        _object_refresh=stream_world_objects_after_teleport,
    )
    if fixspeed_pending:
        self_resync_responses = build_same_map_teleport_self_resync_responses(session)
    else:
        self_resync_responses = build_same_map_teleport_self_resync_responses(session)
    Logger.info(
        "[Teleport] same-map teleport ack destination=%s pos=(%.2f %.2f %.2f %.2f)",
        destination,
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )
    responses = [
        (
            "SMSG_MESSAGECHAT",
            encode_skyfire_messagechat_system_payload(
                f"[Teleport] same-map ack -> {destination}"
            ),
        )
    ]
    responses.extend(self_resync_responses)
    responses.extend(world_refresh_responses)
    responses.extend(_build_current_weather_response(session, reason="near-teleport-ack"))
    if fixspeed_pending:
        for opcode_name, speed_value in (
            ("SMSG_MOVE_SET_WALK_SPEED", float(getattr(session, "walk_speed", 2.5) or 2.5)),
            ("SMSG_MOVE_SET_RUN_SPEED", float(getattr(session, "run_speed", 7.0) or 7.0)),
            ("SMSG_MOVE_SET_SWIM_SPEED", float(getattr(session, "swim_speed", 4.7) or 4.7)),
            ("SMSG_MOVE_SET_FLIGHT_SPEED", float(getattr(session, "fly_speed", 7.0) or 7.0)),
        ):
            responses.append((opcode_name, build_move_set_speed_payload(session, opcode_name, speed_value)))
        refresh_response = _build_run_speed_refresh_response(session)
        if refresh_response is not None:
            responses.append(refresh_response)
        responses.insert(
            1,
            (
                "SMSG_MESSAGECHAT",
                encode_skyfire_messagechat_system_payload("[FixSpeed] same-map ack -> speed refresh"),
            ),
        )
    session.teleport_destination = None
    return 0, responses

@register("MSG_MOVE_WORLDPORT_ACK")
@register("CMSG_MOVE_WORLDPORT_ACK")
def handle_move_worldport_ack(session, _ctx: PacketContext):
    if not bool(getattr(session, "worldport_ack_pending", False)):
        log_transport_event(
            TransportDebugEvent.LATE_ACK_IGNORED,
            transport_guid=int(
                getattr(getattr(session, "movement_state", None), "transport_guid", 0)
                or 0
            ),
            player_guid=int(getattr(session, "char_guid", 0) or 0),
            reason="no_worldport_pending",
        )
        Logger.debug("[Teleport] ignoring unexpected WORLDPORT_ACK")
        return 0, None

    from server.modules.handlers.world.teleport.transition import (
        should_ignore_worldport_ack,
    )

    if should_ignore_worldport_ack(session):
        Logger.info(
            "[TeleportTransition] ignoring superseded WORLDPORT_ACK "
            "generation=%s destination=%s",
            int(getattr(session, "world_transition_generation", 0) or 0),
            str(getattr(session, "teleport_destination", "") or "?"),
        )
        return 0, None

    if bool(getattr(session, "_worldporttest_active", False)):
        Logger.info(
            "[WorldportTest] worldport_ack player=%s map=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "map_id", 0) or 0),
        )

    if bool(getattr(session, "teleport_pending", False)):
        pending = getattr(session, "pending_transport_transfer", None)
        expected_generation = int(
            (
                pending.get("world_transition_generation", 0)
                if isinstance(pending, dict)
                else getattr(
                    session,
                    "world_transition_loading_generation",
                    0,
                )
            )
            or 0
        )
        expected_owner = str(
            getattr(session, "world_transition_owner", "") or ""
        )
        from server.modules.handlers.world.opcodes.login import (
            ensure_worldport_bootstrap_started,
        )

        responses = ensure_worldport_bootstrap_started(
            session,
            "worldport_ack",
            expected_generation=expected_generation,
            expected_owner=expected_owner,
        )
        return 0, responses or None

    destination = str(getattr(session, "teleport_destination", "") or "?")
    # Compatibility path for ACKs that are not attached to a pending
    # generation-owned worldport. Active worldports returned above.
    session.near_teleport_pending = False
    session.worldport_ack_pending = False
    pending_transport_diagnostics = getattr(session, "pending_transport_transfer", None)
    _log_transport_worldport_ack_diagnostics(session, pending_transport_diagnostics)
    try:
        complete_pending_transport_transfer(session)
    except Exception as exc:
        session.pending_transport_transfer = None
        session.transport_transfer_pending = False
        Logger.warning(
            "[TransportTransfer] post_worldport_reattach_failed error=%s",
            str(exc),
        )

    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    _save_session_position(session, reason="worldport", online=1, force=True)
    Logger.info(
        "[Teleport] world transfer ack destination=%s pos=(%.2f %.2f %.2f %.2f)",
        destination,
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )

    responses = [
        (
            "SMSG_MESSAGECHAT",
            encode_skyfire_messagechat_system_payload(
                f"[Teleport] worldport ack -> {destination}"
            ),
        )
    ]
    if is_player_world_active(session):
        from server.modules.handlers.world.world_refresh import get_world_refresh_service

        streamed_world_responses = get_world_refresh_service().refresh_after_transport(
            session,
            context="worldport-ack",
            _teleport_resync=_post_teleport_multiplayer_resync,
            _object_refresh=stream_world_objects_after_teleport,
        )
        responses.extend(streamed_world_responses)
        responses.extend(
            _build_current_weather_response(session, reason="worldport-ack")
        )
    else:
        from server.modules.handlers.world.world_refresh import get_world_refresh_service

        responses.extend(
            get_world_refresh_service().refresh_player_world(
                session,
                context="worldport-ack-inactive",
                stream_world_objects=False,
                teleport_resync_reason="worldport-ack",
                _teleport_resync=_post_teleport_multiplayer_resync,
            )
        )
    if isinstance(pending_transport_diagnostics, dict):
        destination_entry = pending_transport_diagnostics.get("destination_entry")
        if isinstance(destination_entry, dict):
            try:
                from server.modules.handlers.world.transport_runtime import (
                    is_cross_map_boat_entry,
                    is_cross_map_zeppelin_entry,
                    transport_passenger_attachment,
                )

                is_boat = is_cross_map_boat_entry(destination_entry)
                is_zeppelin = is_cross_map_zeppelin_entry(destination_entry)
                if is_boat or is_zeppelin:
                    state = _movement_state(session)
                    destination_guid = int(
                        pending_transport_diagnostics.get("destination_guid", 0) or 0
                    )
                    runtime_attachment = transport_passenger_attachment(
                        destination_guid,
                        int(getattr(session, "char_guid", 0) or 0),
                    )
                    outbound_names = [name for name, _payload in responses]
                    first_update = next(
                        (
                            name
                            for name in outbound_names
                            if name in {"SMSG_PLAYER_MOVE", "SMSG_UPDATE_OBJECT"}
                        ),
                        "none",
                    )
                    Logger.info(
                        "[TransportTransferDiag] before_post_worldport_update transfer_id=%s "
                        "kind=%s player_world=(%.3f %.3f %.3f %.3f) "
                        "transport_guid=0x%016X local_offset=(%.3f %.3f %.3f %.3f) "
                        "attached=%s runtime_attachment=%s first_update=%s "
                        "self_movement_packet=%s world_sent=(%.3f %.3f %.3f %.3f)",
                        str(
                            pending_transport_diagnostics.get("transfer_id", "unknown")
                            or "unknown"
                        ),
                        "boat" if is_boat else "zeppelin",
                        float(getattr(session, "x", 0.0) or 0.0),
                        float(getattr(session, "y", 0.0) or 0.0),
                        float(getattr(session, "z", 0.0) or 0.0),
                        float(getattr(session, "orientation", 0.0) or 0.0),
                        int(getattr(state, "transport_guid", 0) or 0)
                        & 0xFFFFFFFFFFFFFFFF,
                        float(getattr(state, "transport_x", 0.0) or 0.0),
                        float(getattr(state, "transport_y", 0.0) or 0.0),
                        float(getattr(state, "transport_z", 0.0) or 0.0),
                        float(getattr(state, "transport_orientation", 0.0) or 0.0),
                        "true"
                        if bool(getattr(state, "has_transport_data", False))
                        and int(getattr(state, "transport_guid", 0) or 0)
                        == destination_guid
                        else "false",
                        "true" if runtime_attachment is not None else "false",
                        first_update,
                        "true" if "SMSG_PLAYER_MOVE" in outbound_names else "false",
                        float(getattr(session, "x", 0.0) or 0.0),
                        float(getattr(session, "y", 0.0) or 0.0),
                        float(getattr(session, "z", 0.0) or 0.0),
                        float(getattr(session, "orientation", 0.0) or 0.0),
                    )
            except Exception as exc:
                Logger.info(
                    "[TransportTransferDiag] before_post_worldport_update transfer_id=%s "
                    "return_reason=diagnostic_error error=%s",
                    str(
                        pending_transport_diagnostics.get("transfer_id", "unknown")
                        or "unknown"
                    ),
                    str(exc),
                )
    return 0, responses
@register("CMSG_MOVE_FORCE_RUN_SPEED_CHANGE_ACK")
def handle_move_force_run_speed_change_ack(session, _ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    Logger.debug(
        "[Movement] CMSG_MOVE_FORCE_RUN_SPEED_CHANGE_ACK guid=0x%X run_speed=%.3f",
        _player_guid(session),
        float(getattr(session, "run_speed", 0.0) or 0.0),
    )
    refresh_response = _build_run_speed_refresh_response(session)
    if refresh_response is None:
        return 0, None
    return 0, [refresh_response]


@staticmethod
def get_map_name(map_id: int) -> str:
    row = DatabaseConnection.world_execute_one(
        "SELECT name FROM map WHERE id = :id",
        {"id": int(map_id)},
    )
    return row.get("name") if row else f"Map {map_id}"





def configure(**helpers: Any) -> None:
    """Store helper callbacks provided by the chat opcode module."""
    HELPERS.update(helpers)


def _helper(name: str) -> Any:
    """Return a configured helper or fail fast."""
    if name not in HELPERS:
        raise RuntimeError(f"chat command helper not configured: {name}")
    return HELPERS[name]



HELPERS: dict[str, Any] = {}

def _notification_response(message: str) -> list[tuple[str, bytes]]:
    """Build a system chat response."""
    helper = HELPERS.get("notification_response")
    if callable(helper):
        return helper(message)
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]

def _append_feedback_response(
    responses: list[tuple[str, bytes]] | None,
    message: str,
) -> list[tuple[str, bytes]]:
    """Append a system chat line after command responses."""
    helper = HELPERS.get("append_feedback_response")
    if callable(helper):
        return helper(responses, message)
    merged = list(responses or [])
    merged.extend(_notification_response(message))
    return merged

@register("CMSG_AREATRIGGER")
def handle_areatrigger(session, ctx: PacketContext):
    if len(ctx.payload) < 4:
        return 0, None

    trigger_id = int.from_bytes(ctx.payload[:4], "little")
    from server.modules.handlers.world.teleport.area_trigger import activate_area_trigger

    responses = activate_area_trigger(session, trigger_id, source="client")
    if responses is None:
        return 0, [
            (
                "SMSG_MESSAGECHAT",
                encode_skyfire_messagechat_system_payload(
                    f"[AREATRIGGER] id={trigger_id} (no mapping)"
                ),
            )
        ]
    return 0, (responses or None)
