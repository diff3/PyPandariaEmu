from __future__ import annotations

import math
import struct
import threading
import time
from types import SimpleNamespace
from typing import Any, Optional, Tuple

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitInterPreter, BitWriter
# from modules.handlers.world.opcodes.chat import _append_feedback_response
from shared.Logger import Logger
from server.modules.game.guid import CreatureGuid, GameObjectGuid, GuidHelper, MoTransportGuid
from server.modules.handlers.world.bootstrap.replay import (
    build_database_gameobject_responses,
    build_single_u32_update_object_payload,
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
from server.modules.handlers.world.position.area_service import resolve_zone_from_position
from server.modules.handlers.world.state.runtime import (
    broadcast_player_state_update,
    build_same_map_teleport_self_resync_responses,
    dispatch_responses_to_sessions,
    force_bilateral_visibility_resync,
)


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
_MOVEMENTFLAG_ASCENDING = 0x00200000
_MOVEMENTFLAG_DESCENDING = 0x00400000
_MOVEMENTFLAG_CAN_FLY = 0x00800000
_MOVEMENTFLAG_FLYING = 0x01000000
_MOVEMENTFLAG2_CIRCLE_RUN_SYNC = 0x00000800

_MANUAL_RATCHET_BOAT_GUID = int(MoTransportGuid.from_spawn_guid(9_501_001))
_MANUAL_RATCHET_BOAT_TRANSFER_TIME = 115_000
_MANUAL_RATCHET_BOAT_TRANSFER_X = -1030.0
_MANUAL_RATCHET_BOAT_TRANSFER_Y = -4050.0
_MANUAL_RATCHET_TO_BOOTY_BAY = (0, -14297.2, 531.0, 8.8, 1.0)

_LIFT_STATE_FREE = "FREE"
_LIFT_STATE_MAGNET = "MAGNET"
_LIFT_STATE_ATTACHED = "ATTACHED"
_LIFT_STATE_DETACHING = "DETACHING"
_LIFT_SUPPORT_RADIUS_YARDS = 45.0
_LIFT_SUPPORT_RELEASE_RADIUS_YARDS = 75.0
_LIFT_SUPPORT_MAGNET_RADIUS_YARDS = 55.0
_LIFT_SUPPORT_ABOVE_YARDS = 3.0
_LIFT_SUPPORT_BELOW_YARDS = 8.0
_LIFT_SUPPORT_MAGNET_ABOVE_YARDS = 6.0
_LIFT_SUPPORT_MAGNET_BELOW_YARDS = 12.0
_LIFT_SUPPORT_LOG_INTERVAL_SECONDS = 0.75
_LIFT_SUPPORT_CACHE_SECONDS = 5.0
_LIFT_SUPPORT_MAX_STATIC_SECONDS = 35.0
_LIFT_SUPPORT_GRACE_SECONDS = 0.75
_LIFT_SUPPORT_STABILIZE_SECONDS = 1.5
_LIFT_SUPPORT_NO_RELOCK_SECONDS = 1.0
_LIFT_SUPPORT_STABLE_HEARTBEATS_REQUIRED = 2
_LIFT_SUPPORT_ATTACH_SECONDS = 1.75
_LIFT_SUPPORT_STABLE_Z_DELTA = 0.75
_LIFT_SUPPORT_LAND_Z_THRESHOLD = 3.0
_LIFT_SUPPORT_HEARTBEAT_Z_THRESHOLD = 2.5
_LIFT_SUPPORT_MAX_BAD_PACKETS = 3
_THUNDER_BLUFF_LIFT_LOW_Z = 68.586
_THUNDER_BLUFF_LIFT_HIGH_Z = 130.080
_THUNDER_BLUFF_LIFT_PERIOD_SECONDS = 32.0
_THUNDER_BLUFF_LIFT_TICK_SECONDS = 0.25
_THUNDER_BLUFF_LIFT_TICK_MIN_DELTA_Z = 0.04
_ELEVATOR_ATTACH_RADIUS_YARDS = 42.0
_ELEVATOR_RELEASE_RADIUS_YARDS = 58.0
_ELEVATOR_ATTACH_Z_THRESHOLD = 3.5
_ELEVATOR_FALL_ATTACH_Z_THRESHOLD = 10.0
_ELEVATOR_STEP_HEIGHT_THRESHOLD = 2.75
_ELEVATOR_JUMP_LOCAL_Z_THRESHOLD = 14.0
_ELEVATOR_NO_RELOCK_SECONDS = 1.0
_LIFT_SUPPORT_APPLY_OPCODES = frozenset({
    "MSG_MOVE_FALL_LAND",
    "MSG_MOVE_HEARTBEAT",
    "MSG_MOVE_START_FORWARD",
})
_LIFT_SUPPORT_ACTIVE_REFRESH_OPCODES = frozenset({
    "MSG_MOVE_START_FORWARD",
    "MSG_MOVE_STOP",
})
_LIFT_SUPPORT_RELEASE_OPCODES = frozenset({
    "MSG_MOVE_JUMP",
    "MSG_MOVE_START_BACKWARD",
    "MSG_MOVE_START_FORWARD",
    "MSG_MOVE_START_STRAFE_LEFT",
    "MSG_MOVE_START_STRAFE_RIGHT",
})
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


def _movement_sync_guid(session) -> int:
    return int(getattr(session, "char_guid", 0) or _player_guid(session) or 0)


def _movement_state(session):
    state = getattr(session, "movement_state", None)
    if state is None:
        from server.session.world_session import MovementState

        state = MovementState()
        session.movement_state = state

    state.x = float(getattr(state, "x", getattr(session, "x", 0.0)) or 0.0)
    state.y = float(getattr(state, "y", getattr(session, "y", 0.0)) or 0.0)
    state.z = float(getattr(state, "z", getattr(session, "z", 0.0)) or 0.0)
    state.orientation = float(getattr(state, "orientation", getattr(session, "orientation", 0.0)) or 0.0)
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
    state = _movement_state(session)
    state_flags = int(getattr(state, "flags", 0) or 0)
    return bool(
        getattr(session, "is_flying", False)
        or getattr(session, "can_fly", False)
        or state_flags & (_MOVEMENTFLAG_CAN_FLY | _MOVEMENTFLAG_FLYING)
    )


def _has_active_flying_mount(session) -> bool:
    """Return true while a restored mount should own flying state.

    Login restore can race with stale client fall packets.  Keep this check
    small and explicit so landing handling cannot accidentally confirm those.
    """
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
    if _lift_support_active(session):
        return True
    if int(getattr(_movement_state(session), "transport_guid", 0) or 0):
        return True
    loaded_lifts = getattr(session, "loaded_lift_entries", None)
    return isinstance(loaded_lifts, dict) and bool(loaded_lifts)


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
    session.x = float(state.x)
    session.y = float(state.y)
    session.z = float(state.z)
    session.orientation = float(state.orientation)
    _remember_valid_orientation(session, state.orientation)


def _store_transport_state_from_parsed(session, opcode_name: str, parsed: dict[str, Any]) -> None:
    state = _movement_state(session)
    previous_guid = int(getattr(state, "transport_guid", 0) or 0)

    if not bool(parsed.get("has_transport_data")):
        if previous_guid:
            _log_transport_passenger_detach(session, previous_guid, opcode_name)
            Logger.info(
                "[TRANSPORT_STATE] clear opcode=%s previous_tguid=0x%016X",
                opcode_name,
                previous_guid & 0xFFFFFFFFFFFFFFFF,
            )
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
    state.has_transport_data = True
    state.transport_guid = transport_guid
    state.transport_x = float(parsed.get("transport_x", 0.0) or 0.0)
    state.transport_y = float(parsed.get("transport_y", 0.0) or 0.0)
    state.transport_z = float(parsed.get("transport_z", 0.0) or 0.0)
    state.transport_orientation = float(parsed.get("transport_orientation", 0.0) or 0.0)
    state.transport_time = int(parsed.get("transport_time", 0) or 0) & 0xFFFFFFFF
    state.transport_time2 = int(parsed.get("transport_time2", 0) or 0) & 0xFFFFFFFF
    state.transport_time3 = int(parsed.get("transport_time3", 0) or 0) & 0xFFFFFFFF
    state.transport_seat = int(parsed.get("transport_seat", -1))
    state.transport_vehicle_id = int(parsed.get("transport_vehicle_id", 0) or 0)

    loaded_lifts = getattr(session, "loaded_lift_entries", None)
    lift = loaded_lifts.get(transport_guid) if isinstance(loaded_lifts, dict) else None
    if previous_guid != transport_guid:
        _log_transport_passenger_attach(session, transport_guid, opcode_name)
    Logger.info(
        "[TRANSPORT_STATE] set opcode=%s tguid=0x%016X lift=%s "
        "offset=(%.3f %.3f %.3f) torient=%.3f time=%u seat=%s",
        opcode_name,
        transport_guid & 0xFFFFFFFFFFFFFFFF,
        "yes" if isinstance(lift, dict) else "no",
        float(state.transport_x),
        float(state.transport_y),
        float(state.transport_z),
        float(state.transport_orientation),
        int(state.transport_time),
        int(state.transport_seat),
    )


def _transport_entry_for_guid(session, transport_guid: int) -> dict[str, Any] | None:
    loaded_transport_entries = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transport_entries, dict):
        entry = loaded_transport_entries.get(int(transport_guid))
        if isinstance(entry, dict):
            return entry

    loaded_lifts = getattr(session, "loaded_lift_entries", None)
    if isinstance(loaded_lifts, dict):
        entry = loaded_lifts.get(int(transport_guid))
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
        from server.modules.handlers.world.transport_runtime import is_thunder_bluff_elevator_entry
    except Exception:
        return False
    return bool(is_thunder_bluff_elevator_entry(entry))


def _has_loaded_real_runtime_elevator(session) -> bool:
    loaded_transport_entries = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transport_entries, dict) and any(
        _is_real_runtime_elevator_entry(entry)
        for entry in loaded_transport_entries.values()
        if isinstance(entry, dict)
    ):
        return True

    loaded_lifts = getattr(session, "loaded_lift_entries", None)
    return bool(
        isinstance(loaded_lifts, dict)
        and any(
            isinstance(entry, dict) and _is_thunder_bluff_lift(entry)
            for entry in loaded_lifts.values()
        )
    )


def _log_transport_passenger_attach(session, transport_guid: int, opcode_name: str) -> None:
    entry = _transport_entry_for_guid(session, int(transport_guid))
    if not _is_real_runtime_elevator_entry(entry):
        return
    Logger.info(
        "[WorldElevator] passenger attached opcode=%s char=%s tguid=0x%016X "
        "entry=%s local=(%.3f %.3f %.3f)",
        str(opcode_name),
        int(getattr(session, "char_guid", 0) or 0),
        int(transport_guid) & 0xFFFFFFFFFFFFFFFF,
        int(entry.get("entry", 0) or 0),
        float(getattr(_movement_state(session), "transport_x", 0.0) or 0.0),
        float(getattr(_movement_state(session), "transport_y", 0.0) or 0.0),
        float(getattr(_movement_state(session), "transport_z", 0.0) or 0.0),
    )


def _log_transport_passenger_detach(session, transport_guid: int, opcode_name: str) -> None:
    entry = _transport_entry_for_guid(session, int(transport_guid))
    if not _is_real_runtime_elevator_entry(entry):
        return
    Logger.info(
        "[WorldElevator] passenger detached opcode=%s char=%s tguid=0x%016X entry=%s",
        str(opcode_name),
        int(getattr(session, "char_guid", 0) or 0),
        int(transport_guid) & 0xFFFFFFFFFFFFFFFF,
        int(entry.get("entry", 0) or 0),
    )


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
    return responses


def _maybe_start_manual_boat_transfer(session, opcode_name: str) -> list[tuple[str, bytes]]:
    state = _movement_state(session)
    transport_guid = int(getattr(state, "transport_guid", 0) or 0)
    if transport_guid != _MANUAL_RATCHET_BOAT_GUID:
        return []
    if int(getattr(session, "map_id", 0) or 0) != 1:
        return []
    if bool(getattr(session, "manual_boat_transfer_pending", False)):
        return []
    if _is_teleporting(session):
        return []

    transport_time = int(getattr(state, "transport_time", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    if transport_time < _MANUAL_RATCHET_BOAT_TRANSFER_TIME:
        return []
    if x > _MANUAL_RATCHET_BOAT_TRANSFER_X or y > _MANUAL_RATCHET_BOAT_TRANSFER_Y:
        return []

    from server.modules.handlers.world.login.packets import build_login_packet

    map_id, dest_x, dest_y, dest_z, orientation = _MANUAL_RATCHET_TO_BOOTY_BAY
    session.manual_boat_transfer_pending = True
    session.teleport_pending = True
    session.worldport_ack_pending = True
    session.near_teleport_pending = False
    session.teleport_destination = "manual-boat:ratchet-to-booty-bay"
    session.map_id = int(map_id)
    session.x = float(dest_x)
    session.y = float(dest_y)
    session.z = float(dest_z)
    session.orientation = float(orientation)
    session.persist_map_id = int(map_id)
    session.persist_x = float(dest_x)
    session.persist_y = float(dest_y)
    session.persist_z = float(dest_z)
    session.persist_orientation = float(orientation)
    _clear_transport_state(session)

    ctx = type(
        "Ctx",
        (),
        {
            "map_id": int(map_id),
            "x": float(dest_x),
            "y": float(dest_y),
            "z": float(dest_z),
            "orientation": float(orientation),
        },
    )()
    Logger.info(
        "[WorldBoat] transfer start opcode=%s tguid=0x%016X transport_time=%s "
        "from=(%.2f %.2f) to=(map=%s %.2f %.2f %.2f %.2f)",
        opcode_name,
        transport_guid & 0xFFFFFFFFFFFFFFFF,
        int(transport_time),
        float(x),
        float(y),
        int(map_id),
        float(dest_x),
        float(dest_y),
        float(dest_z),
        float(orientation),
    )
    responses = _clear_loaded_world_objects_for_transfer(session)
    responses.extend(
        [
            ("SMSG_TRANSFER_PENDING", build_login_packet("SMSG_TRANSFER_PENDING", ctx)),
            ("SMSG_NEW_WORLD", build_login_packet("SMSG_NEW_WORLD", ctx)),
            (
                "SMSG_MESSAGECHAT",
                encode_skyfire_messagechat_system_payload(
                    "[WorldBoat] Ratchet -> Booty Bay transfer"
                ),
            ),
        ]
    )
    return responses


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


def build_smsg_player_move_payload_old(session) -> bytes | None:
    state = _movement_state(session)
    guid_value = _movement_sync_guid(session)
    if guid_value <= 0:
        return None

    raw_guid = int(guid_value).to_bytes(8, "little", signed=False)
    move_flags = _movement_flags_for_outbound_sync(session, state)
    move_flags2 = int(state.flags2)
    timestamp = _outbound_movement_timestamp_ms(session)
    x = float(state.x)
    y = float(state.y)
    z = float(state.z)
    orientation = float(state.orientation)
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
    payload.extend(struct.pack("<f", orientation))  # MSEOrientation
    _append_guid_byte_seq(payload, raw_guid, (3,))
    _append_guid_byte_seq(payload, raw_guid, (0, 2, 6))
    payload.extend(struct.pack("<f", x))  # MSEPositionX
    _append_guid_byte_seq(payload, raw_guid, (4, 7))
    return bytes(payload)


def build_smsg_player_move_payload_stable_old(session) -> bytes | None:
    state = _movement_state(session)
    guid_value = _movement_sync_guid(session)
    if guid_value <= 0:
        return None

    raw_guid = int(guid_value).to_bytes(8, "little", signed=False)
    timestamp = _outbound_movement_timestamp_ms(session)
    x = float(state.x)
    y = float(state.y)
    z = float(state.z)
    orientation = float(state.orientation)
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
        payload.extend(struct.pack("<f", orientation))
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
    bits.write_bits(0, 1)  # MSEHasTransportData
    bits.write_bits(1 if raw_guid[4] else 0, 1)
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
    if raw_guid[5]:
        payload.append((raw_guid[5] ^ 1) & 0xFF)  # MSEGuidByte5
    if raw_guid[1]:
        payload.append((raw_guid[1] ^ 1) & 0xFF)  # MSEGuidByte1
    payload.extend(struct.pack("<f", z))  # MSEPositionZ
    if timestamp:
        payload.extend(struct.pack("<I", timestamp))  # MSETimestamp
    if has_orientation:
        payload.extend(struct.pack("<f", orientation))  # MSEOrientation
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


def build_smsg_player_move_payload(session) -> bytes | None:
    return build_smsg_player_move_payload_stable_old(session)


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
    payload.extend(struct.pack("<f", float(getattr(session, "orientation", 0.0) or 0.0)))

    state.counter = (counter + 1) & 0xFFFFFFFF
    return bytes(payload)


def _is_teleporting(session) -> bool:
    return bool(
        getattr(session, "near_teleport_pending", False)
        or getattr(session, "worldport_ack_pending", False)
        or getattr(session, "teleport_pending", False)
    )


def _consume_pending_teleport_on_movement(session, opcode_name: str) -> None:
    # Movement must stay usable during teleport, but the explicit ack still
    # owns the teleport lifecycle. Clearing pending state here breaks repeated
    # area-trigger teleports because the later ack gets discarded.
    if not _is_teleporting(session):
        return
    Logger.debug("[Teleport] movement resumed on %s while teleport ack is pending", str(opcode_name))


_MAX_MOVEMENT_POSITION_DELTA = 200.0
_MAX_MOVEMENT_Z_DELTA = 100.0
_POSITION_SAVE_INTERVAL_SECONDS = 30.0
_STATIONARY_EPSILON = 0.01
_SIM_TURN_RATE_RAD_PER_SEC = math.pi
_GAMEOBJECT_STREAM_LOAD_RADIUS = 120.0
_GAMEOBJECT_STREAM_UNLOAD_RADIUS = 150.0
_GAMEOBJECT_STREAM_INTERVAL_SECONDS = 0.5
_NPC_STREAM_UNLOAD_RADIUS = 150.0
_NPC_STREAM_INTERVAL_SECONDS = 0.5
_JUMP_PEER_INTERPOLATION_ENABLED = True
_JUMP_PEER_INTERPOLATION_INTERVAL_SECONDS = 0.016
_JUMP_PEER_INTERPOLATION_MAX_SECONDS = 1.25
_JUMP_GRAVITY = 19.291105
_DEFAULT_JUMP_VERTICAL_SPEED = 7.955547
_FLY_PEER_INTERPOLATION_ENABLED = True
_FLY_PEER_INTERPOLATION_INTERVAL_SECONDS = 0.016
_FLY_PEER_INTERPOLATION_MAX_SECONDS = 60.0
_FLY_PITCH_PEER_INTERPOLATION_MAX_SECONDS = 0.75
_FLY_PITCH_EPSILON = 0.02

# TODO:
# - Move replay_movement_focus_sequence* and related UPDATE_OBJECT replay helpers
#   into dedicated bootstrap/runtime modules once login packet builders are disentangled.
# - Move teleport-specific movement replay/broadcast helpers after the login
#   extraction phase so movement owns all movement-focused world transitions.


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


def _send_jump_interpolation_snapshot(
    session,
    *,
    x: float,
    y: float,
    z: float,
    orientation: float,
    fall_time_ms: int,
    counter: int,
) -> None:
    state = _movement_state(session)
    synthetic_state = SimpleNamespace(
        x=float(x),
        y=float(y),
        z=float(z),
        orientation=float(orientation),
        flags=(int(getattr(state, "flags", 0) or 0) | _MOVEMENTFLAG_FALLING),
        flags2=int(getattr(state, "flags2", 0) or 0),
        timestamp_ms=int(getattr(state, "timestamp_ms", 0) or 0),
        client_timestamp_ms=int(getattr(state, "client_timestamp_ms", 0) or 0),
        server_movement_timestamp_ms=int(getattr(state, "server_movement_timestamp_ms", 0) or 0),
        last_valid_orientation=float(getattr(state, "last_valid_orientation", orientation) or orientation),
        counter=int(counter) & 0xFFFFFFFF,
        pitch=float(getattr(state, "pitch", 0.0) or 0.0),
        has_fall_data=True,
        fall_time=int(fall_time_ms) & 0xFFFFFFFF,
        fall_vertical_speed=float(getattr(state, "fall_vertical_speed", 0.0) or 0.0),
        fall_horizontal_speed=float(getattr(state, "fall_horizontal_speed", 0.0) or 0.0),
        fall_sin_angle=float(getattr(state, "fall_sin_angle", 0.0) or 0.0),
        fall_cos_angle=float(getattr(state, "fall_cos_angle", 0.0) or 0.0),
        is_ascending=False,
        is_descending=False,
    )
    synthetic_session = SimpleNamespace(
        char_guid=int(getattr(session, "char_guid", 0) or 0),
        world_guid=int(getattr(session, "world_guid", 0) or 0),
        player_guid=int(getattr(session, "player_guid", 0) or 0),
        can_fly=False,
        is_flying=False,
        movement_state=synthetic_state,
    )
    payload = build_smsg_player_move_payload(synthetic_session)
    if not payload:
        return

    targets = _visible_peer_targets(session)
    if not targets:
        return

    dispatch_responses_to_sessions(targets, [("SMSG_PLAYER_MOVE", payload)])

    Logger.debug(
        "[JUMP_INTERP] player=%s peers=%s t=%sms pos=(%.3f, %.3f, %.3f)",
        int(getattr(session, "char_guid", 0) or 0),
        len(targets),
        int(fall_time_ms),
        float(x),
        float(y),
        float(z),
    )


def _start_jump_peer_interpolation(session) -> None:
    if not _JUMP_PEER_INTERPOLATION_ENABLED:
        return
    if not _visible_peer_targets(session):
        return

    state = _movement_state(session)
    start_x = float(getattr(state, "x", getattr(session, "x", 0.0)) or 0.0)
    start_y = float(getattr(state, "y", getattr(session, "y", 0.0)) or 0.0)
    start_z = float(getattr(state, "z", getattr(session, "z", 0.0)) or 0.0)
    orientation = float(getattr(state, "orientation", getattr(session, "orientation", 0.0)) or 0.0)
    vertical_speed = abs(float(getattr(state, "fall_vertical_speed", 0.0) or 0.0))
    if vertical_speed <= 0.01:
        vertical_speed = _DEFAULT_JUMP_VERTICAL_SPEED

    horizontal_speed = abs(float(getattr(state, "fall_horizontal_speed", 0.0) or 0.0))
    flags = int(getattr(state, "flags", 0) or 0)
    if horizontal_speed <= 0.01 and flags & (
        _MOVEMENTFLAG_FORWARD
        | _MOVEMENTFLAG_BACKWARD
        | _MOVEMENTFLAG_STRAFE_LEFT
        | _MOVEMENTFLAG_STRAFE_RIGHT
    ):
        horizontal_speed = float(getattr(session, "run_speed", 7.0) or 7.0)

    direction = orientation
    if flags & _MOVEMENTFLAG_BACKWARD:
        direction = _normalize_orientation(direction + math.pi) or direction
    elif flags & _MOVEMENTFLAG_STRAFE_LEFT:
        direction = _normalize_orientation(direction + (math.pi / 2.0)) or direction
    elif flags & _MOVEMENTFLAG_STRAFE_RIGHT:
        direction = _normalize_orientation(direction - (math.pi / 2.0)) or direction

    generation = int(getattr(session, "_jump_interpolation_generation", 0) or 0) + 1
    session._jump_interpolation_generation = generation
    base_counter = int(getattr(state, "counter", 0) or 0) & 0xFFFFFFFF
    start_monotonic = time.monotonic()

    def _worker() -> None:
        step = 0
        while True:
            next_tick = start_monotonic + ((step + 1) * _JUMP_PEER_INTERPOLATION_INTERVAL_SECONDS)
            sleep_seconds = next_tick - time.monotonic()
            if sleep_seconds > 0.0:
                time.sleep(sleep_seconds)
            if int(getattr(session, "_jump_interpolation_generation", 0) or 0) != generation:
                return

            live_state = _movement_state(session)
            if not _movement_is_airborne(session):
                return

            elapsed = time.monotonic() - start_monotonic
            if elapsed <= 0.0:
                continue
            if elapsed > _JUMP_PEER_INTERPOLATION_MAX_SECONDS:
                return

            z = start_z + (vertical_speed * elapsed) - (0.5 * _JUMP_GRAVITY * elapsed * elapsed)
            if z <= start_z and elapsed > 0.25:
                return

            x = start_x + (math.cos(direction) * horizontal_speed * elapsed)
            y = start_y + (math.sin(direction) * horizontal_speed * elapsed)
            _send_jump_interpolation_snapshot(
                session,
                x=x,
                y=y,
                z=z,
                orientation=float(getattr(live_state, "orientation", orientation) or orientation),
                fall_time_ms=int(elapsed * 1000.0),
                counter=(base_counter + step + 1) & 0xFFFFFFFF,
            )
            step += 1

    threading.Thread(
        target=_worker,
        name=f"jump-interp-{int(getattr(session, 'char_guid', 0) or 0)}",
        daemon=True,
    ).start()


def _stop_jump_peer_interpolation(session) -> None:
    session._jump_interpolation_generation = int(getattr(session, "_jump_interpolation_generation", 0) or 0) + 1


def _send_fly_interpolation_snapshot(
    session,
    *,
    x: float,
    y: float,
    z: float,
    orientation: float,
    pitch: float,
    counter: int,
    ascending: bool,
    descending: bool,
) -> None:
    state = _movement_state(session)
    flags = int(getattr(state, "flags", 0) or 0)
    flags |= _MOVEMENTFLAG_CAN_FLY | _MOVEMENTFLAG_FLYING
    flags &= ~(_MOVEMENTFLAG_ASCENDING | _MOVEMENTFLAG_DESCENDING)
    if ascending:
        flags |= _MOVEMENTFLAG_ASCENDING
    elif descending:
        flags |= _MOVEMENTFLAG_DESCENDING

    synthetic_state = SimpleNamespace(
        x=float(x),
        y=float(y),
        z=float(z),
        orientation=float(orientation),
        flags=int(flags),
        flags2=int(getattr(state, "flags2", 0) or 0),
        timestamp_ms=int(getattr(state, "timestamp_ms", 0) or 0),
        client_timestamp_ms=int(getattr(state, "client_timestamp_ms", 0) or 0),
        server_movement_timestamp_ms=int(getattr(state, "server_movement_timestamp_ms", 0) or 0),
        last_valid_orientation=float(getattr(state, "last_valid_orientation", orientation) or orientation),
        counter=int(counter) & 0xFFFFFFFF,
        pitch=float(pitch),
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=0.0,
        is_ascending=bool(ascending),
        is_descending=bool(descending),
    )
    synthetic_session = SimpleNamespace(
        char_guid=int(getattr(session, "char_guid", 0) or 0),
        world_guid=int(getattr(session, "world_guid", 0) or 0),
        player_guid=int(getattr(session, "player_guid", 0) or 0),
        can_fly=True,
        is_flying=True,
        movement_state=synthetic_state,
    )
    payload = build_smsg_player_move_payload(synthetic_session)
    if not payload:
        return

    targets = _visible_peer_targets(session)
    if not targets:
        return

    dispatch_responses_to_sessions(targets, [("SMSG_PLAYER_MOVE", payload)])

    Logger.debug(
        "[FLY_INTERP] player=%s peers=%s pos=(%.3f, %.3f, %.3f) pitch=%.3f asc=%s desc=%s",
        int(getattr(session, "char_guid", 0) or 0),
        len(targets),
        float(x),
        float(y),
        float(z),
        float(pitch),
        bool(ascending),
        bool(descending),
    )


def _start_fly_peer_interpolation(session, vertical_sign: int) -> None:
    if not _FLY_PEER_INTERPOLATION_ENABLED:
        return
    if int(vertical_sign) == 0:
        return
    if not _visible_peer_targets(session):
        return

    state = _movement_state(session)
    start_x = float(getattr(state, "x", getattr(session, "x", 0.0)) or 0.0)
    start_y = float(getattr(state, "y", getattr(session, "y", 0.0)) or 0.0)
    start_z = float(getattr(state, "z", getattr(session, "z", 0.0)) or 0.0)
    orientation = float(getattr(state, "orientation", getattr(session, "orientation", 0.0)) or 0.0)
    vertical_speed = abs(float(getattr(session, "fly_speed", 0.0) or 0.0))
    if vertical_speed <= 0.01:
        vertical_speed = abs(float(getattr(session, "run_speed", 7.0) or 7.0)) * 3.2
    if vertical_speed <= 0.01:
        vertical_speed = 14.0

    generation = int(getattr(session, "_fly_interpolation_generation", 0) or 0) + 1
    session._fly_interpolation_generation = generation
    base_counter = int(getattr(state, "counter", 0) or 0) & 0xFFFFFFFF
    start_monotonic = time.monotonic()

    def _worker() -> None:
        step = 0
        while True:
            next_tick = start_monotonic + ((step + 1) * _FLY_PEER_INTERPOLATION_INTERVAL_SECONDS)
            sleep_seconds = next_tick - time.monotonic()
            if sleep_seconds > 0.0:
                time.sleep(sleep_seconds)
            if int(getattr(session, "_fly_interpolation_generation", 0) or 0) != generation:
                return

            live_state = _movement_state(session)
            if not _movement_is_flying(session):
                return

            ascending = bool(getattr(live_state, "is_ascending", False))
            descending = bool(getattr(live_state, "is_descending", False))
            if vertical_sign > 0 and not ascending:
                return
            if vertical_sign < 0 and not descending:
                return

            elapsed = time.monotonic() - start_monotonic
            if elapsed <= 0.0:
                continue
            if elapsed > _FLY_PEER_INTERPOLATION_MAX_SECONDS:
                return

            z = start_z + (float(vertical_sign) * vertical_speed * elapsed)
            _send_fly_interpolation_snapshot(
                session,
                x=float(getattr(live_state, "x", start_x) or start_x),
                y=float(getattr(live_state, "y", start_y) or start_y),
                z=z,
                orientation=float(getattr(live_state, "orientation", orientation) or orientation),
                pitch=float(getattr(live_state, "pitch", 0.0) or 0.0),
                counter=(base_counter + step + 1) & 0xFFFFFFFF,
                ascending=ascending,
                descending=descending,
            )
            step += 1

    threading.Thread(
        target=_worker,
        name=f"fly-interp-{int(getattr(session, 'char_guid', 0) or 0)}",
        daemon=True,
    ).start()


def _stop_fly_peer_interpolation(session) -> None:
    session._fly_interpolation_generation = int(getattr(session, "_fly_interpolation_generation", 0) or 0) + 1


def _start_fly_pitch_peer_interpolation(session) -> None:
    if not _FLY_PEER_INTERPOLATION_ENABLED:
        return
    if not _visible_peer_targets(session):
        return

    state = _movement_state(session)
    flags = int(getattr(state, "flags", 0) or 0)
    if flags & (_MOVEMENTFLAG_ASCENDING | _MOVEMENTFLAG_DESCENDING):
        return
    moving_forward = bool(flags & _MOVEMENTFLAG_FORWARD)
    moving_backward = bool(flags & _MOVEMENTFLAG_BACKWARD)
    if not (moving_forward or moving_backward):
        return

    pitch = float(getattr(state, "pitch", 0.0) or 0.0)
    if abs(pitch) < _FLY_PITCH_EPSILON:
        return

    fly_speed = abs(float(getattr(session, "fly_speed", 0.0) or 0.0))
    if fly_speed <= 0.01:
        fly_speed = abs(float(getattr(session, "run_speed", 7.0) or 7.0)) * 3.2
    if fly_speed <= 0.01:
        fly_speed = 14.0

    start_x = float(getattr(state, "x", getattr(session, "x", 0.0)) or 0.0)
    start_y = float(getattr(state, "y", getattr(session, "y", 0.0)) or 0.0)
    start_z = float(getattr(state, "z", getattr(session, "z", 0.0)) or 0.0)
    orientation = float(getattr(state, "orientation", getattr(session, "orientation", 0.0)) or 0.0)
    direction = orientation
    if moving_backward:
        direction = _normalize_orientation(direction + math.pi) or direction

    horizontal_speed = fly_speed * max(0.0, math.cos(pitch))
    vertical_speed = -fly_speed * math.sin(pitch)
    if moving_backward:
        vertical_speed = -vertical_speed

    generation = int(getattr(session, "_fly_interpolation_generation", 0) or 0) + 1
    session._fly_interpolation_generation = generation
    base_counter = int(getattr(state, "counter", 0) or 0) & 0xFFFFFFFF
    start_monotonic = time.monotonic()

    Logger.debug(
        "[FLY_PITCH_INTERP_START] player=%s pos=(%.3f, %.3f, %.3f) pitch=%.3f vertical_speed=%.3f",
        int(getattr(session, "char_guid", 0) or 0),
        float(start_x),
        float(start_y),
        float(start_z),
        float(pitch),
        float(vertical_speed),
    )

    def _worker() -> None:
        step = 0
        while True:
            next_tick = start_monotonic + ((step + 1) * _FLY_PEER_INTERPOLATION_INTERVAL_SECONDS)
            sleep_seconds = next_tick - time.monotonic()
            if sleep_seconds > 0.0:
                time.sleep(sleep_seconds)
            if int(getattr(session, "_fly_interpolation_generation", 0) or 0) != generation:
                return

            live_state = _movement_state(session)
            if not _movement_is_flying(session):
                return
            live_flags = int(getattr(live_state, "flags", 0) or 0)
            if live_flags & (_MOVEMENTFLAG_ASCENDING | _MOVEMENTFLAG_DESCENDING):
                return
            if not (live_flags & (_MOVEMENTFLAG_FORWARD | _MOVEMENTFLAG_BACKWARD)):
                return

            elapsed = time.monotonic() - start_monotonic
            if elapsed <= 0.0:
                continue
            if elapsed > _FLY_PITCH_PEER_INTERPOLATION_MAX_SECONDS:
                return

            x = start_x + (math.cos(direction) * horizontal_speed * elapsed)
            y = start_y + (math.sin(direction) * horizontal_speed * elapsed)
            z = start_z + (vertical_speed * elapsed)
            _send_fly_interpolation_snapshot(
                session,
                x=x,
                y=y,
                z=z,
                orientation=float(getattr(live_state, "orientation", orientation) or orientation),
                pitch=float(getattr(live_state, "pitch", pitch) or pitch),
                counter=(base_counter + step + 1) & 0xFFFFFFFF,
                ascending=False,
                descending=False,
            )
            step += 1

    threading.Thread(
        target=_worker,
        name=f"fly-pitch-interp-{int(getattr(session, 'char_guid', 0) or 0)}",
        daemon=True,
    ).start()


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

    responses = list(build_database_gameobject_responses(session, loaded_guids=loaded_gameobjects))

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
            keep_guids.add(
                int(MoTransportGuid.from_spawn_guid(int(entry.get("guid", 0) or 0)))
            )
        else:
            keep_guids.add(
                int(GameObjectGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), realm_id))
            )
    try:
        from server.modules.handlers.world.transport_runtime import synthetic_transport_entries_near

        keep_guids.update(
            int(entry.get("world_guid", 0) or 0)
            for entry in synthetic_transport_entries_near(session)
            if int(entry.get("world_guid", 0) or 0) > 0
        )
    except Exception as exc:
        Logger.warning("[WorldTransport] synthetic keep lookup failed err=%s", exc)

    stale_guids = sorted(int(guid) for guid in loaded_gameobjects if int(guid) not in keep_guids)
    loaded_lift_entries = getattr(session, "loaded_lift_entries", None)
    loaded_lifts = getattr(session, "loaded_lifts", None)
    loaded_transport_entries = getattr(session, "loaded_transport_entries", None)
    for guid in stale_guids:
        is_lift = isinstance(loaded_lift_entries, dict) and int(guid) in loaded_lift_entries
        is_transport = (
            isinstance(loaded_transport_entries, dict)
            and int(guid) in loaded_transport_entries
        )
        if is_lift:
            lift = loaded_lift_entries.get(int(guid), {})
            Logger.info(
                "[WorldLift] stream despawn guid=0x%X entry=%s pos=(%.2f %.2f %.2f)",
                int(guid),
                int(lift.get("entry", 0) or 0) if isinstance(lift, dict) else 0,
                float(lift.get("x", 0.0) or 0.0) if isinstance(lift, dict) else 0.0,
                float(lift.get("y", 0.0) or 0.0) if isinstance(lift, dict) else 0.0,
                float(lift.get("z", 0.0) or 0.0) if isinstance(lift, dict) else 0.0,
            )
        elif is_transport:
            transport = loaded_transport_entries.get(int(guid), {})
            Logger.info(
                "[WorldTransport] stream despawn guid=0x%X entry=%s pos=(%.2f %.2f %.2f)",
                int(guid),
                int(transport.get("entry", 0) or 0) if isinstance(transport, dict) else 0,
                float(transport.get("x", 0.0) or 0.0) if isinstance(transport, dict) else 0.0,
                float(transport.get("y", 0.0) or 0.0) if isinstance(transport, dict) else 0.0,
                float(transport.get("z", 0.0) or 0.0) if isinstance(transport, dict) else 0.0,
            )
        else:
            Logger.debug("[GO_STREAM] despawn guid=0x%X", int(guid))
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                _build_out_of_range_update_object_payload(map_id=map_id, guid=int(guid)),
            )
        )
        loaded_gameobjects.discard(int(guid))
        if isinstance(loaded_lift_entries, dict):
            loaded_lift_entries.pop(int(guid), None)
        if isinstance(loaded_transport_entries, dict):
            loaded_transport_entries.pop(int(guid), None)
        if isinstance(loaded_lifts, set):
            loaded_lifts.discard(int(guid))

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

    from server.modules.handlers.world.bootstrap.replay import build_database_creature_responses

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


def _maybe_stream_world_objects(session) -> list[tuple[str, bytes]]:
    responses = []
    responses.extend(_maybe_stream_gameobjects(session))
    responses.extend(_maybe_stream_npcs(session))
    return responses


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


def _clear_dance_emote_state_on_move(session) -> None:
    responses = []

    if int(getattr(session, "player_stand_state", 0) or 0) != 0:
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
        flags &= ~(_MOVEMENTFLAG_TURN_LEFT | _MOVEMENTFLAG_TURN_RIGHT)
    elif opcode_name == "MSG_MOVE_FALL_LAND":
        flags &= ~_MOVEMENTFLAG_FALLING
        flags &= ~(_MOVEMENTFLAG_TURN_LEFT | _MOVEMENTFLAG_TURN_RIGHT)
        flags &= ~(
            _MOVEMENTFLAG_FLYING
            | _MOVEMENTFLAG_ASCENDING
            | _MOVEMENTFLAG_DESCENDING
        )
        state.is_ascending = False
        state.is_descending = False
    elif opcode_name == "MSG_MOVE_START_ASCEND":
        state.is_ascending = True
        state.is_descending = False
        flags |= _MOVEMENTFLAG_ASCENDING
        flags &= ~_MOVEMENTFLAG_DESCENDING
    elif opcode_name == "MSG_MOVE_STOP_ASCEND":
        state.is_ascending = False
        flags &= ~_MOVEMENTFLAG_ASCENDING
    elif opcode_name == "MSG_MOVE_START_DESCEND":
        state.is_descending = True
        state.is_ascending = False
        flags |= _MOVEMENTFLAG_DESCENDING
        flags &= ~_MOVEMENTFLAG_ASCENDING
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


def _clear_landed_movement_state(state) -> bool:
    previous_flags = int(getattr(state, "flags", 0) or 0)
    previous_moving = bool(
        previous_flags
        & (
            _MOVEMENTFLAG_FORWARD
            | _MOVEMENTFLAG_BACKWARD
            | _MOVEMENTFLAG_STRAFE_LEFT
            | _MOVEMENTFLAG_STRAFE_RIGHT
            | _MOVEMENTFLAG_TURN_LEFT
            | _MOVEMENTFLAG_TURN_RIGHT
        )
    )
    changed = _clear_jump_fall_state(state)
    state.flags = int(getattr(state, "flags", 0) or 0) & ~(
        _MOVEMENTFLAG_FORWARD
        | _MOVEMENTFLAG_BACKWARD
        | _MOVEMENTFLAG_STRAFE_LEFT
        | _MOVEMENTFLAG_STRAFE_RIGHT
        | _MOVEMENTFLAG_TURN_LEFT
        | _MOVEMENTFLAG_TURN_RIGHT
    )
    return changed or previous_moving


def _apply_post_parse_movement_cleanup(
    session,
    state,
    opcode_name: str,
    *,
    on_lift_support: bool = False,
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
        flags_after &= ~(
            _MOVEMENTFLAG_FORWARD
            | _MOVEMENTFLAG_BACKWARD
            | _MOVEMENTFLAG_FALLING
        )

    if on_lift_support:
        flags_after &= ~_MOVEMENTFLAG_FALLING

    if flags_after != flags_before:
        state.flags = int(flags_after)
        if opcode_name == "MSG_MOVE_FALL_LAND" or on_lift_support:
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
            "pos=(%.3f %.3f %.3f) lift=%s",
            opcode_name,
            flags_before,
            flags_after,
            float(getattr(state, "x", 0.0) or 0.0),
            float(getattr(state, "y", 0.0) or 0.0),
            float(getattr(state, "z", 0.0) or 0.0),
            bool(on_lift_support),
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
            if _clear_landed_movement_state(state):
                Logger.debug(
                    "[POST_JUMP_RESET] opcode=%s cleared fall/turn state flags=0x%X",
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
    return (current - incoming) < 60000


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
    if not all(math.isfinite(value) for value in (x, y, z)):
        return False

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)

    if current_x == 0.0 and current_y == 0.0 and current_z == 0.0:
        return True

    planar_delta = math.hypot(x - current_x, y - current_y)
    vertical_delta = abs(z - current_z)

    if planar_delta > _MAX_MOVEMENT_POSITION_DELTA or vertical_delta > _MAX_MOVEMENT_Z_DELTA:
        log = Logger.debug if opcode_name in {"MSG_MOVE_FALL_LAND", "MSG_MOVE_HEARTBEAT"} else Logger.warning
        log(
            f"[Movement] ignoring implausible {opcode_name} update "
            f"dx={x - current_x:.3f} dy={y - current_y:.3f} dz={z - current_z:.3f}"
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
        if parsed_flying["timestamp"] is not None:
            state.timestamp_ms = int(parsed_flying["timestamp"]) & 0xFFFFFFFF
        else:
            state.timestamp_ms = _movement_timestamp_ms(session)
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
        if bool(getattr(state, "has_transport_data", False)):
            Logger.info(
                "[TRANSPORT_STATE] clear opcode=%s reason=no_skyfire_parse previous_tguid=0x%016X",
                opcode_name,
                int(getattr(state, "transport_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
            )
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
        if timestamp is not None:
            state.timestamp_ms = int(timestamp) & 0xFFFFFFFF
        else:
            state.timestamp_ms = _movement_timestamp_ms(session)
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
        return False
    _record_movement_packet_state(session, opcode_name, payload)
    _apply_post_parse_movement_cleanup(session, state, opcode_name)
    active_flying_mount = _has_active_flying_mount(session)
    if opcode_name == "MSG_MOVE_FALL_LAND":
        if active_flying_mount:
            Logger.info(
                "[Movement] ignoring fall-land while flying mount is active guid=0x%X spell=%s",
                _player_guid(session),
                int(getattr(session, "mount_spell", 0) or 0),
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
            return True
        setattr(session, "is_flying", False)
        state.is_ascending = False
        state.is_descending = False
        state.flags &= ~(
            _MOVEMENTFLAG_FORWARD
            | _MOVEMENTFLAG_BACKWARD
            | _MOVEMENTFLAG_STRAFE_LEFT
            | _MOVEMENTFLAG_STRAFE_RIGHT
            | _MOVEMENTFLAG_TURN_LEFT
            | _MOVEMENTFLAG_TURN_RIGHT
            | _MOVEMENTFLAG_FLYING
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
    elif opcode_name in {"MSG_MOVE_START_ASCEND", "MSG_MOVE_START_DESCEND"}:
        setattr(session, "is_flying", True)
    elif active_flying_mount:
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
    if movement is not None:
        x, y, z, orientation = movement
        state.x = float(x)
        state.y = float(y)
        state.z = float(z)
        state.orientation = float(orientation)
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
    session.persist_map_id = int(position.map)
    resolved_zone = int(
        resolve_zone_from_position(
            int(position.map),
            float(position.x),
            float(position.y),
        ) or 0
    )
    session.persist_zone = resolved_zone or int(getattr(session, "zone", 0) or 0)
    if resolved_zone:
        session.zone = int(resolved_zone)
    session.persist_instance_id = int(getattr(session, "instance_id", 0) or 0)
    session.persist_x = float(position.x)
    session.persist_y = float(position.y)
    session.persist_z = float(position.z)
    session.persist_orientation = float(position.orientation)
    if POSITION_DEBUG_ENABLED:
        Logger.debug(
            "[POS_DEBUG] capture player=%s pos=%s source=%s",
            int(getattr(session, "char_guid", 0) or 0),
            format_position(position),
            type(source).__name__,
        )


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
    try:
        area_id = int(getattr(session, "zone", 0) or getattr(session, "persist_zone", 0) or 0)
        return discover_area(session, area_id)
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


def _ensure_lift_support_cache(session, *, x: float, y: float) -> None:
    loaded_lifts = getattr(session, "loaded_lift_entries", None)
    if isinstance(loaded_lifts, dict) and loaded_lifts:
        return

    now = time.time()
    last_refresh = float(getattr(session, "last_lift_support_cache_at", 0.0) or 0.0)
    if (now - last_refresh) < _LIFT_SUPPORT_CACHE_SECONDS:
        return
    session.last_lift_support_cache_at = now

    map_id = int(getattr(session, "map_id", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    try:
        entries = DatabaseConnection.get_gameobjects_near(
            map_id,
            float(x),
            float(y),
            radius=450.0,
            limit=120,
        )
    except Exception as exc:
        Logger.debug("[WorldLift] support cache query failed: %s", exc)
        return

    cache: dict[int, dict[str, Any]] = {}
    for entry in entries:
        if int(entry.get("type", 0) or 0) != 11:
            continue
        spawn_guid = int(entry.get("guid", 0) or 0)
        world_guid = GameObjectGuid.from_spawn_guid(spawn_guid, realm_id)
        cache[int(world_guid)] = {
            "guid": spawn_guid,
            "world_guid": int(world_guid),
            "entry": int(entry.get("entry", 0) or 0),
            "map": map_id,
            "x": float(entry.get("x", 0.0) or 0.0),
            "y": float(entry.get("y", 0.0) or 0.0),
            "z": float(entry.get("z", 0.0) or 0.0),
            "orientation": float(entry.get("orientation", 0.0) or 0.0),
            "size": float(entry.get("size", 1.0) or 1.0),
            "data0": int(entry.get("data0", 0) or 0),
            "data1": int(entry.get("data1", 0) or 0),
        }

    if cache:
        session.loaded_lift_entries = cache
        Logger.info(
            "[WorldLift] support cache loaded count=%s map=%s pos=(%.2f %.2f)",
            len(cache),
            map_id,
            float(x),
            float(y),
        )


def _lift_support_guid(lift: dict[str, Any]) -> int:
    return int(lift.get("world_guid", 0) or lift.get("guid", 0) or 0)


def _lift_support_radius(lift: dict[str, Any]) -> float:
    return max(
        _LIFT_SUPPORT_RADIUS_YARDS,
        _LIFT_SUPPORT_RADIUS_YARDS * float(lift.get("size", 1.0) or 1.0),
    )


def _lift_support_release_radius(lift: dict[str, Any]) -> float:
    return max(
        _LIFT_SUPPORT_RELEASE_RADIUS_YARDS,
        _LIFT_SUPPORT_RELEASE_RADIUS_YARDS * float(lift.get("size", 1.0) or 1.0),
    )


def _lift_support_magnet_radius(lift: dict[str, Any]) -> float:
    return max(
        _LIFT_SUPPORT_MAGNET_RADIUS_YARDS,
        _LIFT_SUPPORT_MAGNET_RADIUS_YARDS * float(lift.get("size", 1.0) or 1.0),
    )


def _lift_support_z_threshold(opcode_name: str) -> float:
    if opcode_name == "MSG_MOVE_FALL_LAND":
        return _LIFT_SUPPORT_LAND_Z_THRESHOLD
    return _LIFT_SUPPORT_HEARTBEAT_Z_THRESHOLD


def _is_thunder_bluff_lift(lift: dict[str, Any]) -> bool:
    if int(lift.get("map", 0) or 0) != 1:
        return False
    lift_z = float(lift.get("z", 0.0) or 0.0)
    return (
        abs(lift_z - _THUNDER_BLUFF_LIFT_LOW_Z) <= 1.0
        or abs(lift_z - _THUNDER_BLUFF_LIFT_HIGH_Z) <= 1.0
    )


def _lift_transport_period_seconds(lift: dict[str, Any]) -> float:
    """Return the transport animation period used for simple type 11 support."""
    data0 = int(lift.get("data0", 0) or 0)
    if data0 >= 1000:
        return max(4.0, float(data0) / 1000.0)
    return _THUNDER_BLUFF_LIFT_PERIOD_SECONDS


def _thunder_bluff_lift_platform_z(lift: dict[str, Any], now: float) -> float:
    """Approximate the client-side type 11 elevator animation from a timer."""
    low_z = _THUNDER_BLUFF_LIFT_LOW_Z
    high_z = _THUNDER_BLUFF_LIFT_HIGH_Z
    period = _lift_transport_period_seconds(lift)
    half_period = period * 0.5
    if half_period <= 0.0:
        return float(lift.get("z", low_z) or low_z)

    static_z = float(lift.get("z", low_z) or low_z)
    phase = 0.0
    if abs(static_z - high_z) < abs(static_z - low_z):
        phase = half_period

    timer = (float(now) + phase) % period
    if timer <= half_period:
        progress = timer / half_period
    else:
        progress = 1.0 - ((timer - half_period) / half_period)
    progress = max(0.0, min(1.0, progress))
    return low_z + ((high_z - low_z) * progress)


def _start_lift_motion(session, lift: dict[str, Any], now: float) -> None:
    platform_z = _lift_support_platform_z(session, lift, now, active=True)
    session.supported_lift_motion_direction = 0.0
    session.supported_lift_motion_started_at = float(now)
    session.supported_lift_motion_start_z = platform_z
    session.supported_lift_last_platform_z = platform_z


def _lift_support_platform_z(
    session,
    lift: dict[str, Any],
    now: float,
    *,
    active: bool,
) -> float:
    static_z = float(lift.get("z", 0.0) or 0.0)
    if _is_thunder_bluff_lift(lift):
        return _thunder_bluff_lift_platform_z(lift, now)
    if not active:
        return static_z
    return static_z


def _lift_support_active(session) -> bool:
    return int(getattr(session, "supported_lift_guid", 0) or 0) != 0


def _real_lift_transport_only(session) -> bool:
    """Return whether lift support should be bypassed for pure client transport."""
    return False


def _lift_support_state(session) -> str:
    state = str(getattr(session, "lift_state", _LIFT_STATE_FREE) or _LIFT_STATE_FREE)
    if state not in {
        _LIFT_STATE_FREE,
        _LIFT_STATE_MAGNET,
        _LIFT_STATE_ATTACHED,
        _LIFT_STATE_DETACHING,
    }:
        return _LIFT_STATE_FREE
    return state


def _set_lift_support_state(
    session,
    state: str,
    *,
    opcode_name: str,
    reason: str,
    now: float,
) -> None:
    previous = _lift_support_state(session)
    if previous == state:
        return
    session.lift_state = state
    Logger.info(
        "[WorldLift] state %s -> %s reason=%s opcode=%s t=%.3f",
        previous,
        state,
        str(reason),
        str(opcode_name),
        float(now),
    )


def _lift_support_falling_state(session, movement_flags: int) -> bool:
    return bool(
        int(movement_flags) & (_MOVEMENTFLAG_FALLING | _MOVEMENTFLAG_DESCENDING)
        or bool(getattr(_movement_state(session), "has_fall_data", False))
    )


def _lift_support_stabilizing(session, now: float) -> bool:
    return float(now) <= float(getattr(session, "lift_stabilizing_until", 0.0) or 0.0)


def _start_lift_support_stabilization(session, now: float, opcode_name: str) -> None:
    until = float(now) + _LIFT_SUPPORT_STABILIZE_SECONDS
    current_until = float(getattr(session, "lift_stabilizing_until", 0.0) or 0.0)
    if current_until >= until:
        return
    session.lift_stabilizing_until = until
    Logger.info(
        "[WorldLift] stabilization start opcode=%s until=%.3f duration=%.3f",
        str(opcode_name),
        until,
        _LIFT_SUPPORT_STABILIZE_SECONDS,
    )


def _queue_lift_support_message(session, message: str) -> None:
    if not bool(getattr(session, "debug_lift_chat_messages", False)):
        return
    messages = getattr(session, "lift_support_messages", None)
    if not isinstance(messages, list):
        messages = []
        session.lift_support_messages = messages
    if not messages or messages[-1] != message:
        messages.append(message)


def _drain_lift_support_messages(session) -> list[tuple[str, bytes]]:
    messages = getattr(session, "lift_support_messages", None)
    if not isinstance(messages, list) or not messages:
        return []
    session.lift_support_messages = []
    return [
        ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(str(message)))
        for message in messages
    ]


def _send_lift_transport_responses(session, responses: list[tuple[str, bytes]]) -> None:
    sender = getattr(session, "send_response", None)
    if not callable(sender) or not responses:
        return
    try:
        sender(responses)
    except Exception as exc:
        Logger.warning(
            "[WorldLift] transport tick send failed guid=%s err=%s",
            int(getattr(session, "char_guid", 0) or 0),
            exc,
        )


def _elevator_states(session) -> dict[int, dict[str, Any]]:
    states = getattr(session, "runtime_elevator_states", None)
    if not isinstance(states, dict):
        states = {}
        session.runtime_elevator_states = states
    return states


def _elevator_state_for_lift(
    session,
    lift: dict[str, Any],
    now: float,
) -> dict[str, Any]:
    guid = _lift_support_guid(lift)
    states = _elevator_states(session)
    state = states.get(guid)
    if isinstance(state, dict):
        _tick_elevator_state(state, now)
        return state

    static_z = float(lift.get("z", _THUNDER_BLUFF_LIFT_LOW_Z) or _THUNDER_BLUFF_LIFT_LOW_Z)
    low_z = _THUNDER_BLUFF_LIFT_LOW_Z
    high_z = _THUNDER_BLUFF_LIFT_HIGH_Z
    current_z = low_z
    direction = 1.0
    if abs(static_z - high_z) < abs(static_z - low_z):
        current_z = high_z
        direction = -1.0

    period = _lift_transport_period_seconds(lift)
    travel_seconds = max(1.0, period * 0.5)
    speed = abs(high_z - low_z) / travel_seconds
    state = {
        "guid": int(guid),
        "entry": int(lift.get("entry", 0) or 0),
        "map_id": int(lift.get("map", 0) or 0),
        "base_x": float(lift.get("x", 0.0) or 0.0),
        "base_y": float(lift.get("y", 0.0) or 0.0),
        "low_z": float(low_z),
        "high_z": float(high_z),
        "current_z": float(current_z),
        "direction": float(direction),
        "period": float(period),
        "speed": float(speed),
        "last_tick": float(now),
    }
    states[int(guid)] = state
    Logger.info(
        "[WorldLift] elevator runtime init guid=%s entry=%s base=(%.2f %.2f) "
        "z=%.2f low=%.2f high=%.2f direction=%.1f speed=%.3f period=%.2f",
        int(guid),
        int(state["entry"]),
        float(state["base_x"]),
        float(state["base_y"]),
        float(state["current_z"]),
        float(state["low_z"]),
        float(state["high_z"]),
        float(state["direction"]),
        float(state["speed"]),
        float(state["period"]),
    )
    return state


def _tick_elevator_state(state: dict[str, Any], now: float) -> None:
    last_tick = float(state.get("last_tick", now) or now)
    elapsed = max(0.0, min(1.0, float(now) - last_tick))
    if elapsed <= 0.0:
        return

    current_z = float(state.get("current_z", 0.0) or 0.0)
    direction = float(state.get("direction", 1.0) or 1.0)
    speed = float(state.get("speed", 0.0) or 0.0)
    low_z = float(state.get("low_z", current_z) or current_z)
    high_z = float(state.get("high_z", current_z) or current_z)
    next_z = current_z + (direction * speed * elapsed)
    if next_z >= high_z:
        next_z = high_z
        direction = -1.0
    elif next_z <= low_z:
        next_z = low_z
        direction = 1.0

    state["current_z"] = float(next_z)
    state["direction"] = float(direction)
    state["last_tick"] = float(now)


def _find_elevator_candidate(
    session,
    *,
    x: float,
    y: float,
    z: float,
    now: float,
) -> tuple[dict[str, Any], dict[str, Any], float, float] | None:
    _ensure_lift_support_cache(session, x=float(x), y=float(y))
    loaded_lifts = getattr(session, "loaded_lift_entries", None)
    if not isinstance(loaded_lifts, dict) or not loaded_lifts:
        return None

    map_id = int(getattr(session, "map_id", 0) or 0)
    best: tuple[dict[str, Any], dict[str, Any], float, float] | None = None
    best_score = float("inf")
    for lift in loaded_lifts.values():
        if not isinstance(lift, dict):
            continue
        if int(lift.get("map", map_id) or 0) != map_id:
            continue
        if not _is_thunder_bluff_lift(lift):
            continue

        state = _elevator_state_for_lift(session, lift, now)
        dx = float(x) - float(state.get("base_x", 0.0) or 0.0)
        dy = float(y) - float(state.get("base_y", 0.0) or 0.0)
        distance = math.sqrt((dx * dx) + (dy * dy))
        if distance > _ELEVATOR_ATTACH_RADIUS_YARDS:
            continue
        dz = float(z) - float(state.get("current_z", 0.0) or 0.0)
        score = (abs(dz) * 100.0) + distance
        if score < best_score:
            best = (lift, state, distance, dz)
            best_score = score
    return best


def _detach_runtime_elevator(
    session,
    *,
    reason: str,
    opcode_name: str,
    x: float,
    y: float,
    z: float,
) -> None:
    guid = int(getattr(session, "attached_elevator_guid", 0) or 0)
    if not guid:
        return
    Logger.info(
        "[WorldLift] elevator detach reason=%s opcode=%s guid=%s "
        "pos=(%.2f %.2f %.2f)",
        str(reason),
        str(opcode_name),
        guid,
        float(x),
        float(y),
        float(z),
    )
    session.attached_elevator_guid = 0
    session.elevator_local_offset_x = 0.0
    session.elevator_local_offset_y = 0.0
    session.elevator_local_offset_z = 0.0
    session.no_elevator_relock_until = time.time() + (
        _ELEVATOR_NO_RELOCK_SECONDS if reason == "jump" else 0.0
    )
    session._lift_transport_generation = int(
        getattr(session, "_lift_transport_generation", 0) or 0
    ) + 1


def _attach_runtime_elevator(
    session,
    lift: dict[str, Any],
    state: dict[str, Any],
    *,
    opcode_name: str,
    x: float,
    y: float,
    z: float,
    distance: float,
    dz: float,
) -> None:
    guid = int(state.get("guid", 0) or 0)
    session.attached_elevator_guid = guid
    session.elevator_local_offset_x = float(x) - float(state.get("base_x", 0.0) or 0.0)
    session.elevator_local_offset_y = float(y) - float(state.get("base_y", 0.0) or 0.0)
    session.elevator_local_offset_z = float(z) - float(state.get("current_z", 0.0) or 0.0)
    session.supported_lift_guid = 0
    session.lift_state = _LIFT_STATE_FREE
    _start_lift_transport_thread(session)
    Logger.info(
        "[WorldLift] elevator attach opcode=%s guid=%s entry=%s "
        "player=(%.2f %.2f %.2f) elevator=(%.2f %.2f %.2f) "
        "local=(%.2f %.2f %.2f) distance=%.2f dz=%.2f",
        str(opcode_name),
        guid,
        int(lift.get("entry", 0) or 0),
        float(x),
        float(y),
        float(z),
        float(state.get("base_x", 0.0) or 0.0),
        float(state.get("base_y", 0.0) or 0.0),
        float(state.get("current_z", 0.0) or 0.0),
        float(getattr(session, "elevator_local_offset_x", 0.0) or 0.0),
        float(getattr(session, "elevator_local_offset_y", 0.0) or 0.0),
        float(getattr(session, "elevator_local_offset_z", 0.0) or 0.0),
        float(distance),
        float(dz),
    )


def _apply_runtime_elevator_position(
    session,
    state: dict[str, Any],
    *,
    opcode_name: str,
    update_offset_from_client: bool,
    preserve_airborne_state: bool = False,
    client_x: float | None = None,
    client_y: float | None = None,
    client_z: float | None = None,
) -> tuple[float, float, float]:
    if update_offset_from_client and client_x is not None and client_y is not None:
        session.elevator_local_offset_x = (
            float(client_x) - float(state.get("base_x", 0.0) or 0.0)
        )
        session.elevator_local_offset_y = (
            float(client_y) - float(state.get("base_y", 0.0) or 0.0)
        )
        if client_z is not None:
            client_dz = float(client_z) - float(state.get("current_z", 0.0) or 0.0)
            z_threshold = (
                _ELEVATOR_JUMP_LOCAL_Z_THRESHOLD
                if preserve_airborne_state or opcode_name == "MSG_MOVE_JUMP"
                else _ELEVATOR_STEP_HEIGHT_THRESHOLD
            )
            if abs(client_dz) <= z_threshold:
                session.elevator_local_offset_z = client_dz

    x = float(state.get("base_x", 0.0) or 0.0) + float(
        getattr(session, "elevator_local_offset_x", 0.0) or 0.0
    )
    y = float(state.get("base_y", 0.0) or 0.0) + float(
        getattr(session, "elevator_local_offset_y", 0.0) or 0.0
    )
    z = float(state.get("current_z", 0.0) or 0.0) + float(
        getattr(session, "elevator_local_offset_z", 0.0) or 0.0
    )

    session.x = x
    session.y = y
    session.z = z
    session.position_dirty = True
    movement_state = _movement_state(session)
    movement_state.x = x
    movement_state.y = y
    movement_state.z = z
    movement_state.orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    if not preserve_airborne_state:
        movement_state.flags = int(getattr(movement_state, "flags", 0) or 0) & ~(
            _MOVEMENTFLAG_FALLING | _MOVEMENTFLAG_DESCENDING
        )
        _clear_jump_fall_state(movement_state)
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    Logger.debug(
        "[WorldLift] elevator attached move opcode=%s guid=%s pos=(%.2f %.2f %.2f)",
        str(opcode_name),
        int(state.get("guid", 0) or 0),
        x,
        y,
        z,
    )
    return x, y, z


def _runtime_elevator_support(
    session,
    *,
    opcode_name: str,
    x: float,
    y: float,
    z: float,
    previous_z: float,
    movement_flags: int,
) -> tuple[bool, float, float, float, dict[str, Any] | None]:
    try:
        from server.modules.handlers.world.feature_config import elevators_enabled

        if not elevators_enabled():
            if int(getattr(session, "attached_elevator_guid", 0) or 0):
                _detach_runtime_elevator(
                    session,
                    reason="disabled",
                    opcode_name=opcode_name,
                    x=float(x),
                    y=float(y),
                    z=float(z),
                )
            return False, float(x), float(y), float(z), None
    except Exception:
        return False, float(x), float(y), float(z), None

    now = time.time()
    session.runtime_elevator_bypass_old_support = False
    active_guid = int(getattr(session, "attached_elevator_guid", 0) or 0)
    if _is_teleporting(session):
        _detach_runtime_elevator(
            session,
            reason="teleport_pending",
            opcode_name=opcode_name,
            x=float(x),
            y=float(y),
            z=float(z),
        )
        return False, float(x), float(y), float(z), None

    if active_guid:
        states = _elevator_states(session)
        state = states.get(active_guid)
        if not isinstance(state, dict):
            _detach_runtime_elevator(
                session,
                reason="missing_state",
                opcode_name=opcode_name,
                x=float(x),
                y=float(y),
                z=float(z),
            )
            return False, float(x), float(y), float(z), None
        _tick_elevator_state(state, now)

        dx = float(x) - float(state.get("base_x", 0.0) or 0.0)
        dy = float(y) - float(state.get("base_y", 0.0) or 0.0)
        distance = math.sqrt((dx * dx) + (dy * dy))
        if distance > _ELEVATOR_RELEASE_RADIUS_YARDS:
            _detach_runtime_elevator(
                session,
                reason="outside_xy",
                opcode_name=opcode_name,
                x=float(x),
                y=float(y),
                z=float(z),
            )
            return False, float(x), float(y), float(z), None

        update_offset = opcode_name in {
            "MSG_MOVE_START_FORWARD",
            "MSG_MOVE_START_BACKWARD",
            "MSG_MOVE_START_STRAFE_LEFT",
            "MSG_MOVE_START_STRAFE_RIGHT",
            "MSG_MOVE_HEARTBEAT",
            "MSG_MOVE_STOP",
            "MSG_MOVE_JUMP",
        }
        preserve_airborne = bool(
            opcode_name == "MSG_MOVE_JUMP"
            or int(movement_flags) & (_MOVEMENTFLAG_FALLING | _MOVEMENTFLAG_DESCENDING)
            or bool(getattr(_movement_state(session), "has_fall_data", False))
        )
        new_x, new_y, new_z = _apply_runtime_elevator_position(
            session,
            state,
            opcode_name=opcode_name,
            update_offset_from_client=update_offset,
            preserve_airborne_state=preserve_airborne,
            client_x=float(x),
            client_y=float(y),
            client_z=float(z),
        )
        return True, new_x, new_y, new_z, state

    if opcode_name == "MSG_MOVE_JUMP":
        session.no_elevator_relock_until = now + _ELEVATOR_NO_RELOCK_SECONDS
        return False, float(x), float(y), float(z), None
    if now < float(getattr(session, "no_elevator_relock_until", 0.0) or 0.0):
        return False, float(x), float(y), float(z), None

    candidate = _find_elevator_candidate(
        session,
        x=float(x),
        y=float(y),
        z=float(z),
        now=now,
    )
    if candidate is None:
        return False, float(x), float(y), float(z), None

    lift, state, distance, dz = candidate
    session.runtime_elevator_bypass_old_support = True
    is_falling = bool(
        int(movement_flags) & (_MOVEMENTFLAG_FALLING | _MOVEMENTFLAG_DESCENDING)
        or bool(getattr(_movement_state(session), "has_fall_data", False))
        or float(z) < float(previous_z) - 0.05
        or opcode_name == "MSG_MOVE_FALL_LAND"
    )
    z_threshold = (
        _ELEVATOR_FALL_ATTACH_Z_THRESHOLD
        if is_falling
        else _ELEVATOR_ATTACH_Z_THRESHOLD
    )
    if abs(float(dz)) > z_threshold:
        last_log = float(getattr(session, "last_elevator_miss_log_at", 0.0) or 0.0)
        if now - last_log >= _LIFT_SUPPORT_LOG_INTERVAL_SECONDS:
            session.last_elevator_miss_log_at = now
            Logger.info(
                "[WorldLift] elevator miss opcode=%s guid=%s entry=%s "
                "distance=%.2f dz=%.2f threshold=%.2f player_z=%.2f current_z=%.2f",
                str(opcode_name),
                int(state.get("guid", 0) or 0),
                int(state.get("entry", 0) or 0),
                float(distance),
                float(dz),
                float(z_threshold),
                float(z),
                float(state.get("current_z", 0.0) or 0.0),
            )
        return False, float(x), float(y), float(z), None

    _attach_runtime_elevator(
        session,
        lift,
        state,
        opcode_name=opcode_name,
        x=float(x),
        y=float(y),
        z=float(z),
        distance=float(distance),
        dz=float(dz),
    )
    new_x, new_y, new_z = _apply_runtime_elevator_position(
        session,
        state,
        opcode_name=opcode_name,
        update_offset_from_client=False,
    )
    return True, new_x, new_y, new_z, state


def _start_lift_transport_thread(session) -> None:
    generation = int(getattr(session, "_lift_transport_generation", 0) or 0) + 1
    session._lift_transport_generation = generation

    def _worker() -> None:
        while True:
            time.sleep(_THUNDER_BLUFF_LIFT_TICK_SECONDS)
            if int(getattr(session, "_lift_transport_generation", 0) or 0) != generation:
                return
            if not (
                _lift_support_active(session)
                or int(getattr(session, "attached_elevator_guid", 0) or 0)
            ):
                return
            _tick_lift_transport_support(session)

    threading.Thread(
        target=_worker,
        name=f"lift-{int(getattr(session, 'char_guid', 0) or 0)}",
        daemon=True,
    ).start()


def _tick_lift_transport_support(session) -> None:
    attached_guid = int(getattr(session, "attached_elevator_guid", 0) or 0)
    if attached_guid:
        if _is_teleporting(session):
            _detach_runtime_elevator(
                session,
                reason="teleport_pending",
                opcode_name="ELEVATOR_TICK",
                x=float(getattr(session, "x", 0.0) or 0.0),
                y=float(getattr(session, "y", 0.0) or 0.0),
                z=float(getattr(session, "z", 0.0) or 0.0),
            )
            return
        state = _elevator_states(session).get(attached_guid)
        if not isinstance(state, dict):
            _detach_runtime_elevator(
                session,
                reason="missing_state",
                opcode_name="ELEVATOR_TICK",
                x=float(getattr(session, "x", 0.0) or 0.0),
                y=float(getattr(session, "y", 0.0) or 0.0),
                z=float(getattr(session, "z", 0.0) or 0.0),
            )
            return
        now = time.time()
        _tick_elevator_state(state, now)
        movement_state = _movement_state(session)
        preserve_airborne = bool(
            int(getattr(movement_state, "flags", 0) or 0)
            & (_MOVEMENTFLAG_FALLING | _MOVEMENTFLAG_DESCENDING)
            or bool(getattr(movement_state, "has_fall_data", False))
        )
        x, y, z = _apply_runtime_elevator_position(
            session,
            state,
            opcode_name="ELEVATOR_TICK",
            update_offset_from_client=False,
            preserve_airborne_state=preserve_airborne,
        )
        payload = build_smsg_player_move_payload(session)
        responses: list[tuple[str, bytes]] = []
        if payload:
            responses.append(("SMSG_PLAYER_MOVE", payload))
        _send_lift_transport_responses(session, responses)
        broadcast_player_state_update(session, force=True)
        Logger.debug(
            "[WorldLift] elevator tick guid=%s z=%.2f pos=(%.2f %.2f %.2f)",
            attached_guid,
            float(state.get("current_z", 0.0) or 0.0),
            x,
            y,
            z,
        )
        return

    active_guid = int(getattr(session, "supported_lift_guid", 0) or 0)
    if not active_guid or _is_teleporting(session):
        return

    loaded_lifts = getattr(session, "loaded_lift_entries", None)
    lift = loaded_lifts.get(active_guid) if isinstance(loaded_lifts, dict) else None
    if not isinstance(lift, dict) or not _is_thunder_bluff_lift(lift):
        return

    now = time.time()
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)
    lift_x = float(lift.get("x", 0.0) or 0.0)
    lift_y = float(lift.get("y", 0.0) or 0.0)
    dx = x - lift_x
    dy = y - lift_y
    distance = math.sqrt((dx * dx) + (dy * dy))
    release_radius = _lift_support_release_radius(lift)
    if distance > release_radius:
        _clear_lift_support_state(
            session,
            reason="outside_xy",
            opcode_name="LIFT_TRANSPORT_TICK",
            x=x,
            y=y,
            z=z,
            lift=lift,
        )
        return

    platform_z = _lift_support_platform_z(session, lift, now, active=True)
    if abs(platform_z - z) < _THUNDER_BLUFF_LIFT_TICK_MIN_DELTA_Z:
        return

    session.z = float(platform_z)
    session.position_dirty = True
    movement_state = _movement_state(session)
    movement_state.x = x
    movement_state.y = y
    movement_state.z = float(platform_z)
    movement_state.orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    movement_state.flags = int(getattr(movement_state, "flags", 0) or 0) & ~(
        _MOVEMENTFLAG_FALLING | _MOVEMENTFLAG_DESCENDING
    )
    _clear_jump_fall_state(movement_state)
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)

    payload = build_smsg_player_move_payload(session)
    responses: list[tuple[str, bytes]] = []
    if payload:
        responses.append(("SMSG_PLAYER_MOVE", payload))
    responses.extend(_drain_lift_support_messages(session))
    _send_lift_transport_responses(session, responses)
    broadcast_player_state_update(session, force=True)
    Logger.debug(
        "[WorldLift] transport tick guid=%s entry=%s pos=(%.2f %.2f %.2f)->z=%.2f distance=%.2f",
        active_guid,
        int(lift.get("entry", 0) or 0),
        x,
        y,
        z,
        platform_z,
        distance,
    )


def _clear_lift_support_state(
    session,
    *,
    reason: str,
    opcode_name: str,
    x: float,
    y: float,
    z: float,
    lift: dict[str, Any] | None = None,
    no_relock_seconds: float = 0.0,
) -> None:
    active_guid = int(getattr(session, "supported_lift_guid", 0) or 0)
    if not active_guid:
        return

    lift_guid = active_guid
    entry = 0
    if isinstance(lift, dict):
        lift_guid = _lift_support_guid(lift) or active_guid
        entry = int(lift.get("entry", 0) or 0)
        lift_x = float(lift.get("x", 0.0) or 0.0)
        lift_y = float(lift.get("y", 0.0) or 0.0)
        lift_z = float(lift.get("z", 0.0) or 0.0)
    else:
        lift_x = float("nan")
        lift_y = float("nan")
        lift_z = float("nan")

    dx = float(x) - lift_x if math.isfinite(lift_x) else 0.0
    dy = float(y) - lift_y if math.isfinite(lift_y) else 0.0
    distance = math.sqrt((dx * dx) + (dy * dy)) if math.isfinite(lift_x) else 0.0
    dz = float(z) - lift_z if math.isfinite(lift_z) else 0.0
    started_at = float(getattr(session, "supported_lift_started_at", 0.0) or 0.0)
    duration = max(0.0, time.time() - started_at) if started_at else 0.0
    now = time.time()

    Logger.info(
        "[WorldLift] support release reason=%s opcode=%s state=%s guid=%s entry=%s "
        "pos=(%.2f %.2f %.2f) lift=(%.2f %.2f %.2f) "
        "distance=%.2f dz=%.2f duration=%.3f",
        str(reason),
        str(opcode_name),
        _lift_support_state(session),
        int(lift_guid),
        int(entry),
        float(x),
        float(y),
        float(z),
        lift_x,
        lift_y,
        lift_z,
        distance,
        dz,
        duration,
    )
    session.supported_lift_guid = 0
    session.supported_lift_started_at = 0.0
    session.supported_lift_last_seen_at = 0.0
    session.supported_lift_bad_z_heartbeats = 0
    session.support_bad_counter = 0
    session.lift_stabilizing_until = 0.0
    session.lift_stable_packet_counter = 0
    session.supported_lift_motion_direction = 0.0
    session.supported_lift_motion_started_at = 0.0
    session.supported_lift_motion_start_z = 0.0
    session.supported_lift_last_platform_z = 0.0
    session._lift_transport_generation = int(
        getattr(session, "_lift_transport_generation", 0) or 0
    ) + 1
    if no_relock_seconds > 0.0:
        session.no_lift_relock_until = now + float(no_relock_seconds)
        _set_lift_support_state(
            session,
            _LIFT_STATE_DETACHING,
            opcode_name=opcode_name,
            reason=reason,
            now=now,
        )
    else:
        session.no_lift_relock_until = 0.0
        _set_lift_support_state(
            session,
            _LIFT_STATE_FREE,
            opcode_name=opcode_name,
            reason=reason,
            now=now,
        )
    _queue_lift_support_message(session, "unlock from lift")


def _find_loaded_lift_support(
    session,
    *,
    opcode_name: str,
    x: float,
    y: float,
    z: float,
    previous_z: float,
    movement_flags: int,
) -> dict[str, Any] | None:
    active_guid = int(getattr(session, "supported_lift_guid", 0) or 0)
    if (
        opcode_name not in _LIFT_SUPPORT_APPLY_OPCODES
        and not (active_guid and opcode_name in _LIFT_SUPPORT_ACTIVE_REFRESH_OPCODES)
    ):
        return None

    _ensure_lift_support_cache(session, x=float(x), y=float(y))

    loaded_lifts = getattr(session, "loaded_lift_entries", None)
    if not isinstance(loaded_lifts, dict) or not loaded_lifts:
        return None

    is_falling = bool(
        movement_flags & (_MOVEMENTFLAG_FALLING | _MOVEMENTFLAG_DESCENDING)
    )
    is_fall_packet = (
        opcode_name == "MSG_MOVE_FALL_LAND"
        or bool(getattr(_movement_state(session), "has_fall_data", False))
    )
    is_descending = float(z) < (float(previous_z) - 0.05)
    if not (active_guid or is_falling or is_fall_packet or is_descending):
        return None

    map_id = int(getattr(session, "map_id", 0) or 0)
    best_lift: dict[str, Any] | None = None
    best_distance_sq = float("inf")
    nearest_lift: dict[str, Any] | None = None
    nearest_distance_sq = float("inf")
    nearest_dz = 0.0
    now = time.time()
    magnet_candidate = bool(
        not active_guid and (is_falling or is_fall_packet or is_descending)
    )

    for lift_key, lift in loaded_lifts.items():
        if not isinstance(lift, dict):
            continue
        if int(lift.get("map", map_id) or 0) != map_id:
            continue
        if active_guid and _lift_support_guid(lift) != active_guid:
            continue

        platform_z = _lift_support_platform_z(
            session,
            lift,
            now,
            active=bool(active_guid),
        )
        if active_guid and _is_thunder_bluff_lift(lift):
            if z > _THUNDER_BLUFF_LIFT_HIGH_Z + _LIFT_SUPPORT_MAGNET_ABOVE_YARDS:
                continue
            if z < _THUNDER_BLUFF_LIFT_LOW_Z - _LIFT_SUPPORT_MAGNET_BELOW_YARDS:
                continue
        else:
            above_limit = (
                _LIFT_SUPPORT_MAGNET_ABOVE_YARDS
                if magnet_candidate
                else _LIFT_SUPPORT_ABOVE_YARDS
            )
            below_limit = (
                _LIFT_SUPPORT_MAGNET_BELOW_YARDS
                if magnet_candidate
                else _LIFT_SUPPORT_BELOW_YARDS
            )
            if z > platform_z + above_limit:
                continue
            if z < platform_z - below_limit:
                continue
            if (
                previous_z < platform_z - 2.0
                and z < platform_z - 2.0
                and not magnet_candidate
            ):
                continue

        lift_x = float(lift.get("x", 0.0) or 0.0)
        lift_y = float(lift.get("y", 0.0) or 0.0)
        dx = float(x) - lift_x
        dy = float(y) - lift_y
        distance_sq = (dx * dx) + (dy * dy)
        if distance_sq < nearest_distance_sq:
            nearest_lift = lift
            nearest_distance_sq = distance_sq
            nearest_dz = float(z) - platform_z
        radius = (
            _lift_support_release_radius(lift)
            if active_guid
            else _lift_support_magnet_radius(lift)
            if magnet_candidate
            else _lift_support_radius(lift)
        )
        if distance_sq > radius * radius:
            continue
        if distance_sq < best_distance_sq:
            best_distance_sq = distance_sq
            best_lift = lift

    if best_lift is None and nearest_lift is not None:
        now = time.time()
        last_log = float(getattr(session, "last_lift_support_miss_log_at", 0.0) or 0.0)
        if (now - last_log) >= _LIFT_SUPPORT_LOG_INTERVAL_SECONDS:
            session.last_lift_support_miss_log_at = now
            Logger.debug(
                "[WorldLift] support miss pos=(%.2f %.2f %.2f) "
                "nearest_guid=%s entry=%s distance=%.2f dz=%.2f flags=0x%X",
                float(x),
                float(y),
                float(z),
                int(nearest_lift.get("guid", 0) or 0),
                int(nearest_lift.get("entry", 0) or 0),
                math.sqrt(nearest_distance_sq),
                nearest_dz,
                int(movement_flags),
            )

    return best_lift


def _apply_loaded_lift_support(
    session,
    *,
    opcode_name: str,
    x: float,
    y: float,
    z: float,
    previous_z: float,
    movement_flags: int,
) -> tuple[float, dict[str, Any] | None]:
    elevator_handled, _elevator_x, _elevator_y, elevator_z, elevator_state = (
        _runtime_elevator_support(
            session,
            opcode_name=opcode_name,
            x=float(x),
            y=float(y),
            z=float(z),
            previous_z=float(previous_z),
            movement_flags=int(movement_flags),
        )
    )
    if elevator_handled:
        return float(elevator_z), {"runtime_elevator": True, "state": elevator_state}
    if bool(getattr(session, "runtime_elevator_bypass_old_support", False)):
        return float(z), None

    if _real_lift_transport_only(session):
        if _lift_support_active(session):
            _clear_lift_support_state(
                session,
                reason="real_transport_only",
                opcode_name=opcode_name,
                x=float(x),
                y=float(y),
                z=float(z),
            )
        now = time.time()
        last_log = float(getattr(session, "last_lift_real_only_log_at", 0.0) or 0.0)
        if (now - last_log) >= _LIFT_SUPPORT_LOG_INTERVAL_SECONDS:
            session.last_lift_real_only_log_at = now
            Logger.debug(
                "[WorldLift] fake support disabled real_transport_only=1 "
                "opcode=%s pos=(%.2f %.2f %.2f)",
                str(opcode_name),
                float(x),
                float(y),
                float(z),
            )
        return float(z), None

    now = time.time()
    active_guid = int(getattr(session, "supported_lift_guid", 0) or 0)
    lift_state = _lift_support_state(session)
    falling_state = _lift_support_falling_state(session, int(movement_flags))
    stabilizing = _lift_support_stabilizing(session, now)
    magnet_candidate = bool(
        not active_guid
        and (
            falling_state
            or opcode_name == "MSG_MOVE_FALL_LAND"
            or float(z) < (float(previous_z) - 0.05)
        )
    )

    if _is_teleporting(session):
        _clear_lift_support_state(
            session,
            reason="teleport_pending",
            opcode_name=opcode_name,
            x=float(x),
            y=float(y),
            z=float(z),
        )
        return float(z), None

    no_relock_until = float(getattr(session, "no_lift_relock_until", 0.0) or 0.0)
    if not active_guid and now < no_relock_until:
        Logger.info(
            "[WorldLift] acquire denied reason=no_relock opcode=%s flags=0x%X "
            "fall=%s remaining=%.3f state=%s",
            opcode_name,
            int(movement_flags),
            bool(falling_state),
            no_relock_until - now,
            lift_state,
        )
        return float(z), None
    if not active_guid and lift_state == _LIFT_STATE_DETACHING and now >= no_relock_until:
        _set_lift_support_state(
            session,
            _LIFT_STATE_FREE,
            opcode_name=opcode_name,
            reason="no_relock_expired",
            now=now,
        )
        lift_state = _LIFT_STATE_FREE

    can_refresh_active = bool(
        active_guid and opcode_name in _LIFT_SUPPORT_ACTIVE_REFRESH_OPCODES
    )
    if opcode_name not in _LIFT_SUPPORT_APPLY_OPCODES and not can_refresh_active:
        if opcode_name in _LIFT_SUPPORT_RELEASE_OPCODES:
            if opcode_name == "MSG_MOVE_JUMP":
                _clear_lift_support_state(
                    session,
                    reason="moving_away",
                    opcode_name=opcode_name,
                    x=float(x),
                    y=float(y),
                    z=float(z),
                    no_relock_seconds=_LIFT_SUPPORT_NO_RELOCK_SECONDS,
                )
                return float(z), None
            if active_guid:
                Logger.info(
                    "[WorldLift] moving_away ignored opcode=%s flags=0x%X "
                    "fall=%s stabilizing=%s duration=%.3f state=%s",
                    opcode_name,
                    int(movement_flags),
                    bool(falling_state),
                    bool(stabilizing),
                    max(
                        0.0,
                        now - float(
                            getattr(session, "supported_lift_started_at", 0.0) or 0.0
                        ),
                    ),
                    lift_state,
                )
                return float(z), None
            _clear_lift_support_state(
                session,
                reason="moving_away",
                opcode_name=opcode_name,
                x=float(x),
                y=float(y),
                z=float(z),
            )
        return float(z), None

    lift = _find_loaded_lift_support(
        session,
        opcode_name=opcode_name,
        x=float(x),
        y=float(y),
        z=float(z),
        previous_z=float(previous_z),
        movement_flags=int(movement_flags),
    )
    if lift is None:
        _clear_lift_support_state(
            session,
            reason="outside_xy",
            opcode_name=opcode_name,
            x=float(x),
            y=float(y),
            z=float(z),
        )
        return float(z), None

    lift_guid = _lift_support_guid(lift)
    active_for_lift = bool(active_guid == lift_guid)
    platform_z = _lift_support_platform_z(
        session,
        lift,
        now,
        active=active_for_lift and lift_state == _LIFT_STATE_ATTACHED,
    )
    lift_x = float(lift.get("x", 0.0) or 0.0)
    lift_y = float(lift.get("y", 0.0) or 0.0)
    dx = float(x) - lift_x
    dy = float(y) - lift_y
    distance_sq = (dx * dx) + (dy * dy)
    radius = (
        _lift_support_release_radius(lift)
        if active_guid == lift_guid
        else _lift_support_magnet_radius(lift)
        if magnet_candidate
        else _lift_support_radius(lift)
    )
    started_at = float(getattr(session, "supported_lift_started_at", 0.0) or 0.0)
    duration = max(0.0, now - started_at) if started_at else 0.0
    if active_guid and opcode_name in _LIFT_SUPPORT_RELEASE_OPCODES:
        Logger.info(
            "[WorldLift] moving_away ignored opcode=%s flags=0x%X "
            "fall=%s stabilizing=%s distance=%.2f dz=%.2f duration=%.3f",
            opcode_name,
            int(movement_flags),
            bool(falling_state),
            bool(stabilizing),
            math.sqrt(distance_sq),
            float(z) - platform_z,
            duration,
        )

    if distance_sq > radius * radius:
        distance = math.sqrt(distance_sq)
        huge_escape = distance > (radius + 10.0)
        if active_guid and not huge_escape:
            bad_count = int(getattr(session, "support_bad_counter", 0) or 0) + 1
            session.support_bad_counter = bad_count
            Logger.info(
                "[WorldLift] bad_counter reason=outside_xy opcode=%s "
                "count=%s/%s flags=0x%X fall=%s stabilizing=%s "
                "distance=%.2f radius=%.2f dz=%.2f duration=%.3f",
                opcode_name,
                bad_count,
                _LIFT_SUPPORT_MAX_BAD_PACKETS,
                int(movement_flags),
                bool(falling_state),
                bool(stabilizing),
                distance,
                radius,
                float(z) - platform_z,
                duration,
            )
            if bad_count < _LIFT_SUPPORT_MAX_BAD_PACKETS:
                return float(z), None
        else:
            session.support_bad_counter = _LIFT_SUPPORT_MAX_BAD_PACKETS

        if int(getattr(session, "support_bad_counter", 0) or 0) >= _LIFT_SUPPORT_MAX_BAD_PACKETS:
            _clear_lift_support_state(
                session,
                reason="outside_xy",
                opcode_name=opcode_name,
                x=float(x),
                y=float(y),
                z=float(z),
                lift=lift,
            )
        return float(z), None

    z_delta = abs(float(z) - platform_z)
    z_threshold = (
        max(_LIFT_SUPPORT_MAGNET_ABOVE_YARDS, _LIFT_SUPPORT_MAGNET_BELOW_YARDS)
        if magnet_candidate
        else max(_lift_support_z_threshold(opcode_name), 6.0)
        if active_for_lift
        else _lift_support_z_threshold(opcode_name)
    )
    in_grace = bool(active_guid and duration <= _LIFT_SUPPORT_GRACE_SECONDS)
    if z_delta > z_threshold:
        if in_grace:
            last_grace_log = float(
                getattr(session, "last_lift_support_grace_log_at", 0.0) or 0.0
            )
            if (now - last_grace_log) >= _LIFT_SUPPORT_LOG_INTERVAL_SECONDS:
                session.last_lift_support_grace_log_at = now
                Logger.info(
                    "[WorldLift] support sticky grace opcode=%s guid=%s entry=%s "
                    "pos=(%.2f %.2f %.2f) lift=(%.2f %.2f %.2f) "
                    "distance=%.2f dz=%.2f threshold=%.2f duration=%.3f",
                    opcode_name,
                    int(lift_guid),
                    int(lift.get("entry", 0) or 0),
                    float(x),
                    float(y),
                    float(z),
                    lift_x,
                    lift_y,
                    platform_z,
                    math.sqrt(distance_sq),
                    float(z) - platform_z,
                    z_threshold,
                    duration,
                )
            return float(z), None

        bad_z_count = int(getattr(session, "support_bad_counter", 0) or 0) + 1
        session.support_bad_counter = bad_z_count
        session.supported_lift_bad_z_heartbeats = bad_z_count
        Logger.info(
            "[WorldLift] bad_counter reason=z_too_far opcode=%s "
            "count=%s/%s flags=0x%X fall=%s stabilizing=%s "
            "distance=%.2f dz=%.2f threshold=%.2f duration=%.3f",
            opcode_name,
            bad_z_count,
            _LIFT_SUPPORT_MAX_BAD_PACKETS,
            int(movement_flags),
            bool(falling_state),
            bool(stabilizing),
            math.sqrt(distance_sq),
            float(z) - platform_z,
            z_threshold,
            duration,
        )
        if bad_z_count >= _LIFT_SUPPORT_MAX_BAD_PACKETS:
            _clear_lift_support_state(
                session,
                reason="z_too_far",
                opcode_name=opcode_name,
                x=float(x),
                y=float(y),
                z=float(z),
                lift=lift,
            )
        return float(z), None
    session.supported_lift_bad_z_heartbeats = 0
    session.support_bad_counter = 0

    if active_guid and active_guid != lift_guid:
        _clear_lift_support_state(
            session,
            reason="outside_xy",
            opcode_name=opcode_name,
            x=float(x),
            y=float(y),
            z=float(z),
            lift=lift,
        )
        active_guid = 0

    if active_guid:
        if lift_state == _LIFT_STATE_MAGNET:
            stable_opcode = opcode_name in {
                "MSG_MOVE_HEARTBEAT",
                "MSG_MOVE_STOP",
            }
            stable_packet = bool(
                stable_opcode
                and not falling_state
                and z_delta <= _LIFT_SUPPORT_STABLE_Z_DELTA
                and distance_sq <= radius * radius
            )
            if stable_packet:
                stable_count = int(
                    getattr(session, "lift_stable_packet_counter", 0) or 0
                ) + 1
                session.lift_stable_packet_counter = stable_count
            else:
                stable_count = int(
                    getattr(session, "lift_stable_packet_counter", 0) or 0
                )
                if opcode_name == "MSG_MOVE_JUMP" or falling_state:
                    stable_count = 0
                    session.lift_stable_packet_counter = 0
            duration_ready = bool(
                duration >= _LIFT_SUPPORT_ATTACH_SECONDS
                and not falling_state
                and z_delta <= _LIFT_SUPPORT_STABLE_Z_DELTA
                and distance_sq <= radius * radius
            )
            Logger.info(
                "[WorldLift] stabilization progress opcode=%s state=%s "
                "stable=%s count=%s/%s duration_ready=%s flags=0x%X "
                "fall=%s distance=%.2f dz=%.2f duration=%.3f",
                opcode_name,
                lift_state,
                bool(stable_packet),
                int(stable_count),
                _LIFT_SUPPORT_STABLE_HEARTBEATS_REQUIRED,
                bool(duration_ready),
                int(movement_flags),
                bool(falling_state),
                math.sqrt(distance_sq),
                float(z) - platform_z,
                duration,
            )
            if stable_count >= _LIFT_SUPPORT_STABLE_HEARTBEATS_REQUIRED or duration_ready:
                attach_reason = "stable_packets"
                if duration_ready and stable_count < _LIFT_SUPPORT_STABLE_HEARTBEATS_REQUIRED:
                    attach_reason = "stable_duration"
                _set_lift_support_state(
                    session,
                    _LIFT_STATE_ATTACHED,
                    opcode_name=opcode_name,
                    reason=attach_reason,
                    now=now,
                )
                lift_state = _LIFT_STATE_ATTACHED
                _start_lift_motion(session, lift, now)
                platform_z = _lift_support_platform_z(
                    session,
                    lift,
                    now,
                    active=True,
                )
                Logger.info(
                    "[WorldLift] transport support attached opcode=%s "
                    "guid=%s entry=%s z=%.2f period=%.2f",
                    opcode_name,
                    int(lift_guid),
                    int(lift.get("entry", 0) or 0),
                    platform_z,
                    _lift_transport_period_seconds(lift),
                )
        if opcode_name == "MSG_MOVE_FALL_LAND":
            _start_lift_support_stabilization(session, now, opcode_name)
            stabilizing = True
        if started_at and (now - started_at) > _LIFT_SUPPORT_MAX_STATIC_SECONDS:
            _clear_lift_support_state(
                session,
                reason="timeout",
                opcode_name=opcode_name,
                x=float(x),
                y=float(y),
                z=float(z),
                lift=lift,
            )
            return float(z), None
    else:
        session.supported_lift_guid = int(lift_guid)
        session.supported_lift_started_at = now
        session.supported_lift_acquired_at = now
        session.supported_lift_bad_z_heartbeats = 0
        session.support_bad_counter = 0
        session.lift_stable_packet_counter = 0
        _set_lift_support_state(
            session,
            _LIFT_STATE_MAGNET,
            opcode_name=opcode_name,
            reason="magnet_acquire",
            now=now,
        )
        lift_state = _LIFT_STATE_MAGNET
        session.supported_lift_motion_direction = 0.0
        session.supported_lift_motion_started_at = 0.0
        session.supported_lift_motion_start_z = platform_z
        session.supported_lift_last_platform_z = platform_z
        if _is_thunder_bluff_lift(lift):
            _start_lift_transport_thread(session)
        _start_lift_support_stabilization(session, now, opcode_name)
        stabilizing = True
        _queue_lift_support_message(session, "locked to lift")
        Logger.info(
            "[WorldLift] support acquire opcode=%s guid=%s entry=%s "
            "pos=(%.2f %.2f %.2f) lift=(%.2f %.2f %.2f) "
            "distance=%.2f dz=%.2f state=%s magnet=%s flags=0x%X",
            opcode_name,
            int(lift_guid),
            int(lift.get("entry", 0) or 0),
            float(x),
            float(y),
            float(z),
            lift_x,
            lift_y,
            platform_z,
            math.sqrt(distance_sq),
            float(z) - platform_z,
            lift_state,
            bool(magnet_candidate),
            int(movement_flags),
        )

    session.supported_lift_last_seen_at = now
    if stabilizing:
        last_stable_log = float(
            getattr(session, "last_lift_stabilizing_log_at", 0.0) or 0.0
        )
        if (now - last_stable_log) >= _LIFT_SUPPORT_LOG_INTERVAL_SECONDS:
            session.last_lift_stabilizing_log_at = now
            Logger.info(
                "[WorldLift] stabilization active opcode=%s flags=0x%X "
                "fall=%s duration=%.3f distance=%.2f dz=%.2f",
                opcode_name,
                int(movement_flags),
                bool(falling_state),
                duration,
                math.sqrt(distance_sq),
                float(z) - platform_z,
            )

    is_landing = opcode_name == "MSG_MOVE_FALL_LAND"
    is_falling = bool(
        int(movement_flags)
        & (_MOVEMENTFLAG_FALLING | _MOVEMENTFLAG_DESCENDING)
    )
    has_fall_data = bool(getattr(_movement_state(session), "has_fall_data", False))
    if not (active_for_lift or is_landing or is_falling or has_fall_data):
        return float(z), None

    last_log = float(getattr(session, "last_lift_support_log_at", 0.0) or 0.0)
    if (now - last_log) >= _LIFT_SUPPORT_LOG_INTERVAL_SECONDS:
        session.last_lift_support_log_at = now
        Logger.info(
            "[WorldLift] support apply opcode=%s guid=%s entry=%s "
            "pos=(%.2f %.2f %.2f)->z=%.2f lift=(%.2f %.2f %.2f) "
            "distance=%.2f dz=%.2f previous_z=%.2f duration=%.3f "
            "state=%s magnet=%s flags=0x%X",
            opcode_name,
            int(lift_guid),
            int(lift.get("entry", 0) or 0),
            float(x),
            float(y),
            float(z),
            platform_z,
            lift_x,
            lift_y,
            platform_z,
            math.sqrt(distance_sq),
            float(z) - platform_z,
            float(previous_z),
            duration,
            lift_state,
            bool(magnet_candidate),
            int(movement_flags),
        )

    return platform_z, lift


@register("MSG_MOVE_START_FORWARD")
@register("MSG_MOVE_START_BACKWARD")
@register("MSG_MOVE_START_STRAFE_LEFT")
@register("MSG_MOVE_START_STRAFE_RIGHT")
@register("MSG_MOVE_STOP_STRAFE")
@register("MSG_MOVE_STOP")
@register("MSG_MOVE_HEARTBEAT")
@register("MSG_MOVE_JUMP")
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
    Logger.debug(f"[MOVE] opcode={opcode_name}")
    _consume_pending_teleport_on_movement(session, opcode_name)
    _clear_dance_emote_state_on_move(session)
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
            if opcode_name in {"MSG_MOVE_STOP", "MSG_MOVE_STOP_ASCEND", "MSG_MOVE_STOP_DESCEND"}:
                _stop_fly_peer_interpolation(session)
            broadcast_player_state_update(session, force=True)
            if opcode_name == "MSG_MOVE_START_ASCEND":
                _start_fly_peer_interpolation(session, 1)
            elif opcode_name == "MSG_MOVE_START_DESCEND":
                _start_fly_peer_interpolation(session, -1)
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
            stream_responses = _maybe_stream_world_objects(session)
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

    if not _accept_movement_update(session, opcode_name, x, y, z, orientation):
        return 0, None

    adjusted_movement = (x, y, z, orientation)

    if not _store_authoritative_movement(session, opcode_name, ctx.payload, adjusted_movement):
        return 0, None
    enter_response = _flying_speed_enter_response(session, was_flying)
    if enter_response is not None:
        movement_responses.append(enter_response)
    if opcode_name == "MSG_MOVE_FALL_LAND" and not _has_active_flying_mount(session):
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

    lift_support = None
    transport_guid = int(getattr(state, "transport_guid", 0) or 0)
    if transport_guid:
        _ensure_lift_support_cache(session, x=float(x), y=float(y))
        loaded_lifts = getattr(session, "loaded_lift_entries", None)
        transport_lift = (
            loaded_lifts.get(transport_guid)
            if isinstance(loaded_lifts, dict)
            else None
        )
        if isinstance(transport_lift, dict):
            if _lift_support_active(session):
                _clear_lift_support_state(
                    session,
                    reason="real_transport_attach",
                    opcode_name=opcode_name,
                    x=float(x),
                    y=float(y),
                    z=float(z),
                    lift=transport_lift,
                )
            Logger.info(
                "[WorldLift] real transport active opcode=%s tguid=0x%016X "
                "offset=(%.3f %.3f %.3f) world=(%.3f %.3f %.3f)",
                opcode_name,
                transport_guid & 0xFFFFFFFFFFFFFFFF,
                float(getattr(state, "transport_x", 0.0) or 0.0),
                float(getattr(state, "transport_y", 0.0) or 0.0),
                float(getattr(state, "transport_z", 0.0) or 0.0),
                float(x),
                float(y),
                float(z),
            )
    if not is_flying_movement:
        if transport_guid:
            supported_z = float(z)
        else:
            supported_z, lift_support = _apply_loaded_lift_support(
                session,
                opcode_name=opcode_name,
                x=float(x),
                y=float(y),
                z=float(z),
                previous_z=float(previous_z),
                movement_flags=int(movement_flags),
            )
        if lift_support is not None:
            z = float(supported_z)
            _clear_jump_fall_state(state)
            _apply_post_parse_movement_cleanup(
                session,
                state,
                opcode_name,
                on_lift_support=True,
            )
            state.flags = int(getattr(state, "flags", 0) or 0) & ~_MOVEMENTFLAG_DESCENDING

    state.x = float(x)
    state.y = float(y)
    state.z = float(z)
    if is_flying_movement:
        session.pitch = float(getattr(state, "pitch", 0.0) or 0.0)
        state.orientation = float(normalized_orientation)
        _remember_valid_orientation(session, state.orientation)
        session.x = float(state.x)
        session.y = float(state.y)
        session.z = float(state.z)
        session.orientation = float(state.orientation)
        Logger.debug(
            "[FLY_PITCH] pitch=%.6f z=%.6f flags=0x%X",
            float(session.pitch),
            float(session.z),
            int(getattr(state, "flags", 0) or 0),
        )
    else:
        state.orientation = float(normalized_orientation)
        _remember_valid_orientation(session, state.orientation)
        _sync_session_from_movement_state(session)
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    discovery_responses = _maybe_discover_current_area(session)
    if discovery_responses:
        movement_responses.extend(discovery_responses)
    if opcode_name == "MSG_MOVE_HEARTBEAT":
        _maybe_periodic_position_save(session)
    if lift_support is not None:
        lift_move_payload = build_smsg_player_move_payload(session)
        if lift_move_payload:
            movement_responses.append(("SMSG_PLAYER_MOVE", lift_move_payload))
    lift_message_responses = _drain_lift_support_messages(session)
    if lift_message_responses:
        movement_responses.extend(lift_message_responses)
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
    if opcode_name == "MSG_MOVE_FALL_LAND":
        _stop_jump_peer_interpolation(session)
        _stop_fly_peer_interpolation(session)
    elif opcode_name in {"MSG_MOVE_STOP", "MSG_MOVE_SET_PITCH", "MSG_MOVE_STOP_ASCEND", "MSG_MOVE_STOP_DESCEND"}:
        _stop_fly_peer_interpolation(session)
    broadcast_player_state_update(session, force=force_broadcast)
    if opcode_name == "MSG_MOVE_JUMP":
        _start_jump_peer_interpolation(session)
    elif opcode_name == "MSG_MOVE_START_ASCEND":
        _start_fly_peer_interpolation(session, 1)
    elif opcode_name == "MSG_MOVE_START_DESCEND":
        _start_fly_peer_interpolation(session, -1)

    Logger.debug(
        f"[MOVE] guid=0x{_player_guid(session):X} "
        f"pos=({session.x:.3f}, {session.y:.3f}, {session.z:.3f}) facing={session.orientation:.3f}"
    )
    stream_responses = _maybe_stream_world_objects(session)
    if stream_responses:
        movement_responses.extend(stream_responses)
    boat_transfer_responses = _maybe_start_manual_boat_transfer(session, opcode_name)
    if boat_transfer_responses:
        movement_responses.extend(boat_transfer_responses)
    companion_responses = _maybe_move_companion_pet_for_opcode(session, opcode_name)
    if companion_responses:
        movement_responses.extend(companion_responses)
    return 0, (movement_responses or None)


@register("MSG_MOVE_SET_FACING")
def handle_msg_move_set_facing(session, ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    _consume_pending_teleport_on_movement(session, "MSG_MOVE_SET_FACING")
    payload = bytes(ctx.payload or b"")
    if len(payload) < 4:
        Logger.warning("[Movement] MSG_MOVE_SET_FACING payload too short")
        return 0, None
    _clear_dance_emote_state_on_move(session)

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
    state.orientation = float(normalized_orientation)
    _sync_session_from_movement_state(session)
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    discovery_responses = _maybe_discover_current_area(session)
    _maybe_periodic_position_save(session)

    Logger.debug(
        f"[MOVE] opcode=MSG_MOVE_SET_FACING guid=0x{_player_guid(session):X} "
        f"facing={session.orientation:.3f}"
    )
    _stop_fly_peer_interpolation(session)
    broadcast_player_state_update(session, force=True)
    stream_responses = _maybe_stream_world_objects(session)
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
    if not bool(getattr(session, "near_teleport_pending", False)):
        Logger.debug("[Teleport] ignoring unexpected CMSG_MOVE_TELEPORT_ACK")
        return 0, [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload("[Teleport] unexpected near-teleport ack ignored"))]

    destination = str(getattr(session, "teleport_destination", "") or "?")
    session.near_teleport_pending = False
    session.worldport_ack_pending = False
    fixspeed_pending = bool(getattr(session, "fixspeed_pending", False))
    session.fixspeed_pending = False
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    _save_session_position(session, reason="near-teleport", online=1, force=True)
    post_teleport_responses = _post_teleport_multiplayer_resync(
        session,
        reason="near-teleport-ack",
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
    responses.extend(post_teleport_responses)
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

@register("CMSG_MOVE_WORLDPORT_ACK")
def handle_move_worldport_ack(session, _ctx: PacketContext):
    if not bool(getattr(session, "worldport_ack_pending", False)):
        Logger.debug("[Teleport] ignoring unexpected WORLDPORT_ACK")
        return 0, None

    destination = str(getattr(session, "teleport_destination", "") or "?")
    # WORLDPORT_ACK only confirms the transfer packet. The loading screen
    # completion still owns the final world bootstrap and pending reset.
    session.near_teleport_pending = False
    session.worldport_ack_pending = False
    session.manual_boat_transfer_pending = False

    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    _save_session_position(session, reason="worldport", online=1, force=True)
    post_teleport_responses = _post_teleport_multiplayer_resync(
        session,
        reason="worldport-ack",
    )

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
    responses.extend(post_teleport_responses)
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

    current_map_id = int(getattr(session, "map_id", 0) or 0)
    px = float(getattr(session, "x", 0.0) or 0.0)
    py = float(getattr(session, "y", 0.0) or 0.0)
    pz = float(getattr(session, "z", 0.0) or 0.0)

    Logger.info(
        "[AREATRIGGER] id=%s map=%s pos=(%.2f %.2f %.2f)",
        trigger_id, current_map_id, px, py, pz
    )

    row = DatabaseConnection.get_areatrigger_teleport(trigger_id)
    if not row:
        return 0, [
            (
                "SMSG_MESSAGECHAT",
                encode_skyfire_messagechat_system_payload(
                    f"[AREATRIGGER] id={trigger_id} (no mapping)"
                ),
            )
        ]

    target_map = int(row["target_map"])
    x = float(row["target_position_x"])
    y = float(row["target_position_y"])
    z = float(row["target_position_z"])
    o = float(row.get("target_orientation", 0.0) or 0.0)

    same_map = (current_map_id == target_map)
    session.teleport_destination = f"areatrigger:{trigger_id}"

    Logger.debug(
        "[AREATRIGGER] target map=%s pos=(%.2f %.2f %.2f %.2f)",
        target_map, x, y, z, o
    )

    # --- IMPORTANT: set flags BEFORE teleport ---
    session.near_teleport_pending = same_map
    session.teleport_pending = not same_map
    session.worldport_ack_pending = not same_map

    # Lazy import (avoid circular import)
    from server.modules.handlers.world.opcodes import chat as chat_handlers

    responses = chat_handlers.apply_player_state_change(
        session,
        position=(x, y, z, o),
        map_id=target_map,
    )

    # --- DO NOT reset flags here ---

    if same_map:
        msg = (
            f"[Teleport] near start -> {session.teleport_destination} "
            f"({x:.1f} {y:.1f} {z:.1f})"
        )
    else:
        msg = (
            f"[Teleport] transfer start -> {session.teleport_destination} "
            f"map={target_map} ({x:.1f} {y:.1f} {z:.1f})"
        )

    responses = _append_feedback_response(responses, msg)

    return 0, responses
