from __future__ import annotations

import math
import struct
import time
from typing import Any, Optional, Tuple

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitWriter
# from modules.handlers.world.opcodes.chat import _append_feedback_response
from shared.Logger import Logger
from server.modules.game.guid import GameObjectGuid, GuidHelper
from server.modules.handlers.world.bootstrap.replay import (
    build_database_gameobject_responses,
    build_single_u32_update_object_payload,
)
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
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
)


def _append_guid_byte_seq(payload: bytearray, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        value = raw_guid[index]
        if value:
            payload.append((value ^ 1) & 0xFF)


_MOVEMENTFLAG_FORWARD = 0x00000001
_MOVEMENTFLAG_BACKWARD = 0x00000002
_MOVEMENTFLAG_STRAFE_LEFT = 0x00000004
_MOVEMENTFLAG_STRAFE_RIGHT = 0x00000008
_MOVEMENTFLAG_TURN_LEFT = 0x00000010
_MOVEMENTFLAG_TURN_RIGHT = 0x00000020
_MOVEMENTFLAG_LEFT = _MOVEMENTFLAG_TURN_LEFT
_MOVEMENTFLAG_RIGHT = _MOVEMENTFLAG_TURN_RIGHT
_MOVEMENTFLAG_FALLING = 0x00000800

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
    state.counter = int(getattr(state, "counter", 0) or 0) & 0xFFFFFFFF
    return state


def _sync_session_from_movement_state(session) -> None:
    state = _movement_state(session)
    session.x = float(state.x)
    session.y = float(state.y)
    session.z = float(state.z)
    session.orientation = float(state.orientation)


def _movement_flags_for_sync(session) -> int:
    return int(_movement_state(session).flags)


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
    move_flags = int(state.flags)
    move_flags2 = int(state.flags2)
    timestamp = _movement_timestamp_ms(session)
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
    timestamp = _movement_timestamp_ms(session)
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

    move_flags = int(state.flags)
    move_flags2 = int(state.flags2)
    has_orientation = not math.isclose(float(orientation), 0.0, abs_tol=1e-6)
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

# TODO:
# - Move replay_movement_focus_sequence* and related UPDATE_OBJECT replay helpers
#   into dedicated bootstrap/runtime modules once login packet builders are disentangled.
# - Move teleport-specific movement replay/broadcast helpers after the login
#   extraction phase so movement owns all movement-focused world transitions.


def _player_guid(session) -> int:
    return int(getattr(session, "world_guid", 0) or getattr(session, "player_guid", 0) or 0)


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
    keep_guids = {
        int(GameObjectGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), realm_id))
        for entry in keep_entries
    }

    stale_guids = sorted(int(guid) for guid in loaded_gameobjects if int(guid) not in keep_guids)
    for guid in stale_guids:
        Logger.debug("[GO_STREAM] despawn guid=0x%X", int(guid))
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                _build_out_of_range_update_object_payload(map_id=map_id, guid=int(guid)),
            )
        )
        loaded_gameobjects.discard(int(guid))

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
    state.flags = int(flags)
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


def _apply_early_movement_cleanup(session, opcode_name: str) -> None:
    if opcode_name not in {"MSG_MOVE_FALL_LAND", "MSG_MOVE_STOP_STRAFE"}:
        return

    state = _movement_state(session)
    if opcode_name == "MSG_MOVE_FALL_LAND":
        if _clear_jump_fall_state(state):
            Logger.debug("[LAND_RESET] cleared fall state")
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
    if len(payload) < 12:
        return None

    try:
        first, second, third = struct.unpack_from("<fff", payload, 0)
    except struct.error:
        return None

    orientation = float(getattr(session, "orientation", 0.0) or 0.0)

    if opcode_name == "MSG_MOVE_HEARTBEAT":
        # SkyFire 5.4.8 MovementHeartBeat starts with PositionZ, PositionX, PositionY.
        z, x, y = first, second, third
        orientation_offsets = ()
        if len(payload) >= 51:
            orientation_offsets = (23, 20)
        elif len(payload) >= 32:
            orientation_offsets = (18, 20)
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

    if opcode_name == "MSG_MOVE_START_BACKWARD":
        # SkyFire 5.4.8 MovementStartBackward starts with PositionY, PositionZ, PositionX.
        y, z, x = first, second, third
        return (float(x), float(y), float(z), float(orientation))

    if opcode_name == "MSG_MOVE_STOP":
        # SkyFire 5.4.8 MovementStop starts with PositionX, PositionY, PositionZ.
        x, y, z = first, second, third
        if len(payload) >= 24:
            try:
                candidate = struct.unpack_from("<f", payload, 20)[0]
                normalized = _normalize_orientation(candidate)
                if normalized is not None:
                    orientation = float(normalized)
            except struct.error:
                pass
        return (float(x), float(y), float(z), float(orientation))

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
        if len(payload) >= 28:
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
        if len(payload) >= 28:
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
        if len(payload) >= 36:
            orientation_offsets = (32, 24)
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
    _apply_movement_flags(state, opcode_name)
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
    incoming_timestamp = _extract_packet_timestamp(opcode_name, payload)
    if incoming_timestamp is not None and _is_stale_client_timestamp(state.timestamp_ms, incoming_timestamp):
        Logger.debug(
            "[Movement] ignoring stale %s timestamp current=%u incoming=%u",
            opcode_name,
            int(state.timestamp_ms),
            int(incoming_timestamp),
        )
        return False
    _record_movement_packet_state(session, opcode_name, payload)
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


@register("MSG_MOVE_START_FORWARD")
@register("MSG_MOVE_START_BACKWARD")
@register("MSG_MOVE_START_STRAFE_LEFT")
@register("MSG_MOVE_START_STRAFE_RIGHT")
@register("MSG_MOVE_STOP_STRAFE")
@register("MSG_MOVE_STOP")
@register("MSG_MOVE_HEARTBEAT")
@register("MSG_MOVE_JUMP")
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

    movement = parse_movement_info(session, opcode_name, ctx.payload, ctx.decoded)
    if movement is None:
        if opcode_name in {
            "MSG_MOVE_START_FORWARD",
            "MSG_MOVE_START_BACKWARD",
            "MSG_MOVE_START_STRAFE_LEFT",
            "MSG_MOVE_START_STRAFE_RIGHT",
            "MSG_MOVE_STOP_STRAFE",
            "MSG_MOVE_STOP",
            "MSG_MOVE_START_TURN_LEFT",
            "MSG_MOVE_START_TURN_RIGHT",
            "MSG_MOVE_STOP_TURN",
        }:
            if not _store_authoritative_movement(session, opcode_name, ctx.payload, None):
                return 0, None
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
            stream_responses = _maybe_stream_gameobjects(session)
            return 0, (stream_responses or None)
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

    normalized_orientation = _normalize_orientation(orientation)
    if normalized_orientation is None:
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
    elif opcode_name == "MSG_MOVE_HEARTBEAT":
        if previous_normalized_orientation is not None:
            if opcode_name == "MSG_MOVE_HEARTBEAT" and _is_effectively_stationary(
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
            normalized_orientation = float(previous_normalized_orientation)

    state = _movement_state(session)
    state.x = float(x)
    state.y = float(y)
    state.z = float(z)
    state.orientation = float(normalized_orientation)
    _sync_session_from_movement_state(session)
    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    if opcode_name == "MSG_MOVE_HEARTBEAT":
        _maybe_periodic_position_save(session)
    force_broadcast = opcode_name in {"MSG_MOVE_HEARTBEAT", "MSG_MOVE_JUMP"}
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
    stream_responses = _maybe_stream_gameobjects(session)
    return 0, (stream_responses or None)


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
    _maybe_periodic_position_save(session)

    Logger.debug(
        f"[MOVE] opcode=MSG_MOVE_SET_FACING guid=0x{_player_guid(session):X} "
        f"facing={session.orientation:.3f}"
    )
    broadcast_player_state_update(session, force=True)
    stream_responses = _maybe_stream_gameobjects(session)
    return 0, (stream_responses or None)


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
    broadcast_player_state_update(session, force=True)
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

    _capture_persist_position_from_session(session)
    _mark_position_dirty(session)
    _save_session_position(session, reason="worldport", online=1, force=True)
    broadcast_player_state_update(session, force=True)

    Logger.info(
        "[Teleport] world transfer ack destination=%s pos=(%.2f %.2f %.2f %.2f)",
        destination,
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )

    return 0, [
        (
            "SMSG_MESSAGECHAT",
            encode_skyfire_messagechat_system_payload(
                f"[Teleport] worldport ack -> {destination}"
            ),
        )
    ]
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
