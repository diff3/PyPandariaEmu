from __future__ import annotations

import math
import struct
import sys
from types import SimpleNamespace
import types

replay_module = types.ModuleType("server.modules.handlers.world.bootstrap.replay")
replay_module.build_database_gameobject_responses = lambda *args, **kwargs: []
replay_module.build_multi_u32_update_object_payload = lambda *args, **kwargs: b""
replay_module.build_single_u32_update_object_payload = lambda *args, **kwargs: b""
sys.modules.setdefault("server.modules.handlers.world.bootstrap.replay", replay_module)

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type("DatabaseConnection", (), {})
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

from server.modules.handlers.world.opcodes import movement
from server.modules.handlers.world.state.player_visible_snapshot import (
    build_player_visible_snapshot,
)


def _payload_bits_msb(payload: bytes):
    for byte in payload:
        for bit in range(7, -1, -1):
            yield (byte >> bit) & 1


def _read_bits(bit_iter, width: int) -> int:
    value = 0
    for _index in range(width):
        value = (value << 1) | next(bit_iter)
    return value


def _decode_smsg_player_move_state(payload: bytes) -> tuple[int, int, float]:
    bit_iter = _payload_bits_msb(payload)
    _read_bits(bit_iter, 5)
    has_orientation = not bool(_read_bits(bit_iter, 1))
    _read_bits(bit_iter, 6)
    has_flags = not bool(_read_bits(bit_iter, 1))
    _read_bits(bit_iter, 1)
    movement_flags = _read_bits(bit_iter, 30) if has_flags else 0
    has_flags2 = not bool(_read_bits(bit_iter, 1))
    _read_bits(bit_iter, 3)
    movement_flags2 = _read_bits(bit_iter, 13) if has_flags2 else 0
    _read_bits(bit_iter, 24)

    offset = 11 if has_flags2 else 9
    _y = struct.unpack_from("<f", payload, offset)[0]
    offset += 4
    _z = struct.unpack_from("<f", payload, offset)[0]
    offset += 4
    offset += 4  # timestamp
    orientation = struct.unpack_from("<f", payload, offset)[0] if has_orientation else 0.0
    return movement_flags, movement_flags2, orientation


def test_build_smsg_player_move_payload_uses_session_state() -> None:
    state = SimpleNamespace(
        x=1.5,
        y=2.5,
        z=3.5,
        orientation=0.75,
        flags=0,
        flags2=0,
        timestamp_ms=123,
        counter=0,
    )
    session = SimpleNamespace(char_guid=7, world_guid=7, movement_state=state)

    payload = movement.build_smsg_player_move_payload(session)

    assert payload is not None
    assert struct.pack("<f", 2.5) in payload
    assert struct.pack("<f", 3.5) in payload
    assert struct.pack("<f", 1.5) in payload
    assert struct.pack("<f", 0.75) in payload


def test_build_smsg_player_move_payload_adds_flying_flags_for_peers() -> None:
    state = SimpleNamespace(
        x=1.5,
        y=2.5,
        z=30.5,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=123,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        is_ascending=True,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        world_guid=7,
        movement_state=state,
        can_fly=True,
        is_flying=True,
    )

    payload = movement.build_smsg_player_move_payload(session)
    movement_flags, _movement_flags2, orientation = _decode_smsg_player_move_state(payload)

    assert movement_flags & movement._MOVEMENTFLAG_CAN_FLY
    assert movement_flags & movement._MOVEMENTFLAG_FLYING
    assert movement_flags & movement._MOVEMENTFLAG_ASCENDING
    assert not movement_flags & movement._MOVEMENTFLAG_DESCENDING
    assert round(orientation, 6) == 1.25


def test_fall_land_stops_flying_animation_but_keeps_capability() -> None:
    state = SimpleNamespace(
        x=1.5,
        y=2.5,
        z=30.5,
        orientation=1.25,
        flags=(
            movement._MOVEMENTFLAG_CAN_FLY
            | movement._MOVEMENTFLAG_FLYING
            | movement._MOVEMENTFLAG_ASCENDING
        ),
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        is_ascending=True,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        world_guid=7,
        movement_state=state,
        can_fly=True,
        is_flying=True,
    )

    ok = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_FALL_LAND",
        b"",
        (1.5, 2.5, 30.5, 1.25),
    )
    payload = movement.build_smsg_player_move_payload(session)
    movement_flags, _movement_flags2, orientation = _decode_smsg_player_move_state(payload)

    assert ok is True
    assert session.can_fly is True
    assert session.is_flying is False
    assert state.is_ascending is False
    assert state.is_descending is False
    assert movement_flags & movement._MOVEMENTFLAG_CAN_FLY
    assert not movement_flags & movement._MOVEMENTFLAG_FLYING
    assert not movement_flags & movement._MOVEMENTFLAG_ASCENDING
    assert not movement_flags & movement._MOVEMENTFLAG_DESCENDING
    assert round(orientation, 6) == 1.25


def test_stable_moving_heartbeats_keep_flying_animation() -> None:
    state = SimpleNamespace(
        x=1.5,
        y=2.5,
        z=30.5,
        orientation=1.25,
        flags=(
            movement._MOVEMENTFLAG_CAN_FLY
            | movement._MOVEMENTFLAG_FLYING
            | movement._MOVEMENTFLAG_FORWARD
            | movement._MOVEMENTFLAG_TURN_RIGHT
        ),
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        world_guid=7,
        movement_state=state,
        can_fly=True,
        is_flying=True,
    )

    for index in range(4):
        ok = movement._store_authoritative_movement(
            session,
            "MSG_MOVE_HEARTBEAT",
            b"",
            (1.5 + float(index), 2.5, 30.5, 1.25),
        )
        assert ok is True

    payload = movement.build_smsg_player_move_payload(session)
    movement_flags, _movement_flags2, _orientation = _decode_smsg_player_move_state(payload)

    assert session.is_flying is True
    assert movement_flags & movement._MOVEMENTFLAG_FLYING


def test_peer_move_build_does_not_advance_inbound_timestamp(monkeypatch) -> None:
    monkeypatch.setattr(movement.time, "time", lambda: 1.010)
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=1.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=1,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
    )
    session = SimpleNamespace(char_guid=2, world_guid=2, movement_state=state)
    start_turn_payload = (b"\x00" * 20) + (1000).to_bytes(4, "little")
    stop_turn_payload = (b"\x00" * 20) + (1001).to_bytes(4, "little")

    ok = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_START_TURN_RIGHT",
        start_turn_payload,
        None,
    )
    assert ok is True
    assert state.timestamp_ms == 1000
    assert state.flags & movement._MOVEMENTFLAG_TURN_RIGHT

    payload = movement.build_smsg_player_move_payload(session)

    assert payload is not None
    assert state.timestamp_ms == 1000
    assert state.server_movement_timestamp_ms == 1010

    ok = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_STOP_TURN",
        stop_turn_payload,
        None,
    )

    assert ok is True
    assert state.timestamp_ms == 1001
    assert not state.flags & movement._MOVEMENTFLAG_TURN_RIGHT


def test_stop_turn_after_peer_move_build_clears_peer_turn_flags(monkeypatch) -> None:
    monkeypatch.setattr(movement.time, "time", lambda: 1.010)
    state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=1,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
    )
    session = SimpleNamespace(
        char_guid=2,
        world_guid=2,
        map_id=1,
        zone=1,
        movement_state=state,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
    )
    start_turn_payload = (b"\x00" * 20) + (1000).to_bytes(4, "little")
    stop_turn_payload = (b"\x00" * 20) + (1001).to_bytes(4, "little")

    assert movement._store_authoritative_movement(
        session,
        "MSG_MOVE_START_TURN_RIGHT",
        start_turn_payload,
        None,
    )
    assert movement.build_smsg_player_move_payload(session) is not None
    assert movement._store_authoritative_movement(
        session,
        "MSG_MOVE_STOP_TURN",
        stop_turn_payload,
        None,
    )

    payload = movement.build_smsg_player_move_payload(session)
    movement_flags, _movement_flags2, _orientation = _decode_smsg_player_move_state(payload)

    assert not state.flags & movement._MOVEMENTFLAG_TURN_RIGHT
    assert not movement_flags & movement._MOVEMENTFLAG_TURN_RIGHT


def test_forward_turn_right_sets_reference_flags2_for_peer_prediction() -> None:
    state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=1,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
    )
    session = SimpleNamespace(
        char_guid=2,
        world_guid=2,
        map_id=1,
        zone=1,
        movement_state=state,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
    )

    movement._store_authoritative_movement(session, "MSG_MOVE_START_FORWARD", b"", None)
    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_RIGHT", b"", None)

    payload = movement.build_smsg_player_move_payload(session)
    movement_flags, movement_flags2, _orientation = _decode_smsg_player_move_state(payload)

    assert movement_flags == (
        movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_TURN_RIGHT
    )
    assert movement_flags2 == movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC
    assert payload[:8].hex() == "8810000002104000"


def test_forward_turn_left_sets_reference_flags2_for_peer_prediction() -> None:
    state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=1,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
    )
    session = SimpleNamespace(
        char_guid=2,
        world_guid=2,
        map_id=1,
        zone=1,
        movement_state=state,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
    )

    movement._store_authoritative_movement(session, "MSG_MOVE_START_FORWARD", b"", None)
    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_LEFT", b"", None)

    payload = movement.build_smsg_player_move_payload(session)
    movement_flags, movement_flags2, _orientation = _decode_smsg_player_move_state(payload)

    assert movement_flags == (
        movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_TURN_LEFT
    )
    assert movement_flags2 == movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC
    assert payload[:8].hex() == "8810000001104000"


def test_circle_run_flags2_clears_when_combination_ends() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=0,
    )
    session = SimpleNamespace(movement_state=state)

    movement._store_authoritative_movement(session, "MSG_MOVE_START_FORWARD", b"", None)
    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_RIGHT", b"", None)
    assert state.flags2 & movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP_TURN", b"", None)
    assert not state.flags2 & movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC

    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_LEFT", b"", None)
    assert state.flags2 & movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP", b"", None)
    assert not state.flags2 & movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC


def test_post_jump_ground_movement_clears_fall_state_without_canceling_held_turn() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_FALLING | movement._MOVEMENTFLAG_TURN_RIGHT,
        flags2=0,
        timestamp_ms=1000,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=123,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=2.0,
        fall_sin_angle=0.47,
        fall_cos_angle=-0.88,
    )
    session = SimpleNamespace(movement_state=state)

    ok = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_START_FORWARD",
        b"",
        (1.0, 2.0, 3.0, 0.5),
    )

    assert ok is True
    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert not state.flags & movement._MOVEMENTFLAG_FALLING
    assert state.flags & movement._MOVEMENTFLAG_TURN_RIGHT
    assert state.has_fall_data is False
    assert state.fall_time == 0
    assert state.fall_vertical_speed == 0.0


def test_snapshot_and_smsg_player_move_agree_on_orientation_and_flags() -> None:
    state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.75,
        flags=movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_TURN_LEFT,
        flags2=movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC,
        timestamp_ms=1000,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=1,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
    )
    session = SimpleNamespace(
        char_guid=2,
        world_guid=2,
        map_id=1,
        zone=1,
        movement_state=state,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.75,
    )

    snapshot = build_player_visible_snapshot(session)
    payload = movement.build_smsg_player_move_payload(session)
    movement_flags, movement_flags2, orientation = _decode_smsg_player_move_state(payload)

    assert snapshot.orientation == 1.75
    assert round(orientation, 6) == round(snapshot.orientation, 6)
    assert movement_flags == snapshot.movement_flags
    assert movement_flags2 == snapshot.movement_flags2


def test_build_smsg_player_move_payload_no_fall_output_unchanged(monkeypatch) -> None:
    monkeypatch.setattr(movement.time, "time", lambda: 1000.0)
    state = SimpleNamespace(
        x=1.5,
        y=2.5,
        z=3.5,
        orientation=0.75,
        flags=0,
        flags2=0,
        timestamp_ms=123,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
    )
    session = SimpleNamespace(char_guid=7, world_guid=7, movement_state=state)

    payload = movement.build_smsg_player_move_payload(session)

    assert payload is not None
    assert payload.hex() == "891a00000000000020400000604040420f000000403f060000c03f"


def test_build_smsg_player_move_payload_keeps_zero_orientation_in_normal_layout(monkeypatch) -> None:
    monkeypatch.setattr(movement.time, "time", lambda: 1000.0)
    state = SimpleNamespace(
        x=1.5,
        y=2.5,
        z=3.5,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=123,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
    )
    session = SimpleNamespace(char_guid=7, world_guid=7, movement_state=state)

    payload = movement.build_smsg_player_move_payload(session)

    assert payload is not None
    assert payload.hex() == "891a00000000000020400000604040420f0000000000060000c03f"


def test_build_smsg_player_move_payload_with_fall_data_includes_minimal_fall_body(monkeypatch) -> None:
    monkeypatch.setattr(movement.time, "time", lambda: 1000.0)
    state = SimpleNamespace(
        x=1.5,
        y=2.5,
        z=3.5,
        orientation=0.75,
        flags=movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=123,
        counter=0,
        has_fall_data=True,
        fall_time=321,
        fall_vertical_speed=-7.955547,
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=0.0,
    )
    session = SimpleNamespace(char_guid=7, world_guid=7, movement_state=state)

    payload = movement.build_smsg_player_move_payload(session)

    assert payload is not None
    assert struct.pack("<I", 321) in payload
    assert struct.pack("<f", -7.955547) in payload
    assert struct.pack("<fI", -7.955547, 321) in payload


def test_build_smsg_player_move_payload_jump_matches_captured_layout(monkeypatch) -> None:
    expected = bytes.fromhex(
        "8A0C08000000005C177E46DA005541F0D83A0064DEA740"
        "D893FEC0390300000C31010000E8887D46"
    )
    timestamp = struct.unpack_from("<I", expected, 15)[0]
    monkeypatch.setattr(movement.time, "time", lambda: timestamp / 1000.0)
    state = SimpleNamespace(
        x=struct.unpack_from("<f", expected, 36)[0],
        y=struct.unpack_from("<f", expected, 7)[0],
        z=struct.unpack_from("<f", expected, 11)[0],
        orientation=struct.unpack_from("<f", expected, 19)[0],
        flags=movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=(timestamp - 1) & 0xFFFFFFFF,
        counter=struct.unpack_from("<I", expected, 32)[0],
        has_fall_data=True,
        fall_time=struct.unpack_from("<I", expected, 27)[0],
        fall_vertical_speed=struct.unpack_from("<f", expected, 23)[0],
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=0.0,
    )
    session = SimpleNamespace(char_guid=0x0D, world_guid=0x0D, movement_state=state)

    payload = movement.build_smsg_player_move_payload(session)

    assert payload == expected


def test_build_smsg_player_move_payload_running_jump_includes_direction_block(monkeypatch) -> None:
    monkeypatch.setattr(movement.time, "time", lambda: 1000.0)
    state = SimpleNamespace(
        x=16212.125,
        y=16253.887695,
        z=14.920669,
        orientation=1.697978,
        flags=movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=999999,
        counter=0x12345678,
        has_fall_data=True,
        fall_time=0,
        fall_vertical_speed=-7.955547,
        fall_horizontal_speed=7.0,
        fall_sin_angle=0.991923,
        fall_cos_angle=-0.126840,
    )
    session = SimpleNamespace(char_guid=0x0D, world_guid=0x0D, movement_state=state)

    payload = movement.build_smsg_player_move_payload(session)

    assert payload is not None
    assert len(payload) == 52
    assert payload[:7] == bytes.fromhex("8A4C0800000000")
    assert payload[23:39] == struct.pack("<fffI", 0.991923, 7.0, -0.126840, 0)
    assert payload[39:43] == struct.pack("<f", -7.955547)
    assert payload[43] == 0x0C
    assert payload[44:48] == struct.pack("<I", 0x12345678)
    assert payload[48:52] == struct.pack("<f", 16212.125)


def test_msg_move_jump_records_horizontal_fall_direction() -> None:
    payload = bytes.fromhex(
        "8DF77D4680507D460FBB6E4108000000494000080040040F"
        "D893FEC0AFEE7D3F3CE201BE0000E040000000005C57D93F8DAE1017"
    )
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=0.0,
    )
    session = SimpleNamespace(movement_state=state)

    movement._record_movement_packet_state(session, "MSG_MOVE_JUMP", payload)

    assert state.has_fall_data is True
    assert state.fall_time == 0
    assert round(state.fall_vertical_speed, 6) == round(-7.955547, 6)
    assert round(state.fall_horizontal_speed, 6) == 7.0
    assert round(state.fall_sin_angle, 6) == round(0.991923, 6)
    assert round(state.fall_cos_angle, 6) == round(-0.126840, 6)


def test_airborne_heartbeat_after_normal_jump_refreshes_fall_time() -> None:
    jump_payload = bytes.fromhex(
        "00FB7D46C1A27D46BF5B5E4108000000494000080040040C"
        "D893FEC0433FC7BEF6D16BBF0000000000000000C3A4624021A32C05"
    )
    heartbeat_payload = bytes.fromhex(
        "A96B7741C1A27D4600FB7D46000000904540000800800C433FC7BE"
        "F6D16BBF00000000D893FEC0F4010000C3A4624015A52C05"
    )
    state = SimpleNamespace(
        x=16232.6884765625,
        y=16254.75,
        z=13.8973989487,
        orientation=3.5413062572,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=0,
        pitch=0.0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=0.0,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        x=state.x,
        y=state.y,
        z=state.z,
        orientation=state.orientation,
        movement_state=state,
        can_fly=False,
        is_flying=False,
    )

    movement._store_authoritative_movement(
        session,
        "MSG_MOVE_JUMP",
        jump_payload,
        movement.parse_movement_info(session, "MSG_MOVE_JUMP", jump_payload, decoded={}),
    )
    assert state.flags & movement._MOVEMENTFLAG_FALLING
    assert state.fall_time == 0

    parsed = movement.parse_movement_info(session, "MSG_MOVE_HEARTBEAT", heartbeat_payload, decoded={})
    stored = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_HEARTBEAT",
        heartbeat_payload,
        parsed,
    )

    assert stored is True
    assert parsed is not None
    assert state.flags & movement._MOVEMENTFLAG_FALLING
    assert state.fall_time == 500
    assert round(state.fall_vertical_speed, 6) == round(-7.9555473328, 6)
    assert round(state.fall_sin_angle, 6) == round(-0.3891545236, 6)
    assert round(state.fall_cos_angle, 6) == round(-0.9211724997, 6)


def test_stop_forward_during_jump_keeps_falling_state() -> None:
    state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        flags=movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=0,
        pitch=0.0,
        has_fall_data=True,
        fall_time=250,
        fall_vertical_speed=-7.955547,
        fall_horizontal_speed=7.0,
        fall_sin_angle=0.1,
        fall_cos_angle=0.9,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        x=state.x,
        y=state.y,
        z=state.z,
        orientation=state.orientation,
        movement_state=state,
        can_fly=False,
        is_flying=False,
    )

    stored = movement._store_authoritative_movement(session, "MSG_MOVE_STOP", b"", None)

    assert stored is True
    assert state.flags & movement._MOVEMENTFLAG_FALLING
    assert not state.flags & movement._MOVEMENTFLAG_FORWARD
    assert state.has_fall_data is True


def test_strafe_packets_use_separate_flags_from_turn() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        counter=0,
    )
    session = SimpleNamespace(movement_state=state)

    movement._store_authoritative_movement(session, "MSG_MOVE_START_STRAFE_LEFT", b"", None)

    assert state.flags & movement._MOVEMENTFLAG_STRAFE_LEFT
    assert not state.flags & movement._MOVEMENTFLAG_TURN_LEFT

    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_RIGHT", b"", None)

    assert state.flags & movement._MOVEMENTFLAG_STRAFE_LEFT
    assert state.flags & movement._MOVEMENTFLAG_TURN_RIGHT

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP_STRAFE", b"", None)

    assert not state.flags & movement._MOVEMENTFLAG_STRAFE_LEFT
    assert state.flags & movement._MOVEMENTFLAG_TURN_RIGHT


def test_heartbeat_preserves_active_turn_flag_while_moving() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_FORWARD,
        flags2=0,
        timestamp_ms=0,
        counter=0,
    )
    session = SimpleNamespace(movement_state=state)

    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_RIGHT", b"", None)
    movement._store_authoritative_movement(session, "MSG_MOVE_HEARTBEAT", b"", (1.0, 2.0, 3.0, 0.5))

    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert state.flags & movement._MOVEMENTFLAG_TURN_RIGHT

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP_TURN", b"", None)

    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert not state.flags & movement._MOVEMENTFLAG_TURN_RIGHT


def test_moving_turn_keeps_forward_and_turn_flags_until_stop() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        counter=0,
    )
    session = SimpleNamespace(movement_state=state)

    movement._store_authoritative_movement(session, "MSG_MOVE_START_FORWARD", b"", None)
    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_LEFT", b"", None)
    for index in range(5):
        movement._store_authoritative_movement(
            session,
            "MSG_MOVE_HEARTBEAT",
            b"",
            (float(index), 0.0, 0.0, 0.25 * float(index)),
        )

    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert state.flags & movement._MOVEMENTFLAG_TURN_LEFT

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP_TURN", b"", None)

    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert not state.flags & movement._MOVEMENTFLAG_TURN_LEFT

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP", b"", None)

    assert not state.flags & movement._MOVEMENTFLAG_FORWARD


def test_parse_real_start_strafe_left_payload() -> None:
    session = SimpleNamespace(orientation=0.0)
    payload = bytes.fromhex(
        "CEF47D4636864F415A8A7D46880000000A0000000440000C35C7F60529A54C40"
    )

    parsed = movement.parse_movement_info(session, "MSG_MOVE_START_STRAFE_LEFT", payload, decoded={})

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16226.587891, 3)
    assert round(y, 3) == round(16253.201172, 3)
    assert round(z, 3) == round(12.970266, 3)
    assert round(orientation, 3) == round(3.197581, 3)


def test_parse_real_start_strafe_right_payload() -> None:
    session = SimpleNamespace(orientation=0.0)
    payload = bytes.fromhex(
        "E2097E462C897D4644AD544180000004440000000840000C3CC3F60529A54C40"
    )

    parsed = movement.parse_movement_info(session, "MSG_MOVE_START_STRAFE_RIGHT", payload, decoded={})

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16226.292969, 3)
    assert round(y, 3) == round(16258.470703, 3)
    assert round(z, 3) == round(13.292301, 3)
    assert round(orientation, 3) == round(3.197581, 3)


def test_parse_real_stop_strafe_payload() -> None:
    session = SimpleNamespace(orientation=0.0)
    payload = bytes.fromhex("574B4F41628A7D4646F47D462C1000000110000C29A54C4048C7F605")

    parsed = movement.parse_movement_info(session, "MSG_MOVE_STOP_STRAFE", payload, decoded={})

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16226.595703, 3)
    assert round(y, 3) == round(16253.068359, 3)
    assert round(z, 3) == round(12.955894, 3)
    assert round(orientation, 3) == round(3.197581, 3)


def test_parse_flying_heartbeat_len_31_reads_orientation_from_offset_23() -> None:
    session = SimpleNamespace(orientation=0.0, is_flying=True, can_fly=True)
    payload = bytes.fromhex(
        "B80DF7410A567E463D557E46000000924141A000000602E1C0A64051A4BF0B"
    )

    parsed = movement.parse_movement_info(session, "MSG_MOVE_HEARTBEAT", payload, decoded={})

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16277.509766, 3)
    assert round(y, 3) == round(16277.30957, 3)
    assert round(z, 3) == round(30.881699, 3)
    assert round(orientation, 3) == round(5.211045, 3)


def test_parse_flying_heartbeat_len_30_preserves_previous_facing_when_no_valid_candidate_exists() -> None:
    session = SimpleNamespace(orientation=6.282735, is_flying=True, can_fly=True)
    payload = bytearray()
    payload.extend(struct.pack("<fff", 176.719711, 1445.731812, 3442.134521))
    while len(payload) < 30:
        payload.append(0)

    parsed = movement.parse_movement_info(session, "MSG_MOVE_HEARTBEAT", bytes(payload), decoded={})

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(1445.731812, 3)
    assert round(y, 3) == round(3442.134521, 3)
    assert round(z, 3) == round(176.719711, 3)
    assert round(orientation, 3) == round(6.282735, 3)


def test_parse_flying_heartbeat_len_30_rejects_small_false_near_zero_orientation() -> None:
    session = SimpleNamespace(orientation=5.959146, is_flying=True, can_fly=True)
    payload = bytearray()
    payload.extend(struct.pack("<fff", 171.161972, 1442.490479, 3433.467285))
    while len(payload) < 23:
        payload.append(0)
    payload.extend(struct.pack("<f", 0.011767))
    while len(payload) < 30:
        payload.append(0)

    parsed = movement.parse_movement_info(session, "MSG_MOVE_HEARTBEAT", bytes(payload), decoded={})

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert round(orientation, 3) == round(5.959146, 3)


def test_parse_stop_ascend_len_35_reads_orientation_from_offset_31() -> None:
    session = SimpleNamespace(orientation=0.0)
    payload = bytes.fromhex(
        "A20FE741EB057E4606027E4652800000004180000002063DD3BF0BB6B002BF2C320E40"
    )

    parsed = movement.parse_movement_info(session, "MSG_MOVE_STOP_ASCEND", payload, decoded={})

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16257.479492, 3)
    assert round(y, 3) == round(16256.505859, 3)
    assert round(z, 3) == round(28.882633, 3)
    assert round(orientation, 3) == round(2.221812, 3)


def test_start_ascend_sequence_begins_with_exact_yxz_coordinate_order() -> None:
    sequence = movement._SKYFIRE_FLYING_MOVEMENT_SEQUENCES["MSG_MOVE_START_ASCEND"]

    assert sequence[:3] == (
        "MSEPositionY",
        "MSEPositionX",
        "MSEPositionZ",
    )


def test_start_backward_sequence_begins_with_exact_yzx_coordinate_order() -> None:
    sequence = movement._SKYFIRE_FLYING_MOVEMENT_SEQUENCES["MSG_MOVE_START_BACKWARD"]

    assert sequence[:3] == (
        "MSEPositionY",
        "MSEPositionZ",
        "MSEPositionX",
    )


def test_parse_start_ascend_prefers_plausible_layout_for_current_position() -> None:
    session = SimpleNamespace(
        x=100.0,
        y=200.0,
        z=30.0,
        orientation=1.25,
        is_flying=True,
        can_fly=True,
    )
    payload = bytearray()
    payload.extend(struct.pack("<fff", 30.0, 100.0, 200.0))
    payload.extend(b"\x00" * 13)
    payload.extend(struct.pack("<f", 1.5))
    while len(payload) < 33:
        payload.append(0)

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_START_ASCEND",
        bytes(payload),
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert x == 100.0
    assert y == 200.0
    assert z == 30.0
    assert orientation == 1.5


def test_parse_start_ascend_len_30_preserves_previous_facing_when_only_zeroish_candidate_exists() -> None:
    session = SimpleNamespace(
        x=1447.887695,
        y=3429.055908,
        z=171.161896,
        orientation=3.542,
        is_flying=True,
        can_fly=True,
    )
    payload = bytearray()
    payload.extend(struct.pack("<fff", 3429.055908, 1447.887695, 171.161896))
    while len(payload) < 23:
        payload.append(0)
    payload.extend(struct.pack("<f", 1.0e-8))
    while len(payload) < 30:
        payload.append(0)

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_START_ASCEND",
        bytes(payload),
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(1447.887695, 3)
    assert round(y, 3) == round(3429.055908, 3)
    assert round(z, 3) == round(171.161896, 3)
    assert round(orientation, 3) == round(3.542, 3)


def test_parse_stop_ascend_len_30_preserves_previous_facing_when_payload_has_no_valid_orientation() -> None:
    session = SimpleNamespace(
        orientation=3.542,
        is_flying=True,
        can_fly=True,
    )
    payload = bytearray()
    payload.extend(struct.pack("<fff", 173.135895, 1447.887695, 3429.055908))
    while len(payload) < 30:
        payload.append(0)

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP_ASCEND",
        bytes(payload),
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(1447.887695, 3)
    assert round(y, 3) == round(3429.055908, 3)
    assert round(z, 3) == round(173.135895, 3)
    assert round(orientation, 3) == round(3.542, 3)


def test_real_stop_ascend_sequence_extracts_pitch_and_timestamp() -> None:
    session = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        is_flying=True,
        can_fly=True,
        movement_state=SimpleNamespace(pitch=0.0),
    )
    payload = bytes.fromhex(
        "A20FE741EB057E4606027E4652800000004180000002063DD3BF0BB6B002BF2C320E40"
    )

    parsed = movement._parse_skyfire_flying_movement_info(
        session,
        "MSG_MOVE_STOP_ASCEND",
        payload,
    )

    assert parsed is not None
    assert round(parsed["x"], 3) == round(16257.479492, 3)
    assert round(parsed["y"], 3) == round(16256.505859, 3)
    assert round(parsed["z"], 3) == round(28.882633, 3)
    assert round(parsed["orientation"], 6) == round(2.221812248, 6)
    assert round(parsed["pitch"], 6) == round(-0.510508895, 6)
    assert parsed["flags"] == (
        movement._MOVEMENTFLAG_CAN_FLY
        | movement._MOVEMENTFLAG_FLYING
    )
    assert parsed["timestamp"] == 197120829
    assert parsed["parser_path"] == "skyfire_sequence:MSG_MOVE_STOP_ASCEND"


def test_real_stop_turn_sequence_extracts_orientation_flags_and_timestamp() -> None:
    session = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=SimpleNamespace(pitch=0.0),
    )
    payload = bytes.fromhex("368A7D46ED85504159F77D4600000022A210000C91D8873FF1ACF605")

    parsed = movement._parse_skyfire_flying_movement_info(
        session,
        "MSG_MOVE_STOP_TURN",
        payload,
    )

    assert parsed is not None
    assert round(parsed["x"], 3) == round(16226.552734, 3)
    assert round(parsed["y"], 3) == round(16253.836914, 3)
    assert round(parsed["z"], 3) == round(13.032697, 3)
    assert round(parsed["orientation"], 6) == round(1.061296582, 6)
    assert parsed["flags"] == 0
    assert not parsed["flags"] & movement._MOVEMENTFLAG_TURN_LEFT
    assert not parsed["flags"] & movement._MOVEMENTFLAG_TURN_RIGHT
    assert parsed["flags2"] == 0x800
    assert parsed["timestamp"] == 100052209
    assert parsed["parser_path"] == "skyfire_sequence:MSG_MOVE_STOP_TURN"


def test_record_stop_turn_state_uses_sequence_flags_authoritatively() -> None:
    session = SimpleNamespace(
        movement_state=SimpleNamespace(
            x=0.0,
            y=0.0,
            z=0.0,
            orientation=0.0,
            flags=movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_TURN_RIGHT,
            flags2=99,
            timestamp_ms=0,
            counter=0,
            pitch=0.0,
        )
    )
    payload = bytes.fromhex("368A7D46ED85504159F77D4600000022A210000C91D8873FF1ACF605")

    parsed = movement._parse_skyfire_flying_movement_info(
        session,
        "MSG_MOVE_STOP_TURN",
        payload,
    )

    assert parsed is not None
    movement._record_movement_packet_state(session, "MSG_MOVE_STOP_TURN", payload)
    state = movement._movement_state(session)

    assert state.flags == parsed["flags"]
    assert state.flags2 == parsed["flags2"]
    assert state.timestamp_ms == parsed["timestamp"]
    assert state.flags == 0
    assert not state.flags & movement._MOVEMENTFLAG_TURN_RIGHT


def test_record_stop_state_uses_sequence_flags_authoritatively() -> None:
    session = SimpleNamespace(
        movement_state=SimpleNamespace(
            x=0.0,
            y=0.0,
            z=0.0,
            orientation=0.0,
            flags=(
                movement._MOVEMENTFLAG_FORWARD
                | movement._MOVEMENTFLAG_TURN_LEFT
                | movement._MOVEMENTFLAG_TURN_RIGHT
            ),
            flags2=77,
            timestamp_ms=0,
            counter=0,
            pitch=0.0,
        )
    )
    payload = bytes.fromhex("727A7D46E6FF7D46AFE24F41120000020890000C1C422940169DF605")

    parsed = movement._parse_skyfire_flying_movement_info(
        session,
        "MSG_MOVE_STOP",
        payload,
    )

    assert parsed is not None
    movement._record_movement_packet_state(session, "MSG_MOVE_STOP", payload)
    state = movement._movement_state(session)

    assert state.flags == parsed["flags"]
    assert state.flags2 == parsed["flags2"]
    assert state.timestamp_ms == parsed["timestamp"]
    assert not state.flags & movement._MOVEMENTFLAG_FORWARD
    assert not state.flags & movement._MOVEMENTFLAG_TURN_LEFT
    assert not state.flags & movement._MOVEMENTFLAG_TURN_RIGHT


def test_real_start_forward_sequence_extracts_orientation_flags_and_timestamp() -> None:
    session = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=SimpleNamespace(pitch=0.0),
    )
    payload = bytes.fromhex("EFD74F41CD867D4633F97D4628000000421000000000080C209BF6051C422940")

    parsed = movement._parse_skyfire_flying_movement_info(
        session,
        "MSG_MOVE_START_FORWARD",
        payload,
    )

    assert parsed is not None
    assert round(parsed["x"], 3) == round(16225.700195, 3)
    assert round(parsed["y"], 3) == round(16254.299805, 3)
    assert round(parsed["z"], 3) == round(12.990218, 3)
    assert round(parsed["orientation"], 6) == round(2.644660234, 6)
    assert parsed["flags"] & movement._MOVEMENTFLAG_FORWARD
    assert parsed["flags2"] == 0x800
    assert parsed["timestamp"] == 100047648
    assert parsed["parser_path"] == "skyfire_sequence:MSG_MOVE_START_FORWARD"


def test_parse_flying_stop_turn_preserves_previous_facing_when_payload_is_zeroish() -> None:
    session = SimpleNamespace(
        orientation=6.283,
        is_flying=True,
        can_fly=True,
    )
    payload = bytearray()
    payload.extend(struct.pack("<fff", 1441.156494, 176.719711, 3436.836670))
    while len(payload) < 24:
        payload.append(0)

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP_TURN",
        bytes(payload),
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(1441.156494, 3)
    assert round(y, 3) == round(3436.836670, 3)
    assert round(z, 3) == round(176.719711, 3)
    assert round(orientation, 3) == round(6.283, 3)


def test_store_authoritative_flying_heartbeat_uses_sequence_flags_pitch_timestamp_and_fall_data() -> None:
    session = SimpleNamespace(
        char_guid=7,
        world_guid=7,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.25,
        can_fly=True,
        is_flying=True,
        movement_state=SimpleNamespace(
            x=10.0,
            y=20.0,
            z=30.0,
            orientation=0.25,
            flags=0,
            flags2=0,
            timestamp_ms=0,
            server_movement_timestamp_ms=0,
            counter=0,
            pitch=0.0,
            has_fall_data=False,
            fall_time=0,
            fall_vertical_speed=0.0,
            fall_horizontal_speed=0.0,
            fall_sin_angle=0.0,
            fall_cos_angle=0.0,
            is_ascending=False,
            is_descending=False,
        ),
    )
    payload = bytes.fromhex(
        "A96B7741C1A27D4600FB7D46000000904540000800800C433FC7BE"
        "F6D16BBF00000000D893FEC0F4010000C3A4624015A52C05"
    )

    parsed = movement.parse_movement_info(session, "MSG_MOVE_HEARTBEAT", payload, decoded={})
    stored = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_HEARTBEAT",
        payload,
        parsed,
    )
    state = movement._movement_state(session)

    assert stored is True
    assert parsed is not None
    assert round(parsed[0], 3) == round(16232.6884765625, 3)
    assert round(parsed[1], 3) == round(16254.75, 3)
    assert round(parsed[2], 3) == round(15.4637842178, 3)
    assert round(parsed[3], 6) == round(3.5413062572, 6)
    assert state.flags == movement._MOVEMENTFLAG_FALLING
    assert state.flags2 == 0
    assert state.timestamp_ms == 86811925
    assert state.pitch == 0.0
    assert state.has_fall_data is True
    assert state.fall_time == 500
    assert round(state.fall_vertical_speed, 6) == round(-7.9555473328, 6)
    assert round(state.fall_horizontal_speed, 6) == 0.0
    assert round(state.fall_sin_angle, 6) == round(-0.3891545236, 6)
    assert round(state.fall_cos_angle, 6) == round(-0.9211724997, 6)
    assert state.is_ascending is False
    assert state.is_descending is False


def test_parse_flying_start_turn_right_rejects_small_false_near_zero_orientation() -> None:
    session = SimpleNamespace(
        orientation=5.257773,
        is_flying=True,
        can_fly=True,
    )
    payload = bytearray()
    payload.extend(struct.pack("<fff", 1447.513, 171.161972, 3438.344))
    while len(payload) < 24:
        payload.append(0)
    payload.extend(struct.pack("<f", 0.011767))

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_START_TURN_RIGHT",
        bytes(payload),
        decoded={},
    )

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert round(orientation, 3) == round(5.257773, 3)


def test_parse_flying_stop_preserves_previous_facing_when_payload_is_zeroish() -> None:
    session = SimpleNamespace(
        orientation=5.959146,
        is_flying=True,
        can_fly=True,
    )
    payload = bytearray()
    payload.extend(struct.pack("<fff", 1444.620, 3431.111, 173.248032))
    while len(payload) < 24:
        payload.append(0)

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP",
        bytes(payload),
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(1444.620, 3)
    assert round(y, 3) == round(3431.111, 3)
    assert round(z, 3) == round(173.248032, 3)
    assert round(orientation, 3) == round(5.959146, 3)


def test_stop_strafe_zero_orientation_preserves_previous_facing() -> None:
    session = SimpleNamespace(orientation=1.25)
    payload = bytearray()
    payload.extend(struct.pack("<fff", 12.0, 34.0, 56.0))
    payload.extend(b"\x00" * 8)
    payload.extend(struct.pack("<f", 0.0))

    parsed = movement.parse_movement_info(session, "MSG_MOVE_STOP_STRAFE", bytes(payload), decoded={})

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert orientation == 1.25


def test_fall_land_clears_fall_data_in_movement_state() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=123,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=2.0,
        fall_sin_angle=0.47,
        fall_cos_angle=-0.88,
    )
    session = SimpleNamespace(movement_state=state)

    movement._record_movement_packet_state(session, "MSG_MOVE_FALL_LAND", b"\x00" * 28)

    assert state.has_fall_data is False
    assert state.fall_time == 0
    assert state.fall_vertical_speed == 0.0
    assert state.fall_horizontal_speed == 0.0
    assert state.fall_sin_angle == 0.0
    assert state.fall_cos_angle == 0.0


def test_small_timestamp_backstep_fall_land_still_clears_fall_state() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=1000,
        counter=0,
        has_fall_data=True,
        fall_time=123,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=2.0,
        fall_sin_angle=0.47,
        fall_cos_angle=-0.88,
    )
    session = SimpleNamespace(movement_state=state)
    payload = (b"\x00" * 24) + (999).to_bytes(4, "little")

    ok = movement._store_authoritative_movement(session, "MSG_MOVE_FALL_LAND", payload, None)

    assert ok is True
    assert state.client_timestamp_ms == 999
    assert state.timestamp_ms == 1001
    assert state.has_fall_data is False
    assert state.fall_time == 0
    assert state.fall_vertical_speed == 0.0
    assert state.fall_horizontal_speed == 0.0
    assert state.fall_sin_angle == 0.0
    assert state.fall_cos_angle == 0.0
    assert not state.flags & movement._MOVEMENTFLAG_FALLING


def test_fall_land_preserves_held_locomotion_flags() -> None:
    state = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.5,
        flags=(
            movement._MOVEMENTFLAG_FORWARD
            | movement._MOVEMENTFLAG_STRAFE_LEFT
            | movement._MOVEMENTFLAG_TURN_RIGHT
            | movement._MOVEMENTFLAG_FALLING
        ),
        flags2=0,
        timestamp_ms=1000,
        client_timestamp_ms=1000,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=123,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=2.0,
        fall_sin_angle=0.47,
        fall_cos_angle=-0.88,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        x=state.x,
        y=state.y,
        z=state.z,
        orientation=state.orientation,
        movement_state=state,
        can_fly=False,
        is_flying=False,
    )
    payload = (b"\x00" * 24) + (1001).to_bytes(4, "little")

    ok = movement._store_authoritative_movement(session, "MSG_MOVE_FALL_LAND", payload, None)

    assert ok is True
    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert state.flags & movement._MOVEMENTFLAG_STRAFE_LEFT
    assert state.flags & movement._MOVEMENTFLAG_TURN_RIGHT
    assert not state.flags & movement._MOVEMENTFLAG_FALLING
    assert state.has_fall_data is False


def test_older_fall_land_cannot_overwrite_newer_position() -> None:
    state = SimpleNamespace(
        x=4.0,
        y=0.0,
        z=0.0,
        orientation=0.25,
        flags=movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=1500,
        client_timestamp_ms=1500,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=100,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=7.0,
        fall_sin_angle=0.0,
        fall_cos_angle=1.0,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        x=4.0,
        y=0.0,
        z=0.0,
        orientation=0.25,
        movement_state=state,
        can_fly=False,
        is_flying=False,
    )
    payload = (b"\x00" * 24) + (1200).to_bytes(4, "little")

    ok = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_FALL_LAND",
        payload,
        (1.0, 0.0, 0.0, 0.5),
    )

    assert ok is True
    assert state.x == 4.0
    assert state.y == 0.0
    assert state.z == 0.0
    assert state.orientation == 0.25
    assert session.x == 4.0
    assert session.y == 0.0
    assert session.z == 0.0
    assert session.orientation == 0.25
    assert not state.flags & movement._MOVEMENTFLAG_FALLING
    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert state.has_fall_data is False


def test_older_movement_packet_cannot_move_player_backwards() -> None:
    state = SimpleNamespace(
        x=8.0,
        y=0.0,
        z=0.0,
        orientation=1.0,
        flags=movement._MOVEMENTFLAG_FORWARD,
        flags2=0,
        timestamp_ms=2000,
        client_timestamp_ms=2000,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=0.0,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        x=8.0,
        y=0.0,
        z=0.0,
        orientation=1.0,
        movement_state=state,
        can_fly=False,
        is_flying=False,
    )
    payload = (b"\x00" * 28) + (1500).to_bytes(4, "little")

    ok = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_HEARTBEAT",
        payload,
        (2.0, 0.0, 0.0, 0.5),
    )

    assert ok is True
    assert state.x == 8.0
    assert state.y == 0.0
    assert state.z == 0.0
    assert state.orientation == 1.0
    assert session.x == 8.0
    assert session.y == 0.0
    assert session.z == 0.0
    assert session.orientation == 1.0


def test_jump_then_current_fall_land_updates_position_and_clears_fall_state() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_FORWARD,
        flags2=0,
        timestamp_ms=1000,
        client_timestamp_ms=1000,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=0.0,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=state,
        can_fly=False,
        is_flying=False,
    )

    jump_ok = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_JUMP",
        (b"\x00" * 48) + (1100).to_bytes(4, "little"),
        (1.0, 0.0, 1.0, 0.25),
    )
    land_ok = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_FALL_LAND",
        (b"\x00" * 24) + (1200).to_bytes(4, "little"),
        (4.0, 0.0, 0.0, 0.25),
    )

    assert jump_ok is True
    assert land_ok is True
    assert state.x == 4.0
    assert state.y == 0.0
    assert state.z == 0.0
    assert state.orientation == 0.25
    assert session.x == 4.0
    assert not state.flags & movement._MOVEMENTFLAG_FALLING
    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert state.has_fall_data is False


def test_fall_land_does_not_cancel_active_flying_mount() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=100.0,
        orientation=0.0,
        flags=(
            movement._MOVEMENTFLAG_CAN_FLY
            | movement._MOVEMENTFLAG_FLYING
            | movement._MOVEMENTFLAG_FALLING
        ),
        flags2=0,
        timestamp_ms=1000,
        client_timestamp_ms=1000,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=123,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=2.0,
        fall_sin_angle=0.47,
        fall_cos_angle=-0.88,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        movement_state=state,
        can_fly=True,
        is_flying=True,
        mount_spell=72286,
    )
    payload = (b"\x00" * 24) + (1001).to_bytes(4, "little")

    ok = movement._store_authoritative_movement(session, "MSG_MOVE_FALL_LAND", payload, None)

    assert ok is True
    assert session.is_flying is True
    assert state.flags & movement._MOVEMENTFLAG_CAN_FLY
    assert state.flags & movement._MOVEMENTFLAG_FLYING
    assert not state.flags & movement._MOVEMENTFLAG_FALLING
    assert state.has_fall_data is False


def test_start_swim_enters_swimming_and_clears_fall_and_flying() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=10.0,
        orientation=0.0,
        flags=(
            movement._MOVEMENTFLAG_FALLING
            | movement._MOVEMENTFLAG_FLYING
            | movement._MOVEMENTFLAG_ASCENDING
        ),
        flags2=0,
        timestamp_ms=1000,
        client_timestamp_ms=1000,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=123,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=2.0,
        fall_sin_angle=0.47,
        fall_cos_angle=-0.88,
        is_ascending=True,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        movement_state=state,
        can_fly=True,
        is_flying=True,
        mount_spell=0,
    )

    ok = movement._store_authoritative_movement(session, "MSG_MOVE_START_SWIM", b"", None)

    assert ok is True
    assert session.is_flying is False
    assert state.flags & movement._MOVEMENTFLAG_SWIMMING
    assert not state.flags & movement._MOVEMENTFLAG_FALLING
    assert not state.flags & movement._MOVEMENTFLAG_FLYING
    assert not state.flags & movement._MOVEMENTFLAG_ASCENDING
    assert not state.flags & movement._MOVEMENTFLAG_DESCENDING
    assert state.has_fall_data is False
    assert state.is_ascending is False
    assert state.is_descending is False


def test_start_swim_wins_over_active_flying_mount() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=10.0,
        orientation=0.0,
        flags=(
            movement._MOVEMENTFLAG_CAN_FLY
            | movement._MOVEMENTFLAG_FLYING
            | movement._MOVEMENTFLAG_FALLING
        ),
        flags2=0,
        timestamp_ms=1000,
        client_timestamp_ms=1000,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=123,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=2.0,
        fall_sin_angle=0.47,
        fall_cos_angle=-0.88,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        movement_state=state,
        can_fly=True,
        is_flying=True,
        mount_spell=72286,
    )

    ok = movement._store_authoritative_movement(session, "MSG_MOVE_START_SWIM", b"", None)

    assert ok is True
    assert movement._movement_is_flying(session) is False
    assert movement._has_active_flying_mount(session) is False
    assert session.is_flying is False
    assert state.flags & movement._MOVEMENTFLAG_CAN_FLY
    assert state.flags & movement._MOVEMENTFLAG_SWIMMING
    assert not state.flags & movement._MOVEMENTFLAG_FLYING
    assert not state.flags & movement._MOVEMENTFLAG_FALLING


def test_stop_swim_clears_swimming_flag() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_SWIMMING,
        flags2=0,
        timestamp_ms=1000,
        client_timestamp_ms=1000,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=False,
        fall_time=0,
        fall_vertical_speed=0.0,
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=0.0,
        is_ascending=False,
        is_descending=False,
    )
    session = SimpleNamespace(
        char_guid=7,
        movement_state=state,
        can_fly=False,
        is_flying=False,
        mount_spell=0,
    )

    ok = movement._store_authoritative_movement(session, "MSG_MOVE_STOP_SWIM", b"", None)

    assert ok is True
    assert not state.flags & movement._MOVEMENTFLAG_SWIMMING


def test_swim_opcodes_use_normal_movement_handler() -> None:
    from server.modules.handlers.world.dispatcher import HANDLERS

    assert HANDLERS["MSG_MOVE_START_SWIM"] is movement.handle_movement_packet
    assert HANDLERS["MSG_MOVE_STOP_SWIM"] is movement.handle_movement_packet


def test_small_timestamp_backstep_stop_strafe_still_clears_strafe_flags() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_STRAFE_LEFT,
        flags2=0,
        timestamp_ms=1000,
        counter=0,
    )
    session = SimpleNamespace(movement_state=state)
    payload = (b"\x00" * 20) + (999).to_bytes(4, "little")

    ok = movement._store_authoritative_movement(session, "MSG_MOVE_STOP_STRAFE", payload, None)

    assert ok is True
    assert state.client_timestamp_ms == 999
    assert state.timestamp_ms == 1001
    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert not state.flags & movement._MOVEMENTFLAG_STRAFE_LEFT
    assert not state.flags & movement._MOVEMENTFLAG_STRAFE_RIGHT


def test_severely_stale_stop_strafe_is_rejected_after_cleanup() -> None:
    state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_STRAFE_LEFT,
        flags2=0,
        timestamp_ms=20000,
        client_timestamp_ms=20000,
        counter=0,
    )
    session = SimpleNamespace(movement_state=state)
    payload = (b"\x00" * 20) + (999).to_bytes(4, "little")

    ok = movement._store_authoritative_movement(session, "MSG_MOVE_STOP_STRAFE", payload, None)

    assert ok is False
    assert state.flags & movement._MOVEMENTFLAG_FORWARD
    assert not state.flags & movement._MOVEMENTFLAG_STRAFE_LEFT
    assert not state.flags & movement._MOVEMENTFLAG_STRAFE_RIGHT


def test_handle_movement_packet_updates_session_position_and_orientation(monkeypatch) -> None:
    session = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_START_FORWARD",
        opcode=0,
        payload=b"\x01\x02\x03\x04",
        decoded={},
    )
    movement_state = SimpleNamespace(x=0.0, y=0.0, z=0.0, orientation=0.0, flags=0, flags2=0, timestamp_ms=0, counter=0)

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (1.0, 2.0, 3.0, 0.5))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_normalize_orientation", lambda value: float(value))

    movement.handle_movement_packet(session, ctx)

    assert session.x == 1.0
    assert session.y == 2.0
    assert session.z == 3.0
    assert session.orientation == 0.5


def test_handle_msg_move_jump_force_broadcasts_start(monkeypatch) -> None:
    session = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_JUMP",
        opcode=0,
        payload=b"\x01\x02\x03\x04",
        decoded={},
    )
    movement_state = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        fall_time=0,
    )
    calls = []

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (1.0, 2.0, 3.0, 0.5))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(movement, "_sync_session_from_movement_state", lambda _session: None)
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "_normalize_orientation", lambda value: float(value))
    monkeypatch.setattr(
        movement,
        "broadcast_player_state_update",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    movement.handle_movement_packet(session, ctx)

    assert calls
    assert calls[-1][1] == {"force": True}


def test_handle_start_turn_updates_position_and_orientation(monkeypatch) -> None:
    session = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_START_TURN_RIGHT",
        opcode=0,
        payload=b"\x01\x02\x03\x04",
        decoded={},
    )
    movement_state = SimpleNamespace(x=0.0, y=0.0, z=0.0, orientation=0.0, flags=0, flags2=0, timestamp_ms=0, counter=0)

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (1.0, 2.0, 3.0, 0.5))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_normalize_orientation", lambda value: float(value))

    movement.handle_movement_packet(session, ctx)

    assert movement_state.x == 1.0
    assert movement_state.y == 2.0
    assert movement_state.z == 3.0
    assert movement_state.orientation == 0.5
    assert session.x == 1.0
    assert session.y == 2.0
    assert session.z == 3.0
    assert session.orientation == 0.5


def test_handle_movement_packet_keeps_previous_orientation_when_missing(monkeypatch) -> None:
    session = SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=1.75,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_START_FORWARD",
        opcode=0,
        payload=b"\x01\x02\x03\x04",
        decoded={},
    )
    movement_state = SimpleNamespace(x=0.0, y=0.0, z=0.0, orientation=1.75, flags=0, flags2=0, timestamp_ms=0, counter=0)

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (1.0, 2.0, 3.0, None))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_normalize_orientation", lambda value: None if value is None else float(value))

    movement.handle_movement_packet(session, ctx)

    assert session.x == 1.0
    assert session.y == 2.0
    assert session.z == 3.0
    assert session.orientation == 1.75


def test_handle_flying_heartbeat_accepts_new_orientation_even_when_not_turning(monkeypatch) -> None:
    session = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
        can_fly=True,
        is_flying=True,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_HEARTBEAT",
        opcode=0,
        payload=b"\x00" * 31,
        decoded={},
    )
    movement_state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=False,
    )

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (10.0, 20.0, 30.0, 5.211044788360596))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)

    movement.handle_movement_packet(session, ctx)

    assert round(session.orientation, 3) == round(5.211045, 3)


def test_handle_flying_heartbeat_keeps_parsed_orientation_without_fallback(monkeypatch) -> None:
    session = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
        can_fly=True,
        is_flying=True,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_HEARTBEAT",
        opcode=0,
        payload=b"\x00" * 30,
        decoded={},
    )
    movement_state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=False,
    )

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (10.0, 25.0, 30.0, 1.25))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)

    movement.handle_movement_packet(session, ctx)

    assert round(session.orientation, 3) == round(1.25, 3)


def test_handle_flying_heartbeat_accepts_orientation_when_can_fly_without_turn_flags(monkeypatch) -> None:
    session = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
        can_fly=True,
        is_flying=False,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_HEARTBEAT",
        opcode=0,
        payload=b"\x00" * 31,
        decoded={},
    )
    movement_state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=False,
    )
    debug_messages: list[str] = []

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (10.0, 20.0, 30.0, 5.211044788360596))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        movement.Logger,
        "debug",
        lambda message, *args: debug_messages.append(message % args if args else message),
    )

    movement.handle_movement_packet(session, ctx)

    assert round(session.orientation, 3) == round(5.211045, 3)
    assert any(
        "[ORIENTATION_ACCEPT]" in message and "is_flying=True" in message and "accepted=True" in message
        for message in debug_messages
    )


def test_handle_msg_move_set_facing_updates_session_orientation(monkeypatch) -> None:
    movement_state = SimpleNamespace(orientation=0.0)
    session = SimpleNamespace(orientation=0.0)
    payload = struct.pack("<f", 1.25)
    ctx = SimpleNamespace(payload=payload)

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: setattr(target, "orientation", movement_state.orientation),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "_normalize_orientation", lambda value: float(value))
    monkeypatch.setattr(movement, "_player_guid", lambda _session: 7)

    movement.handle_msg_move_set_facing(session, ctx)

    assert session.orientation == 1.25


def test_handle_start_ascend_sets_flight_speed_once_on_flying_entry(monkeypatch) -> None:
    session = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
        run_speed=7.0,
        fly_speed=7.0,
        can_fly=True,
        is_flying=False,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_START_ASCEND",
        opcode=0,
        payload=b"\x00" * 35,
        decoded={},
    )
    movement_state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=False,
    )

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (10.0, 20.0, 31.0, 1.25))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)

    def _store(_session, _opcode_name, _payload, _movement_data):
        _session.is_flying = True
        return True

    monkeypatch.setattr(movement, "_store_authoritative_movement", _store)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "build_move_set_flight_speed_payload", lambda _session: b"flight-speed")

    status, responses = movement.handle_movement_packet(session, ctx)

    assert status == 0
    assert round(session.fly_speed, 3) == round(22.4, 3)
    assert responses == [("SMSG_MOVE_SET_FLIGHT_SPEED", b"flight-speed")]


def test_handle_fall_land_clears_flying_state_and_restores_run_speed(monkeypatch) -> None:
    broadcast_calls: list[bool] = []
    session = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=35.0,
        orientation=1.25,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
        run_speed=7.0,
        fly_speed=22.4,
        can_fly=True,
        is_flying=True,
    )
    movement_state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=35.0,
        orientation=1.25,
        flags=(
            movement._MOVEMENTFLAG_FLYING
            | movement._MOVEMENTFLAG_ASCENDING
            | movement._MOVEMENTFLAG_DESCENDING
        ),
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=False,
        is_ascending=True,
        is_descending=True,
        pitch=0.75,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_FALL_LAND",
        opcode=0,
        payload=b"\x00" * 40,
        decoded={},
    )

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (10.0, 20.0, 30.0, 1.25))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(
        movement,
        "broadcast_player_state_update",
        lambda _session, force=False: broadcast_calls.append(bool(force)),
    )
    monkeypatch.setattr(movement, "build_move_set_run_speed_payload", lambda _session: b"run-speed")

    status, responses = movement.handle_movement_packet(session, ctx)

    assert status == 0
    assert responses == [("SMSG_MOVE_SET_RUN_SPEED", b"run-speed")]
    assert session.is_flying is False
    assert movement_state.is_ascending is False
    assert movement_state.is_descending is False
    assert movement_state.pitch == 0.0
    assert not movement_state.flags & movement._MOVEMENTFLAG_FLYING
    assert not movement_state.flags & movement._MOVEMENTFLAG_ASCENDING
    assert not movement_state.flags & movement._MOVEMENTFLAG_DESCENDING
    assert broadcast_calls == [True]


def test_handle_ground_fall_land_does_not_restore_unchanged_run_speed(monkeypatch) -> None:
    run_speed_responses: list[bool] = []
    session = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=31.0,
        orientation=1.25,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
        run_speed=7.0,
        fly_speed=7.0,
        can_fly=False,
        is_flying=False,
    )
    movement_state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=31.0,
        orientation=1.25,
        flags=movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_FALLING,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=100,
        fall_vertical_speed=-7.9,
        fall_horizontal_speed=7.0,
        fall_sin_angle=0.0,
        fall_cos_angle=1.0,
        is_ascending=False,
        is_descending=False,
        pitch=0.0,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_FALL_LAND",
        opcode=0,
        payload=b"\x00" * 40,
        decoded={},
    )

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (11.0, 20.0, 30.0, 1.25))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        movement,
        "build_move_set_run_speed_payload",
        lambda _session: run_speed_responses.append(True) or b"run-speed",
    )

    status, responses = movement.handle_movement_packet(session, ctx)

    assert status == 0
    assert responses is None
    assert run_speed_responses == []
    assert session.is_flying is False
    assert not movement_state.flags & movement._MOVEMENTFLAG_FALLING
    assert movement_state.flags & movement._MOVEMENTFLAG_FORWARD


def test_handle_fall_land_on_active_flying_mount_does_not_restore_run_speed(monkeypatch) -> None:
    run_speed_responses: list[bool] = []
    session = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=35.0,
        orientation=1.25,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
        run_speed=14.0,
        fly_speed=44.8,
        can_fly=True,
        is_flying=True,
        mount_spell=72286,
    )
    movement_state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=35.0,
        orientation=1.25,
        flags=(
            movement._MOVEMENTFLAG_CAN_FLY
            | movement._MOVEMENTFLAG_FLYING
            | movement._MOVEMENTFLAG_FALLING
        ),
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        counter=0,
        has_fall_data=True,
        fall_time=10,
        fall_vertical_speed=-1.0,
        fall_horizontal_speed=0.0,
        fall_sin_angle=0.0,
        fall_cos_angle=1.0,
        is_ascending=False,
        is_descending=False,
        pitch=0.0,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_FALL_LAND",
        opcode=0,
        payload=b"\x00" * 40,
        decoded={},
    )

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (10.0, 20.0, 30.0, 1.25))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        movement,
        "build_move_set_run_speed_payload",
        lambda _session: run_speed_responses.append(True) or b"run-speed",
    )

    status, responses = movement.handle_movement_packet(session, ctx)

    assert status == 0
    assert responses is None
    assert run_speed_responses == []
    assert session.is_flying is True
    assert movement_state.flags & movement._MOVEMENTFLAG_CAN_FLY
    assert movement_state.flags & movement._MOVEMENTFLAG_FLYING
    assert not movement_state.flags & movement._MOVEMENTFLAG_FALLING


def test_handle_flying_heartbeat_uses_flying_flags_to_keep_pitch_and_z(monkeypatch) -> None:
    debug_messages: list[str] = []
    session = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        pitch=0.0,
        char_guid=7,
        world_guid=7,
        map_id=1,
        realm_id=1,
        can_fly=False,
        is_flying=False,
    )
    ctx = SimpleNamespace(
        name="MSG_MOVE_HEARTBEAT",
        opcode=0,
        payload=b"\x00" * 31,
        decoded={},
    )
    movement_state = SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        pitch=0.0,
        flags=movement._MOVEMENTFLAG_FLYING,
        flags2=0,
        timestamp_ms=0,
        counter=0,
        has_fall_data=False,
    )

    monkeypatch.setattr(movement, "_consume_pending_teleport_on_movement", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args, **kwargs: (10.0, 20.0, 36.5, 2.5))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args, **kwargs: True)

    def _store(_session, _opcode_name, _payload, _movement_data):
        movement_state.pitch = 0.75
        movement_state.flags = movement._MOVEMENTFLAG_FLYING
        return True

    monkeypatch.setattr(movement, "_store_authoritative_movement", _store)
    monkeypatch.setattr(movement, "_movement_state", lambda _session: movement_state)
    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: (
            setattr(target, "x", movement_state.x),
            setattr(target, "y", movement_state.y),
            setattr(target, "z", movement_state.z),
            setattr(target, "orientation", movement_state.orientation),
        ),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda _session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda _session: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda _session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        movement.Logger,
        "debug",
        lambda message, *args: debug_messages.append(message % args if args else message),
    )

    movement.handle_movement_packet(session, ctx)

    assert session.z == 36.5
    assert session.orientation == 2.5
    assert session.pitch == 0.75
    assert any("[FLY_PITCH]" in message and "pitch=0.750000" in message for message in debug_messages)


def test_post_teleport_resync_dismounts_active_mount(monkeypatch) -> None:
    calls = []
    spells_module = types.ModuleType("server.modules.handlers.world.opcodes.spells")

    def fake_dismount(session):
        session.is_mounted = False
        session.mount_spell = None
        session.mount_display_id = 0
        session.can_fly = False
        session.is_flying = False
        return [("SMSG_DISMOUNT", b"dismount")]

    spells_module.dismount = fake_dismount
    monkeypatch.setitem(
        sys.modules,
        "server.modules.handlers.world.opcodes.spells",
        spells_module,
    )
    opcodes_module = sys.modules["server.modules.handlers.world.opcodes"]
    monkeypatch.setattr(opcodes_module, "spells", spells_module, raising=False)
    monkeypatch.setattr(
        movement,
        "broadcast_player_state_update",
        lambda *args, **kwargs: calls.append(("broadcast", args, kwargs)),
    )
    monkeypatch.setattr(
        movement,
        "force_bilateral_visibility_resync",
        lambda *args, **kwargs: calls.append(("resync", args, kwargs)),
    )
    monkeypatch.setattr(
        movement,
        "build_smsg_player_move_payload",
        lambda session: b"move",
    )
    session = SimpleNamespace(
        char_guid=7,
        world_guid=7,
        is_mounted=True,
        mount_spell=72286,
        mount_display_id=31007,
        can_fly=True,
        is_flying=True,
    )

    responses = movement._post_teleport_multiplayer_resync(
        session,
        reason="test-teleport",
    )

    assert responses == [
        ("SMSG_DISMOUNT", b"dismount"),
        ("SMSG_PLAYER_MOVE", b"move"),
    ]
    assert session.is_mounted is False
    assert session.mount_spell is None
    assert session.mount_display_id == 0
    assert session.can_fly is False
    assert session.is_flying is False
    assert calls[0][0] == "broadcast"
    assert calls[1][0] == "resync"
