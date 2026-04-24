from __future__ import annotations

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
