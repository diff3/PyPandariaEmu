import sys
import types
import struct


database_module = types.ModuleType("server.modules.database.DatabaseConnection")


class _DatabaseConnection:
    pass


database_module.DatabaseConnection = _DatabaseConnection
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

from server.modules.handlers.world.opcodes import movement


class _FakeSession:
    def __init__(self):
        self.near_teleport_pending = True
        self.teleport_destination = "Orgrimmar"
        self.x = 100.0
        self.y = 200.0
        self.z = 300.0
        self.orientation = 1.25
        self.map_id = 1
        self.char_guid = 7


def test_same_map_teleport_payload_matches_pandaria548_capture_layout():
    session = _FakeSession()
    session.world_guid = 0x03
    session.char_guid = 0x03
    session.x = 16226.2001953125
    session.y = 16257.0
    session.z = 13.202199935913086
    session.orientation = 1.6500699520111084
    session.movement_state = types.SimpleNamespace(counter=14)

    payload = movement.build_same_map_teleport_payload(session)

    assert payload.hex().upper() == "900006363C534100047E46CD887D460E000000027E35D33F"
    assert struct.unpack("<I", payload[15:19])[0] == 14
    assert session.movement_state.counter == 15


def test_movement_packets_advance_same_map_teleport_counter():
    session = _FakeSession()
    session.movement_state = types.SimpleNamespace(
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        counter=11,
    )

    movement._record_movement_packet_state(session, "MSG_MOVE_HEARTBEAT", b"\x00" * 32)
    movement._record_movement_packet_state(session, "MSG_MOVE_FALL_LAND", b"\x00" * 28)

    payload = movement.build_same_map_teleport_payload(session)

    assert struct.unpack("<I", payload[15:19])[0] == 13
    assert session.movement_state.counter == 14


def test_same_map_teleport_ack_builds_self_resync(monkeypatch):
    session = _FakeSession()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        movement,
        "_capture_persist_position_from_session",
        lambda target: calls.append(("capture", target)),
    )
    monkeypatch.setattr(
        movement,
        "_mark_position_dirty",
        lambda target: calls.append(("dirty", target)),
    )
    monkeypatch.setattr(
        movement,
        "_save_session_position",
        lambda target, **kwargs: calls.append(("save", kwargs)),
    )
    monkeypatch.setattr(
        movement,
        "broadcast_player_state_update",
        lambda target, *, force=False: calls.append(("broadcast", force)),
    )
    monkeypatch.setattr(
        movement,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )
    monkeypatch.setitem(
        sys.modules,
        "server.modules.handlers.world.opcodes.chat",
        types.SimpleNamespace(
            _build_fixplayer_responses=lambda target: [("SMSG_UPDATE_OBJECT", b"fixplayer")]
        ),
    )

    status, responses = movement.handle_move_teleport_ack(session, None)

    assert status == 0
    assert session.near_teleport_pending is False
    assert responses == [
        ("SMSG_MESSAGECHAT", b"[Teleport] same-map ack -> Orgrimmar"),
        ("SMSG_UPDATE_OBJECT", b"fixplayer"),
    ]
    assert calls == [
        ("capture", session),
        ("dirty", session),
        ("save", {"reason": "near-teleport", "online": 1, "force": True}),
        ("broadcast", True),
    ]


def test_same_map_teleport_ack_with_fixspeed_refreshes_speed_and_player_move(monkeypatch):
    session = _FakeSession()
    session.fixspeed_pending = True
    session.teleport_destination = "FixSpeed"
    session.walk_speed = 2.5
    session.run_speed = 35.0
    session.swim_speed = 23.5
    session.fly_speed = 35.0

    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda target, **kwargs: None)
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda target, *, force=False: None)
    monkeypatch.setattr(
        movement,
        "build_same_map_teleport_self_resync_responses",
        lambda target: [("SMSG_UPDATE_OBJECT", b"0006")],
    )
    monkeypatch.setattr(
        movement,
        "build_move_set_speed_payload",
        lambda target, opcode_name, speed: f"{opcode_name}|{float(speed):.2f}".encode(),
    )
    monkeypatch.setattr(
        movement,
        "_build_run_speed_refresh_response",
        lambda target: ("SMSG_PLAYER_MOVE", b"player-move"),
    )
    monkeypatch.setattr(
        movement,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )

    status, responses = movement.handle_move_teleport_ack(session, None)

    assert status == 0
    assert session.near_teleport_pending is False
    assert session.fixspeed_pending is False
    assert responses == [
        ("SMSG_MESSAGECHAT", b"[Teleport] same-map ack -> FixSpeed"),
        ("SMSG_MESSAGECHAT", b"[FixSpeed] same-map ack -> speed refresh"),
        ("SMSG_UPDATE_OBJECT", b"0006"),
        ("SMSG_MOVE_SET_WALK_SPEED", b"SMSG_MOVE_SET_WALK_SPEED|2.50"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"SMSG_MOVE_SET_RUN_SPEED|35.00"),
        ("SMSG_MOVE_SET_SWIM_SPEED", b"SMSG_MOVE_SET_SWIM_SPEED|23.50"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"SMSG_MOVE_SET_FLIGHT_SPEED|35.00"),
        ("SMSG_PLAYER_MOVE", b"player-move"),
    ]


def test_move_set_run_speed_payload_matches_pandaria548_live_layout():
    session = _FakeSession()
    session.world_guid = 0x0000000700000003
    session.player_guid = session.world_guid
    session.run_speed = 70.0
    session.movement_state = types.SimpleNamespace(counter=27)

    payload = movement.build_move_set_run_speed_payload(session)

    assert payload == bytes.fromhex("411B000000060200008C42")
    assert session.movement_state.counter == 29


def test_move_set_speed_payloads_match_pandaria548_focus_captures():
    session = _FakeSession()
    session.world_guid = 0x0000000700000003
    session.player_guid = session.world_guid
    session.movement_state = types.SimpleNamespace(counter=70)

    walk = movement.build_move_set_speed_payload(session, "SMSG_MOVE_SET_WALK_SPEED", 25.0)
    run = movement.build_move_set_speed_payload(session, "SMSG_MOVE_SET_RUN_SPEED", 70.0)
    swim = movement.build_move_set_speed_payload(session, "SMSG_MOVE_SET_SWIM_SPEED", 47.22221755981445)
    flight = movement.build_move_set_speed_payload(session, "SMSG_MOVE_SET_FLIGHT_SPEED", 70.0)

    assert walk.hex().upper() == "44460000000000C8410206"
    assert run.hex().upper() == "4148000000060200008C42"
    assert swim.hex().upper() == "484A0000008DE33C420602"
    assert flight.hex().upper() == "00008C424C000000240206"
    assert session.movement_state.counter == 78


def test_run_speed_change_ack_returns_player_move_refresh(monkeypatch):
    session = _FakeSession()
    session.world_guid = 0x0000000700000003
    session.player_guid = session.world_guid
    session.run_speed = 35.0
    session.movement_state = types.SimpleNamespace(
        x=11.0,
        y=22.0,
        z=33.0,
        orientation=1.5,
        flags=0,
        flags2=0,
        timestamp_ms=123,
        client_timestamp_ms=0,
        counter=9,
    )
    calls: list[object] = []

    monkeypatch.setattr(
        movement,
        "_sync_session_from_movement_state",
        lambda target: calls.append(("sync", target)),
    )
    monkeypatch.setattr(
        movement,
        "build_smsg_player_move_payload",
        lambda target: b"player-move",
    )

    status, responses = movement.handle_move_force_run_speed_change_ack(session, None)

    assert status == 0
    assert responses == [("SMSG_PLAYER_MOVE", b"player-move")]
    assert calls == [("sync", session)]
