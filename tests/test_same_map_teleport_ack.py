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
        "build_same_map_teleport_self_resync_responses",
        lambda target: [
            ("SMSG_UPDATE_OBJECT", b"0002"),
            ("SMSG_UPDATE_OBJECT", b"0006"),
        ],
    )
    monkeypatch.setattr(
        movement,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )

    status, responses = movement.handle_move_teleport_ack(session, None)

    assert status == 0
    assert session.near_teleport_pending is False
    assert responses == [
        ("SMSG_MESSAGECHAT", b"[Teleport] same-map ack -> Orgrimmar"),
        ("SMSG_UPDATE_OBJECT", b"0002"),
        ("SMSG_UPDATE_OBJECT", b"0006"),
    ]
    assert calls == [
        ("capture", session),
        ("dirty", session),
        ("save", {"reason": "near-teleport", "online": 1, "force": True}),
        ("broadcast", True),
    ]
