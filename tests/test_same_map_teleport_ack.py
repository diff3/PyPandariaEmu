import sys
import types
import struct
from types import SimpleNamespace

import pytest


database_module = types.ModuleType("server.modules.database.DatabaseConnection")


class _DatabaseConnection:
    @staticmethod
    def get_gameobjects_near(*args, **kwargs):
        return []

    @staticmethod
    def get_areatrigger_teleport(*args, **kwargs):
        return None


database_module.DatabaseConnection = _DatabaseConnection
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

replay_module = types.ModuleType("server.modules.handlers.world.bootstrap.replay")
replay_module.build_single_u32_update_object_payload = lambda **kwargs: b""
replay_module.build_multi_u32_update_object_payload = lambda **kwargs: b""
replay_module.build_database_gameobject_responses = lambda session, loaded_guids=None, **kwargs: []
replay_module.build_database_creature_responses = lambda session, loaded_guids=None, **kwargs: []
sys.modules["server.modules.handlers.world.bootstrap.replay"] = replay_module
creatures_module = types.ModuleType("server.modules.handlers.world.bootstrap.creatures")
creatures_module.build_database_creature_responses = lambda session, loaded_guids=None, **kwargs: []
sys.modules["server.modules.handlers.world.bootstrap.creatures"] = creatures_module

sys.modules.pop("server.modules.handlers.world.opcodes.movement", None)
from server.modules.handlers.world.opcodes import movement
sys.modules.pop("server.modules.handlers.world.opcodes.movement", None)


class _FakeSession:
    def __init__(self):
        self.near_teleport_pending = True
        self.worldport_ack_pending = False
        self.teleport_destination = "Orgrimmar"
        self.x = 100.0
        self.y = 200.0
        self.z = 300.0
        self.orientation = 1.25
        self.map_id = 1
        self.char_guid = 7


@pytest.fixture(autouse=True)
def _stub_teleport_visibility_stream(monkeypatch, request):
    if request.node.name == "test_post_teleport_visibility_stream_bypasses_movement_throttle":
        return
    monkeypatch.setattr(
        movement,
        "stream_world_objects_after_teleport",
        lambda _session, *, context: [],
    )


def test_first_movement_packet_keeps_teleport_pending_until_ack(monkeypatch):
    session = _FakeSession()
    session.teleport_pending = True
    session.near_teleport_pending = False
    session.worldport_ack_pending = True
    session.movement_state = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.5,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        counter=0,
    )
    calls = []

    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args: (10.0, 20.0, 30.0, 1.5))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args: True)
    monkeypatch.setattr(
        movement,
        "_store_authoritative_movement",
        lambda target, opcode_name, payload, movement_data: calls.append(("store", opcode_name, movement_data)) or True,
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: calls.append(("capture", target)))
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: calls.append(("dirty", target)))
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda target, force=False: calls.append(("broadcast", force)))

    status, responses = movement.handle_movement_packet(
        session,
        SimpleNamespace(name="MSG_MOVE_HEARTBEAT", opcode=0, payload=b"", decoded={}),
    )

    assert status == 0
    assert responses is None
    assert session.teleport_pending is True
    assert session.worldport_ack_pending is True
    assert session.near_teleport_pending is False
    assert session.x == 10.0
    assert session.y == 20.0
    assert session.z == 30.0
    assert session.orientation == 1.25
    assert calls[0] == ("store", "MSG_MOVE_HEARTBEAT", (10.0, 20.0, 30.0, 1.5))


def test_first_valid_movement_packet_clears_stale_near_teleport_pending(monkeypatch):
    session = _FakeSession()
    session.teleport_pending = False
    session.near_teleport_pending = True
    session.worldport_ack_pending = False
    session.movement_state = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.5,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        counter=0,
    )

    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args: (10.0, 20.0, 30.0, 1.5))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args: True)
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: None)
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda target, force=False: None)

    status, responses = movement.handle_movement_packet(
        session,
        SimpleNamespace(name="MSG_MOVE_START_FORWARD", opcode=0, payload=b"", decoded={}),
    )

    assert status == 0
    assert responses is None
    assert session.teleport_pending is False
    assert session.worldport_ack_pending is False
    assert session.near_teleport_pending is False


def test_movement_clears_stale_near_teleport_before_transport_transfer(monkeypatch):
    session = _FakeSession()
    session.teleport_pending = False
    session.near_teleport_pending = True
    session.worldport_ack_pending = False
    session.movement_state = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.5,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        counter=0,
    )
    transfer_checks = []

    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args: (10.0, 20.0, 30.0, 1.5))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args: True)
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: None)
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda target, force=False: None)
    monkeypatch.setattr(movement, "_maybe_stream_world_objects", lambda target: [])
    monkeypatch.setattr(movement, "_maybe_move_companion_pet_for_opcode", lambda *args: [])
    monkeypatch.setattr(
        movement,
        "_maybe_start_transport_route_transfer",
        lambda target, opcode_name: transfer_checks.append(movement._is_teleporting(target)) or [],
    )

    status, responses = movement.handle_movement_packet(
        session,
        SimpleNamespace(name="MSG_MOVE_HEARTBEAT", opcode=0, payload=b"", decoded={}),
    )

    assert status == 0
    assert responses is None
    assert session.near_teleport_pending is False
    assert transfer_checks == [False]


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
        "force_bilateral_visibility_resync",
        lambda target, *, reason: calls.append(("visibility", reason)),
    )
    monkeypatch.setattr(
        movement,
        "build_same_map_teleport_self_resync_responses",
        lambda target: [("SMSG_UPDATE_OBJECT", b"0006")],
    )
    monkeypatch.setattr(
        movement,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )

    status, responses = movement.handle_move_teleport_ack(session, None)

    assert status == 0
    assert session.near_teleport_pending is False
    assert session.worldport_ack_pending is False
    assert session.teleport_destination is None
    assert responses == [
        ("SMSG_MESSAGECHAT", b"[Teleport] same-map ack -> Orgrimmar"),
        ("SMSG_UPDATE_OBJECT", b"0006"),
    ]
    assert calls == [
        ("capture", session),
        ("dirty", session),
        ("save", {"reason": "near-teleport", "online": 1, "force": True}),
        ("broadcast", True),
        ("visibility", "near-teleport-ack"),
    ]


def test_same_map_teleport_ack_streams_world_objects_immediately(monkeypatch):
    session = _FakeSession()
    calls: list[str] = []

    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda target, **kwargs: None)
    monkeypatch.setattr(movement, "_post_teleport_multiplayer_resync", lambda target, **kwargs: [])
    monkeypatch.setattr(movement, "build_same_map_teleport_self_resync_responses", lambda target: [])
    monkeypatch.setattr(movement, "encode_skyfire_messagechat_system_payload", lambda message: message.encode("utf-8"))
    monkeypatch.setattr(
        movement,
        "stream_world_objects_after_teleport",
        lambda target, *, context: calls.append(context) or [("SMSG_UPDATE_OBJECT", b"post-teleport-visible")],
    )

    status, responses = movement.handle_move_teleport_ack(session, None)

    assert status == 0
    assert calls == ["near-teleport-ack"]
    assert ("SMSG_UPDATE_OBJECT", b"post-teleport-visible") in responses


def test_post_teleport_visibility_stream_bypasses_movement_throttle(monkeypatch):
    session = _FakeSession()
    session.loaded_gameobjects = set()
    session.loaded_transport_entries = {}
    session.loaded_npcs = set()
    session.last_gameobject_stream_at = 999999.0
    session.last_npc_stream_at = 999999.0
    calls: list[str] = []

    monkeypatch.setattr(
        movement,
        "_maybe_stream_world_objects",
        lambda target: calls.append("stream") or [("SMSG_UPDATE_OBJECT", b"visible-without-move")],
    )

    responses = movement.stream_world_objects_after_teleport(session, context="test")

    assert responses == [("SMSG_UPDATE_OBJECT", b"visible-without-move")]
    assert calls == ["stream"]
    assert session.last_gameobject_stream_at == 0.0
    assert session.last_npc_stream_at == 0.0


def test_same_map_teleport_ack_refreshes_mounted_state(monkeypatch):
    from server.modules.handlers.world.opcodes import spells as spells_handlers

    session = _FakeSession()
    session.is_mounted = True
    session.mount_display_id = 2404
    session.mount_spell = 59535
    session.run_speed = 14.0
    session.fly_speed = 14.0
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda *args, **kwargs: None)
    monkeypatch.setattr(movement, "_post_teleport_multiplayer_resync", lambda target, **kwargs: [
        ("SMSG_UPDATE_OBJECT", b"mount:2404"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"run-speed"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"flight-speed"),
        ("SMSG_PLAYER_MOVE", b"move"),
    ])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda target, *, force=False: calls.append(("broadcast", force)))
    monkeypatch.setattr(movement, "force_bilateral_visibility_resync", lambda target, *, reason: calls.append(("visibility", reason)))
    monkeypatch.setattr(movement, "build_same_map_teleport_self_resync_responses", lambda target: [])
    monkeypatch.setattr(movement, "build_move_set_run_speed_payload", lambda target: b"run-speed")
    monkeypatch.setattr(movement, "build_move_set_flight_speed_payload", lambda target: b"flight-speed")
    monkeypatch.setattr(movement, "build_smsg_player_move_payload", lambda target: b"move")
    monkeypatch.setattr(movement, "encode_skyfire_messagechat_system_payload", lambda message: message.encode("utf-8"))
    monkeypatch.setattr(spells_handlers, "build_mount_visual_responses", lambda target, display_id: [
        ("SMSG_UPDATE_OBJECT", f"mount:{display_id}".encode("ascii"))
    ])
    monkeypatch.setattr(spells_handlers, "_broadcast_mount_visual_to_visible_peers", lambda target, display_id: calls.append(("mount-peers", display_id)))

    status, responses = movement.handle_move_teleport_ack(session, None)

    assert status == 0
    assert responses == [
        ("SMSG_MESSAGECHAT", b"[Teleport] same-map ack -> Orgrimmar"),
        ("SMSG_UPDATE_OBJECT", b"mount:2404"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"run-speed"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"flight-speed"),
        ("SMSG_PLAYER_MOVE", b"move"),
    ]
    assert calls == []


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
    monkeypatch.setattr(movement, "force_bilateral_visibility_resync", lambda target, *, reason: None)
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
    assert session.worldport_ack_pending is False
    assert session.teleport_destination is None
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


def test_worldport_ack_keeps_teleport_pending_for_loading_screen_completion(monkeypatch):
    session = _FakeSession()
    session.teleport_pending = True
    session.near_teleport_pending = False
    session.worldport_ack_pending = True
    session.teleport_destination = "Silvermoon"

    calls = []
    stream_calls: list[str] = []
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda target, **kwargs: None)
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda target, *, force=False: None)
    monkeypatch.setattr(
        movement,
        "force_bilateral_visibility_resync",
        lambda target, *, reason: calls.append((target, reason)),
    )
    monkeypatch.setattr(
        movement,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )
    monkeypatch.setattr(
        movement,
        "stream_world_objects_after_teleport",
        lambda target, *, context: stream_calls.append(context)
        or [("SMSG_UPDATE_OBJECT", b"worldport-visible")],
    )

    status, responses = movement.handle_move_worldport_ack(session, None)

    assert status == 0
    assert session.teleport_pending is True
    assert session.worldport_ack_pending is False
    assert session.near_teleport_pending is False
    assert session.teleport_destination == "Silvermoon"
    assert responses == [
        ("SMSG_MESSAGECHAT", b"[Teleport] worldport ack -> Silvermoon"),
        ("SMSG_UPDATE_OBJECT", b"worldport-visible"),
    ]
    assert calls == [(session, "worldport-ack")]
    assert stream_calls == ["worldport-ack"]


def test_areatrigger_same_map_can_teleport_again_after_movement_resumes(monkeypatch):
    session = _FakeSession()
    session.teleport_pending = False
    session.near_teleport_pending = True
    session.worldport_ack_pending = False
    session.movement_state = SimpleNamespace(
        x=100.0,
        y=200.0,
        z=300.0,
        orientation=1.25,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        counter=0,
    )

    monkeypatch.setattr(
        movement.DatabaseConnection,
        "get_areatrigger_teleport",
        lambda trigger_id: {
            "target_map": 1,
            "target_position_x": 120.0 if int(trigger_id) == 100 else 220.0,
            "target_position_y": 240.0 if int(trigger_id) == 100 else 340.0,
            "target_position_z": 15.0,
            "target_orientation": 0.75,
        },
    )
    chat_stub = types.ModuleType("server.modules.handlers.world.opcodes.chat")
    def _apply_area_trigger_teleport(target, **kwargs):
        target.near_teleport_pending = True
        target.teleport_pending = False
        target.worldport_ack_pending = False
        return [("SMSG_MOVE_TELEPORT", f"teleport:{target.teleport_destination}".encode("utf-8"))]

    chat_stub.apply_player_state_change = _apply_area_trigger_teleport
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.opcodes.chat", chat_stub)
    import server.modules.handlers.world.opcodes as world_opcodes
    monkeypatch.setattr(world_opcodes, "chat", chat_stub, raising=False)
    monkeypatch.setattr(
        movement,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda target, **kwargs: None)
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda target, *, force=False: None)
    monkeypatch.setattr(
        movement,
        "build_same_map_teleport_self_resync_responses",
        lambda target: [("SMSG_UPDATE_OBJECT", b"0006")],
    )
    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args: (120.0, 240.0, 15.0, 0.75))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args: True)

    movement.handle_movement_packet(
        session,
        SimpleNamespace(name="MSG_MOVE_START_FORWARD", opcode=0, payload=b"", decoded={}),
    )
    assert session.near_teleport_pending is False
    assert session.worldport_ack_pending is False


def test_move_set_run_speed_payload_uses_movement_sync_guid():
    session = _FakeSession()
    session.world_guid = 0x0000000700000003
    session.player_guid = session.world_guid
    session.run_speed = 70.0
    session.movement_state = types.SimpleNamespace(counter=27)

    payload = movement.build_move_set_run_speed_payload(session)

    assert payload == bytes.fromhex("411B000000010600008C42")
    assert session.movement_state.counter == 29


def test_move_set_speed_payloads_match_movement_sync_guid_layout():
    session = _FakeSession()
    session.world_guid = 0x0000000700000003
    session.player_guid = session.world_guid
    session.movement_state = types.SimpleNamespace(counter=70)

    walk = movement.build_move_set_speed_payload(session, "SMSG_MOVE_SET_WALK_SPEED", 25.0)
    run = movement.build_move_set_speed_payload(session, "SMSG_MOVE_SET_RUN_SPEED", 70.0)
    swim = movement.build_move_set_speed_payload(session, "SMSG_MOVE_SET_SWIM_SPEED", 47.22221755981445)
    flight = movement.build_move_set_speed_payload(session, "SMSG_MOVE_SET_FLIGHT_SPEED", 70.0)

    assert walk.hex().upper() == "44460000000000C8410601"
    assert run.hex().upper() == "4148000000010600008C42"
    assert swim.hex().upper() == "484A0000008DE33C420106"
    assert flight.hex().upper() == "00008C424C000000240601"
    assert session.movement_state.counter == 78


def test_move_set_speed_payloads_fall_back_to_player_world_guid_when_char_guid_missing():
    session = _FakeSession()
    session.char_guid = 0
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


def test_move_set_can_fly_payload_uses_movement_sync_guid():
    session = _FakeSession()
    session.world_guid = 0x0000000700000003
    session.player_guid = session.world_guid
    session.movement_state = types.SimpleNamespace(counter=27)

    payload = movement.build_move_set_can_fly_payload(session, True)

    assert payload == bytes.fromhex("14130000000601")
    assert session.movement_state.counter == 27


def test_move_unset_can_fly_payload_uses_movement_sync_guid():
    session = _FakeSession()
    session.world_guid = 0x0000000700000003
    session.player_guid = session.world_guid
    session.movement_state = types.SimpleNamespace(counter=27)

    payload = movement.build_move_set_can_fly_payload(session, False)

    assert payload == bytes.fromhex("24016900000006")
    assert session.movement_state.counter == 27


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


def test_stream_nearby_gameobjects_spawns_new_and_despawns_far(monkeypatch):
    session = _FakeSession()
    session.realm_id = 1
    session.loaded_gameobjects = {movement.GameObjectGuid.from_spawn_guid(9, 1)}

    new_world_guid = movement.GameObjectGuid.from_spawn_guid(4, 1)

    monkeypatch.setattr(
        movement,
        "build_database_gameobject_responses",
        lambda target, loaded_guids=None, **kwargs: (
            loaded_guids.add(new_world_guid) if isinstance(loaded_guids, set) else None
        ) or [("SMSG_UPDATE_OBJECT", b"spawn-go")],
    )
    monkeypatch.setattr(
        movement.DatabaseConnection,
        "get_gameobjects_near",
        lambda map_id, x, y, radius, limit=400: [{"guid": 4}],
        raising=False,
    )

    responses = movement._stream_nearby_gameobjects(session)

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"spawn-go")
    assert responses[1][0] == "SMSG_UPDATE_OBJECT"
    assert session.loaded_gameobjects == {new_world_guid}


def test_stream_nearby_gameobjects_allows_map_zero(monkeypatch):
    session = _FakeSession()
    session.map_id = 0
    session.realm_id = 1

    monkeypatch.setattr(
        movement,
        "build_database_gameobject_responses",
        lambda target, loaded_guids=None, **kwargs: [("SMSG_UPDATE_OBJECT", b"spawn-go")],
    )
    monkeypatch.setattr(
        movement.DatabaseConnection,
        "get_gameobjects_near",
        lambda map_id, x, y, radius, limit=400: [],
        raising=False,
    )

    responses = movement._stream_nearby_gameobjects(session)

    assert responses == [("SMSG_UPDATE_OBJECT", b"spawn-go")]


def test_stream_nearby_npcs_spawns_new_and_despawns_far(monkeypatch):
    session = _FakeSession()
    session.realm_id = 1
    session.npcs_visible = True
    session.npc_auto_stream = True
    session.loaded_npcs = {movement.CreatureGuid.from_spawn_guid(9, 1)}

    new_world_guid = movement.CreatureGuid.from_spawn_guid(4, 1)

    monkeypatch.setattr(
        creatures_module,
        "build_database_creature_responses",
        lambda target, loaded_guids=None: (
            loaded_guids.add(new_world_guid) if isinstance(loaded_guids, set) else None
        ) or [("SMSG_UPDATE_OBJECT", b"spawn-npc")],
        raising=False,
    )
    monkeypatch.setattr(
        movement.DatabaseConnection,
        "get_creatures_near",
        lambda map_id, x, y, radius, limit=400: [{"guid": 4}],
        raising=False,
    )

    responses = movement._stream_nearby_npcs(session)

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"spawn-npc")
    assert responses[1][0] == "SMSG_UPDATE_OBJECT"
    assert session.loaded_npcs == {new_world_guid}


def test_companion_follow_ignores_turn_only_opcodes(monkeypatch):
    session = _FakeSession()
    session.summoned_companion_world_guid = 123

    monkeypatch.setattr(movement, "_maybe_move_companion_pet", lambda target: [("SMSG_PLAYER_MOVE", b"pet")])

    assert movement._maybe_move_companion_pet_for_opcode(session, "MSG_MOVE_START_TURN_LEFT") == []
    assert movement._maybe_move_companion_pet_for_opcode(session, "MSG_MOVE_SET_FACING") == []
    assert movement._maybe_move_companion_pet_for_opcode(session, "MSG_MOVE_START_FORWARD") == [
        ("SMSG_PLAYER_MOVE", b"pet")
    ]


def test_handle_movement_packet_returns_stream_responses(monkeypatch):
    session = _FakeSession()
    session.teleport_pending = False
    session.near_teleport_pending = False
    session.movement_state = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.5,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        counter=0,
    )

    monkeypatch.setattr(movement, "_clear_dance_emote_state_on_move", lambda *args: None)
    monkeypatch.setattr(movement, "parse_movement_info", lambda *args: (10.0, 20.0, 30.0, 1.5))
    monkeypatch.setattr(movement, "_accept_movement_update", lambda *args: True)
    monkeypatch.setattr(movement, "_store_authoritative_movement", lambda *args: True)
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda target: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda target: None)
    monkeypatch.setattr(movement, "_maybe_periodic_position_save", lambda target: None)
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda target, force=False: None)
    monkeypatch.setattr(movement, "_maybe_stream_gameobjects", lambda target: [("SMSG_UPDATE_OBJECT", b"go-stream")])

    status, responses = movement.handle_movement_packet(
        session,
        SimpleNamespace(name="MSG_MOVE_HEARTBEAT", opcode=0, payload=b"", decoded={}),
    )

    assert status == 0
    assert responses == [("SMSG_UPDATE_OBJECT", b"go-stream")]
