from pathlib import Path
import importlib
import math
import sys
import types
from types import SimpleNamespace


def _import_replay():
    packets_module = types.ModuleType("server.modules.handlers.world.login.packets")
    packets_module.build_login_packet = lambda *args, **kwargs: b""
    sys.modules["server.modules.handlers.world.login.packets"] = packets_module

    db_module = types.ModuleType("server.modules.database.DatabaseConnection")
    db_module.DatabaseConnection = type(
        "DatabaseConnection",
        (),
        {
            "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
            "get_creatures_near": staticmethod(lambda *args, **kwargs: []),
            "get_creature_template": staticmethod(lambda *args, **kwargs: {}),
        },
    )
    sys.modules["server.modules.database.DatabaseConnection"] = db_module

    runtime_module = types.ModuleType("server.session.runtime")
    runtime_module.session = SimpleNamespace()
    sys.modules["server.session.runtime"] = runtime_module

    sys.modules.pop("server.modules.handlers.world.bootstrap.replay", None)
    return importlib.import_module("server.modules.handlers.world.bootstrap.replay")


def test_static_update_object_capture_is_skipped_for_db_loader():
    replay = _import_replay()
    session = SimpleNamespace(map_id=1, zone=1637, x=1570.0, y=-4397.0)
    path = Path("SMSG_UPDATE_OBJECT_1773613176_0003.json")

    assert replay._should_skip_static_update_object_capture(session, path) is True


def test_build_gameobject_update_payload_uses_mo_transport_guid():
    replay = _import_replay()
    entry = {
        "guid": 4,
        "entry": 175354,
        "x": 1569.97,
        "y": -4397.41,
        "z": 16.05,
        "orientation": 0.0,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "display_id": 3015,
        "flags": 40,
        "size": 1.0,
        "type": 15,
        "state": 1,
        "animprogress": 255,
        "faction": 0,
    }

    payload = replay._build_gameobject_update_payload(map_id=1, entry=entry, realm_id=1)
    update_type = payload[6]
    packed_guid = replay.extract_first_update_object_guid_info(payload)[0]

    assert update_type == 1
    assert packed_guid == replay.MoTransportGuid.from_spawn_guid(4)


def test_build_gameobject_update_payload_uses_db_rotation(monkeypatch):
    from server.modules.handlers.world.bootstrap import gameobjects

    captured = {}

    def fake_encode_packet(opcode_name, fields):
        captured["opcode_name"] = opcode_name
        captured["fields"] = dict(fields)
        return b"payload"

    monkeypatch.setattr(gameobjects.EncoderHandler, "encode_packet", fake_encode_packet)
    entry = {
        "guid": 4,
        "entry": 175354,
        "x": 1569.97,
        "y": -4397.41,
        "z": 16.05,
        "orientation": 1.5,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.6816387600233341,
        "rotation3": 0.7316888688738209,
        "display_id": 3015,
        "flags": 40,
        "size": 1.0,
        "type": 15,
        "state": 1,
        "animprogress": 255,
        "faction": 0,
    }

    payload = gameobjects._build_gameobject_update_payload(map_id=1, entry=entry, realm_id=1)
    field_values = gameobjects._build_gameobject_field_values(
        entry,
        world_guid=gameobjects.MoTransportGuid.from_spawn_guid(4),
    )

    assert payload == b"payload"
    assert captured["opcode_name"] == "GAMEOBJECT_CREATE"
    assert captured["fields"]["stationary_orientation"] == gameobjects._stationary_orientation(entry)
    assert captured["fields"]["gameobject_rotation_packed"] == gameobjects._gameobject_rotation_packed(entry)
    assert captured["fields"]["gameobject_rotation_packed"] != 0
    assert field_values[14] == gameobjects._u32_from_float(entry["rotation2"])
    assert field_values[15] == gameobjects._u32_from_float(entry["rotation3"])


def test_build_gameobject_update_payload_derives_upright_rotation_from_orientation(monkeypatch):
    from server.modules.handlers.world.bootstrap import gameobjects

    captured = {}

    monkeypatch.setattr(
        gameobjects.EncoderHandler,
        "encode_packet",
        lambda opcode_name, fields: captured.setdefault("fields", dict(fields)) or b"payload",
    )
    entry = {
        "guid": 4,
        "entry": 175354,
        "x": 1569.97,
        "y": -4397.41,
        "z": 16.05,
        "orientation": 1.5,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "display_id": 3015,
        "flags": 40,
        "size": 1.0,
        "type": 15,
        "state": 1,
        "animprogress": 255,
        "faction": 0,
    }

    gameobjects._build_gameobject_update_payload(map_id=1, entry=entry, realm_id=1)
    field_values = gameobjects._build_gameobject_field_values(
        entry,
        world_guid=gameobjects.MoTransportGuid.from_spawn_guid(4),
    )

    assert captured["fields"]["stationary_orientation"] == entry["orientation"]
    assert captured["fields"]["gameobject_rotation_packed"] == gameobjects._gameobject_rotation_packed(entry)
    assert captured["fields"]["gameobject_rotation_packed"] != 0
    assert field_values[14] == gameobjects._u32_from_float(math.sin(0.75))
    assert field_values[15] == gameobjects._u32_from_float(math.cos(0.75))


def test_gameobject_stationary_orientation_uses_db_quaternion_yaw():
    from server.modules.handlers.world.bootstrap import gameobjects

    entry = {
        "orientation": -1.65806,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.737277,
        "rotation3": -0.67559,
    }

    expected = math.fmod(2.0 * math.atan2(entry["rotation2"], entry["rotation3"]), math.tau)
    if expected < 0.0:
        expected += math.tau

    assert gameobjects._stationary_orientation(entry) == expected
    assert gameobjects._stationary_orientation(entry) > 0.0


def test_gameobject_rotation_uses_large_command_board_db_orientation_without_display_hack():
    from server.modules.handlers.world.bootstrap import gameobjects

    entry = {
        "orientation": 0.383971,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "display_id": 10014,
    }

    assert gameobjects._stationary_orientation(entry) == 0.383971
    rotation = gameobjects._rotation_components(entry)
    assert rotation[0] == 0.0
    assert rotation[1] == 0.0
    assert math.isclose(rotation[2], math.sin(gameobjects._stationary_orientation(entry) * 0.5))
    assert math.isclose(rotation[3], math.cos(gameobjects._stationary_orientation(entry) * 0.5))
    assert gameobjects._gameobject_rotation_packed(entry) != 0


def test_gameobject_stationary_orientation_does_not_flip_other_identity_models():
    from server.modules.handlers.world.bootstrap import gameobjects

    entry = {
        "orientation": 0.383971,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "display_id": 3015,
    }

    assert gameobjects._stationary_orientation(entry) == 0.383971


def test_replay_movement_focus_sequence_appends_db_gameobjects():
    replay = _import_replay()
    session = SimpleNamespace(map_id=1, zone=1637, x=1570.0, y=-4397.0, realm_id=1)

    replay.USE_SERVER_BUILT_MINIMAL_PLAYER = False
    replay._build_dynamic_active_mover_packet = lambda _session: ("SMSG_MOVE_SET_ACTIVE_MOVER", b"ACTIVE")
    replay._build_replayed_update_object_packet = (
        lambda _session, opcode_name, path, update_index: (opcode_name, path.name.encode())
    )
    replay.build_database_gameobject_responses = lambda _session: [("SMSG_UPDATE_OBJECT", b"DBOBJ")]

    responses = replay.replay_movement_focus_sequence(session)

    assert responses[0] == ("SMSG_MOVE_SET_ACTIVE_MOVER", b"ACTIVE")
    assert responses[-1] == ("SMSG_UPDATE_OBJECT", b"DBOBJ")


def test_replay_movement_focus_sequence_appends_hybrid_player_value_update(monkeypatch):
    replay = _import_replay()
    session = SimpleNamespace(map_id=1, zone=1637, x=1570.0, y=-4397.0, realm_id=1)

    monkeypatch.setattr(replay, "USE_SERVER_BUILT_MINIMAL_PLAYER", True)
    monkeypatch.setattr(
        replay,
        "_build_world_login_context",
        lambda _session: SimpleNamespace(map_id=1, world_guid=0x300010000000D),
    )
    monkeypatch.setattr(
        replay,
        "build_server_built_minimal_player_value_update",
        lambda _ctx: b"VALUE",
    )
    monkeypatch.setattr(
        replay,
        "_build_dynamic_active_mover_packet",
        lambda _session: ("SMSG_MOVE_SET_ACTIVE_MOVER", b"ACTIVE"),
    )
    monkeypatch.setattr(
        replay,
        "_build_replayed_update_object_packet",
        lambda _session, opcode_name, path, update_index: (opcode_name, path.name.encode()),
    )
    monkeypatch.setattr(
        replay,
        "build_database_gameobject_responses",
        lambda _session: [("SMSG_UPDATE_OBJECT", b"DBOBJ")],
    )
    monkeypatch.setattr(
        replay,
        "make_update_object_response",
        lambda payload, update_index=None: ("SMSG_UPDATE_OBJECT", payload),
    )

    responses = replay.replay_movement_focus_sequence(session)

    replay_index = responses.index(
        ("SMSG_UPDATE_OBJECT", b"SMSG_UPDATE_OBJECT_1773613176_0002.json")
    )
    assert responses[replay_index + 1] == ("SMSG_UPDATE_OBJECT", b"VALUE")


def test_replay_movement_focus_sequence_skips_hybrid_player_value_update_on_none(monkeypatch):
    replay = _import_replay()
    session = SimpleNamespace(map_id=1, zone=1637, x=1570.0, y=-4397.0, realm_id=1)

    monkeypatch.setattr(replay, "USE_SERVER_BUILT_MINIMAL_PLAYER", True)
    monkeypatch.setattr(
        replay,
        "_build_world_login_context",
        lambda _session: SimpleNamespace(map_id=1, world_guid=0x300010000000D),
    )
    monkeypatch.setattr(
        replay,
        "build_server_built_minimal_player_value_update",
        lambda _ctx: None,
    )
    monkeypatch.setattr(
        replay,
        "_build_dynamic_active_mover_packet",
        lambda _session: ("SMSG_MOVE_SET_ACTIVE_MOVER", b"ACTIVE"),
    )
    monkeypatch.setattr(
        replay,
        "_build_replayed_update_object_packet",
        lambda _session, opcode_name, path, update_index: (opcode_name, path.name.encode()),
    )
    monkeypatch.setattr(
        replay,
        "build_database_gameobject_responses",
        lambda _session: [],
    )
    monkeypatch.setattr(
        replay,
        "make_update_object_response",
        lambda payload, update_index=None: ("SMSG_UPDATE_OBJECT", payload),
    )

    responses = replay.replay_movement_focus_sequence(session)

    assert ("SMSG_UPDATE_OBJECT", b"VALUE") not in responses


def test_build_database_gameobject_responses_allows_map_zero(monkeypatch):
    replay = _import_replay()
    session = SimpleNamespace(map_id=0, x=-8803.0, y=633.0, realm_id=1)

    db_module = sys.modules["server.modules.database.DatabaseConnection"]
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_gameobjects_near",
        staticmethod(lambda map_id, x, y, radius, limit: [{"guid": 4, "entry": 175354}]),
    )
    monkeypatch.setattr(
        replay,
        "_build_gameobject_update_payload",
        lambda **kwargs: b"payload",
    )
    monkeypatch.setattr(
        replay,
        "make_update_object_response",
        lambda payload: ("SMSG_UPDATE_OBJECT", payload),
    )

    responses = replay.build_database_gameobject_responses(session)

    assert responses == [("SMSG_UPDATE_OBJECT", b"payload")]


def test_build_creature_barncastle_payload_patches_only_map_and_position():
    replay = _import_replay()
    entry = {
        "guid": 68,
        "entry": 2457,
        "x": -8903.01,
        "y": 641.83,
        "z": 99.62,
        "orientation": 1.25,
        "modelid": 1437,
        "template": {"modelid1": 1437},
    }

    original = replay._load_npc_barncastle_template()
    payload = replay._build_creature_barncastle_payload(map_id=0, entry=entry)

    assert len(payload) == 222
    assert payload[0:2] == b"\x00\x00"
    assert payload[2:48] == original[2:48]
    assert payload[56:60] == original[56:60]
    assert payload[64:83] == original[64:83]
    assert payload[87:] == original[87:]
    assert payload[48:52] != original[48:52]
    assert payload[52:56] != original[52:56]
    assert payload[60:64] != original[60:64]
    assert payload[83:87] != original[83:87]


def test_build_database_creature_responses_spawns_npc_near_player(monkeypatch):
    replay = _import_replay()
    session = SimpleNamespace(
        npcs_visible=True,
        map_id=1,
        x=100.0,
        y=200.0,
        z=30.0,
        orientation=0.0,
        realm_id=1,
    )

    db_module = sys.modules["server.modules.database.DatabaseConnection"]
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_creatures_near",
        staticmethod(
            lambda map_id, x, y, radius, limit: [
                {
                    "guid": 68,
                    "entry": 2457,
                    "npcflag": 0x2000,
                    "x": 1000.0,
                    "y": 2000.0,
                    "z": 99.0,
                    "orientation": 1.0,
                }
            ]
        ),
    )
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_creature_template",
        staticmethod(lambda entry: {"modelid1": 1437, "npcflag": 0x4}),
    )

    captured = {}

    def _fake_build(*, map_id, entry, realm_id):
        captured["map_id"] = map_id
        captured["entry"] = dict(entry)
        captured["realm_id"] = realm_id
        return b"npc"

    monkeypatch.setattr(replay, "_build_creature_update_payload", _fake_build)
    monkeypatch.setattr(replay, "make_update_object_response", lambda payload: ("SMSG_UPDATE_OBJECT", payload))

    responses = replay.build_database_creature_responses(session)

    assert responses == [("SMSG_UPDATE_OBJECT", b"npc")]
    assert captured["map_id"] == 1
    assert captured["realm_id"] == 1
    assert captured["entry"]["guid"] == 68
    assert captured["entry"]["entry"] == 2457
    assert captured["entry"]["npcflag"] == 0x2000
    assert captured["entry"]["template"] == {"modelid1": 1437, "npcflag": 0x4}
    assert captured["entry"]["x"] == 1000.0
    assert captured["entry"]["y"] == 2000.0
    assert captured["entry"]["z"] == 99.0


def test_build_database_creature_responses_tracks_loaded_world_guid(monkeypatch):
    replay = _import_replay()
    session = SimpleNamespace(
        npcs_visible=True,
        map_id=1,
        x=100.0,
        y=200.0,
        z=30.0,
        orientation=0.0,
        realm_id=1,
    )

    db_module = sys.modules["server.modules.database.DatabaseConnection"]
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_creatures_near",
        staticmethod(
            lambda map_id, x, y, radius, limit: [
                {"guid": 68, "entry": 2457, "x": 1000.0, "y": 2000.0, "z": 99.0, "orientation": 1.0}
            ]
        ),
    )
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_creature_template",
        staticmethod(lambda entry: {"modelid1": 1437}),
    )
    monkeypatch.setattr(replay, "_build_creature_update_payload", lambda **kwargs: b"npc")
    monkeypatch.setattr(replay, "make_update_object_response", lambda payload: ("SMSG_UPDATE_OBJECT", payload))

    loaded_guids = set()
    first = replay.build_database_creature_responses(session, loaded_guids=loaded_guids)
    second = replay.build_database_creature_responses(session, loaded_guids=loaded_guids)

    assert first == [("SMSG_UPDATE_OBJECT", b"npc")]
    assert second == []
    assert replay.CreatureGuid.from_spawn_guid(68, 1) in loaded_guids


def test_build_creature_update_payload_uses_create_object2():
    replay = _import_replay()
    entry = {
        "guid": 68,
        "entry": 2457,
        "x": -8903.01,
        "y": 641.83,
        "z": 99.62,
        "orientation": 1.25,
        "modelid": 1437,
        "template": {"modelid1": 1437},
    }

    payload = replay._build_creature_update_payload(map_id=0, entry=entry, realm_id=1)

    assert payload[0:2] == b"\x00\x00"
    assert payload[2:6] == b"\x01\x00\x00\x00"
    assert payload[6] == 2


def test_build_creature_field_values_uses_spawn_npc_flags():
    replay = _import_replay()
    world_guid = replay.CreatureGuid.from_spawn_guid(68, 1)
    entry = {
        "guid": 68,
        "entry": 3310,
        "npcflag": 0x00002000,
        "template": {"modelid1": 1437},
    }

    fields = replay._build_creature_field_values(entry, world_guid=world_guid)

    assert fields[87] == 0x00002000


def test_build_creature_field_values_uses_template_npc_flags():
    replay = _import_replay()
    world_guid = replay.CreatureGuid.from_spawn_guid(68, 1)
    entry = {
        "guid": 68,
        "entry": 3310,
        "npcflag": 0,
        "template": {"modelid1": 1437, "npcflag": 0x00002003},
    }

    fields = replay._build_creature_field_values(entry, world_guid=world_guid)

    assert fields[87] == 0x00002003


def test_build_database_creature_responses_skips_dnd_triggers(monkeypatch):
    replay = _import_replay()
    session = SimpleNamespace(
        npcs_visible=True,
        map_id=1,
        x=100.0,
        y=200.0,
        z=30.0,
        orientation=0.0,
        realm_id=1,
    )

    db_module = sys.modules["server.modules.database.DatabaseConnection"]
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_creatures_near",
        staticmethod(
            lambda map_id, x, y, radius, limit: [
                {"guid": 68, "entry": 37574, "x": 1000.0, "y": 2000.0, "z": 99.0, "orientation": 1.0}
            ]
        ),
    )
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_creature_template",
        staticmethod(lambda entry: {"name": "[DND] Shaker - Small", "modelid1": 21955}),
    )

    assert replay.build_database_creature_responses(session) == []
