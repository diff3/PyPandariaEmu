from pathlib import Path
import importlib
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


def test_build_gameobject_update_payload_uses_gameobject_guid():
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
    assert packed_guid == replay.GameObjectGuid.from_spawn_guid(4, 1)


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
                {"guid": 68, "entry": 2457, "x": 1000.0, "y": 2000.0, "z": 99.0, "orientation": 1.0}
            ]
        ),
    )
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_creature_template",
        staticmethod(lambda entry: {"modelid1": 1437}),
    )

    captured = {}

    def _fake_build(*, map_id, entry):
        captured["map_id"] = map_id
        captured["entry"] = dict(entry)
        return b"npc"

    monkeypatch.setattr(replay, "_build_creature_barncastle_payload", _fake_build)
    monkeypatch.setattr(replay, "make_update_object_response", lambda payload: ("SMSG_UPDATE_OBJECT", payload))

    responses = replay.build_database_creature_responses(session)

    assert responses == [("SMSG_UPDATE_OBJECT", b"npc")]
    assert captured["map_id"] == 1
    assert captured["entry"]["x"] == 106.0
    assert captured["entry"]["y"] == 200.0
    assert captured["entry"]["z"] == 30.0
