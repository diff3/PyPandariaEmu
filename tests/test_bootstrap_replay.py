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
        {"get_gameobjects_near": staticmethod(lambda *args, **kwargs: [])},
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

    replay._build_dynamic_active_mover_packet = lambda _session: ("SMSG_MOVE_SET_ACTIVE_MOVER", b"ACTIVE")
    replay._build_replayed_update_object_packet = (
        lambda _session, opcode_name, path, update_index: (opcode_name, path.name.encode())
    )
    replay.build_database_gameobject_responses = lambda _session: [("SMSG_UPDATE_OBJECT", b"DBOBJ")]

    responses = replay.replay_movement_focus_sequence(session)

    assert responses[0] == ("SMSG_MOVE_SET_ACTIVE_MOVER", b"ACTIVE")
    assert responses[-1] == ("SMSG_UPDATE_OBJECT", b"DBOBJ")
