from pathlib import Path
import importlib
import math
import sys
import struct
import types
from types import SimpleNamespace


def _import_creatures():
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

    sys.modules.pop("server.modules.handlers.world.bootstrap.creatures", None)
    return importlib.import_module("server.modules.handlers.world.bootstrap.creatures")


def _import_gameobjects():
    db_module = types.ModuleType("server.modules.database.DatabaseConnection")
    db_module.DatabaseConnection = type(
        "DatabaseConnection",
        (),
        {
            "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
        },
    )
    sys.modules["server.modules.database.DatabaseConnection"] = db_module

    transport_runtime_module = types.ModuleType("server.modules.handlers.world.transport_runtime")
    transport_runtime_module.cached_transport_runtime_entry = lambda _session, entry, **kwargs: entry
    transport_runtime_module.prepare_runtime_transport_entry = lambda entry, **kwargs: entry
    transport_runtime_module.register_loaded_transport_entry = lambda *args, **kwargs: True
    transport_runtime_module.synthetic_transport_entries_near = lambda *args, **kwargs: []
    sys.modules["server.modules.handlers.world.transport_runtime"] = transport_runtime_module

    sys.modules.pop("server.modules.handlers.world.bootstrap.gameobjects", None)
    return importlib.import_module("server.modules.handlers.world.bootstrap.gameobjects")


def test_build_gameobject_update_payload_uses_mo_transport_guid():
    gameobjects = _import_gameobjects()
    from server.modules.handlers.world.bootstrap.playerobjects import extract_first_update_object_guid_info

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

    payload = gameobjects._build_gameobject_update_payload(map_id=1, entry=entry, realm_id=1)
    update_type = payload[6]
    packed_guid = extract_first_update_object_guid_info(payload)[0]

    assert update_type == 1
    assert packed_guid == gameobjects.MoTransportGuid.from_spawn_guid(4)


def test_build_gameobject_update_payload_sanitizes_yaw_only_db_rotation(monkeypatch):
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
    assert field_values[14] == gameobjects._u32_from_float(math.sin(entry["orientation"] * 0.5))
    assert field_values[15] == gameobjects._u32_from_float(math.cos(entry["orientation"] * 0.5))


def test_build_gameobject_update_payload_preserves_real_unit_quaternion(monkeypatch):
    from server.modules.handlers.world.bootstrap import gameobjects

    monkeypatch.setattr(
        gameobjects.EncoderHandler,
        "encode_packet",
        lambda _opcode_name, _fields: b"payload",
    )
    entry = {
        "guid": 4,
        "entry": 175354,
        "x": 1569.97,
        "y": -4397.41,
        "z": 16.05,
        "orientation": 1.5,
        "rotation0": 0.25,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": math.sqrt(1.0 - (0.25 * 0.25)),
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

    assert field_values[12] == gameobjects._u32_from_float(entry["rotation0"])
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


def test_gameobject_stationary_orientation_uses_db_orientation_not_quaternion_yaw():
    from server.modules.handlers.world.bootstrap import gameobjects

    entry = {
        "orientation": -1.65806,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.737277,
        "rotation3": -0.67559,
    }

    expected = math.fmod(entry["orientation"], math.tau)
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


def test_build_database_gameobject_responses_allows_map_zero(monkeypatch):
    gameobjects = _import_gameobjects()
    session = SimpleNamespace(map_id=0, x=-8803.0, y=633.0, realm_id=1)

    db_module = sys.modules["server.modules.database.DatabaseConnection"]
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_gameobjects_near",
        staticmethod(lambda map_id, x, y, radius, limit: [{"guid": 4, "entry": 175354}]),
    )
    monkeypatch.setattr(
        gameobjects,
        "_build_gameobject_update_payload",
        lambda **kwargs: b"payload",
    )
    monkeypatch.setattr(
        gameobjects,
        "make_update_object_response",
        lambda payload: ("SMSG_UPDATE_OBJECT", payload),
    )
    responses = gameobjects.build_database_gameobject_responses(session)

    assert responses == [("SMSG_UPDATE_OBJECT", b"payload")]


def test_build_database_gameobject_responses_marks_bootstrap_creates_loaded(monkeypatch):
    gameobjects = _import_gameobjects()
    session = SimpleNamespace(map_id=1, x=-995.0, y=-3822.0, realm_id=1)

    db_module = sys.modules["server.modules.database.DatabaseConnection"]
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_gameobjects_near",
        staticmethod(
            lambda map_id, x, y, radius, limit: [
                {"guid": 4, "entry": 176495, "type": 15, "map": 1, "x": x, "y": y, "z": 0.0}
            ]
        ),
    )
    monkeypatch.setattr(
        gameobjects,
        "_build_gameobject_update_payload",
        lambda **kwargs: b"transport-create",
    )
    monkeypatch.setattr(
        gameobjects,
        "make_update_object_response",
        lambda payload: ("SMSG_UPDATE_OBJECT", payload),
    )

    transport_runtime_module = sys.modules["server.modules.handlers.world.transport_runtime"]

    def _fake_register_loaded_transport_entry(_session, entry, world_guid, map_id):
        _session.loaded_transport_entries = {int(world_guid): dict(entry)}
        return True

    monkeypatch.setattr(
        transport_runtime_module,
        "register_loaded_transport_entry",
        _fake_register_loaded_transport_entry,
    )

    responses = gameobjects.build_database_gameobject_responses(session)
    expected_guid = int(gameobjects.MoTransportGuid.from_spawn_guid(4))

    assert responses == [("SMSG_UPDATE_OBJECT", b"transport-create")]
    assert session.loaded_gameobjects == {expected_guid}
    assert expected_guid in session.loaded_transport_entries


def test_database_transport_bootstrap_uses_authoritative_runtime_entry(monkeypatch):
    gameobjects = _import_gameobjects()
    session = SimpleNamespace(map_id=1, x=50.0, y=0.0, realm_id=1)
    clone_guid = int(gameobjects.MoTransportGuid.from_spawn_guid(100007))
    canonical_guid = int(gameobjects.MoTransportGuid.from_spawn_guid(7))
    captured_entries = []

    db_module = sys.modules["server.modules.database.DatabaseConnection"]
    monkeypatch.setattr(
        db_module.DatabaseConnection,
        "get_gameobjects_near",
        staticmethod(
            lambda map_id, x, y, radius, limit: [
                {
                    "guid": 100007,
                    "world_guid": clone_guid,
                    "entry": 20808,
                    "type": 15,
                    "map": 1,
                    "x": 0.0,
                    "y": 0.0,
                    "z": 0.0,
                    "transport_path_progress": 0,
                }
            ]
        ),
    )

    transport_runtime_module = sys.modules["server.modules.handlers.world.transport_runtime"]

    def _fake_register_loaded_transport_entry(_session, entry, world_guid, map_id):
        loaded = getattr(_session, "loaded_transport_entries", {})
        loaded[int(world_guid)] = dict(entry)
        _session.loaded_transport_entries = loaded
        return True

    def _fake_cached_transport_runtime_entry(_session, entry):
        moved = dict(entry)
        moved["guid"] = 7
        moved["world_guid"] = canonical_guid
        moved["x"] = 50.0
        moved["y"] = 0.0
        moved["transport_path_progress"] = 500
        return moved

    monkeypatch.setattr(
        transport_runtime_module,
        "register_loaded_transport_entry",
        _fake_register_loaded_transport_entry,
    )
    monkeypatch.setattr(
        transport_runtime_module,
        "cached_transport_runtime_entry",
        _fake_cached_transport_runtime_entry,
    )
    monkeypatch.setattr(
        gameobjects,
        "_build_gameobject_update_payload",
        lambda **kwargs: captured_entries.append(dict(kwargs["entry"])) or b"transport-create",
    )
    monkeypatch.setattr(
        gameobjects,
        "make_update_object_response",
        lambda payload: ("SMSG_UPDATE_OBJECT", payload),
    )

    responses = gameobjects.build_database_gameobject_responses(session)

    assert responses == [("SMSG_UPDATE_OBJECT", b"transport-create")]
    assert captured_entries[0]["world_guid"] == canonical_guid
    assert captured_entries[0]["x"] == 50.0
    assert captured_entries[0]["transport_path_progress"] == 500
    assert session.loaded_gameobjects == {canonical_guid}
    assert clone_guid not in session.loaded_transport_entries
    assert canonical_guid in session.loaded_transport_entries


def test_build_database_creature_responses_spawns_npc_near_player(monkeypatch):
    creatures = _import_creatures()
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

    monkeypatch.setattr(creatures, "_build_creature_update_payload", _fake_build)
    monkeypatch.setattr(creatures, "make_update_object_response", lambda payload: ("SMSG_UPDATE_OBJECT", payload))

    responses = creatures.build_database_creature_responses(session)

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
    creatures = _import_creatures()
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
    monkeypatch.setattr(creatures, "_build_creature_update_payload", lambda **kwargs: b"npc")
    monkeypatch.setattr(creatures, "make_update_object_response", lambda payload: ("SMSG_UPDATE_OBJECT", payload))

    loaded_guids = set()
    first = creatures.build_database_creature_responses(session, loaded_guids=loaded_guids)
    second = creatures.build_database_creature_responses(session, loaded_guids=loaded_guids)

    assert first == [("SMSG_UPDATE_OBJECT", b"npc")]
    assert second == []
    assert creatures.CreatureGuid.from_spawn_guid(68, 1) in loaded_guids


def test_build_creature_update_payload_uses_create_object2():
    creatures = _import_creatures()
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

    payload = creatures._build_creature_update_payload(map_id=0, entry=entry, realm_id=1)

    assert payload[0:2] == b"\x00\x00"
    assert payload[2:6] == b"\x01\x00\x00\x00"
    assert payload[6] == 2


def test_build_creature_update_payload_normalizes_negative_orientation():
    creatures = _import_creatures()
    entry = {
        "guid": 68,
        "entry": 2457,
        "x": -8903.01,
        "y": 641.83,
        "z": 99.62,
        "orientation": -1.0,
        "modelid": 1437,
        "template": {"modelid1": 1437},
    }

    payload = creatures._build_creature_update_payload(map_id=0, entry=entry, realm_id=1)
    x_offset = payload.find(struct.pack("<f", entry["x"]))

    assert x_offset >= 0
    packet_orientation = struct.unpack_from("<f", payload, x_offset + 4)[0]
    assert math.isclose(packet_orientation, math.tau - 1.0, rel_tol=0.0, abs_tol=0.000001)


def test_build_creature_update_payload_normalizes_overrange_orientation():
    creatures = _import_creatures()
    entry = {
        "guid": 68,
        "entry": 2457,
        "x": -8903.01,
        "y": 641.83,
        "z": 99.62,
        "orientation": math.tau + 1.25,
        "modelid": 1437,
        "template": {"modelid1": 1437},
    }

    payload = creatures._build_creature_update_payload(map_id=0, entry=entry, realm_id=1)
    x_offset = payload.find(struct.pack("<f", entry["x"]))

    assert x_offset >= 0
    packet_orientation = struct.unpack_from("<f", payload, x_offset + 4)[0]
    assert math.isclose(packet_orientation, 1.25, rel_tol=0.0, abs_tol=0.000001)


def test_build_creature_field_values_uses_spawn_npc_flags():
    creatures = _import_creatures()
    world_guid = creatures.CreatureGuid.from_spawn_guid(68, 1)
    entry = {
        "guid": 68,
        "entry": 3310,
        "npcflag": 0x00002000,
        "template": {"modelid1": 1437},
    }

    fields = creatures._build_creature_field_values(entry, world_guid=world_guid)

    assert fields[87] == 0x00002000


def test_build_creature_field_values_uses_template_npc_flags():
    creatures = _import_creatures()
    world_guid = creatures.CreatureGuid.from_spawn_guid(68, 1)
    entry = {
        "guid": 68,
        "entry": 3310,
        "npcflag": 0,
        "template": {"modelid1": 1437, "npcflag": 0x00002003},
    }

    fields = creatures._build_creature_field_values(entry, world_guid=world_guid)

    assert fields[87] == 0x00002003


def test_build_database_creature_responses_skips_dnd_triggers(monkeypatch):
    creatures = _import_creatures()
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

    assert creatures.build_database_creature_responses(session) == []
