from __future__ import annotations

import sys
import types
from types import SimpleNamespace

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type(
    "DatabaseConnection",
    (),
    {
        "get_gameobject_spawn": staticmethod(lambda _guid: None),
        "delete_gameobject_spawn": staticmethod(lambda _guid: None),
        "restore_gameobject_spawn": staticmethod(lambda _entry: False),
        "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
        "get_gameobject_template": staticmethod(lambda _entry: None),
        "get_level_stats_for_class": staticmethod(lambda *_args, **_kwargs: []),
    },
)
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

from server.modules.handlers.world import dispatcher
from server.modules.handlers.world.features import godel
from server.modules.handlers.world.opcodes import entities


def _session() -> SimpleNamespace:
    session = SimpleNamespace(
        char_guid=7,
        account_id=1,
        realm_id=1,
        map_id=1,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.0,
        loaded_gameobjects=set(),
        loaded_gameobject_entries={},
        loaded_transport_entries={},
    )
    return session


def _entry(**overrides) -> dict:
    entry = {
        "guid": 12345,
        "entry": 678,
        "world_guid": 0xF110000000003039,
        "map_id": 1,
        "map": 1,
        "phaseId": 0,
        "phaseGroup": 0,
        "x": 11.0,
        "y": 22.0,
        "z": 33.0,
        "orientation": 1.5,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "spawntimesecs": 300,
        "animprogress": 255,
        "state": 1,
        "type": 5,
        "display_id": 100,
        "name": "Debug Crate",
        "flags": 1,
        "size": 1.0,
    }
    entry.update(overrides)
    return entry


def _messages(responses):
    return [payload for opcode, payload in responses if opcode == "SMSG_MESSAGECHAT"]


def test_godel_on_enables_selection_mode():
    session = _session()

    responses = godel.enable(session)

    assert getattr(session, "_godel_enabled") is True
    assert getattr(session, "_godel_selected") is None
    assert _messages(responses)


def test_godel_first_click_only_selects(monkeypatch):
    session = _session()
    entry = _entry()
    session._godel_enabled = True
    deleted: list[int] = []
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(godel.DatabaseConnection, "delete_gameobject_spawn", lambda guid: deleted.append(guid))

    responses = godel.handle_gameobject_click(session, entry)

    assert responses is not None
    assert getattr(session, "_godel_selected")["key"] == (12345, 678)
    assert deleted == []
    assert _messages(responses)


def test_godel_second_click_deletes_and_stores_undo(monkeypatch):
    session = _session()
    entry = _entry()
    session._godel_enabled = True
    session._godel_selected = {"key": (12345, 678), "entry": dict(entry), "world_guid": int(entry["world_guid"])}
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(godel.DatabaseConnection, "delete_gameobject_spawn", lambda _guid: dict(entry))

    responses = godel.handle_gameobject_click(session, entry)

    assert getattr(session, "_godel_selected") is None
    assert getattr(session, "_godel_undo")["guid"] == 12345
    assert responses[0][0] == "SMSG_UPDATE_OBJECT"


def test_godel_clicking_different_object_replaces_selection(monkeypatch):
    session = _session()
    first = _entry(guid=1, entry=10, name="First")
    second = _entry(guid=2, entry=20, name="Second")
    session._godel_enabled = True
    session._godel_selected = {"key": (1, 10), "entry": first, "world_guid": int(first["world_guid"])}
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(second))

    responses = godel.handle_gameobject_click(session, second)

    assert getattr(session, "_godel_selected")["key"] == (2, 20)
    assert getattr(session, "_godel_undo", None) is None
    assert _messages(responses)


def test_godel_off_clears_selection():
    session = _session()
    session._godel_enabled = True
    session._godel_selected = {"key": (1, 1)}

    godel.disable(session)

    assert getattr(session, "_godel_enabled") is False
    assert getattr(session, "_godel_selected") is None


def test_godel_undo_restores_latest_deleted(monkeypatch):
    session = _session()
    entry = _entry()
    session._godel_undo = dict(entry)
    restored: list[int] = []
    monkeypatch.setattr(godel.DatabaseConnection, "restore_gameobject_spawn", lambda value: restored.append(value["guid"]) or True)
    monkeypatch.setattr(godel, "_create_payload", lambda _session, _entry: ("SMSG_UPDATE_OBJECT", b"create"))

    responses = godel.undo(session)

    assert restored == [12345]
    assert getattr(session, "_godel_undo") is None
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"create")


def test_godel_rejects_transports(monkeypatch):
    session = _session()
    entry = _entry(type=15)
    session._godel_enabled = True
    session._godel_selected = {"key": (12345, 678), "entry": dict(entry), "world_guid": int(entry["world_guid"])}
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))

    responses = godel.handle_gameobject_click(session, entry)

    assert getattr(session, "_godel_undo", None) is None
    assert _messages(responses)


def test_gameobject_use_in_delete_mode_does_not_select(monkeypatch):
    session = _session()
    entry = _entry()
    session._godel_enabled = True
    monkeypatch.setattr(entities, "_decode_gameobject_use_guid", lambda *_args, **_kwargs: int(entry["world_guid"]))
    monkeypatch.setattr(entities, "_find_visible_gameobject", lambda *_args, **_kwargs: dict(entry))
    monkeypatch.setattr(entities, "activate_gameobject_teleport", lambda *_args, **_kwargs: None)

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(name="CMSG_GAME_OBJ_USE", payload=b"", decoded={}),
    )

    assert code == 0
    assert responses is None
    assert getattr(session, "_godel_selected", None) is None


def test_gameobject_use_logs_godel_probe(monkeypatch):
    session = _session()
    entry = _entry()
    session._godel_enabled = True
    log_messages: list[str] = []
    monkeypatch.setattr(entities.Logger, "info", lambda message, *args: log_messages.append(message % args if args else message))
    monkeypatch.setattr(entities, "_decode_gameobject_use_guid", lambda *_args, **_kwargs: int(entry["world_guid"]))
    monkeypatch.setattr(entities, "_find_visible_gameobject", lambda *_args, **_kwargs: dict(entry))
    monkeypatch.setattr(entities, "activate_gameobject_teleport", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))

    entities.handle_gameobject_use(
        session,
        SimpleNamespace(name="CMSG_GAME_OBJ_USE", payload=b"", decoded={}),
    )

    assert any("[GoDelProbe] opcode=CMSG_GAME_OBJ_USE" in message for message in log_messages)
    assert any("godel=on" in message for message in log_messages)
    assert any("entry=678" in message for message in log_messages)


def test_gameobject_query_logs_entry_and_godel_mode(monkeypatch):
    session = _session()
    session._godel_enabled = True
    log_messages: list[str] = []
    monkeypatch.setattr(entities.Logger, "info", lambda message, *args: log_messages.append(message % args if args else message))
    monkeypatch.setattr(
        entities.DatabaseConnection,
        "get_gameobject_template",
        lambda _entry: {"entry": 678, "name": "Debug Crate", "type": 5, "displayId": 100},
    )

    code, responses = entities.handle_gameobject_query(
        session,
        SimpleNamespace(name="CMSG_GAMEOBJECT_QUERY", payload=(678).to_bytes(4, "little"), decoded={}),
    )

    assert code == 0
    assert responses is not None
    assert any("[GoDelProbe] opcode=CMSG_GAMEOBJECT_QUERY" in message for message in log_messages)
    assert any("entry=678" in message for message in log_messages)
    assert any("godel=on" in message for message in log_messages)


def test_dispatcher_logs_godel_probe_for_unhandled_object_opcode(monkeypatch):
    session = _session()
    session._godel_enabled = True
    log_messages: list[str] = []
    monkeypatch.setattr(dispatcher.Logger, "info", lambda message, *args: log_messages.append(message % args if args else message))
    monkeypatch.setattr(dispatcher.Logger, "warning", lambda *_args, **_kwargs: None)

    dispatcher.dispatch(
        session,
        "CMSG_GAMEOBJECT_UNKNOWN_DEBUG",
        SimpleNamespace(payload=b"\x01\x02\x03"),
    )

    assert any("dispatcher opcode=CMSG_GAMEOBJECT_UNKNOWN_DEBUG" in message for message in log_messages)
    assert any("handled=false" in message for message in log_messages)


def test_godel_close_first_call_selects_nearest_valid_object(monkeypatch):
    session = _session()
    session._godel_enabled = True
    close_entry = _entry(x=12.0, y=20.0, z=30.0)
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobjects_near", lambda *_args, **_kwargs: [dict(close_entry)])
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(close_entry))

    responses = godel.close(session)

    assert getattr(session, "_godel_selected")["key"] == (12345, 678)
    messages = [payload for opcode, payload in responses if opcode == "SMSG_MESSAGECHAT"]
    assert messages


def test_godel_close_second_call_deletes_same_nearest_object(monkeypatch):
    session = _session()
    session._godel_enabled = True
    close_entry = _entry(x=12.0, y=20.0, z=30.0)
    session._godel_selected = {"key": (12345, 678), "entry": dict(close_entry), "world_guid": int(close_entry["world_guid"])}
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobjects_near", lambda *_args, **_kwargs: [dict(close_entry)])
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(close_entry))
    monkeypatch.setattr(godel.DatabaseConnection, "delete_gameobject_spawn", lambda _guid: dict(close_entry))

    responses = godel.close(session)

    assert getattr(session, "_godel_selected") is None
    assert getattr(session, "_godel_undo")["guid"] == 12345
    assert responses[0][0] == "SMSG_UPDATE_OBJECT"


def test_godel_close_moving_to_another_object_replaces_selection(monkeypatch):
    session = _session()
    session._godel_enabled = True
    first = _entry(guid=1, entry=10, x=12.0, y=20.0, z=30.0)
    second = _entry(guid=2, entry=20, x=11.0, y=20.0, z=30.0)
    session._godel_selected = {"key": (1, 10), "entry": dict(first), "world_guid": int(first["world_guid"])}
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobjects_near", lambda *_args, **_kwargs: [dict(second)])
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(second))

    responses = godel.close(session)

    assert getattr(session, "_godel_selected")["key"] == (2, 20)
    assert getattr(session, "_godel_undo", None) is None
    assert _messages(responses)


def test_godel_close_prefers_object_in_front(monkeypatch):
    session = _session()
    session._godel_enabled = True
    behind = _entry(guid=1, entry=10, x=9.0, y=20.0, z=30.0)
    ahead = _entry(guid=2, entry=20, x=13.0, y=20.0, z=30.0)
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobjects_near", lambda *_args, **_kwargs: [dict(behind), dict(ahead)])
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(ahead))

    godel.close(session)

    assert getattr(session, "_godel_selected")["key"] == (2, 20)


def test_godel_close_ignores_transports(monkeypatch):
    session = _session()
    session._godel_enabled = True
    transport = _entry(guid=1, entry=10, type=15, x=11.0, y=20.0, z=30.0)
    crate = _entry(guid=2, entry=20, x=12.0, y=20.0, z=30.0)
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobjects_near", lambda *_args, **_kwargs: [dict(transport), dict(crate)])
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(crate))

    godel.close(session)

    assert getattr(session, "_godel_selected")["key"] == (2, 20)


def test_godel_close_reports_no_nearby_object(monkeypatch):
    session = _session()
    session._godel_enabled = True
    session._godel_selected = {"key": (1, 1)}
    monkeypatch.setattr(godel.DatabaseConnection, "get_gameobjects_near", lambda *_args, **_kwargs: [])

    responses = godel.close(session)

    assert getattr(session, "_godel_selected") is None
    assert _messages(responses)
