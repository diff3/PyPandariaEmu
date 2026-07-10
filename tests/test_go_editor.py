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
        "search_gameobject_templates": staticmethod(lambda *_args, **_kwargs: []),
        "create_gameobject_spawn": staticmethod(lambda *_args, **_kwargs: None),
        "update_gameobject_spawn_transform": staticmethod(lambda *_args, **_kwargs: None),
    },
)
sys.modules["server.modules.database.DatabaseConnection"] = database_module

from server.modules.handlers.world.features import gameobject_clipboard
from server.modules.handlers.world.features import gameobject_editor
from server.modules.handlers.world.features import gameobject_history
from server.modules.handlers.world.features import go_editor


def _session() -> SimpleNamespace:
    return SimpleNamespace(
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


def _entry(**overrides) -> dict:
    entry = {
        "guid": 12345,
        "entry": 678,
        "world_guid": 0xF110000000003039,
        "map_id": 1,
        "map": 1,
        "spawnMask": 1,
        "phaseId": 0,
        "phaseGroup": 0,
        "x": 12.0,
        "y": 20.0,
        "z": 30.0,
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


def _patch_packets(monkeypatch):
    monkeypatch.setattr(gameobject_editor, "create_payload", lambda _session, _entry: ("SMSG_UPDATE_OBJECT", b"create"))
    monkeypatch.setattr(gameobject_editor, "destroy_payload", lambda _session, _guid: ("SMSG_UPDATE_OBJECT", b"destroy"))
    monkeypatch.setattr(gameobject_editor, "dispatch_to_peers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(gameobject_editor, "add_runtime_references", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(gameobject_editor, "remove_runtime_references", lambda *_args, **_kwargs: None)


def test_find_nearest_editable_gameobject_prefers_front(monkeypatch):
    session = _session()
    behind = _entry(guid=1, entry=10, x=9.0, y=20.0)
    ahead = _entry(guid=2, entry=20, x=13.0, y=20.0)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobjects_near", lambda *_args, **_kwargs: [behind, ahead])
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda guid: dict(ahead if int(guid) == 2 else behind))

    found = gameobject_editor.find_nearest_editable_gameobject(session)

    assert found is not None
    entry, _distance = found
    assert entry["guid"] == 2


def test_find_nearby_default_radius_is_ten_yards(monkeypatch):
    session = _session()
    calls: list[float] = []
    entry = _entry(x=19.0, y=20.0)
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "get_gameobjects_near",
        lambda *_args, **kwargs: calls.append(float(kwargs["radius"])) or [entry],
    )
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))

    nearby = gameobject_editor.find_nearby(session)

    assert calls == [10.0]
    assert nearby


def test_find_nearest_editable_gameobject_ignores_transport(monkeypatch):
    session = _session()
    transport = _entry(guid=1, entry=10, type=15, x=11.0, y=20.0)
    crate = _entry(guid=2, entry=20, x=12.0, y=20.0)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobjects_near", lambda *_args, **_kwargs: [transport, crate])
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda guid: dict(crate if int(guid) == 2 else transport))

    found = gameobject_editor.find_nearest_editable_gameobject(session)

    assert found is not None
    entry, _distance = found
    assert entry["guid"] == 2


def test_go_info_reports_nearest_gameobject(monkeypatch):
    session = _session()
    entry = _entry()
    monkeypatch.setattr(gameobject_editor, "find_nearest_editable_gameobject", lambda _session: (dict(entry), 2.0))

    responses = gameobject_editor.info(session)

    assert _messages(responses)


def test_go_list_uses_supplied_radius(monkeypatch):
    session = _session()
    entry = _entry()
    calls: list[float] = []
    monkeypatch.setattr(gameobject_editor, "find_nearby", lambda _session, radius=10.0: calls.append(radius) or [(dict(entry), 2.0)])

    responses = go_editor.list_nearby_command(session, ["25"])

    assert calls == [25.0]
    assert _messages(responses)


def test_go_search_uses_default_limit_and_formats_results(monkeypatch):
    session = _session()
    calls: list[dict] = []
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "search_gameobject_templates",
        lambda text, *, limit=20: calls.append({"text": text, "limit": limit}) or [
            {"entry": 181310, "name": "Wooden Chair", "type": 7},
            {"entry": 181311, "name": "Small Wooden Chair", "type": 7},
        ],
    )

    responses = go_editor.search(session, ["chair"])

    assert calls == [{"text": "chair", "limit": 20}]
    messages = _messages(responses)
    assert messages


def test_go_search_accepts_limit(monkeypatch):
    session = _session()
    calls: list[dict] = []
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "search_gameobject_templates",
        lambda text, *, limit=20: calls.append({"text": text, "limit": limit}) or [
            {"entry": 181310, "name": "Wooden Chair", "type": 7},
        ],
    )

    go_editor.search(session, ["wooden", "chair", "50"])

    assert calls == [{"text": "wooden chair", "limit": 50}]


def test_go_search_caps_limit_at_100(monkeypatch):
    session = _session()
    calls: list[dict] = []
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "search_gameobject_templates",
        lambda text, *, limit=20: calls.append({"text": text, "limit": limit}) or [
            {"entry": 181310, "name": "Wooden Chair", "type": 7},
        ],
    )

    go_editor.search(session, ["chair", "500"])

    assert calls == [{"text": "chair", "limit": 100}]


def test_go_del_deletes_and_history_can_undo(monkeypatch):
    session = _session()
    entry = _entry()
    _patch_packets(monkeypatch)
    monkeypatch.setattr(gameobject_editor, "find_nearest_editable_gameobject", lambda _session: (dict(entry), 2.0))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "delete_gameobject_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "restore_gameobject_spawn", lambda _entry: True)

    delete_responses = gameobject_editor.delete_nearest(session)
    undo_responses = gameobject_editor.undo(session)

    assert delete_responses[0] == ("SMSG_UPDATE_OBJECT", b"destroy")
    assert undo_responses[0] == ("SMSG_UPDATE_OBJECT", b"create")
    assert any(record["operation"] == "DELETE" for record in gameobject_history.list_history(session))
    assert any(record["operation"] == "UNDO" for record in gameobject_history.list_history(session))


def test_go_undo_without_history_reports_nothing():
    session = _session()

    responses = gameobject_editor.undo(session)

    assert _messages(responses)


def test_go_add_creates_persistent_spawn_and_pushes_history(monkeypatch):
    session = _session()
    created = _entry(guid=999, entry=678, x=session.x, y=session.y, z=session.z)
    calls: list[dict] = []
    _patch_packets(monkeypatch)
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "create_gameobject_spawn",
        lambda entry, **kwargs: calls.append({"entry": entry, **kwargs}) or dict(created),
    )

    responses, result = gameobject_editor.create(session, 678)

    assert result is not None
    assert calls[0]["entry"] == 678
    assert calls[0]["x"] == session.x
    assert calls[0]["orientation"] == session.orientation
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"create")
    assert gameobject_history.list_history(session)[-1]["operation"] == "ADD"


def test_go_move_updates_position_and_pushes_history(monkeypatch):
    session = _session()
    entry = _entry()
    updated = dict(entry, x=session.x, y=session.y, z=session.z)
    calls: list[dict] = []
    _patch_packets(monkeypatch)
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "update_gameobject_spawn_transform",
        lambda guid, **kwargs: calls.append({"guid": guid, **kwargs}) or dict(updated),
    )

    responses, result = gameobject_editor.move(session, entry)

    assert result is not None
    assert calls[0] == {"guid": 12345, "x": 10.0, "y": 20.0, "z": 30.0}
    assert [opcode for opcode, _payload in responses[:2]] == ["SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT"]
    assert gameobject_history.list_history(session)[-1]["operation"] == "MOVE"


def test_go_rotate_updates_orientation_and_pushes_history(monkeypatch):
    session = _session()
    session.orientation = 2.25
    entry = _entry()
    updated = dict(entry, orientation=session.orientation)
    calls: list[dict] = []
    _patch_packets(monkeypatch)
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "update_gameobject_spawn_transform",
        lambda guid, **kwargs: calls.append({"guid": guid, **kwargs}) or dict(updated),
    )

    responses, result = gameobject_editor.rotate(session, entry)

    assert result is not None
    assert calls[0] == {"guid": 12345, "orientation": 2.25}
    assert [opcode for opcode, _payload in responses[:2]] == ["SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT"]
    assert gameobject_history.list_history(session)[-1]["operation"] == "ROTATE"


def test_go_copy_and_place_are_session_local(monkeypatch):
    session_a = _session()
    session_b = _session()
    entry = _entry()
    placed = _entry(guid=999, entry=678, x=session_a.x, y=session_a.y, z=session_a.z)
    _patch_packets(monkeypatch)
    monkeypatch.setattr(gameobject_editor, "find_nearest_editable_gameobject", lambda _session: (dict(entry), 2.0))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "create_gameobject_spawn", lambda *_args, **_kwargs: dict(placed))

    copy_responses = gameobject_clipboard.copy(session_a)
    place_responses = gameobject_clipboard.place(session_a)
    empty_responses = gameobject_clipboard.place(session_b)

    assert _messages(copy_responses)
    assert getattr(session_a, "_go_clipboard")["entry"] == 678
    assert not hasattr(session_b, "_go_clipboard")
    assert place_responses[0] == ("SMSG_UPDATE_OBJECT", b"create")
    assert _messages(empty_responses)
    assert gameobject_history.list_history(session_a)[-1]["operation"] == "PLACE"
    assert gameobject_history.list_history(session_b) == []


def test_go_history_is_session_local():
    session_a = _session()
    session_b = _session()
    gameobject_history.push(session_a, "ADD", _entry())

    assert gameobject_history.list_history(session_a)
    assert gameobject_history.list_history(session_b) == []
    assert _messages(gameobject_editor.history(session_a))


def test_go_place_without_clipboard_reports_nothing_copied():
    session = _session()

    responses = gameobject_clipboard.place(session)

    assert _messages(responses)
