from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

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
        "update_gameobject_spawn_scale": staticmethod(lambda *_args, **_kwargs: None),
        "update_gameobject_template_size": staticmethod(lambda *_args, **_kwargs: False),
        "get_creature_spawn": staticmethod(lambda _guid: None),
        "get_creatures_near": staticmethod(lambda *args, **kwargs: []),
        "get_creature_template": staticmethod(lambda _entry: None),
        "search_creature_templates": staticmethod(lambda *_args, **_kwargs: []),
        "create_creature_spawn": staticmethod(lambda *_args, **_kwargs: None),
        "delete_creature_spawn": staticmethod(lambda _guid: None),
        "restore_creature_spawn": staticmethod(lambda _entry: False),
        "update_creature_spawn_transform": staticmethod(lambda *_args, **_kwargs: None),
    },
)
sys.modules["server.modules.database.DatabaseConnection"] = database_module

from server.modules.handlers.world.features import go_editor
from server.modules.handlers.world.features import npc_editor
from server.modules.handlers.world.features.world_editor import clipboard as gameobject_clipboard
from server.modules.handlers.world.features.world_editor import creature_editor
from server.modules.handlers.world.features.world_editor import gameobject_editor
from server.modules.handlers.world.features.world_editor import history as gameobject_history
from server.modules.handlers.world.features.world_editor import selection
from server.modules.handlers.world.runtime.creature_store import (
    get_creature_runtime_store,
)
from server.modules.handlers.world.runtime.gameobject_store import (
    get_gameobject_runtime_store,
)


@pytest.fixture(autouse=True)
def _clear_gameobject_runtime_store():
    gameobject_store = get_gameobject_runtime_store()
    creature_store = get_creature_runtime_store()
    gameobject_store.clear()
    creature_store.clear()
    yield
    gameobject_store.clear()
    creature_store.clear()


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


def _peer_session() -> SimpleNamespace:
    peer = _session()
    peer.sent = []
    peer.send_response = lambda responses: peer.sent.extend(responses)
    return peer


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
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "DatabaseConnection",
        gameobject_editor.DatabaseConnection,
    )
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "build_gameobject_destroy_response",
        lambda _session, _guid, **_kwargs: (
            "SMSG_UPDATE_OBJECT",
            b"destroy",
        ),
    )
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "build_database_gameobject_responses",
        lambda *_args, **_kwargs: [("SMSG_UPDATE_OBJECT", b"create")],
    )
    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "_create_collision", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "_remove_collision", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "_invalidate_geometry_caches", lambda: None)


def _mark_gameobject_loaded(session, entry):
    world_guid = int(entry["world_guid"])
    session.loaded_gameobjects.add(world_guid)
    session.loaded_gameobject_entries[world_guid] = dict(entry)


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
    assert selection.get_selection(session) is None


def test_go_list_uses_supplied_radius(monkeypatch):
    session = _session()
    entry = _entry()
    calls: list[float] = []
    monkeypatch.setattr(gameobject_editor, "find_nearby", lambda _session, radius=10.0: calls.append(radius) or [(dict(entry), 2.0)])

    responses = go_editor.list_nearby_command(session, ["25"])

    assert calls == [25.0]
    assert _messages(responses)
    assert selection.get_selection(session) is None


def test_go_select_sets_persistent_selection(monkeypatch):
    session = _session()
    entry = _entry()
    monkeypatch.setattr(gameobject_editor, "find_nearest_editable_gameobject", lambda _session: (dict(entry), 2.0))

    responses = go_editor.select(session, [])

    assert _messages(responses)
    selected = selection.get_selection(session, "GameObject")
    assert selected is not None
    assert selected["spawn_id"] == 12345
    assert selected["entry"] == 678


def test_go_select_by_spawnid_uses_database(monkeypatch):
    session = _session()
    entry = _entry(guid=888)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda guid: dict(entry) if int(guid) == 888 else None)

    responses = go_editor.select(session, ["888"])

    assert _messages(responses)
    selected = selection.get_selection(session, "GameObject")
    assert selected is not None
    assert selected["spawn_id"] == 888


def test_go_current_and_clear_use_persistent_selection(monkeypatch):
    session = _session()
    entry = _entry()
    selection.selection_from_gameobject(session, entry)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))

    current = go_editor.current(session)
    cleared = go_editor.clear(session)

    assert _messages(current)
    assert _messages(cleared)
    assert selection.get_selection(session) is None


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
    _mark_gameobject_loaded(session, entry)
    selection.selection_from_gameobject(session, entry)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "delete_gameobject_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "restore_gameobject_spawn", lambda _entry: True)

    delete_responses = gameobject_editor.delete_nearest(session)
    undo_responses = gameobject_editor.undo(session)

    assert delete_responses[0] == ("SMSG_UPDATE_OBJECT", b"destroy")
    assert undo_responses[0] == ("SMSG_UPDATE_OBJECT", b"create")
    assert any(record["operation"] == "DELETE" for record in gameobject_history.list_history(session))
    assert any(record["operation"] == "UNDO" for record in gameobject_history.list_history(session))
    assert selection.get_selection(session) is None


def test_go_del_without_selection_deletes_nearest_gameobject(monkeypatch):
    session = _session()
    entry = _entry()
    _patch_packets(monkeypatch)
    _mark_gameobject_loaded(session, entry)
    monkeypatch.setattr(gameobject_editor, "find_nearest_editable_gameobject", lambda _session: (dict(entry), 2.0))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "delete_gameobject_spawn", lambda _guid: dict(entry))

    responses = gameobject_editor.delete_nearest(session)

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"destroy")
    assert any(b"Debug Crate" in payload for payload in _messages(responses))
    assert gameobject_history.list_history(session)[-1]["operation"] == "DELETE"
    assert selection.get_selection(session) is None


def test_go_del_ignores_creature_selection_and_preserves_it_on_fallback(monkeypatch):
    session = _session()
    entry = _entry(guid=777)
    _patch_packets(monkeypatch)
    _mark_gameobject_loaded(session, entry)
    selection.selection_from_creature(session, {"guid": 44, "entry": 55})
    monkeypatch.setattr(gameobject_editor, "find_nearest_editable_gameobject", lambda _session: (dict(entry), 2.0))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "delete_gameobject_spawn", lambda _guid: dict(entry))

    responses = gameobject_editor.delete_nearest(session)

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"destroy")
    assert selection.get_selection(session, "Creature") is not None
    assert selection.get_selection(session, "GameObject") is None


def test_go_editing_requires_selection():
    session = _session()

    assert _messages(gameobject_editor.move_nearest(session))
    assert _messages(gameobject_editor.rotate_nearest(session))
    assert _messages(gameobject_clipboard.copy(session))


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
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(created))

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
    _mark_gameobject_loaded(session, entry)
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "update_gameobject_spawn_transform",
        lambda guid, **kwargs: calls.append({"guid": guid, **kwargs}) or dict(updated),
    )
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(updated))

    responses, result = gameobject_editor.move(session, entry)

    assert result is not None
    assert calls[0] == {"guid": 12345, "x": 10.0, "y": 20.0, "z": 30.0}
    assert [opcode for opcode, _payload in responses[:2]] == ["SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT"]
    assert gameobject_history.list_history(session)[-1]["operation"] == "MOVE"


def test_repeated_editor_moves_mutate_same_long_lived_runtime_object(monkeypatch):
    session = _session()
    entry = _entry()
    persisted = dict(entry)
    runtime_objects = []
    _patch_packets(monkeypatch)
    _mark_gameobject_loaded(session, entry)

    def update_transform(_guid, **values):
        persisted.update(values)
        return dict(persisted)

    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "update_gameobject_spawn_transform",
        update_transform,
    )
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "get_gameobject_spawn",
        lambda _guid: dict(persisted),
    )
    world_guid = int(entry["world_guid"])

    def refresh_visibility(target):
        target.loaded_gameobjects.add(world_guid)
        target.loaded_gameobject_entries[world_guid] = dict(persisted)
        return [("SMSG_UPDATE_OBJECT", b"create")]

    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "_visibility_refresh_for_session",
        refresh_visibility,
    )
    original_replace = gameobject_editor.gameobject_runtime.replace_persistent_gameobject

    def record_replace(*args, **kwargs):
        result = original_replace(*args, **kwargs)
        runtime_objects.append(
            get_gameobject_runtime_store().get_by_spawn_id(entry["guid"])
        )
        return result

    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "replace_persistent_gameobject",
        record_replace,
    )

    first_responses, first_updated = gameobject_editor.move(session, entry)
    session.x, session.y, session.z = 40.0, 50.0, 60.0
    second_responses, second_updated = gameobject_editor.move(
        session,
        dict(first_updated),
    )

    assert first_updated is not None
    assert second_updated is not None
    assert runtime_objects[0] is runtime_objects[1]
    assert runtime_objects[1].world_position == (40.0, 50.0, 60.0)
    assert [payload for _opcode, payload in first_responses[:2]] == [
        b"destroy",
        b"create",
    ]
    assert [payload for _opcode, payload in second_responses[:2]] == [
        b"destroy",
        b"create",
    ]


def test_go_move_broadcasts_live_recreate_to_loaded_peer(monkeypatch):
    session = _session()
    peer = _peer_session()
    entry = _entry()
    updated = dict(entry, x=session.x, y=session.y, z=session.z)
    world_guid = int(entry["world_guid"])
    session.global_state = SimpleNamespace(sessions=[session, peer])
    peer.global_state = session.global_state
    _mark_gameobject_loaded(session, entry)
    _mark_gameobject_loaded(peer, entry)
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "DatabaseConnection",
        gameobject_editor.DatabaseConnection,
    )
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "build_gameobject_destroy_response",
        lambda _session, _guid, **_kwargs: (
            "SMSG_UPDATE_OBJECT",
            b"destroy",
        ),
    )
    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "_invalidate_geometry_caches", lambda: None)
    def fake_visibility(target, loaded_guids=None):
        loaded_guids.add(world_guid)
        target.loaded_gameobject_entries[world_guid] = dict(updated)
        return [("SMSG_UPDATE_OBJECT", b"create")]
    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "build_database_gameobject_responses", fake_visibility)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "update_gameobject_spawn_transform", lambda _guid, **_kwargs: dict(updated))
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(updated))

    responses, result = gameobject_editor.move(session, entry)

    assert result is not None
    assert responses[:2] == [("SMSG_UPDATE_OBJECT", b"destroy"), ("SMSG_UPDATE_OBJECT", b"create")]
    assert peer.sent == [("SMSG_UPDATE_OBJECT", b"destroy"), ("SMSG_UPDATE_OBJECT", b"create")]
    assert world_guid in peer.loaded_gameobjects
    assert peer.loaded_gameobject_entries[world_guid]["x"] == session.x


def test_go_move_visibility_refresh_runs_for_nearby_peer_without_old_load(monkeypatch):
    session = _session()
    peer = _peer_session()
    entry = _entry()
    updated = dict(entry, x=session.x, y=session.y, z=session.z)
    world_guid = int(entry["world_guid"])
    session.global_state = SimpleNamespace(sessions=[session, peer])
    peer.global_state = session.global_state
    _mark_gameobject_loaded(session, entry)
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "DatabaseConnection",
        gameobject_editor.DatabaseConnection,
    )
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "build_gameobject_destroy_response",
        lambda _session, _guid, **_kwargs: (
            "SMSG_UPDATE_OBJECT",
            b"destroy",
        ),
    )
    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "_invalidate_geometry_caches", lambda: None)
    refresh_sessions: list[object] = []

    def fake_visibility(target, loaded_guids=None):
        refresh_sessions.append(target)
        loaded_guids.add(world_guid)
        target.loaded_gameobject_entries[world_guid] = dict(updated)
        return [("SMSG_UPDATE_OBJECT", b"create")]

    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "build_database_gameobject_responses", fake_visibility)
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "update_gameobject_spawn_transform",
        lambda _guid, **_kwargs: dict(updated),
    )
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(updated))

    responses, result = gameobject_editor.move(session, entry)

    assert result is not None
    assert responses[:2] == [("SMSG_UPDATE_OBJECT", b"destroy"), ("SMSG_UPDATE_OBJECT", b"create")]
    assert peer.sent == [("SMSG_UPDATE_OBJECT", b"create")]
    assert {id(target) for target in refresh_sessions} == {id(session), id(peer)}
    assert world_guid in peer.loaded_gameobjects


def test_go_move_logs_canonical_runtime_reload_lifecycle(monkeypatch):
    session = _session()
    entry = _entry()
    updated = dict(entry, x=session.x, y=session.y, z=session.z)
    actions: list[str] = []
    _patch_packets(monkeypatch)
    _mark_gameobject_loaded(session, entry)
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "update_gameobject_spawn_transform",
        lambda _guid, **_kwargs: dict(updated),
    )
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(updated))
    monkeypatch.setattr(
        gameobject_editor.Logger,
        "info",
        lambda message, *_args, **_kwargs: actions.append(str(message)),
    )

    responses, result = gameobject_editor.move(session, entry)

    assert result is not None
    assert responses[:2] == [("SMSG_UPDATE_OBJECT", b"destroy"), ("SMSG_UPDATE_OBJECT", b"create")]
    global_actions = [
        action
        for action in actions
        if (
            "[PersistentGameObject]" in action
        )
    ]
    assert len(global_actions) == 1
    assert "operation=%s" in global_actions[0]
    assert "destroy_sent=%s" in global_actions[0]
    assert "create_sent=%s" in global_actions[0]


def test_go_rotate_updates_orientation_and_pushes_history(monkeypatch):
    session = _session()
    session.orientation = 2.25
    entry = _entry()
    updated = dict(entry, orientation=session.orientation)
    calls: list[dict] = []
    _patch_packets(monkeypatch)
    _mark_gameobject_loaded(session, entry)
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "update_gameobject_spawn_transform",
        lambda guid, **kwargs: calls.append({"guid": guid, **kwargs}) or dict(updated),
    )
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(updated))

    responses, result = gameobject_editor.rotate(session, entry)

    assert result is not None
    assert calls[0] == {"guid": 12345, "orientation": 2.25}
    assert [opcode for opcode, _payload in responses[:2]] == ["SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT"]
    assert gameobject_history.list_history(session)[-1]["operation"] == "ROTATE"


def test_go_copy_and_place_are_session_local(monkeypatch):
    session_a = _session()
    session_b = _session()
    entry = _entry(size=2.5)
    placed = _entry(guid=999, entry=678, x=session_a.x, y=session_a.y, z=session_a.z, size=2.5)
    create_calls: list[dict] = []
    _patch_packets(monkeypatch)
    selection.selection_from_gameobject(session_a, entry)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "create_gameobject_spawn",
        lambda *_args, **kwargs: create_calls.append(dict(kwargs)) or dict(placed),
    )

    copy_responses = gameobject_clipboard.copy(session_a)
    place_responses = gameobject_clipboard.place(session_a)
    empty_responses = gameobject_clipboard.place(session_b)

    assert _messages(copy_responses)
    stored = gameobject_clipboard.get_clipboard(session_a, "GameObject")
    assert stored is not None
    assert stored["object_type"] == "GameObject"
    assert stored["data"]["entry"] == 678
    assert stored["data"]["size"] == 2.5
    assert create_calls[0]["scale"] == 2.5
    assert gameobject_clipboard.get_clipboard(session_b, "GameObject") is None
    assert place_responses[0] == ("SMSG_UPDATE_OBJECT", b"create")
    assert _messages(empty_responses)
    assert gameobject_history.list_history(session_a)[-1]["operation"] == "PLACE"
    assert gameobject_history.list_history(session_b) == []


def test_go_history_is_session_local():
    session_a = _session()
    session_b = _session()
    record = gameobject_history.push(session_a, "ADD", _entry(), object_type="GameObject", runtime_guid=0xABC)

    assert record["object_type"] == "GameObject"
    assert record["runtime_guid"] == 0xABC
    assert gameobject_history.list_history(session_a)
    assert gameobject_history.list_history(session_b) == []
    assert _messages(gameobject_editor.history(session_a))


def test_history_can_filter_by_object_type():
    session = _session()
    gameobject_history.push(session, "ADD", _entry(), object_type="GameObject")
    gameobject_history.push(session, "ADD", {"entry": 55, "guid": 66, "name": "Wolf"}, object_type="Creature")

    records = gameobject_history.list_history(session, object_type="GameObject")

    assert len(records) == 1
    assert records[0]["object_type"] == "GameObject"


def test_go_place_without_clipboard_reports_nothing_copied():
    session = _session()

    responses = gameobject_clipboard.place(session)

    assert _messages(responses)


def test_go_scale_updates_selected_gameobject(monkeypatch):
    session = _session()
    entry = _entry()
    updated = dict(entry, size=1.75)
    _patch_packets(monkeypatch)
    _mark_gameobject_loaded(session, entry)
    selection.selection_from_gameobject(session, entry)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(entry))
    calls: list[tuple[int, float]] = []
    monkeypatch.setattr(
        gameobject_editor.DatabaseConnection,
        "update_gameobject_spawn_scale",
        lambda spawn_guid, value: calls.append((int(spawn_guid), float(value))) or dict(updated),
    )

    responses = go_editor.scale(session, ["1.75"])

    assert calls == [(12345, 1.75)]
    assert [opcode for opcode, _payload in responses[:2]] == ["SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT"]
    assert gameobject_history.list_history(session)[-1]["operation"] == "SCALE"


def test_go_reload_recreates_selected_runtime_from_database(monkeypatch):
    session = _session()
    old_entry = _entry(x=12.0, y=20.0)
    reloaded = _entry(x=99.0, y=88.0)
    world_guid = int(old_entry["world_guid"])
    session.loaded_gameobjects = {world_guid}
    session.loaded_gameobject_entries = {world_guid: dict(old_entry)}
    selection.selection_from_gameobject(session, old_entry)
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "DatabaseConnection",
        gameobject_editor.DatabaseConnection,
    )
    monkeypatch.setattr(
        gameobject_editor.gameobject_runtime,
        "build_gameobject_destroy_response",
        lambda _session, _guid, **_kwargs: (
            "SMSG_UPDATE_OBJECT",
            b"destroy",
        ),
    )
    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "_invalidate_geometry_caches", lambda: None)
    def fake_visibility(target, loaded_guids=None):
        loaded_guids.add(world_guid)
        target.loaded_gameobject_entries[world_guid] = dict(reloaded)
        return [("SMSG_UPDATE_OBJECT", f"create:{reloaded['x']}".encode())]
    monkeypatch.setattr(gameobject_editor.gameobject_runtime, "build_database_gameobject_responses", fake_visibility)
    monkeypatch.setattr(gameobject_editor.DatabaseConnection, "get_gameobject_spawn", lambda _guid: dict(reloaded))

    responses = go_editor.reload(session)

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"destroy")
    assert responses[1] == ("SMSG_UPDATE_OBJECT", b"create:99.0")
    assert session.loaded_gameobject_entries[world_guid]["x"] == 99.0
    assert selection.get_selection(session, "GameObject")["spawn_id"] == old_entry["guid"]


def test_npc_select_uses_creature_selection(monkeypatch):
    session = _session()
    entry = {
        "guid": 44,
        "entry": 55,
        "map_id": 1,
        "x": 12.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 0.0,
    }
    monkeypatch.setattr(creature_editor, "find_nearest_editable_creature", lambda _session: (dict(entry), 2.0))
    monkeypatch.setattr(creature_editor.DatabaseConnection, "get_creature_template", lambda _entry: {"name": "Wolf", "type": 1})

    responses = npc_editor.select(session, [])

    assert _messages(responses)
    selected = selection.get_selection(session, "Creature")
    assert selected is not None
    assert selected["spawn_id"] == 44
    assert selected["entry"] == 55


def test_repeated_npc_moves_mutate_same_long_lived_creature(monkeypatch):
    session = _session()
    entry = {
        "guid": 44,
        "entry": 55,
        "map_id": 1,
        "x": 12.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 0.0,
        "modelid": 1437,
        "npcflag": 0x2000,
    }
    persisted = dict(entry)
    packet_objects = []
    monkeypatch.setattr(
        creature_editor.DatabaseConnection,
        "get_creature_template",
        lambda _entry: {"name": "Wolf", "modelid1": 1437},
    )

    def update_transform(_guid, **values):
        persisted.update(values)
        return dict(persisted)

    monkeypatch.setattr(
        creature_editor.DatabaseConnection,
        "update_creature_spawn_transform",
        update_transform,
    )
    monkeypatch.setattr(
        creature_editor,
        "destroy_payload",
        lambda _session, _guid: ("SMSG_UPDATE_OBJECT", b"destroy"),
    )
    monkeypatch.setattr(
        creature_editor,
        "create_payload",
        lambda _session, _entry, creature=None: (
            packet_objects.append(creature)
            or ("SMSG_UPDATE_OBJECT", b"create")
        ),
    )
    monkeypatch.setattr(
        creature_editor,
        "dispatch_to_peers",
        lambda *_args, **_kwargs: None,
    )

    first_responses, first_updated = creature_editor.move(session, entry)
    session.x, session.y, session.z = 40.0, 50.0, 60.0
    second_responses, second_updated = creature_editor.move(
        session,
        dict(first_updated),
    )
    stored = get_creature_runtime_store().get_by_spawn_id(entry["guid"])

    assert first_updated is not None
    assert second_updated is not None
    assert packet_objects[0] is packet_objects[1]
    assert stored is packet_objects[0]
    assert stored.world_position == (40.0, 50.0, 60.0)
    assert [payload for _opcode, payload in first_responses[:2]] == [
        b"destroy",
        b"create",
    ]
    assert [payload for _opcode, payload in second_responses[:2]] == [
        b"destroy",
        b"create",
    ]


def test_npc_rotate_mutates_runtime_before_persistence(monkeypatch):
    session = _session()
    session.orientation = 2.25
    entry = {
        "guid": 44,
        "entry": 55,
        "map_id": 1,
        "x": 12.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 0.0,
        "modelid": 1437,
        "npcflag": 0x2000,
    }
    calls = []
    packet_objects = []
    monkeypatch.setattr(
        creature_editor.DatabaseConnection,
        "get_creature_template",
        lambda _entry: {"name": "Wolf", "modelid1": 1437},
    )

    def update_transform(_guid, **values):
        calls.append(dict(values))
        return {**entry, **values}

    monkeypatch.setattr(
        creature_editor.DatabaseConnection,
        "update_creature_spawn_transform",
        update_transform,
    )
    monkeypatch.setattr(
        creature_editor,
        "destroy_payload",
        lambda _session, _guid: ("SMSG_UPDATE_OBJECT", b"destroy"),
    )
    monkeypatch.setattr(
        creature_editor,
        "create_payload",
        lambda _session, _entry, creature=None: (
            packet_objects.append(creature)
            or ("SMSG_UPDATE_OBJECT", b"create")
        ),
    )
    monkeypatch.setattr(
        creature_editor,
        "dispatch_to_peers",
        lambda *_args, **_kwargs: None,
    )

    responses, updated = creature_editor.rotate(session, entry)
    stored = get_creature_runtime_store().get_by_spawn_id(entry["guid"])

    assert updated is not None
    assert calls == [{"orientation": 2.25}]
    assert stored is packet_objects[0]
    assert stored.orientation == 2.25
    assert [payload for _opcode, payload in responses[:2]] == [
        b"destroy",
        b"create",
    ]


def test_gameobject_and_creature_selection_are_exclusive():
    session = _session()
    selection.selection_from_gameobject(session, _entry())
    assert selection.get_selection(session, "GameObject") is not None

    selection.selection_from_creature(session, {"guid": 44, "entry": 55})

    assert selection.get_selection(session, "GameObject") is None
    assert selection.get_selection(session, "Creature") is not None


def test_npc_del_selected_clears_creature_selection(monkeypatch):
    session = _session()
    entry = {
        "guid": 44,
        "entry": 55,
        "map_id": 1,
        "x": 12.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 0.0,
    }
    monkeypatch.setattr(creature_editor, "destroy_payload", lambda _session, _guid: ("SMSG_UPDATE_OBJECT", b"destroy"))
    monkeypatch.setattr(creature_editor, "dispatch_to_peers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(creature_editor, "remove_runtime_references", lambda *_args, **_kwargs: None)
    selection.selection_from_creature(session, entry)
    monkeypatch.setattr(creature_editor.DatabaseConnection, "get_creature_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(creature_editor.DatabaseConnection, "delete_creature_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(creature_editor.DatabaseConnection, "get_creature_template", lambda _entry: {"name": "Wolf", "type": 1})

    responses = creature_editor.delete_selected(session)

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"destroy")
    assert any(b"Wolf" in payload for payload in _messages(responses))
    assert selection.get_selection(session) is None
    assert gameobject_history.list_history(session, object_type="Creature")[-1]["operation"] == "DELETE"


def test_npc_del_without_selection_deletes_nearest_creature(monkeypatch):
    session = _session()
    entry = {
        "guid": 44,
        "entry": 55,
        "map_id": 1,
        "x": 12.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 0.0,
    }
    monkeypatch.setattr(creature_editor, "destroy_payload", lambda _session, _guid: ("SMSG_UPDATE_OBJECT", b"destroy"))
    monkeypatch.setattr(creature_editor, "dispatch_to_peers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(creature_editor, "remove_runtime_references", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(creature_editor, "find_nearest_editable_creature", lambda _session: (dict(entry), 2.0))
    monkeypatch.setattr(creature_editor.DatabaseConnection, "delete_creature_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(creature_editor.DatabaseConnection, "get_creature_template", lambda _entry: {"name": "Wolf", "type": 1})

    responses = creature_editor.delete_selected(session)

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"destroy")
    assert any(b"Wolf" in payload for payload in _messages(responses))
    assert selection.get_selection(session) is None


def test_npc_del_ignores_gameobject_selection_and_preserves_it_on_fallback(monkeypatch):
    session = _session()
    entry = {
        "guid": 44,
        "entry": 55,
        "map_id": 1,
        "x": 12.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 0.0,
    }
    monkeypatch.setattr(creature_editor, "destroy_payload", lambda _session, _guid: ("SMSG_UPDATE_OBJECT", b"destroy"))
    monkeypatch.setattr(creature_editor, "dispatch_to_peers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(creature_editor, "remove_runtime_references", lambda *_args, **_kwargs: None)
    selection.selection_from_gameobject(session, _entry())
    monkeypatch.setattr(creature_editor, "find_nearest_editable_creature", lambda _session: (dict(entry), 2.0))
    monkeypatch.setattr(creature_editor.DatabaseConnection, "delete_creature_spawn", lambda _guid: dict(entry))
    monkeypatch.setattr(creature_editor.DatabaseConnection, "get_creature_template", lambda _entry: {"name": "Wolf", "type": 1})

    responses = creature_editor.delete_selected(session)

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"destroy")
    assert selection.get_selection(session, "GameObject") is not None
    assert selection.get_selection(session, "Creature") is None
