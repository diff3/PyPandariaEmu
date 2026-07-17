#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    },
)
sys.modules["server.modules.database.DatabaseConnection"] = database_module

from server.modules.handlers.world.runtime import gameobject_spawns
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_store import (
    get_gameobject_runtime_store,
)


@pytest.fixture(autouse=True)
def _clear_runtime_store():
    store = get_gameobject_runtime_store()
    store.clear()
    yield
    store.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        realm_id=1,
        map_id=1,
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
        "x": 12.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 1.5,
        "size": 1.0,
        "type": 5,
        "display_id": 100,
        "name": "Debug Crate",
        "flags": 1,
    }
    entry.update(overrides)
    return entry


def _mark_loaded(session, entry):
    world_guid = int(entry["world_guid"])
    session.loaded_gameobjects.add(world_guid)
    session.loaded_gameobject_entries[world_guid] = dict(entry)


def _patch_runtime(monkeypatch, entry):
    world_guid = int(entry["world_guid"])
    monkeypatch.setattr(
        gameobject_spawns.DatabaseConnection,
        "get_gameobject_spawn",
        lambda _spawn_id: dict(entry),
    )
    monkeypatch.setattr(
        gameobject_spawns,
        "build_gameobject_destroy_response",
        lambda _session, _guid, **_kwargs: (
            "SMSG_UPDATE_OBJECT",
            b"destroy",
        ),
    )
    def fake_visibility(target, loaded_guids=None):
        loaded_guids.add(world_guid)
        target.loaded_gameobject_entries[world_guid] = dict(entry)
        return [("SMSG_UPDATE_OBJECT", b"create")]

    monkeypatch.setattr(gameobject_spawns, "build_database_gameobject_responses", fake_visibility)


def test_runtime_object_reuses_preloaded_instance_without_duplicate(monkeypatch):
    session = _session()
    entry = _entry()
    stored = GameObject.from_mapping(
        entry,
        runtime_guid=int(entry["world_guid"]),
    )
    get_gameobject_runtime_store().add(stored)
    original_from_mapping = GameObject.from_mapping
    constructed = []

    def track_construction(cls, mapping, *, runtime_guid=0):
        constructed.append((mapping, runtime_guid))
        return original_from_mapping(mapping, runtime_guid=runtime_guid)

    monkeypatch.setattr(
        GameObject,
        "from_mapping",
        classmethod(track_construction),
    )

    first = gameobject_spawns._runtime_object(session, dict(entry))
    second = gameobject_spawns._runtime_object(session, dict(entry))

    assert first is stored
    assert second is stored
    assert first is second
    assert constructed == []


def test_runtime_object_falls_back_when_store_has_no_spawn(monkeypatch):
    session = _session()
    entry = _entry()
    original_from_mapping = GameObject.from_mapping
    constructed = []

    def track_construction(cls, mapping, *, runtime_guid=0):
        constructed.append((mapping, runtime_guid))
        return original_from_mapping(mapping, runtime_guid=runtime_guid)

    monkeypatch.setattr(
        GameObject,
        "from_mapping",
        classmethod(track_construction),
    )

    runtime_object = gameobject_spawns._runtime_object(session, dict(entry))

    assert runtime_object is not None
    assert runtime_object.runtime_guid == int(entry["world_guid"])
    assert runtime_object.spawn_id == int(entry["guid"])
    assert len(constructed) == 1


def test_runtime_object_falls_back_when_authoritative_mapping_changed(monkeypatch):
    session = _session()
    cached_entry = _entry(x=12.0)
    authoritative_entry = _entry(x=50.0)
    stored = GameObject.from_mapping(
        cached_entry,
        runtime_guid=int(cached_entry["world_guid"]),
    )
    get_gameobject_runtime_store().add(stored)
    original_from_mapping = GameObject.from_mapping
    constructed = []

    def track_construction(cls, mapping, *, runtime_guid=0):
        constructed.append((mapping, runtime_guid))
        return original_from_mapping(mapping, runtime_guid=runtime_guid)

    monkeypatch.setattr(
        GameObject,
        "from_mapping",
        classmethod(track_construction),
    )

    runtime_object = gameobject_spawns._runtime_object(
        session,
        authoritative_entry,
    )

    assert runtime_object is not None
    assert runtime_object is not stored
    assert runtime_object.x == 50.0
    assert stored.x == 12.0
    assert len(constructed) == 1


def test_replace_persistent_gameobject_destroys_old_then_refreshes_visibility(monkeypatch):
    session = _session()
    peer = _session()
    peer.sent = []
    peer.send_response = lambda responses: peer.sent.extend(responses)
    session.global_state = SimpleNamespace(sessions=[session, peer])
    peer.global_state = session.global_state
    old = _entry(x=12.0)
    new = _entry(x=50.0)
    _mark_loaded(session, old)
    _mark_loaded(peer, old)
    _patch_runtime(monkeypatch, new)

    result = gameobject_spawns.replace_persistent_gameobject(session, old["guid"], old_spawn=old)

    assert result.operation == "replace"
    assert result.destroy_sent == 2
    assert result.create_sent == 2
    assert result.responses == [
        ("SMSG_UPDATE_OBJECT", b"destroy"),
        ("SMSG_UPDATE_OBJECT", b"create"),
    ]
    assert peer.sent == [
        ("SMSG_UPDATE_OBJECT", b"destroy"),
        ("SMSG_UPDATE_OBJECT", b"create"),
    ]
    assert session.loaded_gameobject_entries[int(new["world_guid"])]["x"] == 50.0
    assert peer.loaded_gameobject_entries[int(new["world_guid"])]["x"] == 50.0


def test_spawn_persistent_gameobject_uses_normal_visibility_refresh(monkeypatch):
    session = _session()
    entry = _entry(guid=99, world_guid=0xF110000000000099)
    _patch_runtime(monkeypatch, entry)

    result = gameobject_spawns.spawn_persistent_gameobject(session, entry["guid"])

    assert result.operation == "spawn"
    assert result.destroy_sent == 0
    assert result.create_sent == 1
    assert result.responses == [("SMSG_UPDATE_OBJECT", b"create")]
    assert int(entry["world_guid"]) in session.loaded_gameobjects


def test_despawn_persistent_gameobject_clears_visibility_without_create(monkeypatch):
    session = _session()
    entry = _entry()
    _mark_loaded(session, entry)
    _patch_runtime(monkeypatch, entry)

    result = gameobject_spawns.despawn_persistent_gameobject(
        session,
        entry["guid"],
        existing_spawn=entry,
    )

    assert result.operation == "despawn"
    assert result.destroy_sent == 1
    assert result.create_sent == 0
    assert result.responses == [("SMSG_UPDATE_OBJECT", b"destroy")]
    assert int(entry["world_guid"]) not in session.loaded_gameobjects
    assert int(entry["world_guid"]) not in session.loaded_gameobject_entries
