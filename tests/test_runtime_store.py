#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass

from server.modules.handlers.world.runtime.creature_store import (
    CreatureRuntimeStore,
)
from server.modules.handlers.world.runtime.gameobject_store import (
    GameObjectRuntimeStore,
)
from server.modules.handlers.world.runtime.runtime_store import RuntimeStore
from server.modules.handlers.world.runtime.spawned_world_object import (
    SpawnedWorldObject,
    resolve_spawned_world_object,
)


@dataclass
class StoredRuntimeEntry:
    runtime_guid: int
    spawn_id: int


def test_concrete_runtime_stores_share_generic_index_implementation():
    assert issubclass(GameObjectRuntimeStore, RuntimeStore)
    assert issubclass(CreatureRuntimeStore, RuntimeStore)
    assert "add" not in GameObjectRuntimeStore.__dict__
    assert "add" not in CreatureRuntimeStore.__dict__


def test_spawned_world_object_resolver_reuses_or_constructs_as_needed():
    mapping = {
        "guid": 101,
        "entry": 200,
        "map_id": 1,
        "x": 10.0,
        "y": 20.0,
        "z": 30.0,
    }
    store = RuntimeStore[SpawnedWorldObject]()
    stored = store.add(
        SpawnedWorldObject.from_mapping(mapping, runtime_guid=1001)
    )
    fallback_calls = []

    def construct_fallback(data, *, runtime_guid=0):
        fallback_calls.append((data, runtime_guid))
        return SpawnedWorldObject.from_mapping(
            data,
            runtime_guid=runtime_guid,
        )

    reused = resolve_spawned_world_object(
        mapping,
        runtime_guid=1001,
        store=store,
        snapshot_compatible=lambda *_args, **_kwargs: True,
        fallback_factory=construct_fallback,
    )
    fallback = resolve_spawned_world_object(
        mapping,
        runtime_guid=1001,
        store=store,
        snapshot_compatible=lambda *_args, **_kwargs: False,
        fallback_factory=construct_fallback,
    )

    assert reused is stored
    assert fallback is not stored
    assert fallback.runtime_guid == 1001
    assert fallback_calls == [(mapping, 1001)]


def test_runtime_store_indexes_and_removes_one_object_by_both_identities():
    store = RuntimeStore[StoredRuntimeEntry]()
    entry = StoredRuntimeEntry(runtime_guid=1001, spawn_id=101)

    assert store.add(entry) is entry
    assert store.contains(1001)
    assert store.get(1001) is entry
    assert store.get_by_spawn_id(101) is entry
    assert list(store) == [entry]

    assert store.remove(1001) is entry
    assert not store.contains(1001)
    assert store.get_by_spawn_id(101) is None


def test_runtime_store_replaces_conflicting_runtime_and_spawn_identities():
    store = RuntimeStore[StoredRuntimeEntry]()
    first = store.add(StoredRuntimeEntry(runtime_guid=1001, spawn_id=101))
    second = store.add(StoredRuntimeEntry(runtime_guid=1001, spawn_id=102))

    assert store.get(1001) is second
    assert store.get_by_spawn_id(101) is None
    assert store.get_by_spawn_id(102) is second

    third = store.add(StoredRuntimeEntry(runtime_guid=1003, spawn_id=102))

    assert store.get(1001) is None
    assert store.get(1003) is third
    assert store.get_by_spawn_id(102) is third
    assert first is not second


def test_runtime_store_clear_removes_all_indexes():
    store = RuntimeStore[StoredRuntimeEntry]()
    store.add(StoredRuntimeEntry(runtime_guid=1001, spawn_id=101))
    store.add(StoredRuntimeEntry(runtime_guid=1002, spawn_id=102))

    store.clear()

    assert list(store) == []
    assert store.get(1001) is None
    assert store.get_by_spawn_id(102) is None
