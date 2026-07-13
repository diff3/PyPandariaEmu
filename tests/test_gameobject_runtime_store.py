#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_store import (
    GameObjectRuntimeStore,
)


def _gameobject(
    *,
    runtime_guid: int = 1001,
    spawn_id: int = 101,
) -> GameObject:
    return GameObject.from_mapping(
        {
            "guid": spawn_id,
            "entry": 200,
            "map_id": 1,
            "x": 10.0,
            "y": 20.0,
            "z": 30.0,
            "orientation": 1.5,
            "size": 1.0,
        },
        runtime_guid=runtime_guid,
    )


def test_store_retains_identical_object_for_both_identity_lookups():
    store = GameObjectRuntimeStore()
    gameobject = _gameobject()

    store.add(gameobject)

    assert store.contains(gameobject.runtime_guid)
    assert store.get(gameobject.runtime_guid) is gameobject
    assert store.get(gameobject.runtime_guid) is store.get(gameobject.runtime_guid)
    assert store.get_by_spawn_id(gameobject.spawn_id) is gameobject
    assert list(store) == [gameobject]


def test_store_removes_runtime_and_spawn_identity_lookups():
    store = GameObjectRuntimeStore()
    gameobject = store.add(_gameobject())

    removed = store.remove(gameobject.runtime_guid)

    assert removed is gameobject
    assert not store.contains(gameobject.runtime_guid)
    assert store.get(gameobject.runtime_guid) is None
    assert store.get_by_spawn_id(gameobject.spawn_id) is None
    assert list(store) == []


def test_store_clear_removes_all_gameobjects():
    store = GameObjectRuntimeStore()
    store.add(_gameobject(runtime_guid=1001, spawn_id=101))
    store.add(_gameobject(runtime_guid=1002, spawn_id=102))

    store.clear()

    assert list(store) == []
    assert store.get(1001) is None
    assert store.get_by_spawn_id(102) is None
