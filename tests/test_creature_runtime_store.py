#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from server.modules.handlers.world.runtime.creature import Creature
from server.modules.handlers.world.runtime.creature_store import (
    CreatureRuntimeStore,
    creature_identity_matches_mapping,
    creature_matches_mapping,
    get_creature_runtime_store,
    resolve_creature_runtime,
)


def _mapping(*, spawn_id: int = 101) -> dict:
    return {
        "guid": spawn_id,
        "entry": 200,
        "map_id": 1,
        "instance_id": 0,
        "x": 10.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": -1.0,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "size": 1.0,
        "modelid": 1437,
        "npcflag": 0x2000,
    }


def _creature(*, runtime_guid: int = 1001, spawn_id: int = 101) -> Creature:
    return Creature.from_mapping(
        _mapping(spawn_id=spawn_id),
        runtime_guid=runtime_guid,
    )


def test_store_retains_identical_creature_for_both_identity_lookups():
    store = CreatureRuntimeStore()
    creature = store.add(_creature())

    assert store.contains(creature.runtime_guid)
    assert store.get(creature.runtime_guid) is creature
    assert store.get_by_spawn_id(creature.spawn_id) is creature
    assert list(store) == [creature]


def test_store_removes_and_clears_creature_identity_lookups():
    store = CreatureRuntimeStore()
    first = store.add(_creature())
    store.add(_creature(runtime_guid=1002, spawn_id=102))

    assert store.remove(first.runtime_guid) is first
    assert store.get_by_spawn_id(first.spawn_id) is None

    store.clear()

    assert list(store) == []
    assert store.get(1002) is None


def test_snapshot_match_includes_identity_transform_and_packet_state():
    mapping = _mapping()
    creature = Creature.from_mapping(mapping, runtime_guid=1001)

    assert creature_matches_mapping(
        creature,
        mapping,
        runtime_guid=1001,
    )

    changed = dict(mapping, modelid=4321)
    assert not creature_matches_mapping(
        creature,
        changed,
        runtime_guid=1001,
    )
    assert creature_identity_matches_mapping(
        creature,
        changed,
        runtime_guid=1001,
    )


def test_resolver_fallback_constructs_when_global_store_has_no_match():
    mapping = _mapping()
    store = get_creature_runtime_store()
    store.clear()
    try:
        resolved = resolve_creature_runtime(mapping, runtime_guid=1001)
    finally:
        store.clear()

    assert isinstance(resolved, Creature)
    assert resolved.runtime_guid == 1001
    assert resolved.spawn_id == 101


def test_resolver_reuses_mutated_runtime_authority_by_identity():
    mapping = _mapping()
    store = get_creature_runtime_store()
    store.clear()
    stored = store.add(Creature.from_mapping(mapping, runtime_guid=1001))
    stored.set_position(40.0, 50.0, 60.0)
    stored.set_display_id(4321)
    stored.set_npc_flags(0x4000)
    try:
        resolved = resolve_creature_runtime(mapping, runtime_guid=1001)
    finally:
        store.clear()

    assert resolved is stored
    assert resolved.world_position == (40.0, 50.0, 60.0)
    assert resolved.display_id == 4321
    assert resolved.npc_flags == 0x4000
