#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from server.modules.handlers.world.runtime.creature import Creature
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.runtime_object import RuntimeObject
from server.modules.handlers.world.runtime.spawned_world_object import (
    SpawnedWorldObject,
)
from server.modules.handlers.world.runtime.world_object import WorldObject


def runtime_object_at(
    x: float,
    y: float,
    z: float,
    *,
    map_id: int = 1,
    instance_id: int = 0,
) -> RuntimeObject:
    """Create generic runtime geometry without GameObject-specific state."""
    return RuntimeObject(
        runtime_guid=0,
        map_id=map_id,
        instance_id=instance_id,
        x=x,
        y=y,
        z=z,
        orientation=0.0,
        rotation=(0.0, 0.0, 0.0, 1.0),
        scale=1.0,
    )


def test_gameobject_inherits_shared_runtime_identity_and_transform():
    gameobject = GameObject.from_mapping(
        {
            "guid": 123,
            "entry": 456,
            "map": 1,
            "instance_id": 7,
            "x": 10.0,
            "y": 20.0,
            "z": 30.0,
            "orientation": 1.5,
            "rotation0": 0.1,
            "rotation1": 0.2,
            "rotation2": 0.3,
            "rotation3": 0.9,
            "size": 1.25,
            "display_id": 3015,
            "state": 1,
            "flags": 40,
            "faction": 35,
            "artkit": 7,
            "animprogress": 255,
            "type": 5,
        },
        runtime_guid=0xF11000000000007B,
    )

    assert GameObject.__bases__ == (SpawnedWorldObject,)
    assert SpawnedWorldObject.__bases__ == (WorldObject,)
    assert WorldObject.__bases__ == (RuntimeObject,)
    assert isinstance(gameobject, SpawnedWorldObject)
    assert isinstance(gameobject, WorldObject)
    assert isinstance(gameobject, RuntimeObject)
    assert gameobject.runtime_guid == 0xF11000000000007B
    assert gameobject.spawn_id == 123
    assert gameobject.entry == 456
    assert gameobject.map_id == 1
    assert gameobject.instance_id == 7
    assert gameobject.world_position == (10.0, 20.0, 30.0)
    assert gameobject.orientation == 1.5
    assert gameobject.rotation == (0.1, 0.2, 0.3, 0.9)
    assert gameobject.scale == 1.25
    assert gameobject.display_id == 3015
    assert gameobject.state == 1
    assert gameobject.flags == 40
    assert gameobject.faction == 35
    assert gameobject.art_kit == 7
    assert gameobject.animation_progress == 255
    assert gameobject.gameobject_type == 5


def test_gameobject_runtime_snapshot_retains_no_mapping_reference():
    mapping = {
        "guid": 123,
        "entry": 456,
        "map_id": 1,
        "x": 10.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 1.5,
        "size": 1.25,
        "display_id": 3015,
        "state": 1,
        "flags": 40,
        "faction": 35,
        "artkit": 7,
        "animprogress": 255,
        "type": 5,
    }
    gameobject = GameObject.from_mapping(mapping, runtime_guid=789)

    mapping.update(
        display_id=0,
        state=0,
        flags=0,
        faction=0,
        artkit=0,
        animprogress=0,
        type=0,
    )

    assert gameobject.display_id == 3015
    assert gameobject.state == 1
    assert gameobject.flags == 40
    assert gameobject.faction == 35
    assert gameobject.art_kit == 7
    assert gameobject.animation_progress == 255
    assert gameobject.gameobject_type == 5


def test_gameobject_setters_mutate_only_runtime_state():
    mapping = {
        "guid": 123,
        "entry": 456,
        "map_id": 1,
        "x": 10.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 1.5,
        "rotation0": 0.1,
        "rotation1": 0.2,
        "rotation2": 0.3,
        "rotation3": 0.9,
        "size": 1.25,
        "display_id": 3015,
        "state": 1,
        "flags": 40,
        "faction": 35,
        "artkit": 7,
        "animprogress": 255,
        "type": 5,
    }
    persistent_snapshot = dict(mapping)
    gameobject = GameObject.from_mapping(mapping, runtime_guid=789)

    gameobject.set_position(11.0, 22.0, 33.0)
    gameobject.set_orientation(2.5)
    gameobject.set_rotation((0.4, 0.3, 0.2, 0.8))
    gameobject.set_scale(1.75)
    gameobject.set_state(2)
    gameobject.set_flags(17)
    gameobject.set_display_id(4321)
    gameobject.set_faction(14)
    gameobject.set_art_kit(9)
    gameobject.set_animation_progress(127)
    gameobject.set_gameobject_type(3)

    assert gameobject.world_position == (11.0, 22.0, 33.0)
    assert gameobject.orientation == 2.5
    assert gameobject.rotation == (0.4, 0.3, 0.2, 0.8)
    assert gameobject.scale == 1.75
    assert gameobject.state == 2
    assert gameobject.flags == 17
    assert gameobject.display_id == 4321
    assert gameobject.faction == 14
    assert gameobject.art_kit == 9
    assert gameobject.animation_progress == 127
    assert gameobject.gameobject_type == 3
    assert mapping == persistent_snapshot


def test_spawned_world_object_constructs_persistent_identity():
    spawned = SpawnedWorldObject.from_mapping(
        {
            "guid": "123",
            "entry": "456",
            "map": 1,
            "x": 10.0,
            "y": 20.0,
            "z": 30.0,
        },
        runtime_guid=789,
    )

    assert spawned.runtime_guid == 789
    assert spawned.entry == 456
    assert spawned.spawn_id == 123
    assert spawned.map_id == 1
    assert spawned.world_position == (10.0, 20.0, 30.0)


def test_creature_inherits_shared_runtime_identity_and_transform():
    creature = Creature.from_mapping(
        {
            "guid": 321,
            "entry": 654,
            "map_id": 530,
            "instance_id": 9,
            "x": 11.0,
            "y": 22.0,
            "z": 33.0,
            "orientation": 2.5,
            "rotation0": 0.4,
            "rotation1": 0.3,
            "rotation2": 0.2,
            "rotation3": 0.8,
            "size": 1.5,
        },
        runtime_guid=0xF130000000000141,
    )

    assert Creature.__bases__ == (SpawnedWorldObject,)
    assert isinstance(creature, SpawnedWorldObject)
    assert isinstance(creature, WorldObject)
    assert isinstance(creature, RuntimeObject)
    assert creature.runtime_guid == 0xF130000000000141
    assert creature.spawn_id == 321
    assert creature.entry == 654
    assert creature.map_id == 530
    assert creature.instance_id == 9
    assert creature.world_position == (11.0, 22.0, 33.0)
    assert creature.orientation == 2.5
    assert creature.rotation == (0.4, 0.3, 0.2, 0.8)
    assert creature.scale == 1.5


def test_creature_uses_runtime_object_transform_and_distance_helpers():
    first = Creature.from_mapping(
        {
            "guid": 1,
            "entry": 10,
            "map": 1,
            "instance_id": 2,
            "x": 1.0,
            "y": 2.0,
            "z": 3.0,
            "orientation": 0.75,
        }
    )
    second = Creature.from_mapping(
        {
            "guid": 2,
            "entry": 20,
            "map": 1,
            "instance_id": 2,
            "x": 4.0,
            "y": 6.0,
            "z": 15.0,
        }
    )

    assert first.transform == ((1.0, 2.0, 3.0), 0.75, 1.0)
    assert first.distance_squared(second) == 169.0
    assert first.distance_to(second) == 13.0
    assert first.same_map(second)
    assert first.same_instance(second)


def test_runtime_object_preserves_existing_mapping_defaults_and_aliases():
    runtime_object = RuntimeObject.from_mapping(
        {
            "map": 530,
            "map_id": 0,
            "x": None,
            "size": None,
        }
    )

    assert runtime_object.runtime_guid == 0
    assert runtime_object.map_id == 530
    assert runtime_object.instance_id == 0
    assert runtime_object.transform == ((0.0, 0.0, 0.0), 0.0, 1.0)


def test_runtime_object_exposes_generic_position_rotation_and_transform():
    runtime_object = RuntimeObject(
        runtime_guid=10,
        map_id=40,
        instance_id=50,
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.75,
        rotation=(0.1, 0.2, 0.3, 0.9),
        scale=1.25,
    )

    assert runtime_object.world_position == (1.0, 2.0, 3.0)
    assert runtime_object.rotation == (0.1, 0.2, 0.3, 0.9)
    assert runtime_object.transform == ((1.0, 2.0, 3.0), 0.75, 1.25)


def test_runtime_object_calculates_three_dimensional_distance():
    first = runtime_object_at(1.0, 2.0, 3.0)
    second = runtime_object_at(4.0, 6.0, 15.0)

    assert first.distance_squared(second) == 169.0
    assert first.distance_to(second) == 13.0
    assert second.distance_squared(first) == 169.0
    assert second.distance_to(first) == 13.0


def test_runtime_object_compares_map_identity():
    runtime_object = runtime_object_at(0.0, 0.0, 0.0, map_id=1)
    same_map = runtime_object_at(10.0, 20.0, 30.0, map_id=1)
    other_map = runtime_object_at(0.0, 0.0, 0.0, map_id=530)

    assert runtime_object.same_map(same_map)
    assert not runtime_object.same_map(other_map)


def test_runtime_object_compares_complete_map_instance_identity():
    runtime_object = runtime_object_at(
        0.0,
        0.0,
        0.0,
        map_id=1,
        instance_id=7,
    )
    same_instance = runtime_object_at(
        10.0,
        20.0,
        30.0,
        map_id=1,
        instance_id=7,
    )
    other_instance = runtime_object_at(
        0.0,
        0.0,
        0.0,
        map_id=1,
        instance_id=8,
    )
    same_instance_id_on_other_map = runtime_object_at(
        0.0,
        0.0,
        0.0,
        map_id=530,
        instance_id=7,
    )

    assert runtime_object.same_instance(same_instance)
    assert not runtime_object.same_instance(other_instance)
    assert not runtime_object.same_instance(same_instance_id_on_other_map)
