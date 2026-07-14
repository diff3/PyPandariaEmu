#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from server.modules.handlers.world.runtime import (
    Player,
    PlayerRuntimeStore,
    RuntimeObject,
    WorldObject,
    get_player_runtime_store,
    resolve_player_runtime,
)
from server.session.world_session import WorldSession


def test_player_from_session_snapshots_identity_and_geometry_once():
    session = WorldSession(
        player_guid=0x100000000000002A,
        world_guid=0x100000000000002A,
        char_guid=42,
        map_id=530,
        instance_id=7,
        x=101.25,
        y=-202.5,
        z=33.75,
        orientation=1.25,
    )

    player = Player.from_session(session)

    assert Player.__bases__ == (WorldObject,)
    assert isinstance(player, Player)
    assert isinstance(player, WorldObject)
    assert isinstance(player, RuntimeObject)
    assert player.runtime_guid == 0x100000000000002A
    assert player.character_guid == 42
    assert player.map_id == 530
    assert player.instance_id == 7
    assert player.world_position == (101.25, -202.5, 33.75)
    assert player.orientation == 1.25
    assert player.rotation == (0.0, 0.0, 0.0, 1.0)
    assert player.scale == 1.0

    session.map_id = 1
    session.x = 999.0
    session.orientation = 2.5

    assert player.map_id == 530
    assert player.x == 101.25
    assert player.orientation == 1.25


def test_player_runtime_store_uses_character_guid_and_stable_objects():
    store = PlayerRuntimeStore()
    player = Player.from_session(
        WorldSession(
            world_guid=0x100000000000002A,
            char_guid=42,
            map_id=1,
        )
    )

    assert store.add(player) is player
    assert store.contains(42) is True
    assert store.get(42) is player
    assert list(store) == [player]
    assert store.remove(42) is player
    assert store.get(42) is None
    assert store.contains(42) is False

    store.add(player)
    store.clear()

    assert list(store) == []


def test_runtime_package_exports_process_wide_player_store():
    assert get_player_runtime_store() is get_player_runtime_store()


def test_resolve_player_runtime_reuses_store_and_does_not_register_fallback():
    store = get_player_runtime_store()
    store.clear()
    session = WorldSession(
        world_guid=0x100000000000002A,
        char_guid=42,
        map_id=1,
        x=1.0,
        y=2.0,
        z=3.0,
    )

    fallback = resolve_player_runtime(session)

    assert isinstance(fallback, Player)
    assert fallback.character_guid == 42
    assert store.get(42) is None

    stored = Player.from_session(session)
    store.add(stored)
    try:
        assert resolve_player_runtime(session) is stored
    finally:
        store.clear()
