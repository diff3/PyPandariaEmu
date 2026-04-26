#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import FrozenInstanceError

import pytest

from server.modules.handlers.world.state.player_visible_snapshot import (
    build_player_visible_snapshot,
)
from server.session.world_session import MovementState, WorldSession


class _Item:
    def __init__(self, entry: int, display_id: int, inventory_type: int):
        self.entry = entry
        self.display_id = display_id
        self.inventory_type = inventory_type


class _InventoryState:
    def __init__(self):
        self.items = {}

    def get(self, bag: int, slot: int):
        return self.items.get((int(bag), int(slot)))


def test_player_visible_snapshot_reflects_session_state():
    inventory_state = _InventoryState()
    inventory_state.items[(0, 0)] = _Item(1001, 2001, 1)
    inventory_state.items[(0, 4)] = _Item(1005, 2005, 5)

    session = WorldSession()
    session.char_guid = 7
    session.player_name = "Snapshotter"
    session.map_id = 530
    session.zone = 3430
    session.x = 1.25
    session.y = 2.5
    session.z = 3.75
    session.orientation = 4.0
    session.movement_state = MovementState(flags=0x11, flags2=0x02)
    session.is_mounted = True
    session.unit_flags = 0x08000020
    session.mount_display_id = 2404
    session.equipment_cache_raw = [2001, 1, 0, 0]
    session.inventory_state = inventory_state
    session.walk_speed = 2.5
    session.run_speed = 14.0
    session.run_back_speed = 9.0
    session.swim_speed = 9.4
    session.swim_back_speed = 5.0
    session.fly_speed = 14.0
    session.fly_back_speed = 9.0
    session.turn_speed = 3.14
    session.pitch_speed = 3.15

    snapshot = build_player_visible_snapshot(session)

    assert snapshot.guid == 7
    assert snapshot.name == "Snapshotter"
    assert snapshot.map_id == 530
    assert snapshot.zone == 3430
    assert snapshot.x == 1.25
    assert snapshot.y == 2.5
    assert snapshot.z == 3.75
    assert snapshot.orientation == 4.0
    assert snapshot.movement_flags == 0x11
    assert snapshot.movement_flags2 == 0x02
    assert snapshot.is_mounted is True
    assert snapshot.unit_flags == 0x08000020
    assert snapshot.mount_display_id == 2404
    assert snapshot.equipment_cache_raw == (2001, 1, 0, 0)
    assert snapshot.visible_equipment[0].entry == 1001
    assert snapshot.visible_equipment[0].display_id == 2001
    assert snapshot.visible_equipment[0].inventory_type == 1
    assert snapshot.visible_equipment[4].entry == 1005
    assert snapshot.visible_equipment[4].display_id == 2005
    assert snapshot.visible_equipment[4].inventory_type == 5
    assert snapshot.run_speed == 14.0
    assert snapshot.fly_speed == 14.0


def test_player_visible_snapshot_is_read_only_copy():
    session = WorldSession()
    session.char_guid = 9
    session.equipment_cache_raw = [11, 22]

    snapshot = build_player_visible_snapshot(session)
    session.equipment_cache_raw[0] = 99

    assert snapshot.equipment_cache_raw == (11, 22)
    with pytest.raises(FrozenInstanceError):
        snapshot.guid = 10
