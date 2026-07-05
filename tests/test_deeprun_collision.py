#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

class _ColorStub:
    def __getattr__(self, _name: str) -> str:
        return ""


colorama_module = types.ModuleType("colorama")
colorama_module.init = lambda *args, **kwargs: None
colorama_module.Fore = _ColorStub()
colorama_module.Style = _ColorStub()
sys.modules.setdefault("colorama", colorama_module)

yaml_module = types.ModuleType("yaml")
yaml_module.safe_load = lambda *args, **kwargs: {}
yaml_module.load = lambda *args, **kwargs: {}
yaml_module.FullLoader = object
sys.modules.setdefault("yaml", yaml_module)

replay_module = types.ModuleType("server.modules.handlers.world.bootstrap.replay")
replay_module.build_database_gameobject_responses = lambda *args, **kwargs: []
replay_module.build_multi_u32_update_object_payload = lambda *args, **kwargs: b""
replay_module.build_single_u32_update_object_payload = lambda *args, **kwargs: b""
sys.modules.setdefault("server.modules.handlers.world.bootstrap.replay", replay_module)

creatures_module = types.ModuleType("server.modules.handlers.world.bootstrap.creatures")
creatures_module.build_database_creature_responses = lambda *args, **kwargs: []
sys.modules.setdefault("server.modules.handlers.world.bootstrap.creatures", creatures_module)

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type(
    "DatabaseConnection",
    (),
    {"get_gameobjects_near": staticmethod(lambda *args, **kwargs: [])},
)
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

from server.modules.handlers.world.features import deeprun_collision
from server.modules.handlers.world.opcodes import movement


def _deeprun_entry(**overrides):
    entry = {
        "guid": 18806,
        "entry": 176084,
        "map_id": 369,
        "x": 100.0,
        "y": 200.0,
        "z": 50.0,
        "orientation": 0.0,
        "display_id": 3831,
        "type": 11,
        "size": 1.0,
    }
    entry.update(overrides)
    return entry


def _movement_state(**overrides):
    state = {
        "x": 0.0,
        "y": 0.0,
        "z": 0.0,
        "orientation": 0.0,
        "flags": 0,
        "flags2": 0,
        "timestamp_ms": 0,
        "counter": 0,
        "has_fall_data": False,
        "fall_time": 0,
        "fall_vertical_speed": 0.0,
        "fall_horizontal_speed": 0.0,
        "fall_sin_angle": 0.0,
        "fall_cos_angle": 0.0,
        "is_ascending": False,
        "is_descending": False,
        "pitch": 0.0,
        "transport_guid": 0,
    }
    state.update(overrides)
    return SimpleNamespace(**state)


class DeeprunCollisionTests(unittest.TestCase):
    def test_deeprun_entries_are_recognized(self) -> None:
        for entry_id in deeprun_collision.DEEPRUN_ENTRIES:
            self.assertTrue(deeprun_collision.is_deeprun_tram_entry(_deeprun_entry(entry=entry_id)))

    def test_point_inside_axis_aligned_wagon(self) -> None:
        self.assertTrue(
            deeprun_collision.point_inside_deeprun_wagon(
                _deeprun_entry(),
                100.0,
                200.0,
            )
        )

    def test_point_outside_wagon(self) -> None:
        self.assertFalse(
            deeprun_collision.point_inside_deeprun_wagon(
                _deeprun_entry(),
                120.0,
                200.0,
            )
        )

    def test_point_inside_rotated_wagon(self) -> None:
        self.assertTrue(
            deeprun_collision.point_inside_deeprun_wagon(
                _deeprun_entry(orientation=math.pi / 2.0),
                104.0,
                200.0,
            )
        )

    def test_clamp_near_surface(self) -> None:
        entry = _deeprun_entry()
        surface_z = deeprun_collision.deeprun_surface_z(entry)
        with patch.object(
            deeprun_collision.DatabaseConnection,
            "get_gameobjects_near",
            return_value=[entry],
        ):
            clamped, result_z = deeprun_collision.clamp_deeprun_player_z(
                map_id=369,
                world_x=100.0,
                world_y=200.0,
                world_z=float(surface_z) - 2.0,
            )
        self.assertTrue(clamped)
        self.assertAlmostEqual(float(result_z), float(surface_z), places=4)

    def test_no_clamp_far_under_surface(self) -> None:
        entry = _deeprun_entry()
        surface_z = deeprun_collision.deeprun_surface_z(entry)
        with patch.object(
            deeprun_collision.DatabaseConnection,
            "get_gameobjects_near",
            return_value=[entry],
        ):
            clamped, result_z = deeprun_collision.clamp_deeprun_player_z(
                map_id=369,
                world_x=100.0,
                world_y=200.0,
                world_z=float(surface_z) - 10.0,
            )
        self.assertFalse(clamped)
        self.assertAlmostEqual(float(result_z), float(surface_z) - 10.0, places=4)

    def test_no_effect_on_other_map(self) -> None:
        with patch.object(
            deeprun_collision.DatabaseConnection,
            "get_gameobjects_near",
            return_value=[_deeprun_entry(map_id=1)],
        ):
            clamped, result_z = deeprun_collision.clamp_deeprun_player_z(
                map_id=1,
                world_x=100.0,
                world_y=200.0,
                world_z=50.0,
            )
        self.assertFalse(clamped)
        self.assertEqual(result_z, 50.0)

    def test_no_effect_on_other_display_id(self) -> None:
        with patch.object(
            deeprun_collision.DatabaseConnection,
            "get_gameobjects_near",
            return_value=[_deeprun_entry(display_id=9999)],
        ):
            clamped, result_z = deeprun_collision.clamp_deeprun_player_z(
                map_id=369,
                world_x=100.0,
                world_y=200.0,
                world_z=50.0,
            )
        self.assertFalse(clamped)
        self.assertEqual(result_z, 50.0)

    def test_movement_path_clamps_player_to_tram_surface(self) -> None:
        entry = _deeprun_entry()
        state = _movement_state(
            z=46.0,
            flags=movement._MOVEMENTFLAG_FALLING,
            has_fall_data=True,
            fall_time=250,
            fall_vertical_speed=-7.5,
        )
        session = SimpleNamespace(
            char_guid=7,
            world_guid=7,
            movement_state=state,
            map_id=369,
            x=100.0,
            y=200.0,
            z=46.0,
            orientation=0.0,
            can_fly=False,
            is_flying=False,
        )
        expected_surface = deeprun_collision.deeprun_surface_z(entry)

        with patch.object(
            deeprun_collision.DatabaseConnection,
            "get_gameobjects_near",
            return_value=[entry],
        ), patch.object(movement.Logger, "info", return_value=None), patch.object(
            movement.Logger,
            "debug",
            return_value=None,
        ), patch.object(movement.Logger, "warning", return_value=None):
            ok = movement._store_authoritative_movement(
                session,
                "MSG_MOVE_HEARTBEAT",
                b"",
                (100.0, 200.0, float(expected_surface) - 2.0, 0.25),
            )

        self.assertTrue(ok)
        self.assertAlmostEqual(float(state.z), float(expected_surface), places=4)
        self.assertAlmostEqual(float(session.z), float(expected_surface), places=4)
        self.assertEqual(int(state.flags) & movement._MOVEMENTFLAG_FALLING, 0)
        self.assertFalse(state.has_fall_data)


if __name__ == "__main__":
    unittest.main()
