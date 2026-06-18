from __future__ import annotations

import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

if "colorama" not in sys.modules:
    colorama = types.ModuleType("colorama")
    colorama.init = lambda *args, **kwargs: None
    colorama.Fore = types.SimpleNamespace(
        RED="",
        YELLOW="",
        GREEN="",
        CYAN="",
        WHITE="",
        MAGENTA="",
    )
    colorama.Style = types.SimpleNamespace(RESET_ALL="")
    sys.modules["colorama"] = colorama

if "shared.Logger" not in sys.modules:
    logger_module = types.ModuleType("shared.Logger")
    logger_module.Logger = types.SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )
    sys.modules["shared.Logger"] = logger_module

if "server.modules.database.DatabaseConnection" not in sys.modules:
    db_module = types.ModuleType("server.modules.database.DatabaseConnection")
    db_module.DatabaseConnection = type(
        "DatabaseConnection",
        (),
        {"get_creature_template": staticmethod(lambda entry: {})},
    )
    sys.modules["server.modules.database.DatabaseConnection"] = db_module

if "server.modules.handlers.world.bootstrap.creatures" not in sys.modules:
    bootstrap_creatures = types.ModuleType("server.modules.handlers.world.bootstrap.creatures")
    bootstrap_creatures._build_creature_update_payload = lambda **kwargs: b""
    sys.modules["server.modules.handlers.world.bootstrap.creatures"] = bootstrap_creatures

if "server.modules.handlers.world.bootstrap.playerobjects" not in sys.modules:
    bootstrap_playerobjects = types.ModuleType("server.modules.handlers.world.bootstrap.playerobjects")
    bootstrap_playerobjects.make_update_object_response = lambda payload: ("SMSG_UPDATE_OBJECT", payload)
    sys.modules["server.modules.handlers.world.bootstrap.playerobjects"] = bootstrap_playerobjects

if "server.modules.handlers.world.opcodes.movement" not in sys.modules:
    movement_module = types.ModuleType("server.modules.handlers.world.opcodes.movement")
    movement_module._build_out_of_range_update_object_payload = lambda **kwargs: b""
    sys.modules["server.modules.handlers.world.opcodes.movement"] = movement_module

if "server.modules.handlers.world.protocol.movement.spline" not in sys.modules:
    spline_module = types.ModuleType("server.modules.handlers.world.protocol.movement.spline")

    class _SplineVector:
        def __init__(self, x, y, z):
            self.x = x
            self.y = y
            self.z = z

    spline_module.SplineVector = _SplineVector
    spline_module.build_basic_spline_move = lambda **kwargs: b""
    sys.modules["server.modules.handlers.world.protocol.movement.spline"] = spline_module

from server.modules.handlers.world.features.plants_vs_ghouls.definitions import (
    PLANT_SLOTS,
    WAVE_DEFINITIONS,
)
from server.modules.handlers.world.features.plants_vs_ghouls.runtime import (
    PlantsVsGhoulsManager,
)


def _build_session():
    sent_batches: list[list[tuple[str, bytes]]] = []

    def _send_response(batch):
        sent_batches.append(list(batch or []))

    return SimpleNamespace(
        char_guid=42,
        realm_id=1,
        map_id=0,
        x=100.0,
        y=200.0,
        z=30.0,
        orientation=0.0,
        send_response=_send_response,
        loaded_npcs=set(),
        npc_flags_by_guid={},
        npc_positions_by_guid={},
        npc_names_by_guid={},
        plants_vs_ghouls_active=False,
        plants_vs_ghouls_outcome=None,
        sent_batches=sent_batches,
    )


class PlantsVsGhoulsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spawn_patch = patch(
            "server.modules.handlers.world.features.plants_vs_ghouls.spawning.build_creature_spawn_response",
            lambda session, **kwargs: ("SPAWN", str(kwargs["world_guid"]).encode()),
        )
        self.move_patch = patch(
            "server.modules.handlers.world.features.plants_vs_ghouls.spawning.build_creature_move_response",
            lambda session, **kwargs: ("MOVE", str(kwargs["world_guid"]).encode()),
        )
        self.despawn_patch = patch(
            "server.modules.handlers.world.features.plants_vs_ghouls.spawning.build_creature_despawn_response",
            lambda session, **kwargs: ("DESPAWN", str(kwargs["world_guid"]).encode()),
        )
        self.dispatch_patch = patch(
            "server.modules.handlers.world.features.plants_vs_ghouls.spawning.dispatch_responses",
            lambda session, responses: session.sent_batches.append(list(responses or [])),
        )
        self.guid_patch = patch(
            "server.modules.handlers.world.features.plants_vs_ghouls.spawning.make_creature_world_guid",
            lambda realm_id, local_low_guid: (
                (0x000F << 48)
                | ((int(realm_id) & 0xFFFF) << 32)
                | (int(local_low_guid) & 0xFFFFFFFF)
            ),
        )

        self.spawn_patch.start()
        self.move_patch.start()
        self.despawn_patch.start()
        self.dispatch_patch.start()
        self.guid_patch.start()

        self.addCleanup(self.spawn_patch.stop)
        self.addCleanup(self.move_patch.stop)
        self.addCleanup(self.despawn_patch.stop)
        self.addCleanup(self.dispatch_patch.stop)
        self.addCleanup(self.guid_patch.stop)

        self.manager = PlantsVsGhoulsManager(auto_start_thread=False)
        self.session = _build_session()

    def _match(self):
        return self.manager._matches[int(self.session.char_guid)][1]

    def test_match_starts_and_spawns_first_wave(self):
        self.assertTrue(self.manager.start_match(self.session))

        match = self._match()
        self.assertEqual(match.wave_index, 1)
        self.assertTrue(self.session.plants_vs_ghouls_active)
        self.assertEqual(len(match.lanes[0].zombies), 1)
        self.assertEqual(len(match.lanes[2].zombies), 1)
        self.assertEqual(
            [opcode for opcode, _payload in self.session.sent_batches[0]],
            ["SPAWN", "SPAWN"],
        )

    def test_zombies_advance_between_ticks(self):
        self.manager.start_match(self.session)

        zombie = self._match().lanes[0].zombies[0]
        before = zombie.progress
        self.manager.tick_once(dt_seconds=1.0)

        self.assertLess(zombie.progress, before)
        self.assertTrue(
            any(
                opcode == "MOVE"
                for batch in self.session.sent_batches[1:]
                for opcode, _payload in batch
            )
        )

    def test_spitter_damages_zombie(self):
        self.manager.start_match(self.session)
        ok, _message = self.manager.place_plant(self.session, lane_number=1, kind="spitter")
        self.assertTrue(ok)

        zombie = self._match().lanes[0].zombies[0]
        zombie.progress = float(PLANT_SLOTS[0]) + 5.0
        before_hp = zombie.hp
        self.manager.tick_once(dt_seconds=1.0)

        self.assertLess(zombie.hp, before_hp)

    def test_rocknut_blocks_lane_and_takes_damage(self):
        self.manager.start_match(self.session)
        ok, _message = self.manager.place_plant(self.session, lane_number=1, kind="rocknut")
        self.assertTrue(ok)

        match = self._match()
        rocknut = match.lanes[0].plants[0]
        zombie = match.lanes[0].zombies[0]
        zombie.progress = float(PLANT_SLOTS[0]) + 0.25
        before_progress = zombie.progress
        before_hp = rocknut.hp

        self.manager.tick_once(dt_seconds=1.0)

        self.assertEqual(zombie.progress, before_progress)
        self.assertLess(rocknut.hp, before_hp)

    def test_zombie_reaching_goal_causes_loss(self):
        self.manager.start_match(self.session)

        zombie = self._match().lanes[0].zombies[0]
        zombie.progress = 0.1
        self.manager.tick_once(dt_seconds=1.0)

        self.assertNotIn(int(self.session.char_guid), self.manager._matches)
        self.assertEqual(self.session.plants_vs_ghouls_outcome, "loss")

    def test_all_waves_defeated_causes_win(self):
        self.manager.start_match(self.session)

        match = self._match()
        match.wave_index = len(WAVE_DEFINITIONS)
        for lane in match.lanes:
            lane.zombies.clear()

        self.manager.tick_once(dt_seconds=0.25)

        self.assertNotIn(int(self.session.char_guid), self.manager._matches)
        self.assertEqual(self.session.plants_vs_ghouls_outcome, "win")

    def test_cleanup_despawns_temporary_entities(self):
        self.manager.start_match(self.session)
        self.manager.place_plant(self.session, lane_number=1, kind="spitter")

        match = self._match()
        expected = len(match.temporary_guids)
        self.assertGreater(expected, 0)

        self.assertTrue(self.manager.stop_match(self.session, reason="test-stop"))
        self.assertNotIn(int(self.session.char_guid), self.manager._matches)

        despawns = [
            opcode
            for batch in self.session.sent_batches
            for opcode, _payload in batch
            if opcode == "DESPAWN"
        ]
        self.assertGreaterEqual(len(despawns), expected)

    def test_logout_and_map_change_cleanup_clear_match(self):
        self.manager.start_match(self.session)
        self.manager.handle_disconnect(self.session)
        self.assertNotIn(int(self.session.char_guid), self.manager._matches)

        self.manager.start_match(self.session)
        self.manager.handle_map_change(self.session, destination_map_id=1)
        self.assertNotIn(int(self.session.char_guid), self.manager._matches)


if __name__ == "__main__":
    unittest.main()
