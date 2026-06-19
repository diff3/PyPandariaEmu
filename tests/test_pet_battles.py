#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib
import sys
import types
import unittest
from types import SimpleNamespace


def _install_common_stubs() -> None:
    logger_module = types.ModuleType("shared.Logger")
    logger_module.Logger = SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )
    sys.modules["shared.Logger"] = logger_module

    bits_module = types.ModuleType("DSL.modules.bitsHandler")

    class BitWriter:
        def __init__(self) -> None:
            self._bits: list[int] = []

        def write_bit(self, value) -> None:
            self._bits.append(1 if value else 0)

        def write_bits(self, value: int, count: int) -> None:
            current = int(value)
            for _ in range(int(count)):
                self._bits.append(current & 0x1)
                current >>= 1

        def flush(self) -> bytes:
            if not self._bits:
                return b""
            output = bytearray()
            current = 0
            for index, bit in enumerate(self._bits):
                current |= (int(bit) & 0x1) << (index % 8)
                if index % 8 == 7:
                    output.append(current)
                    current = 0
            if len(self._bits) % 8:
                output.append(current)
            return bytes(output)

    bits_module.BitWriter = BitWriter
    sys.modules["DSL.modules.bitsHandler"] = bits_module


class PetBattleRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _install_common_stubs()
        for module_name in (
            "server.modules.handlers.world.features.pet_battles",
            "server.modules.handlers.world.features.pet_battles.state",
            "server.modules.handlers.world.features.pet_battles.packets",
            "server.modules.handlers.world.features.pet_battles.runtime",
        ):
            sys.modules.pop(module_name, None)
        cls.runtime = importlib.import_module("server.modules.handlers.world.features.pet_battles.runtime")

    def setUp(self) -> None:
        self.manager = self.runtime.PetBattleManager()
        self.session = SimpleNamespace(
            char_guid=42,
            player_guid=42,
            world_guid=42,
            x=1.0,
            y=2.0,
            z=3.0,
            pet_battle_session=None,
        )

    def test_start_session_creates_session_and_packets(self):
        responses = self.manager.start_session(self.session)

        self.assertIsNotNone(responses)
        self.assertEqual(
            [opcode for opcode, _payload in responses],
            ["SMSG_PET_BATTLE_QUEUE_STATUS", "SMSG_BATTLE_PET_LOCATION_FINALIZE"],
        )
        self.assertIsNotNone(self.manager.active_session(self.session))
        self.assertIsNotNone(self.session.pet_battle_session)

    def test_duplicate_start_prevention(self):
        self.assertIsNotNone(self.manager.start_session(self.session))
        self.assertIsNone(self.manager.start_session(self.session))

    def test_stop_session_clears_state(self):
        self.manager.start_session(self.session)

        responses = self.manager.stop_session(self.session, reason="unit-test")

        self.assertEqual(
            [opcode for opcode, _payload in responses],
            ["SMSG_PET_BATTLE_QUEUE_STATUS"],
        )
        self.assertIsNone(self.manager.active_session(self.session))
        self.assertIsNone(self.session.pet_battle_session)

    def test_logout_cleanup_clears_active_session(self):
        self.manager.start_session(self.session)

        self.manager.handle_logout(self.session)

        self.assertIsNone(self.manager.active_session(self.session))
        self.assertIsNone(self.session.pet_battle_session)


class PetBattleMapTransferTests(unittest.TestCase):
    def test_map_transfer_clears_active_pet_battle(self):
        _install_common_stubs()

        fake_manager = SimpleNamespace(handle_map_transfer=lambda session: setattr(session, "pet_battle_cleared", True))
        feature_module = types.ModuleType("server.modules.handlers.world.features.pet_battles")
        feature_module.get_pet_battle_manager = lambda: fake_manager
        sys.modules["server.modules.handlers.world.features.pet_battles"] = feature_module

        pvg_module = types.ModuleType("server.modules.handlers.world.features.plants_vs_ghouls")
        pvg_module.get_plants_vs_ghouls_manager = lambda: SimpleNamespace(handle_map_change=lambda *_args, **_kwargs: None)
        sys.modules["server.modules.handlers.world.features.plants_vs_ghouls"] = pvg_module

        halfhill_module = types.ModuleType("server.modules.handlers.world.features.halfhill_farming")
        halfhill_module.get_halfhill_farm_manager = lambda: SimpleNamespace(clear_for_map_transfer=lambda *_args, **_kwargs: None)
        sys.modules["server.modules.handlers.world.features.halfhill_farming"] = halfhill_module

        chat_module = types.ModuleType("server.modules.handlers.world.opcodes.chat")
        chat_module.apply_player_state_change = lambda session, **kwargs: [("SMSG_TRANSFER_PENDING", b""), ("SMSG_NEW_WORLD", b"")]
        sys.modules["server.modules.handlers.world.opcodes.chat"] = chat_module

        sys.modules.pop("server.modules.handlers.world.teleport.map_transfer", None)
        map_transfer = importlib.import_module("server.modules.handlers.world.teleport.map_transfer")

        session = SimpleNamespace(map_id=870, pet_battle_cleared=False)
        destination = map_transfer.TeleportDestination(
            map_id=1,
            x=1.0,
            y=2.0,
            z=3.0,
            orientation=0.0,
            name="test",
        )

        responses = map_transfer.apply_map_transfer(session, destination, reason="unit-test")

        self.assertTrue(session.pet_battle_cleared)
        self.assertEqual([opcode for opcode, _payload in responses], ["SMSG_TRANSFER_PENDING", "SMSG_NEW_WORLD"])


if __name__ == "__main__":
    unittest.main()
