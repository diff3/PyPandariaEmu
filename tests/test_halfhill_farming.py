#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch


def _install_common_stubs() -> None:
    logger_module = types.ModuleType("shared.Logger")
    logger_module.Logger = SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )
    sys.modules["shared.Logger"] = logger_module

    codec_module = types.ModuleType("server.modules.handlers.world.chat.codec")
    codec_module.encode_skyfire_messagechat_system_payload = lambda message: str(message or "").encode("utf-8")
    sys.modules["server.modules.handlers.world.chat.codec"] = codec_module

    sqlalchemy_module = types.ModuleType("sqlalchemy")
    sqlalchemy_module.text = lambda query: query
    sys.modules["sqlalchemy"] = sqlalchemy_module

    db_module = types.ModuleType("server.modules.database.DatabaseConnection")
    db_module.DatabaseConnection = type(
        "DatabaseConnection",
        (),
        {"chars": staticmethod(lambda: None)},
    )
    sys.modules["server.modules.database.DatabaseConnection"] = db_module

    inventory_sync_module = types.ModuleType("server.modules.handlers.world.inventory_sync")
    inventory_sync_module.build_inventory_delta_responses = lambda session, result: [("SMSG_UPDATE_OBJECT", b"inventory")]
    sys.modules["server.modules.handlers.world.inventory_sync"] = inventory_sync_module

    inventory_module = types.ModuleType("server.modules.game.inventory")
    inventory_module.destroy_character_item = lambda session, bag, slot, count=0: SimpleNamespace(ok=True, message="item destroyed")
    inventory_module.add_item_to_character = lambda session, item_entry, count=1: SimpleNamespace(ok=True, message="item added")
    inventory_module.persist_session_inventory = lambda session: True
    sys.modules["server.modules.game.inventory"] = inventory_module


class HalfhillFarmRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _install_common_stubs()
        for module_name in (
            "server.modules.handlers.world.features.halfhill_farming",
            "server.modules.handlers.world.features.halfhill_farming.definitions",
            "server.modules.handlers.world.features.halfhill_farming.state",
            "server.modules.handlers.world.features.halfhill_farming.persistence",
            "server.modules.handlers.world.features.halfhill_farming.planting",
            "server.modules.handlers.world.features.halfhill_farming.harvesting",
            "server.modules.handlers.world.features.halfhill_farming.runtime",
        ):
            sys.modules.pop(module_name, None)
        cls.runtime = importlib.import_module("server.modules.handlers.world.features.halfhill_farming.runtime")
        cls.state = importlib.import_module("server.modules.handlers.world.features.halfhill_farming.state")

    def setUp(self) -> None:
        self.manager = self.runtime.HalfhillFarmManager()
        self.session = SimpleNamespace(char_guid=42, pending_farm_seed=None)

    def test_select_seed_stores_pending_selection(self):
        responses = self.manager.select_seed(self.session, item_entry=79102, bag=255, slot=23)

        self.assertEqual(self.session.pending_farm_seed.seed_item, 79102)
        self.assertEqual(self.session.pending_farm_seed.bag, 255)
        self.assertEqual(self.session.pending_farm_seed.slot, 23)
        self.assertEqual(responses[0][0], "SMSG_MESSAGECHAT")

    def test_plot_use_plants_seed_and_clears_pending(self):
        self.session.pending_farm_seed = self.state.PendingSeedSelection(seed_item=79102, bag=255, slot=23)

        with patch.object(self.runtime.persistence, "load_player_plots", return_value={}), \
             patch.object(self.runtime.persistence, "save_plot", return_value=True) as save_plot, \
             patch.object(self.runtime.planting, "destroy_character_item", return_value=SimpleNamespace(ok=True, message="ok")), \
             patch.object(self.runtime.planting, "persist_session_inventory", return_value=True):
            responses = self.manager.handle_gameobject_use(self.session, {"guid": 262125})

        self.assertIsNone(self.session.pending_farm_seed)
        self.assertTrue(save_plot.called)
        self.assertEqual(responses[0][0], "SMSG_UPDATE_OBJECT")
        self.assertEqual(responses[-1][0], "SMSG_MESSAGECHAT")
        self.assertIn(b"Planted", responses[-1][1])

    def test_plot_use_harvests_mature_crop(self):
        planted_at = 1
        with patch.object(
            self.runtime.persistence,
            "load_player_plots",
            return_value={262125: {"guid": 42, "plot_guid": 262125, "seed_item": 79102, "planted_at": planted_at}},
        ), patch.object(self.runtime.harvesting, "add_item_to_character", return_value=SimpleNamespace(ok=True, message="ok")), \
            patch.object(self.runtime.harvesting, "persist_session_inventory", return_value=True), \
            patch.object(self.runtime.persistence, "clear_plot", return_value=True) as clear_plot, \
            patch.object(self.runtime.time, "time", return_value=1000):
            responses = self.manager.handle_gameobject_use(self.session, {"guid": 262125})

        self.assertTrue(clear_plot.called)
        self.assertEqual(responses[0][0], "SMSG_UPDATE_OBJECT")
        self.assertIn(b"Harvested", responses[-1][1])

    def test_plot_use_reports_empty_status_without_pending_seed(self):
        with patch.object(self.runtime.persistence, "load_player_plots", return_value={}):
            responses = self.manager.handle_gameobject_use(self.session, {"guid": 262125})

        self.assertEqual(responses[0][0], "SMSG_MESSAGECHAT")
        self.assertIn(b"empty", responses[0][1])

    def test_clear_pending_seed_helpers_reset_session_state(self):
        self.session.pending_farm_seed = self.state.PendingSeedSelection(seed_item=80590, bag=0, slot=20)
        self.manager.clear_for_map_transfer(self.session)
        self.assertIsNone(self.session.pending_farm_seed)

        self.session.pending_farm_seed = self.state.PendingSeedSelection(seed_item=79102, bag=0, slot=21)
        self.manager.clear_for_logout(self.session)
        self.assertIsNone(self.session.pending_farm_seed)


class HalfhillFarmHandlerTests(unittest.TestCase):
    def test_use_item_supported_seed_routes_to_farm_manager(self):
        _install_common_stubs()

        bits_module = types.ModuleType("DSL.modules.bitsHandler")
        bits_module.BitInterPreter = type("BitInterPreter", (), {"read_bit": staticmethod(lambda data, byte_pos, bit_pos: (0, byte_pos, bit_pos))})
        bits_module.BitWriter = type("BitWriter", (), {})
        sys.modules["DSL.modules.bitsHandler"] = bits_module

        guid_module = types.ModuleType("server.modules.game.guid")
        guid_module.GuidHelper = type("GuidHelper", (), {"decode": staticmethod(lambda value: SimpleNamespace(low=int(value) & 0xFFFFFFFF))})
        sys.modules["server.modules.game.guid"] = guid_module

        dispatcher_module = types.ModuleType("server.modules.handlers.world.dispatcher")
        dispatcher_module.register = lambda *_args, **_kwargs: (lambda func: func)
        sys.modules["server.modules.handlers.world.dispatcher"] = dispatcher_module

        packets_module = types.ModuleType("server.modules.handlers.world.login.packets")
        packets_module.build_login_packet = lambda *args, **kwargs: b""
        sys.modules["server.modules.handlers.world.login.packets"] = packets_module

        packet_context_module = types.ModuleType("server.modules.protocol.PacketContext")
        packet_context_module.PacketContext = type("PacketContext", (), {})
        sys.modules["server.modules.protocol.PacketContext"] = packet_context_module

        fake_manager = SimpleNamespace(select_seed=lambda session, **kwargs: [("SMSG_MESSAGECHAT", b"seed-selected")])
        feature_module = types.ModuleType("server.modules.handlers.world.features.halfhill_farming")
        feature_module.get_halfhill_farm_manager = lambda: fake_manager
        sys.modules["server.modules.handlers.world.features.halfhill_farming"] = feature_module

        sys.modules.pop("server.modules.handlers.world.opcodes.npc_interaction", None)
        npc_interaction = importlib.import_module("server.modules.handlers.world.opcodes.npc_interaction")

        seed_item = SimpleNamespace(entry=79102)
        session = SimpleNamespace(
            inventory_state=SimpleNamespace(
                items_by_pos={(0, 23): seed_item},
                get=lambda bag, slot: seed_item if (bag, slot) == (0, 23) else None,
            ),
            inventory_by_guid={},
            char_guid=42,
        )

        status, responses = npc_interaction.handle_use_item(session, bytes.fromhex("17ff000000000000000000000000"))
        self.assertEqual(status, 0)
        self.assertEqual(responses, [("SMSG_MESSAGECHAT", b"seed-selected")])

    def test_map_transfer_clears_pending_seed_on_cross_map(self):
        _install_common_stubs()

        fake_manager = SimpleNamespace(clear_for_map_transfer=lambda session: setattr(session, "cleared_pending_seed", True))
        feature_module = types.ModuleType("server.modules.handlers.world.features.halfhill_farming")
        feature_module.get_halfhill_farm_manager = lambda: fake_manager
        sys.modules["server.modules.handlers.world.features.halfhill_farming"] = feature_module

        chat_module = types.ModuleType("server.modules.handlers.world.opcodes.chat")
        chat_module.apply_player_state_change = lambda session, **kwargs: [("SMSG_TRANSFER_PENDING", b""), ("SMSG_NEW_WORLD", b"")]
        sys.modules["server.modules.handlers.world.opcodes.chat"] = chat_module

        sys.modules.pop("server.modules.handlers.world.teleport.map_transfer", None)
        map_transfer = importlib.import_module("server.modules.handlers.world.teleport.map_transfer")

        session = SimpleNamespace(map_id=870, cleared_pending_seed=False)
        destination = map_transfer.TeleportDestination(
            map_id=1,
            x=1.0,
            y=2.0,
            z=3.0,
            orientation=0.0,
            name="test",
        )

        responses = map_transfer.apply_map_transfer(session, destination, reason="unit-test")

        self.assertTrue(session.cleared_pending_seed)
        self.assertEqual([opcode for opcode, _payload in responses], ["SMSG_TRANSFER_PENDING", "SMSG_NEW_WORLD"])


class FarmerYoonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _install_common_stubs()
        for module_name in (
            "server.modules.handlers.world.features.halfhill_farming",
            "server.modules.handlers.world.features.halfhill_farming.definitions",
            "server.modules.handlers.world.features.halfhill_farming.state",
            "server.modules.handlers.world.features.halfhill_farming.persistence",
            "server.modules.handlers.world.features.halfhill_farming.runtime",
            "server.modules.handlers.world.features.halfhill_farming.farmer_yoon",
        ):
            sys.modules.pop(module_name, None)
        cls.runtime = importlib.import_module("server.modules.handlers.world.features.halfhill_farming.runtime")
        cls.farmer_yoon = importlib.import_module("server.modules.handlers.world.features.halfhill_farming.farmer_yoon")

    def setUp(self) -> None:
        self.manager = self.runtime.HalfhillFarmManager()
        self.session = SimpleNamespace(
            char_guid=42,
            inventory_state=SimpleNamespace(items_by_pos={}),
            inventory_by_guid={},
        )

    def test_farm_summary_generation(self):
        planted = {
            262125: {"guid": 42, "plot_guid": 262125, "seed_item": 80590, "planted_at": 10},
            262133: {"guid": 42, "plot_guid": 262133, "seed_item": 79102, "planted_at": 100},
        }
        with patch.object(self.runtime.persistence, "load_player_plots", return_value=planted), \
             patch.object(self.farmer_yoon, "get_halfhill_farm_manager", return_value=self.manager), \
             patch.object(self.runtime.time, "time", return_value=350):
            responses = self.farmer_yoon.build_farm_summary_messages(self.session)

        payloads = [payload.decode("utf-8") for _opcode, payload in responses]
        self.assertIn("Halfhill Farm Status", payloads[0])
        self.assertTrue(any("Plot 1: Mature (Carrot)" in line for line in payloads))
        self.assertTrue(any("Plot 2: Growing (Cabbage)" in line for line in payloads))
        self.assertTrue(any("Plot 3: Empty" in line for line in payloads))

    def test_starter_seed_grant(self):
        with patch.object(self.farmer_yoon, "has_claimed_starter_seeds", return_value=False), \
             patch.object(self.farmer_yoon, "mark_starter_seed_claimed", return_value=True) as mark_claimed, \
             patch.object(self.farmer_yoon, "player_has_supported_seeds", return_value=False), \
             patch.object(self.farmer_yoon, "persist_session_inventory", return_value=True), \
             patch.object(self.farmer_yoon, "add_item_to_character", side_effect=[SimpleNamespace(ok=True, message="ok"), SimpleNamespace(ok=True, message="ok")]):
            responses = self.farmer_yoon.grant_starter_seeds(self.session)

        self.assertTrue(mark_claimed.called)
        payloads = [payload.decode("utf-8") for _opcode, payload in responses if _opcode == "SMSG_MESSAGECHAT"]
        self.assertIn("Starter seeds granted:", payloads)
        self.assertIn("5x Green Cabbage Seeds", payloads)
        self.assertIn("5x Juicycrunch Carrot Seeds", payloads)

    def test_duplicate_starter_seed_prevention(self):
        with patch.object(self.farmer_yoon, "has_claimed_starter_seeds", return_value=True):
            responses = self.farmer_yoon.grant_starter_seeds(self.session)
        self.assertIn("already been claimed", responses[0][1].decode("utf-8"))

    def test_seed_ownership_checks(self):
        self.session.inventory_state = SimpleNamespace(
            items_by_pos={(0, 20): SimpleNamespace(entry=79102)}
        )
        self.assertTrue(self.farmer_yoon.player_has_supported_seeds(self.session))

        self.session.inventory_state = SimpleNamespace(items_by_pos={})
        self.session.inventory_by_guid = {1: SimpleNamespace(entry=80590)}
        self.assertTrue(self.farmer_yoon.player_has_supported_seeds(self.session))

        self.session.inventory_by_guid = {}
        self.assertFalse(self.farmer_yoon.player_has_supported_seeds(self.session))


if __name__ == "__main__":
    unittest.main()
