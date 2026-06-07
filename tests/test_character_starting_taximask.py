#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib
import sys
import types


def _import_characters_module():
    stubbed_modules = (
        "server.modules.database.DatabaseConnection",
        "server.modules.database.CharactersModel",
        "server.modules.handlers.world.login.packets",
    )
    previous_modules = {name: sys.modules.get(name) for name in stubbed_modules}

    database_module = types.ModuleType("server.modules.database.DatabaseConnection")
    database_module.DatabaseConnection = type("DatabaseConnection", (), {})
    sys.modules["server.modules.database.DatabaseConnection"] = database_module

    model_module = types.ModuleType("server.modules.database.CharactersModel")
    for name in (
        "Characters",
        "CharacterAction",
        "CharacterInventory",
        "CharacterSpell",
        "ItemInstance",
    ):
        setattr(model_module, name, type(name, (), {}))
    sys.modules["server.modules.database.CharactersModel"] = model_module

    login_packets_module = types.ModuleType("server.modules.handlers.world.login.packets")
    login_packets_module.build_ENUM_CHARACTERS_RESULT = lambda *args, **kwargs: b""
    sys.modules["server.modules.handlers.world.login.packets"] = login_packets_module

    sys.modules.pop("server.modules.handlers.world.characters.characters", None)
    try:
        return importlib.import_module("server.modules.handlers.world.characters.characters")
    finally:
        for name, module in previous_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _taximask_nodes(raw_mask: str) -> set[int]:
    nodes: set[int] = set()
    for word_index, token in enumerate(str(raw_mask or "").split()):
        word = int(token or 0)
        for bit_index in range(32):
            if word & (1 << bit_index):
                nodes.add((word_index * 32) + bit_index + 1)
    return nodes


def test_horde_new_character_taximask_uses_retail_mop_defaults():
    characters = _import_characters_module()

    nodes = _taximask_nodes(characters._default_taximask(2))

    assert nodes == {
        23,
        536,
        537,
        11,
        384,
        460,
        22,
        402,
        82,
        625,
        631,
        99,
        128,
        310,
    }
    assert 25 not in nodes


def test_alliance_new_character_taximask_uses_retail_mop_defaults():
    characters = _import_characters_module()

    nodes = _taximask_nodes(characters._default_taximask(1))

    assert nodes == {
        2,
        582,
        589,
        6,
        619,
        620,
        26,
        456,
        457,
        94,
        624,
        49,
        100,
        128,
        310,
    }


def test_starting_taximask_combines_with_discovered_nodes():
    characters = _import_characters_module()
    from server.modules.handlers.world.opcodes import taxi

    session = type("Session", (), {})()
    session.taximask_raw = characters._default_taximask(2)

    assert taxi._mark_taxi_node_discovered(session, 25)

    nodes = taxi._taxi_node_ids_from_mask(session.taximask_raw)
    assert 25 in nodes
    assert {23, 536, 537, 22, 128, 310}.issubset(nodes)
