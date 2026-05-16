#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
from types import SimpleNamespace

from server.modules.handlers.world.opcodes import taxi


def test_show_taxi_nodes_marks_basic_horde_nodes(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar"),
            25: taxi.TaxiNode(25, 1, -441.80, -2596.08, 96.06, "The Crossroads, Northern Barrens"),
            536: taxi.TaxiNode(536, 1, -780.26, -4890.27, 19.62, "Sen'jin Village, Durotar"),
            537: taxi.TaxiNode(537, 1, 269.91, -4766.75, 11.49, "Razor Hill, Durotar"),
        },
    )
    session = SimpleNamespace(map_id=1, x=1800.0, y=-4360.0, z=102.0)

    payload = taxi.build_show_taxi_nodes_payload(session, 0)

    node_mask = payload[-taxi._TAXI_NODE_MASK_BYTES:]
    for node_id in (23, 25, 536, 537):
        assert node_mask[node_id // 8] & (1 << (node_id % 8))


def test_activate_taxi_teleports_to_destination_node(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            537: taxi.TaxiNode(537, 1, 269.91, -4766.75, 11.49, "Razor Hill, Durotar"),
        },
    )
    calls = []

    def _fake_apply_player_state_change(session, *, map_id, position):
        calls.append((session, map_id, position))
        return [("SMSG_MOVE_TELEPORT", b"teleport")]

    chat_module = SimpleNamespace(apply_player_state_change=_fake_apply_player_state_change)
    opcodes_module = sys.modules.get("server.modules.handlers.world.opcodes")
    monkeypatch.setattr(taxi, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    monkeypatch.setitem(
        sys.modules,
        "server.modules.handlers.world.opcodes.chat",
        chat_module,
    )
    if opcodes_module is not None:
        monkeypatch.setattr(opcodes_module, "chat", chat_module, raising=False)

    session = SimpleNamespace()
    payload = (537).to_bytes(4, "little") + (23).to_bytes(4, "little") + b"\x00"
    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_MOVE_TELEPORT",
    ]
    assert calls[0][1] == 1
    assert calls[0][2] == (269.91, -4766.75, 11.49, 0.0)


def test_gossip_hello_opens_taxi_nodes(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar"),
        },
    )
    monkeypatch.setattr(taxi, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        npc_flags_by_guid={0: 0x2000},
    )
    _status, responses = taxi.handle_gossip_hello(session, b"\x00")

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_TAXI_NODE_STATUS",
        "SMSG_SHOW_TAXI_NODES",
    ]


def test_taxi_query_available_nodes_uses_nearby_taxi_context_on_bad_guid(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar"),
        },
    )
    monkeypatch.setattr(taxi, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        npc_flags_by_guid={0xF0001000224DF: 0x2000},
    )
    _status, responses = taxi.handle_taxi_query_available_nodes(session, b"\x00\x70\x03\x0e\xb3\x00")

    assert [opcode for opcode, _payload in responses] == ["SMSG_SHOW_TAXI_NODES"]


def test_gossip_hello_does_not_open_taxi_for_vendor(monkeypatch):
    monkeypatch.setattr(taxi, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))

    session = SimpleNamespace(npc_flags_by_guid={0: 0x80})
    _status, responses = taxi.handle_gossip_hello(session, b"\x00")

    assert responses == [("SMSG_GOSSIP_COMPLETE", b"")]


def test_taxi_cheat_marks_all_nodes(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar"),
            315: taxi.TaxiNode(315, 571, 5813.0, 448.0, 658.0, "Dalaran"),
        },
    )

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taxi_cheat_enabled=True,
    )
    payload = taxi.build_show_taxi_nodes_payload(session, 0)
    node_mask = payload[-taxi._TAXI_NODE_MASK_BYTES:]

    assert node_mask[23 // 8] & (1 << (23 % 8))
    assert node_mask[315 // 8] & (1 << (315 % 8))


def test_activate_taxi_express_teleports_to_last_node(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar"),
            53: taxi.TaxiNode(53, 1, 6813.06, -4611.12, 710.67, "Everlook, Winterspring"),
        },
    )
    calls = []

    def _fake_apply_player_state_change(session, *, map_id, position):
        calls.append((session, map_id, position))
        return [("SMSG_MOVE_TELEPORT", b"teleport")]

    chat_module = SimpleNamespace(apply_player_state_change=_fake_apply_player_state_change)
    opcodes_module = sys.modules.get("server.modules.handlers.world.opcodes")
    monkeypatch.setattr(taxi, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    monkeypatch.setitem(
        sys.modules,
        "server.modules.handlers.world.opcodes.chat",
        chat_module,
    )
    if opcodes_module is not None:
        monkeypatch.setattr(opcodes_module, "chat", chat_module, raising=False)

    session = SimpleNamespace()
    payload = bytearray(b"\x00\x00\x0c\x00")
    payload.extend((23).to_bytes(4, "little"))
    payload.extend((53).to_bytes(4, "little"))

    _status, responses = taxi.handle_activate_taxi_express(session, bytes(payload))

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_MOVE_TELEPORT",
    ]
    assert calls[0][1] == 1
    assert calls[0][2] == (6813.06, -4611.12, 710.67, 0.0)
