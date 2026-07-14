#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
import struct
import types
from types import SimpleNamespace

from DSL.modules.bitsHandler import BitWriter
from server.modules.handlers.world import dispatcher
from server.modules.handlers.world import feature_config
from server.modules.handlers.world import taxi_runtime
from server.modules.handlers.world.opcodes import taxi
from server.modules.handlers.world.runtime import (
    FlightPath,
    get_flight_path_runtime_store,
)
from server.modules.handlers.world.state.runtime import is_player_world_active


def _quiet_logger():
    return SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
    )


def _taximask_with_nodes(*node_ids: int) -> str:
    words = [0] * taxi._TAXI_MASK_WORDS
    for node_id in node_ids:
        protocol_bit = int(node_id) - 1
        words[protocol_bit // 32] |= 1 << (protocol_bit % 32)
    return " ".join(str(word) for word in words)


def _show_taxi_node_mask(payload: bytes) -> bytes:
    return payload[-taxi._TAXI_NODE_MASK_BYTES:]


def _show_taxi_current_node_id(payload: bytes, guid: int) -> int:
    raw_guid = int(guid).to_bytes(8, "little", signed=False)
    offset = 5
    for index in (0, 3):
        if raw_guid[index]:
            offset += 1
    return struct.unpack_from("<I", payload, offset)[0]


def _node_mask_has(node_mask: bytes, node_id: int) -> bool:
    protocol_bit = int(node_id) - 1
    return bool(node_mask[protocol_bit // 8] & (1 << (protocol_bit % 8)))


def _node_mask_raw_bit(node_mask: bytes, bit_index: int) -> bool:
    return bool(node_mask[int(bit_index) // 8] & (1 << (int(bit_index) % 8)))


def _activate_taxi_reply_code(payload: bytes) -> int:
    return struct.unpack_from("<I", payload, 0)[0]


def _taxi_node_status(payload: bytes) -> int:
    return int(payload[0]) & 0x03


def _pack_guid_for_decode(
    guid: int,
    *,
    bit_order: tuple[int, ...],
    byte_order: tuple[int, ...],
) -> bytes:
    raw_guid = int(guid).to_bytes(8, "little", signed=False)
    writer = BitWriter()
    for index in bit_order:
        writer.write_bits(1 if raw_guid[index] else 0, 1)

    payload = bytearray(writer.getvalue())
    for index in byte_order:
        if raw_guid[index]:
            payload.append(raw_guid[index] ^ 1)
    return bytes(payload)


def test_show_taxi_nodes_uses_stored_taximask(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            25: taxi.TaxiNode(25, 1, -441.80, -2596.08, 96.06, "The Crossroads, Northern Barrens", 2224, 0),
            536: taxi.TaxiNode(536, 1, -780.26, -4890.27, 19.62, "Sen'jin Village, Durotar", 3574, 0),
            537: taxi.TaxiNode(537, 1, 269.91, -4766.75, 11.49, "Razor Hill, Durotar", 2224, 0),
        },
    )
    session = SimpleNamespace(
        map_id=1,
        x=1800.0,
        y=-4360.0,
        z=102.0,
        taximask_raw=_taximask_with_nodes(23, 536, 537),
        taxi_cheat_enabled=False,
    )

    payload = taxi.build_show_taxi_nodes_payload(session, 0)

    node_mask = _show_taxi_node_mask(payload)
    for node_id in (23, 536, 537):
        assert _node_mask_has(node_mask, node_id)
    assert not _node_mask_has(node_mask, 25)


def test_taxi_mask_uses_protocol_node_index_for_thunder_bluff():
    mask = taxi._build_node_mask((22,))

    assert _node_mask_raw_bit(mask, 21)
    assert not _node_mask_raw_bit(mask, 22)


def test_taxi_mask_uses_protocol_node_index_for_orgrimmar():
    mask = taxi._build_node_mask((23,))

    assert _node_mask_raw_bit(mask, 22)
    assert not _node_mask_raw_bit(mask, 23)


def test_taxi_mask_round_trip_returns_original_node_ids():
    raw_mask = _taximask_with_nodes(22, 23, 25)

    assert taxi._taxi_node_ids_from_mask(raw_mask) == {22, 23, 25}


def test_taxi_multi_node_discovery_decodes_exact_nodes():
    session = SimpleNamespace(taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS))

    assert taxi._mark_taxi_node_discovered(session, 22)
    assert taxi._mark_taxi_node_discovered(session, 23)
    assert taxi._mark_taxi_node_discovered(session, 25)

    assert taxi._taxi_node_ids_from_mask(session.taximask_raw) == {22, 23, 25}


def test_activate_taxi_starts_runtime_flight(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            537: taxi.TaxiNode(537, 1, 269.91, -4766.75, 11.49, "Razor Hill, Durotar", 2224, 0),
        },
    )
    calls = []

    def _fake_start_taxi_flight(
        session,
        path_points,
        *,
        destination_map,
        destination_node,
        source_node=0,
        speed=32.0,
        mount_display_id=6851,
        route_nodes=(),
        current_leg_index=0,
        destination_landing_point=None,
    ):
        calls.append(
            (
                session,
                path_points,
                destination_map,
                destination_node,
                source_node,
                speed,
                mount_display_id,
                route_nodes,
                destination_landing_point,
            )
        )
        return [("SMSG_ON_MONSTER_MOVE", b"taxi")]

    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    monkeypatch.setattr(taxi, "start_taxi_flight", _fake_start_taxi_flight)
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATHS_BY_NODES",
        {(23, 537): taxi.TaxiPath(900, 23, 537, 0)},
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            900: (
                taxi.TaxiPathPoint(1798.27, -4363.27, 102.84),
                taxi.TaxiPathPoint(269.91, -4766.75, 11.49),
            ),
        },
    )

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        orientation=0.0,
        taximask_raw=_taximask_with_nodes(23, 537),
    )
    payload = (537).to_bytes(4, "little") + (23).to_bytes(4, "little") + b"\x00"
    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_ON_MONSTER_MOVE",
    ]
    assert calls[0][2] == 1
    assert calls[0][3] == 537
    assert calls[0][4] == 23
    assert calls[0][6] == 6851
    assert calls[0][7] == (23, 537)
    assert calls[0][8] == taxi.TaxiPathPoint(269.91, -4766.75, 11.49, None, 1)
    assert (
        round(calls[0][1][-1].x, 3),
        round(calls[0][1][-1].y, 3),
        round(calls[0][1][-1].z, 3),
    ) == (269.91, -4766.75, 11.49)


def test_activate_taxi_starts_direct_cross_map_route(monkeypatch):
    calls = []
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            68: taxi.TaxiNode(68, 0, 2270.20, -5343.11, 86.97, "Light's Hope Chapel", 2224, 0),
            83: taxi.TaxiNode(83, 530, 7594.47, -6784.29, 86.46, "Tranquillien", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "_TAXI_PATHS_BY_NODES", {(68, 83): taxi.TaxiPath(766, 68, 83, 0)})
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            766: (
                taxi.TaxiPathPoint(2270.15, -5337.14, 88.78, None, 0),
                taxi.TaxiPathPoint(2300.00, -5400.00, 120.00, None, 0),
                taxi.TaxiPathPoint(7500.00, -6700.00, 120.00, None, 530),
                taxi.TaxiPathPoint(7589.60, -6785.48, 88.06, None, 530),
            ),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    def _fake_start_taxi_flight(
        session,
        path_points,
        *,
        destination_map,
        destination_node,
        source_node=0,
        speed=32.0,
        mount_display_id=6851,
        route_nodes=(),
        current_leg_index=0,
        destination_landing_point=None,
    ):
        calls.append(
            (
                path_points,
                destination_map,
                destination_node,
                source_node,
                route_nodes,
                current_leg_index,
                destination_landing_point,
            )
        )
        return [("SMSG_ON_MONSTER_MOVE", b"taxi-cross-map-start")]

    monkeypatch.setattr(taxi, "start_taxi_flight", _fake_start_taxi_flight)
    session = SimpleNamespace(
        map_id=0,
        x=2270.20,
        y=-5343.11,
        z=86.97,
        orientation=0.0,
        taximask_raw=_taximask_with_nodes(68, 83),
    )
    payload = (83).to_bytes(4, "little") + (68).to_bytes(4, "little") + b"\x00"

    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_ON_MONSTER_MOVE",
    ]
    assert calls[0][1:6] == (0, 83, 68, (68, 83), -1)
    assert calls[0][6] == taxi.TaxiPathPoint(7594.47, -6784.29, 86.46, None, 530)
    assert all(point.map_id == 0 for point in calls[0][0])
    assert calls[0][0][-1] == taxi.TaxiPathPoint(2300.00, -5400.00, 120.00, None, 0)


def test_activate_taxi_starts_direct_reverse_cross_map_route(monkeypatch):
    calls = []
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            68: taxi.TaxiNode(68, 0, 2270.20, -5343.11, 86.97, "Light's Hope Chapel", 2224, 0),
            83: taxi.TaxiNode(83, 530, 7594.47, -6784.29, 86.46, "Tranquillien", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "_TAXI_PATHS_BY_NODES", {(83, 68): taxi.TaxiPath(767, 83, 68, 0)})
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            767: (
                taxi.TaxiPathPoint(7589.60, -6785.48, 88.06, None, 530),
                taxi.TaxiPathPoint(7500.00, -6700.00, 120.00, None, 530),
                taxi.TaxiPathPoint(2300.00, -5400.00, 120.00, None, 0),
                taxi.TaxiPathPoint(2270.19, -5337.79, 89.96, None, 0),
            ),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    def _fake_start_taxi_flight(
        session,
        path_points,
        *,
        destination_map,
        destination_node,
        source_node=0,
        speed=32.0,
        mount_display_id=6851,
        route_nodes=(),
        current_leg_index=0,
        destination_landing_point=None,
    ):
        calls.append(
            (
                path_points,
                destination_map,
                destination_node,
                source_node,
                route_nodes,
                current_leg_index,
                destination_landing_point,
            )
        )
        return [("SMSG_ON_MONSTER_MOVE", b"taxi-reverse-cross-map-start")]

    monkeypatch.setattr(taxi, "start_taxi_flight", _fake_start_taxi_flight)
    session = SimpleNamespace(
        map_id=530,
        x=7594.47,
        y=-6784.29,
        z=86.46,
        orientation=0.0,
        taximask_raw=_taximask_with_nodes(68, 83),
    )
    payload = (68).to_bytes(4, "little") + (83).to_bytes(4, "little") + b"\x00"

    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_ON_MONSTER_MOVE",
    ]
    assert calls[0][1:6] == (530, 68, 83, (83, 68), -1)
    assert calls[0][6] == taxi.TaxiPathPoint(2270.20, -5343.11, 86.97, None, 0)
    assert all(point.map_id == 530 for point in calls[0][0])
    assert calls[0][0][-1] == taxi.TaxiPathPoint(7500.00, -6700.00, 120.00, None, 530)


def test_gossip_hello_opens_taxi_nodes(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        npc_flags_by_guid={0: 0x2000},
    )
    _status, responses = taxi.handle_gossip_hello(session, b"\x00")

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert _taxi_node_status(responses[1][1]) == taxi._TAXI_NODE_STATUS_KNOWN


def test_gossip_hello_discovers_and_persists_current_taxi_node(monkeypatch):
    saved = {}
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            315: taxi.TaxiNode(315, 571, 5813.0, 448.0, 658.0, "Dalaran", 32981, 32981),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    monkeypatch.setattr(
        taxi,
        "_save_character_taximask",
        lambda guid, realm, mask: saved.update(guid=guid, realm=realm, mask=mask) or True,
    )

    session = SimpleNamespace(
        char_guid=1001,
        realm_id=1,
        map_id=571,
        x=5813.0,
        y=448.0,
        z=658.0,
        taximask_raw=" ".join(["0"] * 16),
        npc_flags_by_guid={0: 0x2000},
    )
    _status, responses = taxi.handle_gossip_hello(session, b"\x00")

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert _taxi_node_status(responses[1][1]) == taxi._TAXI_NODE_STATUS_KNOWN
    assert _node_mask_has(taxi._build_node_mask(taxi._known_taxi_node_ids(session)), 315)
    assert saved == {"guid": 1001, "realm": 1, "mask": session.taximask_raw}


def test_gossip_hello_accepts_pandaria_core_guid_order(monkeypatch):
    guid = 0x0F0001000246BF5E
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(2, 4, 0, 3, 6, 7, 5, 1),
        byte_order=(4, 7, 1, 0, 5, 3, 6, 2),
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        npc_flags_by_guid={guid: 0x2000},
    )
    _status, responses = taxi.handle_gossip_hello(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert _taxi_node_status(responses[1][1]) == taxi._TAXI_NODE_STATUS_KNOWN


def test_gossip_hello_accepts_wowpacketparser_guid_order_for_flight_master(monkeypatch):
    guid = 0x0F0001000246BF5E
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(5, 2, 0, 4, 7, 1, 6, 3),
        byte_order=(3, 4, 6, 1, 0, 2, 7, 5),
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        npc_flags_by_guid={guid: 0x2000},
    )
    _status, responses = taxi.handle_gossip_hello(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert _taxi_node_status(responses[1][1]) == taxi._TAXI_NODE_STATUS_KNOWN
    assert _node_mask_has(taxi._build_node_mask(taxi._known_taxi_node_ids(session)), 23)


def test_show_taxi_nodes_uses_flight_master_node_not_player_nearest(monkeypatch):
    guid = 0x0F0001000247A2
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            80: taxi.TaxiNode(80, 1, -894.59, -3773.01, 11.48, "Ratchet, Northern Barrens", 2224, 541),
        },
    )
    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taximask_raw=_taximask_with_nodes(80),
        npc_positions_by_guid={guid: (1, -898.24, -3769.65, 11.79, 5.41)},
    )

    payload = taxi.build_show_taxi_nodes_payload(session, guid)

    assert _show_taxi_current_node_id(payload, guid) == 80
    assert _node_mask_has(_show_taxi_node_mask(payload), 80)


def test_unknown_flight_master_interaction_discovers_npc_node_without_show_payload(monkeypatch):
    guid = 0x0F0001000247A2
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(5, 2, 0, 4, 7, 1, 6, 3),
        byte_order=(3, 4, 6, 1, 0, 2, 7, 5),
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            80: taxi.TaxiNode(80, 1, -894.59, -3773.01, 11.48, "Ratchet, Northern Barrens", 2224, 541),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        npc_flags_by_guid={guid: 0x2000},
        npc_positions_by_guid={guid: (1, -898.24, -3769.65, 11.79, 5.41)},
    )
    _status, responses = taxi.handle_gossip_hello(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert _node_mask_has(taxi._build_node_mask(taxi._known_taxi_node_ids(session)), 80)
    assert not _node_mask_has(taxi._build_node_mask(taxi._known_taxi_node_ids(session)), 23)


def test_known_flight_master_interaction_emits_show_payload_for_npc_node(monkeypatch):
    guid = 0x0F0001000247A2
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(5, 2, 0, 4, 7, 1, 6, 3),
        byte_order=(3, 4, 6, 1, 0, 2, 7, 5),
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            80: taxi.TaxiNode(80, 1, -894.59, -3773.01, 11.48, "Ratchet, Northern Barrens", 2224, 541),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taximask_raw=_taximask_with_nodes(80),
        npc_flags_by_guid={guid: 0x2000},
        npc_positions_by_guid={guid: (1, -898.24, -3769.65, 11.79, 5.41)},
    )
    _status, responses = taxi.handle_gossip_hello(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_TAXI_NODE_STATUS",
        "SMSG_SHOW_TAXI_NODES",
    ]
    assert _show_taxi_current_node_id(responses[1][1], guid) == 80
    assert _node_mask_has(_show_taxi_node_mask(responses[1][1]), 80)


def test_discovery_transition_second_interaction_opens_taxi_nodes(monkeypatch):
    guid = 0x0F0001000247A2
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(5, 2, 0, 4, 7, 1, 6, 3),
        byte_order=(3, 4, 6, 1, 0, 2, 7, 5),
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            80: taxi.TaxiNode(80, 1, -894.59, -3773.01, 11.48, "Ratchet, Northern Barrens", 2224, 541),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=-898.0,
        y=-3769.0,
        z=11.7,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        npc_flags_by_guid={guid: 0x2000},
        npc_positions_by_guid={guid: (1, -898.24, -3769.65, 11.79, 5.41)},
    )

    _status, first = taxi.handle_gossip_hello(session, payload)
    _status, second = taxi.handle_gossip_hello(session, payload)

    assert [opcode for opcode, _payload in first] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert [opcode for opcode, _payload in second] == [
        "SMSG_TAXI_NODE_STATUS",
        "SMSG_SHOW_TAXI_NODES",
    ]
    assert _show_taxi_current_node_id(second[1][1], guid) == 80


def test_taxi_node_status_marks_undiscovered_flight_master(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
        },
    )
    session = SimpleNamespace(
        map_id=1,
        x=1700.0,
        y=-4300.0,
        z=100.0,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        npc_positions_by_guid={123: (1, 1798.27, -4363.27, 102.84, 0.0)},
    )

    response = taxi._build_taxi_node_status_response(session, 123)

    assert response[0] == "SMSG_TAXI_NODE_STATUS"
    assert _taxi_node_status(response[1]) == taxi._TAXI_NODE_STATUS_UNKNOWN
    assert response[1] == taxi.build_taxi_node_status_payload(123, known=taxi._TAXI_NODE_STATUS_UNKNOWN)


def test_taxi_node_status_marks_discovered_flight_master(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
        },
    )
    session = SimpleNamespace(
        map_id=1,
        x=1700.0,
        y=-4300.0,
        z=100.0,
        taximask_raw=_taximask_with_nodes(23),
        npc_positions_by_guid={123: (1, 1798.27, -4363.27, 102.84, 0.0)},
    )

    response = taxi._build_taxi_node_status_response(session, 123)

    assert _taxi_node_status(response[1]) == taxi._TAXI_NODE_STATUS_KNOWN


def test_taxi_available_nodes_guid_decoder_preserves_existing_order():
    guid = 0x0F0001000246BF5E
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(7, 1, 0, 4, 2, 5, 6, 3),
        byte_order=(0, 3, 7, 5, 2, 6, 4, 1),
    )

    assert taxi._decode_taxi_available_nodes_guid(payload) == guid


def test_taxi_node_status_guid_decoder_uses_pandaria_status_order():
    guid = 0x0F0001000246BF5E
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(7, 4, 1, 3, 0, 5, 2, 6),
        byte_order=(7, 1, 5, 2, 4, 0, 6, 3),
    )

    assert taxi._decode_taxi_node_status_guid(payload) == guid


def test_taxi_node_status_live_payload_decodes_requested_flight_master():
    assert taxi._decode_taxi_node_status_guid(bytes.fromhex("6b5f0300420e")) == 0x0F000100025E43


def test_enable_taxi_live_payload_decodes_requested_flight_master():
    assert taxi._decode_enable_taxi_guid(bytes.fromhex("7aeb0e0a0003")) == 0x0F00010002EA0B


def test_handle_taxi_node_status_query_uses_node_status_decoder(monkeypatch):
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    captured = {}

    def _fake_status_response(session, guid):
        captured["guid"] = guid
        return ("SMSG_TAXI_NODE_STATUS", b"status")

    monkeypatch.setattr(taxi, "_build_taxi_node_status_response", _fake_status_response)

    _status, responses = taxi.handle_taxi_node_status_query(
        SimpleNamespace(),
        bytes.fromhex("6b5f0300420e"),
    )

    assert responses == [("SMSG_TAXI_NODE_STATUS", b"status")]
    assert captured["guid"] == 0x0F000100025E43


def test_handle_taxi_query_available_nodes_uses_available_nodes_decoder(monkeypatch):
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    guid = 0x0F0001000246BF5E
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(7, 1, 0, 4, 2, 5, 6, 3),
        byte_order=(0, 3, 7, 5, 2, 6, 4, 1),
    )
    captured = {}

    def _fake_can_use(session, decoded_guid):
        captured["guid"] = decoded_guid
        return False

    monkeypatch.setattr(taxi, "_nearest_taxi_node", lambda session: None)
    monkeypatch.setattr(taxi, "_can_use_taxi_interaction", _fake_can_use)

    _status, responses = taxi.handle_taxi_query_available_nodes(SimpleNamespace(), payload)

    assert responses == [("SMSG_GOSSIP_COMPLETE", b"")]
    assert captured["guid"] == guid


def test_taxi_query_available_nodes_uses_nearby_taxi_context_on_bad_guid(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        npc_flags_by_guid={0xF0001000224DF: 0x2000},
    )
    _status, responses = taxi.handle_taxi_query_available_nodes(session, b"\x00\x70\x03\x0e\xb3\x00")

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]


def test_taxi_query_available_nodes_discovers_current_node(monkeypatch):
    saved = {}
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            315: taxi.TaxiNode(315, 571, 5813.0, 448.0, 658.0, "Dalaran", 32981, 32981),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    monkeypatch.setattr(
        taxi,
        "_save_character_taximask",
        lambda guid, realm, mask: saved.update(guid=guid, realm=realm, mask=mask) or True,
    )

    session = SimpleNamespace(
        char_guid=1002,
        realm_id=1,
        map_id=571,
        x=5813.0,
        y=448.0,
        z=658.0,
        taximask_raw=" ".join(["0"] * 64),
        npc_flags_by_guid={0xF0001000224DF: 0x2000},
    )
    _status, responses = taxi.handle_taxi_query_available_nodes(
        session,
        b"\x00\x70\x03\x0e\xb3\x00",
    )

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert _taxi_node_status(responses[1][1]) == taxi._TAXI_NODE_STATUS_KNOWN
    assert _node_mask_has(taxi._build_node_mask(taxi._known_taxi_node_ids(session)), 315)
    assert saved == {"guid": 1002, "realm": 1, "mask": session.taximask_raw}


def test_enable_taxi_discovers_unknown_flight_master_without_show_payload(monkeypatch):
    guid = 0x0F00010002EA0B
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(3, 1, 6, 0, 4, 7, 2, 5),
        byte_order=(1, 6, 3, 0, 4, 5, 7, 2),
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            71: taxi.TaxiNode(71, 0, -6672.64, -2429.81, 272.86, "New Kargath"),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=0,
        x=-6670.0,
        y=-2430.0,
        z=272.0,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        npc_flags_by_guid={guid: 0x2000},
        npc_positions_by_guid={guid: (0, -6672.64, -2429.81, 272.86, 3.96)},
    )
    _status, responses = taxi.handle_enable_taxi(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert _taxi_node_status(responses[1][1]) == taxi._TAXI_NODE_STATUS_KNOWN
    assert _node_mask_has(taxi._build_node_mask(taxi._known_taxi_node_ids(session)), 71)


def test_enable_taxi_known_flight_master_keeps_existing_flow(monkeypatch):
    guid = 0x0F00010002EA0B
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(3, 1, 6, 0, 4, 7, 2, 5),
        byte_order=(1, 6, 3, 0, 4, 5, 7, 2),
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            71: taxi.TaxiNode(71, 0, -6672.64, -2429.81, 272.86, "New Kargath"),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=0,
        x=-6670.0,
        y=-2430.0,
        z=272.0,
        taximask_raw=_taximask_with_nodes(71),
        npc_flags_by_guid={guid: 0x2000},
        npc_positions_by_guid={guid: (0, -6672.64, -2429.81, 272.86, 3.96)},
    )
    _status, responses = taxi.handle_enable_taxi(session, payload)

    assert responses == []


def test_enable_taxi_discovery_persists_taximask(monkeypatch):
    saved = {}
    guid = 0x0F00010002EA0B
    payload = _pack_guid_for_decode(
        guid,
        bit_order=(3, 1, 6, 0, 4, 7, 2, 5),
        byte_order=(1, 6, 3, 0, 4, 5, 7, 2),
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            71: taxi.TaxiNode(71, 0, -6672.64, -2429.81, 272.86, "New Kargath"),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    monkeypatch.setattr(
        taxi,
        "_save_character_taximask",
        lambda guid, realm, mask: saved.update(guid=guid, realm=realm, mask=mask) or True,
    )

    session = SimpleNamespace(
        char_guid=1003,
        realm_id=1,
        map_id=0,
        x=-6670.0,
        y=-2430.0,
        z=272.0,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        npc_flags_by_guid={guid: 0x2000},
        npc_positions_by_guid={guid: (0, -6672.64, -2429.81, 272.86, 3.96)},
    )
    _status, responses = taxi.handle_enable_taxi(session, payload)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_NEW_TAXI_PATH",
        "SMSG_TAXI_NODE_STATUS",
    ]
    assert saved == {"guid": 1003, "realm": 1, "mask": session.taximask_raw}
    assert _node_mask_has(taxi._build_node_mask(taxi._known_taxi_node_ids(session)), 71)


def test_gossip_hello_does_not_open_taxi_for_vendor(monkeypatch):
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    monkeypatch.setattr(taxi, "_can_use_taxi_interaction", lambda session, guid: False)

    session = SimpleNamespace(npc_flags_by_guid={0: 0x80})
    _status, responses = taxi.handle_gossip_hello(session, b"\x00")

    assert responses == [("SMSG_GOSSIP_COMPLETE", b"")]


def test_taxi_cheat_marks_all_nodes(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            315: taxi.TaxiNode(315, 571, 5813.0, 448.0, 658.0, "Dalaran", 32981, 32981),
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
    node_mask = _show_taxi_node_mask(payload)

    assert _node_mask_has(node_mask, 23)
    assert _node_mask_has(node_mask, 315)


def test_persisted_taximask_node_is_available_without_map_explore(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            315: taxi.TaxiNode(315, 571, 5813.0, 448.0, 658.0, "Dalaran", 32981, 32981),
        },
    )

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taximask_raw=_taximask_with_nodes(315),
        map_cheat_enabled=False,
        taxi_cheat_enabled=False,
    )
    payload = taxi.build_show_taxi_nodes_payload(session, 0)

    assert _node_mask_has(_show_taxi_node_mask(payload), 315)


def test_map_cheat_does_not_unlock_taxi_nodes(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            315: taxi.TaxiNode(315, 571, 5813.0, 448.0, 658.0, "Dalaran", 32981, 32981),
        },
    )

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        map_cheat_enabled=True,
        taxi_cheat_enabled=False,
    )
    payload = taxi.build_show_taxi_nodes_payload(session, 0)

    assert not _node_mask_has(_show_taxi_node_mask(payload), 23)
    assert not _node_mask_has(_show_taxi_node_mask(payload), 315)


def test_activate_taxi_rejects_unknown_destination(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            315: taxi.TaxiNode(315, 571, 5813.0, 448.0, 658.0, "Dalaran", 32981, 32981),
        },
    )
    monkeypatch.setattr(taxi, "_TAXI_PATHS_BY_NODES", {(23, 315): taxi.TaxiPath(901, 23, 315, 0)})
    monkeypatch.setattr(
        taxi,
        "start_taxi_flight",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError),
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        orientation=0.0,
        money=999,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        map_cheat_enabled=True,
        taxi_cheat_enabled=False,
    )
    payload = (315).to_bytes(4, "little") + (23).to_bytes(4, "little") + b"\x00"
    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert [opcode for opcode, _payload in responses] == ["SMSG_ACTIVATE_TAXI_REPLY"]
    assert session.money == 999


def test_activate_taxi_deducts_fare_and_sends_coinage_update(monkeypatch):
    calls = []
    persisted = []
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            537: taxi.TaxiNode(537, 1, 269.91, -4766.75, 11.49, "Razor Hill, Durotar", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "_TAXI_PATHS_BY_NODES", {(23, 537): taxi.TaxiPath(900, 23, 537, 75)})
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {900: (taxi.TaxiPathPoint(1798.27, -4363.27, 102.84), taxi.TaxiPathPoint(269.91, -4766.75, 11.49))},
    )
    monkeypatch.setattr(taxi, "_build_money_update_response", lambda session: ("SMSG_UPDATE_OBJECT", b"money"))
    monkeypatch.setattr(taxi, "_persist_player_money", lambda session: persisted.append(session.money))
    monkeypatch.setattr(taxi, "start_taxi_flight", lambda *args, **kwargs: calls.append((args, kwargs)) or [("SMSG_ON_MONSTER_MOVE", b"taxi")])
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        char_guid=7,
        realm_id=1,
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        orientation=0.0,
        money=100,
        taximask_raw=_taximask_with_nodes(23, 537),
    )
    payload = (537).to_bytes(4, "little") + (23).to_bytes(4, "little") + b"\x00"

    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert session.money == 25
    assert persisted == [25]
    assert len(calls) == 1
    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_UPDATE_OBJECT",
        "SMSG_ON_MONSTER_MOVE",
    ]


def test_activate_taxi_insufficient_money_does_not_start_or_deduct(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            537: taxi.TaxiNode(537, 1, 269.91, -4766.75, 11.49, "Razor Hill, Durotar", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "_TAXI_PATHS_BY_NODES", {(23, 537): taxi.TaxiPath(900, 23, 537, 75)})
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {900: (taxi.TaxiPathPoint(1798.27, -4363.27, 102.84), taxi.TaxiPathPoint(269.91, -4766.75, 11.49))},
    )
    monkeypatch.setattr(taxi, "start_taxi_flight", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "_persist_player_money", lambda session: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        orientation=0.0,
        money=74,
        taximask_raw=_taximask_with_nodes(23, 537),
    )
    payload = (537).to_bytes(4, "little") + (23).to_bytes(4, "little") + b"\x00"

    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert session.money == 74
    assert [opcode for opcode, _payload in responses] == ["SMSG_ACTIVATE_TAXI_REPLY"]
    assert _activate_taxi_reply_code(responses[0][1]) == taxi._TAXI_ACTIVATE_NOT_ENOUGH_MONEY
    assert not getattr(session, "taxi_controls_locked", False)
    assert getattr(session, "taxi_state", None) is None


def test_activate_taxi_winterspring_to_orgrimmar_requires_fare(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            53: taxi.TaxiNode(53, 1, 6813.06, -4611.12, 710.67, "Everlook, Winterspring", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "_TAXI_PATHS_BY_NODES", {(53, 23): taxi.TaxiPath(398, 53, 23, 1020)})
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            398: (
                taxi.TaxiPathPoint(6813.06, -4611.12, 710.67),
                taxi.TaxiPathPoint(1798.27, -4363.27, 102.84),
            ),
        },
    )
    monkeypatch.setattr(taxi, "start_taxi_flight", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "_persist_player_money", lambda session: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "_build_money_update_response", lambda session: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=6813.0,
        y=-4611.0,
        z=710.0,
        orientation=0.0,
        money=0,
        taximask_raw=_taximask_with_nodes(23, 53),
    )
    payload = (23).to_bytes(4, "little") + (53).to_bytes(4, "little") + b"\x00"

    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert session.money == 0
    assert [opcode for opcode, _payload in responses] == ["SMSG_ACTIVATE_TAXI_REPLY"]
    assert _activate_taxi_reply_code(responses[0][1]) == taxi._TAXI_ACTIVATE_NOT_ENOUGH_MONEY
    assert not getattr(session, "taxi_controls_locked", False)
    assert getattr(session, "taxi_state", None) is None


def test_activate_taxi_express_deducts_total_fare_once(monkeypatch):
    persisted = []
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 0.0, 0.0, 0.0, "Start", 2224, 0),
            24: taxi.TaxiNode(24, 1, 10.0, 0.0, 0.0, "Mid", 2224, 0),
            25: taxi.TaxiNode(25, 1, 20.0, 0.0, 0.0, "End", 2224, 0),
        },
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATHS_BY_NODES",
        {(23, 24): taxi.TaxiPath(901, 23, 24, 10), (24, 25): taxi.TaxiPath(902, 24, 25, 20)},
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {901: (taxi.TaxiPathPoint(0.0, 0.0, 0.0), taxi.TaxiPathPoint(10.0, 0.0, 0.0))},
    )
    monkeypatch.setattr(taxi, "_build_money_update_response", lambda session: ("SMSG_UPDATE_OBJECT", b"money"))
    monkeypatch.setattr(taxi, "_persist_player_money", lambda session: persisted.append(session.money))
    monkeypatch.setattr(taxi, "start_taxi_flight", lambda *args, **kwargs: [("SMSG_ON_MONSTER_MOVE", b"taxi")])
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        money=100,
        taximask_raw=_taximask_with_nodes(23, 24, 25),
    )
    payload = bytearray(b"\x00\x00\x0c\x00")
    payload.extend((23).to_bytes(4, "little"))
    payload.extend((24).to_bytes(4, "little"))
    payload.extend((25).to_bytes(4, "little"))

    _status, responses = taxi.handle_activate_taxi_express(session, bytes(payload))

    assert session.money == 70
    assert persisted == [70]
    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_UPDATE_OBJECT",
        "SMSG_ON_MONSTER_MOVE",
    ]


def test_activate_taxi_express_insufficient_total_fare_does_not_start(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 0.0, 0.0, 0.0, "Start", 2224, 0),
            24: taxi.TaxiNode(24, 1, 10.0, 0.0, 0.0, "Mid", 2224, 0),
            25: taxi.TaxiNode(25, 1, 20.0, 0.0, 0.0, "End", 2224, 0),
        },
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATHS_BY_NODES",
        {(23, 24): taxi.TaxiPath(901, 23, 24, 10), (24, 25): taxi.TaxiPath(902, 24, 25, 20)},
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {901: (taxi.TaxiPathPoint(0.0, 0.0, 0.0), taxi.TaxiPathPoint(10.0, 0.0, 0.0))},
    )
    monkeypatch.setattr(taxi, "start_taxi_flight", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "_persist_player_money", lambda session: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "_build_money_update_response", lambda session: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        money=29,
        taximask_raw=_taximask_with_nodes(23, 24, 25),
    )
    payload = bytearray(b"\x00\x00\x0c\x00")
    payload.extend((23).to_bytes(4, "little"))
    payload.extend((24).to_bytes(4, "little"))
    payload.extend((25).to_bytes(4, "little"))

    _status, responses = taxi.handle_activate_taxi_express(session, bytes(payload))

    assert session.money == 29
    assert [opcode for opcode, _payload in responses] == ["SMSG_ACTIVATE_TAXI_REPLY"]
    assert _activate_taxi_reply_code(responses[0][1]) == taxi._TAXI_ACTIVATE_NOT_ENOUGH_MONEY
    assert not getattr(session, "taxi_controls_locked", False)
    assert getattr(session, "taxi_state", None) is None


def test_activate_taxi_zero_price_route_works_with_zero_money(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            537: taxi.TaxiNode(537, 1, 269.91, -4766.75, 11.49, "Razor Hill, Durotar", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "_TAXI_PATHS_BY_NODES", {(23, 537): taxi.TaxiPath(900, 23, 537, 0)})
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {900: (taxi.TaxiPathPoint(1798.27, -4363.27, 102.84), taxi.TaxiPathPoint(269.91, -4766.75, 11.49))},
    )
    monkeypatch.setattr(taxi, "_persist_player_money", lambda session: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(taxi, "start_taxi_flight", lambda *args, **kwargs: [("SMSG_ON_MONSTER_MOVE", b"taxi")])
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        orientation=0.0,
        money=0,
        taximask_raw=_taximask_with_nodes(23, 537),
    )
    payload = (537).to_bytes(4, "little") + (23).to_bytes(4, "little") + b"\x00"

    _status, responses = taxi.handle_activate_taxi(session, payload)

    assert session.money == 0
    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_ON_MONSTER_MOVE",
    ]


def test_global_taxi_cheat_config_does_not_unlock_normal_session(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            315: taxi.TaxiNode(315, 571, 5813.0, 448.0, 658.0, "Dalaran", 32981, 32981),
        },
    )
    monkeypatch.setattr(feature_config, "taxi_cheat_enabled", lambda: True)

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        taximask_raw=" ".join(["0"] * taxi._TAXI_MASK_WORDS),
        taxi_cheat_enabled=False,
    )
    payload = taxi.build_show_taxi_nodes_payload(session, 0)

    assert not _node_mask_has(_show_taxi_node_mask(payload), 23)
    assert not _node_mask_has(_show_taxi_node_mask(payload), 315)


def test_activate_taxi_express_starts_runtime_flight(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 1798.27, -4363.27, 102.84, "Orgrimmar, Durotar", 2224, 0),
            53: taxi.TaxiNode(53, 1, 6813.06, -4611.12, 710.67, "Everlook, Winterspring", 2224, 0),
        },
    )
    calls = []

    def _fake_start_taxi_flight(
        session,
        path_points,
        *,
        destination_map,
        destination_node,
        source_node=0,
        speed=32.0,
        mount_display_id=6851,
        route_nodes=(),
        current_leg_index=0,
        destination_landing_point=None,
    ):
        calls.append(
            (
                session,
                path_points,
                destination_map,
                destination_node,
                source_node,
                speed,
                mount_display_id,
                route_nodes,
                destination_landing_point,
            )
        )
        return [("SMSG_ON_MONSTER_MOVE", b"taxi")]

    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    monkeypatch.setattr(taxi, "start_taxi_flight", _fake_start_taxi_flight)
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATHS_BY_NODES",
        {(23, 53): taxi.TaxiPath(901, 23, 53, 0)},
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            901: (
                taxi.TaxiPathPoint(1798.27, -4363.27, 102.84),
                taxi.TaxiPathPoint(6813.06, -4611.12, 710.67),
            ),
        },
    )

    session = SimpleNamespace(
        map_id=1,
        x=1798.0,
        y=-4363.0,
        z=102.0,
        orientation=0.0,
        taximask_raw=_taximask_with_nodes(23, 53),
    )
    payload = bytearray(b"\x00\x00\x0c\x00")
    payload.extend((23).to_bytes(4, "little"))
    payload.extend((53).to_bytes(4, "little"))

    _status, responses = taxi.handle_activate_taxi_express(session, bytes(payload))

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_ON_MONSTER_MOVE",
    ]
    assert calls[0][2] == 1
    assert calls[0][3] == 53
    assert calls[0][4] == 23
    assert calls[0][6] == 6851
    assert calls[0][7] == (23, 53)
    assert calls[0][8] == taxi.TaxiPathPoint(6813.06, -4611.12, 710.67, None, 1)
    assert (calls[0][1][-1].x, calls[0][1][-1].y, calls[0][1][-1].z) == (6813.06, -4611.12, 710.67)


def test_activate_taxi_express_starts_direct_cross_map_route(monkeypatch):
    calls = []
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            68: taxi.TaxiNode(68, 0, 2270.20, -5343.11, 86.97, "Light's Hope Chapel", 2224, 0),
            83: taxi.TaxiNode(83, 530, 7594.47, -6784.29, 86.46, "Tranquillien", 2224, 0),
        },
    )
    monkeypatch.setattr(taxi, "_TAXI_PATHS_BY_NODES", {(68, 83): taxi.TaxiPath(766, 68, 83, 0)})
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            766: (
                taxi.TaxiPathPoint(2270.15, -5337.14, 88.78, None, 0),
                taxi.TaxiPathPoint(2300.00, -5400.00, 120.00, None, 0),
                taxi.TaxiPathPoint(7500.00, -6700.00, 120.00, None, 530),
                taxi.TaxiPathPoint(7589.60, -6785.48, 88.06, None, 530),
            ),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    def _fake_start_taxi_flight(
        session,
        path_points,
        *,
        destination_map,
        destination_node,
        source_node=0,
        speed=32.0,
        mount_display_id=6851,
        route_nodes=(),
        current_leg_index=0,
        destination_landing_point=None,
    ):
        calls.append((path_points, destination_map, destination_node, source_node, route_nodes, current_leg_index))
        return [("SMSG_ON_MONSTER_MOVE", b"taxi-express-cross-map-start")]

    monkeypatch.setattr(taxi, "start_taxi_flight", _fake_start_taxi_flight)
    session = SimpleNamespace(
        map_id=0,
        x=2270.20,
        y=-5343.11,
        z=86.97,
        orientation=0.0,
        taximask_raw=_taximask_with_nodes(68, 83),
    )
    payload = bytearray(b"\x00\x00\x0c\x00")
    payload.extend((68).to_bytes(4, "little"))
    payload.extend((83).to_bytes(4, "little"))

    _status, responses = taxi.handle_activate_taxi_express(session, bytes(payload))

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_ACTIVATE_TAXI_REPLY",
        "SMSG_ON_MONSTER_MOVE",
    ]
    assert calls[0][1:6] == (0, 83, 68, (68, 83), -1)
    assert all(point.map_id == 0 for point in calls[0][0])


def test_taxi_path_points_prefers_dbc_waypoints(monkeypatch):
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            23: taxi.TaxiNode(23, 1, 0.0, 0.0, 0.0, "Source", 2224, 0),
            537: taxi.TaxiNode(537, 1, 100.0, 0.0, 0.0, "Destination", 2224, 0),
        },
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATHS_BY_NODES",
        {(23, 537): taxi.TaxiPath(900, 23, 537, 0)},
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            900: (
                taxi.TaxiPathPoint(0.0, 0.0, 20.0),
                taxi.TaxiPathPoint(50.0, 25.0, 40.0),
                taxi.TaxiPathPoint(100.0, 0.0, 20.0),
            ),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    session = SimpleNamespace(map_id=1, x=0.0, y=0.0, z=0.0, orientation=0.0)

    _map_id, points = taxi._taxi_path_points_from_nodes(session, (23, 537))

    assert len(points) > 5
    assert (points[0].x, points[0].y, points[0].z) == (0.0, 0.0, 0.0)
    assert (points[-1].x, points[-1].y, points[-1].z) == (100.0, 0.0, 20.0)


def test_resample_taxi_points_keeps_path_line_and_adds_points():
    points = [
        taxi.TaxiPathPoint(0.0, 0.0, 0.0),
        taxi.TaxiPathPoint(10.0, 0.0, 0.0),
    ]

    resampled = taxi._resample_taxi_points(points, 4.0)

    assert [(round(point.x, 3), point.y, point.z) for point in resampled] == [
        (0.0, 0.0, 0.0),
        (3.333, 0.0, 0.0),
        (6.667, 0.0, 0.0),
        (10.0, 0.0, 0.0),
    ]


def test_move_spline_done_continues_multi_leg_taxi(monkeypatch):
    calls = []
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            24: taxi.TaxiNode(24, 1, 10.0, 0.0, 0.0, "Middle", 2224, 0),
            25: taxi.TaxiNode(25, 1, 20.0, 0.0, 0.0, "End", 2224, 0),
        },
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATHS_BY_NODES",
        {(24, 25): taxi.TaxiPath(902, 24, 25, 0)},
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            902: (
                taxi.TaxiPathPoint(10.0, 0.0, 0.0),
                taxi.TaxiPathPoint(20.0, 0.0, 0.0),
            ),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    def _continue(
        session,
        path_points,
        *,
        destination_map,
        destination_node,
        source_node,
        destination_landing_point=None,
    ):
        calls.append((path_points, destination_map, destination_node, source_node, destination_landing_point))
        return [("SMSG_ON_MONSTER_MOVE", b"next")]

    monkeypatch.setattr(taxi, "continue_taxi_flight", _continue)
    previous_path = taxi_runtime.build_taxi_path(
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(10.0, 0.0, 0.0),
        ],
        destination_map=1,
        destination_node=24,
    )
    assert previous_path is not None
    session = SimpleNamespace(
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=None,
        taxi_state=SimpleNamespace(
            active=True,
            completed=False,
            path=previous_path,
            route_nodes=(23, 24, 25),
            current_leg_index=0,
        ),
    )

    _status, responses = taxi.handle_move_spline_done(session, b"")

    assert responses == [("SMSG_ON_MONSTER_MOVE", b"next")]
    assert calls[0][2:4] == (25, 24)
    assert calls[0][4] == taxi.TaxiPathPoint(20.0, 0.0, 0.0, None, 1)


def test_move_spline_done_cross_map_leg_starts_worldport(monkeypatch):
    flight_store = get_flight_path_runtime_store()
    flight_store.clear()
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            24: taxi.TaxiNode(24, 1, 10.0, 0.0, 0.0, "Cross-map source", 2224, 0),
            25: taxi.TaxiNode(25, 0, -30.0, -40.0, 6.0, "Cross-map end", 2224, 0),
        },
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATHS_BY_NODES",
        {(24, 25): taxi.TaxiPath(902, 24, 25, 0)},
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            902: (
                taxi.TaxiPathPoint(12.0, 0.0, 1.0, None, 1),
                taxi.TaxiPathPoint(-10.0, -20.0, 5.0, None, 0),
                taxi.TaxiPathPoint(-30.0, -40.0, 6.0, None, 0),
            ),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())
    monkeypatch.setattr(taxi, "attach_session_to_world_state", lambda session, map_id: None)
    login_packets = types.ModuleType("server.modules.handlers.world.login.packets")
    login_packets.build_login_packet = (
        lambda opcode_name, ctx: f"{opcode_name}|{ctx.map_id}|{ctx.x:.1f}|{ctx.y:.1f}|{ctx.z:.1f}".encode()
    )
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.login.packets", login_packets)

    previous_path = taxi_runtime.build_taxi_path(
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0, None, 1),
            taxi_runtime.TaxiPathPoint(10.0, 0.0, 0.0, None, 1),
        ],
        source_node=23,
        destination_node=24,
        source_map=1,
        destination_map=0,
    )
    assert previous_path is not None
    session = SimpleNamespace(
        char_guid=7,
        map_id=1,
        x=10.0,
        y=0.0,
        z=0.0,
        orientation=1.5,
        movement_state=SimpleNamespace(x=10.0, y=0.0, z=0.0, orientation=1.5),
        loaded_gameobjects={1},
        loaded_npcs={2},
        loaded_transport_entries={3: {}},
        taxi_state=SimpleNamespace(
            active=True,
            completed=False,
            path=previous_path,
            route_nodes=(23, 24, 25),
            current_leg_index=0,
            phase="TAXI_FLIGHT",
        ),
    )
    flight_path = flight_store.add(FlightPath.from_session(session))

    try:
        _status, responses = taxi.handle_move_spline_done(session, b"")
    finally:
        flight_store.clear()

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert responses[0][1] == b"SMSG_TRANSFER_PENDING|0|-10.0|-20.0|5.0"
    assert responses[1][1] == b"SMSG_NEW_WORLD|0|-10.0|-20.0|5.0"
    assert session.map_id == 0
    assert (session.x, session.y, session.z) == (-10.0, -20.0, 5.0)
    assert session.movement_state.x == -10.0
    assert session.pending_taxi_transfer == {
        "source_map": 1,
        "destination_map": 0,
        "source_node": 24,
        "destination_node": 25,
        "world_transition_generation": 1,
    }
    assert session.world_transition_owner == "taxi_worldport"
    assert session.world_transition_generation == 1
    assert session.world_transition_loading_generation == 1
    assert is_player_world_active(session) is False
    assert session.taxi_state.active is True
    assert session.taxi_state.phase == "TAXI_TRANSFER"
    assert session.teleport_pending is True
    assert session.worldport_ack_pending is True
    assert session.loaded_gameobjects == set()
    assert session.loaded_npcs == set()
    assert session.loaded_transport_entries == {}
    assert flight_path.map_id == session.map_id
    assert flight_path.world_position == (session.x, session.y, session.z)
    assert flight_path.orientation == session.orientation


def test_continue_pending_cross_map_taxi_launches_next_leg(monkeypatch):
    calls = []
    monkeypatch.setattr(
        taxi,
        "_TAXI_NODES",
        {
            24: taxi.TaxiNode(24, 1, 10.0, 0.0, 0.0, "Cross-map source", 2224, 0),
            25: taxi.TaxiNode(25, 0, -30.0, -40.0, 6.0, "Cross-map end", 2224, 0),
        },
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATHS_BY_NODES",
        {(24, 25): taxi.TaxiPath(902, 24, 25, 0)},
    )
    monkeypatch.setattr(
        taxi,
        "_TAXI_PATH_POINTS_BY_PATH",
        {
            902: (
                taxi.TaxiPathPoint(12.0, 0.0, 1.0, None, 1),
                taxi.TaxiPathPoint(-10.0, -20.0, 5.0, None, 0),
                taxi.TaxiPathPoint(-30.0, -40.0, 6.0, None, 0),
            ),
        },
    )
    monkeypatch.setattr(taxi, "Logger", _quiet_logger())

    def _continue(
        session,
        path_points,
        *,
        destination_map,
        destination_node,
        source_node,
        destination_landing_point=None,
    ):
        calls.append((path_points, destination_map, destination_node, source_node, destination_landing_point))
        return [("SMSG_ON_MONSTER_MOVE", b"next-cross-map")]

    monkeypatch.setattr(taxi, "continue_taxi_flight", _continue)
    session = SimpleNamespace(
        char_guid=7,
        map_id=0,
        x=-10.0,
        y=-20.0,
        z=5.0,
        orientation=1.5,
        pending_taxi_transfer={
            "source_map": 1,
            "destination_map": 0,
            "source_node": 24,
            "destination_node": 25,
        },
        taxi_state=SimpleNamespace(active=True, completed=False),
    )

    responses = taxi.continue_pending_cross_map_taxi(session)

    assert responses == [("SMSG_ON_MONSTER_MOVE", b"next-cross-map")]
    assert session.pending_taxi_transfer is None
    assert calls[0][1:4] == (0, 25, 24)
    assert calls[0][4] == taxi.TaxiPathPoint(-30.0, -40.0, 6.0, None, 0)
    assert calls[0][0][0] == taxi.TaxiPathPoint(-10.0, -20.0, 5.0, 1.5, 0)
    assert calls[0][0][-1] == taxi.TaxiPathPoint(-30.0, -40.0, 6.0, None, 0)
    assert all(point.map_id == 0 for point in calls[0][0])


def test_cross_map_taxi_can_complete_after_continuation(monkeypatch):
    completed = []
    monkeypatch.setattr(taxi, "complete_taxi_spline", lambda session: completed.append(session))
    session = SimpleNamespace(
        map_id=0,
        taxi_state=SimpleNamespace(
            active=True,
            completed=False,
            route_nodes=(23, 24, 25),
            current_leg_index=1,
        ),
    )

    _status, responses = taxi.handle_move_spline_done(session, b"")

    assert responses is None
    assert completed == [session]


def test_move_spline_done_completes_final_taxi_leg(monkeypatch):
    completed = []
    monkeypatch.setattr(taxi, "complete_taxi_spline", lambda session: completed.append(session))
    session = SimpleNamespace(
        taxi_state=SimpleNamespace(
            active=True,
            completed=False,
            route_nodes=(23, 24),
            current_leg_index=0,
        )
    )

    _status, responses = taxi.handle_move_spline_done(session, b"")

    assert responses is None
    assert completed == [session]


def test_dispatcher_allows_spline_done_while_taxi_active(monkeypatch):
    calls = []
    monkeypatch.setitem(
        dispatcher.HANDLERS,
        "CMSG_MOVE_SPLINE_DONE",
        lambda session, data: (0, calls.append(data)),
    )
    monkeypatch.setattr(taxi_runtime, "is_taxi_active", lambda session: True)

    dispatcher.dispatch(SimpleNamespace(), "CMSG_MOVE_SPLINE_DONE", b"done")

    assert calls == [b"done"]
