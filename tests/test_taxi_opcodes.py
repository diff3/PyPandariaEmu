#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from types import SimpleNamespace

from server.modules.handlers.world import dispatcher
from server.modules.handlers.world import taxi_runtime
from server.modules.handlers.world.opcodes import taxi


def _quiet_logger():
    return SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
    )


def test_show_taxi_nodes_marks_basic_horde_nodes(monkeypatch):
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
    session = SimpleNamespace(map_id=1, x=1800.0, y=-4360.0, z=102.0)

    payload = taxi.build_show_taxi_nodes_payload(session, 0)

    node_mask = payload[-taxi._TAXI_NODE_MASK_BYTES:]
    for node_id in (23, 25, 536, 537):
        assert node_mask[node_id // 8] & (1 << (node_id % 8))


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

    session = SimpleNamespace(map_id=1, x=1798.0, y=-4363.0, z=102.0, orientation=0.0)
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
        "SMSG_TAXI_NODE_STATUS",
        "SMSG_SHOW_TAXI_NODES",
    ]


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

    assert [opcode for opcode, _payload in responses] == ["SMSG_SHOW_TAXI_NODES"]


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
    node_mask = payload[-taxi._TAXI_NODE_MASK_BYTES:]

    assert node_mask[23 // 8] & (1 << (23 % 8))
    assert node_mask[315 // 8] & (1 << (315 % 8))


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

    session = SimpleNamespace(map_id=1, x=1798.0, y=-4363.0, z=102.0, orientation=0.0)
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
