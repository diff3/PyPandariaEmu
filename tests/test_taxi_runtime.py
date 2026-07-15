#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from types import SimpleNamespace
import json

from server.modules.handlers.world import taxi_runtime
from server.modules.handlers.world.runtime import (
    FlightPath,
    FlightPathRuntimeStore,
    Player,
    RuntimeObject,
    WorldObject,
    get_flight_path_runtime_store,
    get_player_runtime_store,
    resolve_flight_path_runtime,
)
from server.session.world_session import MovementState


def _taxi_session():
    return SimpleNamespace(
        char_guid=7,
        realm_id=1,
        world_guid=7,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
        can_fly=False,
        is_flying=False,
        is_mounted=False,
        mount_spell=None,
        mount_display_id=0,
        unit_flags=0,
        run_speed=7.0,
        fly_speed=7.0,
        fly_back_speed=4.5,
    )


def _disable_taxi_side_effects(monkeypatch, *, broadcasts=None):
    monkeypatch.setattr(
        taxi_runtime,
        "_build_mount_visual_responses",
        lambda session, display_id: [],
    )
    monkeypatch.setattr(
        taxi_runtime,
        "_broadcast_mount_visual",
        lambda session, display_id: None,
    )
    monkeypatch.setattr(taxi_runtime, "_send_self_movement", lambda session: None)
    monkeypatch.setattr(
        taxi_runtime,
        "broadcast_player_state_update",
        broadcasts if broadcasts is not None else lambda session, force=False: None,
    )


def _start_test_flight(session):
    return taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(10.0, 0.0, 5.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=5.0,
        mount_display_id=6851,
    )


def test_flight_path_runtime_store_uses_runtime_guid_as_its_only_index():
    session = _taxi_session()
    session.instance_id = 4
    flight_path = FlightPath.from_session(session)
    store = FlightPathRuntimeStore()

    assert isinstance(flight_path, WorldObject)
    assert isinstance(flight_path, RuntimeObject)
    assert flight_path.runtime_guid == 7
    assert flight_path.map_id == 1
    assert flight_path.instance_id == 4
    assert flight_path.world_position == (0.0, 0.0, 0.0)
    assert flight_path.rotation == (0.0, 0.0, 0.0, 1.0)
    assert flight_path.scale == 1.0

    assert store.add(flight_path) is flight_path
    assert store.get(7) is flight_path
    assert store.contains(7) is True
    assert list(store) == [flight_path]
    assert store.remove(7) is flight_path
    assert store.contains(7) is False
    store.add(flight_path)
    store.clear()
    assert list(store) == []


def test_flight_start_registers_stable_runtime_and_tick_publishes_transform(
    monkeypatch,
):
    store = get_flight_path_runtime_store()
    store.clear()
    _disable_taxi_side_effects(monkeypatch)
    session = _taxi_session()

    try:
        _start_test_flight(session)
        flight_path = store.get(7)

        assert isinstance(flight_path, FlightPath)
        assert resolve_flight_path_runtime(session) is flight_path
        assert flight_path.world_position == (session.x, session.y, session.z)

        session._taxi_last_tick_at = 100.0
        assert taxi_runtime.taxi_tick(session, now=101.0) is True

        assert store.get(7) is flight_path
        assert flight_path.map_id == session.map_id
        assert flight_path.world_position == (session.x, session.y, session.z)
        assert flight_path.orientation == session.orientation
    finally:
        store.clear()


def test_flight_path_packet_path_matches_unregistered_fallback(monkeypatch):
    store = get_flight_path_runtime_store()
    store.clear()
    _disable_taxi_side_effects(monkeypatch)
    session = _taxi_session()

    try:
        _start_test_flight(session)
        state = session.taxi_state
        retained = resolve_flight_path_runtime(session)
        retained_response = taxi_runtime._build_taxi_spline_response(session, state)

        assert store.remove(retained.runtime_guid) is retained
        fallback = resolve_flight_path_runtime(session)
        fallback_response = taxi_runtime._build_taxi_spline_response(session, state)

        assert fallback is not retained
        assert store.contains(retained.runtime_guid) is False
        assert fallback_response == retained_response
    finally:
        store.clear()


def test_flight_visibility_broadcast_observes_published_runtime(monkeypatch):
    store = get_flight_path_runtime_store()
    store.clear()
    observed = []

    def capture_broadcast(session, force=False):
        flight_path = resolve_flight_path_runtime(session)
        observed.append(
            (
                flight_path,
                flight_path.map_id,
                flight_path.world_position,
                flight_path.orientation,
                bool(force),
            )
        )

    _disable_taxi_side_effects(monkeypatch, broadcasts=capture_broadcast)
    session = _taxi_session()

    try:
        _start_test_flight(session)
        flight_path = store.get(7)
        session._taxi_last_tick_at = 100.0
        assert taxi_runtime.taxi_tick(session, now=101.0) is True

        assert observed
        assert all(item[0] is flight_path for item in observed)
        assert observed[-1][1] == session.map_id
        assert observed[-1][2] == (session.x, session.y, session.z)
        assert observed[-1][3] == session.orientation
        assert observed[-1][4] is True
    finally:
        store.clear()


def test_flight_completion_and_cancellation_unregister_runtime(monkeypatch):
    store = get_flight_path_runtime_store()
    store.clear()
    _disable_taxi_side_effects(monkeypatch)
    session = _taxi_session()

    _start_test_flight(session)
    first = store.get(7)
    assert first is not None
    taxi_runtime.complete_taxi_spline(session)
    assert store.contains(7) is False

    _start_test_flight(session)
    second = store.get(7)
    assert second is not None
    assert second is not first
    taxi_runtime.cancel_taxi_flight(session, "test_interrupt")
    assert store.contains(7) is False


def test_cancelled_taxi_tick_cannot_overwrite_teleport_destination(monkeypatch):
    _disable_taxi_side_effects(monkeypatch)
    session = _taxi_session()
    _start_test_flight(session)
    stale_state = session.taxi_state

    taxi_runtime.cancel_taxi_flight(
        session,
        "ordinary_teleport",
        send_updates=False,
    )
    session.map_id = 0
    session.x = 100.0
    session.y = 200.0
    session.z = 300.0
    session.orientation = 1.25

    assert stale_state is not None
    assert taxi_runtime.taxi_tick(session, now=101.0) is False
    assert (session.map_id, session.x, session.y, session.z, session.orientation) == (
        0,
        100.0,
        200.0,
        300.0,
        1.25,
    )


def test_taxi_position_boundary_updates_runtime_player():
    session = _taxi_session()
    session.instance_id = 9
    store = get_player_runtime_store()
    store.clear()
    player = store.add(Player.from_session(session))
    point = taxi_runtime.TaxiPathPoint(
        10.0,
        20.0,
        30.0,
        map_id=530,
    )

    try:
        taxi_runtime._apply_taxi_position(session, point, 1.25)

        assert player.map_id == session.map_id == 530
        assert player.instance_id == session.instance_id == 9
        assert player.world_position == (session.x, session.y, session.z)
        assert player.orientation == session.orientation == 1.25
    finally:
        store.clear()


def test_start_taxi_flight_emits_native_spline_without_snapshot_thread(monkeypatch):
    thread_starts = []
    broadcasts = []
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: thread_starts.append(generation))
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: broadcasts.append(force))

    session = _taxi_session()

    responses = taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(10.0, 0.0, 0.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=5.0,
        mount_display_id=6851,
        source_node=1,
        route_nodes=(1, 2),
    )

    assert [opcode for opcode, _payload in responses] == ["SMSG_ON_MONSTER_MOVE"]
    assert thread_starts == []
    assert session.taxi_state.active is True
    assert session.taxi_controls_locked is True
    assert session.can_fly is True
    assert session.is_flying is True
    assert broadcasts


def test_taxi_tick_linearly_interpolates_and_sets_flying_flags(monkeypatch):
    sent = []
    broadcasts = []
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(taxi_runtime, "_send_self_movement", lambda session: sent.append((session.x, session.y, session.z)))
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: broadcasts.append(force))

    session = SimpleNamespace(
        char_guid=7,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
        can_fly=False,
        is_flying=False,
        is_mounted=False,
        mount_spell=None,
        mount_display_id=0,
        unit_flags=0,
        run_speed=7.0,
        fly_speed=7.0,
        fly_back_speed=4.5,
    )

    taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(10.0, 0.0, 5.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=5.0,
        mount_display_id=6851,
    )
    session._taxi_last_tick_at = 100.0

    assert taxi_runtime.taxi_tick(session, now=101.0) is True

    assert 4.45 <= session.x <= 4.49
    assert 2.22 <= session.z <= 2.25
    assert session.can_fly is True
    assert session.is_flying is True
    assert session.movement_state.flags & taxi_runtime._MOVEMENTFLAG_CAN_FLY
    assert session.movement_state.flags & taxi_runtime._MOVEMENTFLAG_FLYING
    assert session.movement_state.flags & taxi_runtime._MOVEMENTFLAG_FORWARD
    assert not session.movement_state.flags & taxi_runtime._MOVEMENTFLAG_ASCENDING
    assert not session.movement_state.flags & taxi_runtime._MOVEMENTFLAG_DESCENDING
    assert sent
    assert broadcasts


def test_taxi_arrival_restores_controls_and_original_state(monkeypatch):
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(taxi_runtime, "_send_self_movement", lambda session: None)
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: None)

    session = SimpleNamespace(
        char_guid=7,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
        can_fly=False,
        is_flying=False,
        is_mounted=False,
        mount_spell=None,
        mount_display_id=0,
        unit_flags=0,
        run_speed=7.0,
        fly_speed=7.0,
        fly_back_speed=4.5,
    )

    taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(1.0, 0.0, 0.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=20.0,
        mount_display_id=6851,
    )
    session._taxi_last_tick_at = 100.0

    assert taxi_runtime.taxi_tick(session, now=101.0) is False

    assert session.x == 1.0
    assert session.taxi_state is None
    assert session.taxi_controls_locked is False
    assert session.can_fly is False
    assert session.is_flying is False
    assert session.is_mounted is False
    assert session.mount_display_id == 0


def test_taxi_arrival_sends_stopped_movement_state_for_short_and_long_routes(monkeypatch):
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: None)

    routes = (
        (
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(10.0, 0.0, 0.0, orientation=1.25),
        ),
        (
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(140.0, 60.0, 25.0),
            taxi_runtime.TaxiPathPoint(260.0, 120.0, 10.0, orientation=1.25),
        ),
    )

    for points in routes:
        sent_flags = []
        monkeypatch.setattr(
            taxi_runtime,
            "_send_self_movement",
            lambda session: sent_flags.append(int(session.movement_state.flags)),
        )
        session = _taxi_session()

        taxi_runtime.start_taxi_flight(
            session,
            list(points),
            destination_map=1,
            destination_node=2,
            speed=20.0,
            mount_display_id=6851,
        )

        assert session.movement_state.flags & taxi_runtime._MOVEMENTFLAG_FORWARD

        taxi_runtime.complete_taxi_spline(session)

        assert sent_flags
        assert sent_flags[-1] & taxi_runtime._MOVEMENTFLAG_FORWARD == 0
        assert sent_flags[-1] & taxi_runtime._MOVEMENTFLAG_CAN_FLY == 0
        assert sent_flags[-1] & taxi_runtime._MOVEMENTFLAG_FLYING == 0
        assert sent_flags[-1] & taxi_runtime._MOVEMENTFLAG_ASCENDING == 0
        assert sent_flags[-1] & taxi_runtime._MOVEMENTFLAG_DESCENDING == 0
        assert session.movement_state.flags == sent_flags[-1]
        assert session.x == points[-1].x
        assert session.orientation == 1.25
        assert session.taxi_state is None


def test_taxi_arrival_uses_destination_landing_height(monkeypatch):
    sent_positions = []
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(
        taxi_runtime,
        "_send_self_movement",
        lambda session: sent_positions.append((session.x, session.y, session.z, session.orientation)),
    )
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: None)

    session = _taxi_session()
    spline_endpoint = taxi_runtime.TaxiPathPoint(-8833.164, 479.763, 112.096)
    landing_point = taxi_runtime.TaxiPathPoint(-8841.060, 489.656, 109.607, None, 0)

    taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(-9000.0, 400.0, 130.0),
            spline_endpoint,
        ],
        destination_map=0,
        destination_node=2,
        speed=20.0,
        mount_display_id=6851,
        destination_landing_point=landing_point,
    )

    assert session.taxi_state.path.points[-1].z == spline_endpoint.z
    assert round(session.taxi_state.path.points[-1].z - landing_point.z, 3) == 2.489

    taxi_runtime.complete_taxi_spline(session)

    assert sent_positions[-1][0:3] == (landing_point.x, landing_point.y, landing_point.z)
    assert session.x == landing_point.x
    assert session.y == landing_point.y
    assert session.z == landing_point.z
    assert session.movement_state.z == landing_point.z
    assert session.taxi_state is None


def test_taxi_disconnect_completion_persists_destination_without_packets(monkeypatch):
    flight_store = get_flight_path_runtime_store()
    flight_store.clear()
    sent_positions = []
    broadcasts = []
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(
        taxi_runtime,
        "_send_self_movement",
        lambda session: sent_positions.append((session.x, session.y, session.z)),
    )
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: broadcasts.append(force))

    session = _taxi_session()
    landing_point = taxi_runtime.TaxiPathPoint(50.0, 60.0, 7.0, None, 1)

    taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(50.0, 60.0, 10.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=20.0,
        mount_display_id=6851,
        destination_landing_point=landing_point,
    )
    assert flight_store.contains(7) is True
    sent_positions.clear()
    broadcasts.clear()

    assert taxi_runtime.complete_taxi_for_disconnect(session) is True

    assert sent_positions == []
    assert broadcasts == []
    assert session.x == landing_point.x
    assert session.y == landing_point.y
    assert session.z == landing_point.z
    assert session.movement_state.z == landing_point.z
    assert session.taxi_state is None
    assert session.taxi_controls_locked is False
    assert session.player_travel_state == taxi_runtime.TAXI_STATE_NORMAL
    assert session.can_fly is False
    assert session.is_flying is False
    assert session.is_mounted is False
    assert session.movement_state.flags & taxi_runtime._MOVEMENTFLAG_FORWARD == 0
    assert flight_store.contains(7) is False


def test_taxi_disconnect_snapshot_resumes_at_same_progress(monkeypatch):
    flight_store = get_flight_path_runtime_store()
    flight_store.clear()
    _disable_taxi_side_effects(monkeypatch)
    saved = []
    monkeypatch.setattr(
        taxi_runtime,
        "_save_persisted_taxi_snapshot",
        lambda guid, realm, value: saved.append((guid, realm, value)) or True,
    )
    session = _taxi_session()
    _start_test_flight(session)
    session._taxi_last_tick_at = 100.0
    assert taxi_runtime.taxi_tick(session, now=101.0) is True
    paused_position = (session.x, session.y, session.z)
    paused_distance = session.taxi_state.traveled_distance

    assert taxi_runtime.persist_taxi_for_disconnect(session) is True
    assert (session.x, session.y, session.z) == paused_position
    assert session.taxi_state is None
    assert flight_store.contains(7) is False
    snapshot = json.loads(saved[-1][2])
    assert snapshot["traveled_distance"] == paused_distance

    relog = _taxi_session()
    assert taxi_runtime.restore_persisted_taxi(relog, saved[-1][2]) is True
    assert (relog.x, relog.y, relog.z) == paused_position
    assert relog.taxi_state.traveled_distance == paused_distance
    assert flight_store.contains(7) is False

    responses = taxi_runtime.activate_restored_taxi(relog)
    assert [opcode for opcode, _payload in responses].count("SMSG_ON_MONSTER_MOVE") == 1
    assert flight_store.contains(7) is True
    relog._taxi_last_tick_at = 200.0
    relog.taxi_state.last_tick_at = 200.0
    assert taxi_runtime.taxi_tick(relog, now=200.5) is True
    assert relog.taxi_state.traveled_distance > paused_distance
    flight_store.clear()


def test_taxi_disconnect_derives_progress_from_client_spline_clock(monkeypatch):
    flight_store = get_flight_path_runtime_store()
    flight_store.clear()
    _disable_taxi_side_effects(monkeypatch)
    saved = []
    monkeypatch.setattr(
        taxi_runtime,
        "_save_persisted_taxi_snapshot",
        lambda guid, realm, value: saved.append(value) or True,
    )
    session = _taxi_session()
    _start_test_flight(session)
    state = session.taxi_state
    state.started_at = 100.0
    state.last_tick_at = 100.0
    state.traveled_distance = 0.0
    monkeypatch.setattr(taxi_runtime.time, "monotonic", lambda: 101.0)

    assert taxi_runtime.persist_taxi_for_disconnect(session) is True

    snapshot = json.loads(saved[-1])
    assert snapshot["traveled_distance"] == 5.0
    assert session.x > 0.0
    assert session.x < 10.0
    relog = _taxi_session()
    assert taxi_runtime.restore_persisted_taxi(relog, saved[-1]) is True
    assert relog.x == session.x
    assert relog.taxi_state.traveled_distance == 5.0
    flight_store.clear()


def test_taxi_z_curve_is_monotone_between_altitude_nodes():
    path = taxi_runtime.build_taxi_path(
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(50.0, 0.0, 50.0),
            taxi_runtime.TaxiPathPoint(100.0, 0.0, 100.0),
            taxi_runtime.TaxiPathPoint(150.0, 0.0, 75.0),
        ],
        destination_map=1,
        destination_node=2,
    )

    assert path is not None
    first_segment = [
        sample.z
        for sample in path.arc_samples
        if sample.segment_index == 1
    ]

    assert first_segment
    assert min(first_segment) >= 50.0
    assert max(first_segment) <= 100.0
    assert first_segment == sorted(first_segment)


def test_taxi_z_smoothing_reduces_sample_step_without_moving_endpoints():
    samples = (
        taxi_runtime.TaxiPathSample(0.0, 0.0, 0.0, 0.0, 1, 0, 0.0, 0.0),
        taxi_runtime.TaxiPathSample(10.0, 0.0, 8.0, 0.0, 1, 0, 0.5, 10.0),
        taxi_runtime.TaxiPathSample(20.0, 0.0, 16.0, 0.0, 1, 0, 1.0, 20.0),
        taxi_runtime.TaxiPathSample(30.0, 0.0, 8.0, 0.0, 1, 1, 0.5, 30.0),
        taxi_runtime.TaxiPathSample(40.0, 0.0, 0.0, 0.0, 1, 1, 1.0, 40.0),
        taxi_runtime.TaxiPathSample(50.0, 0.0, 8.0, 0.0, 1, 2, 0.5, 50.0),
        taxi_runtime.TaxiPathSample(60.0, 0.0, 16.0, 0.0, 1, 2, 1.0, 60.0),
    )

    smoothed = taxi_runtime._smooth_taxi_altitude_samples(samples)

    raw_max_step = max(abs(end.z - start.z) for start, end in zip(samples, samples[1:]))
    smooth_max_step = max(abs(end.z - start.z) for start, end in zip(smoothed, smoothed[1:]))

    assert smoothed[0].z == samples[0].z
    assert smoothed[-1].z == samples[-1].z
    assert smooth_max_step < raw_max_step


def test_taxi_tick_limits_extreme_z_delta_without_changing_xy(monkeypatch):
    sent = []
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(taxi_runtime, "_send_self_movement", lambda session: sent.append((session.x, session.y, session.z)))
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: None)

    session = SimpleNamespace(
        char_guid=7,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
        can_fly=False,
        is_flying=False,
        is_mounted=False,
        mount_spell=None,
        mount_display_id=0,
        unit_flags=0,
        run_speed=7.0,
        fly_speed=7.0,
        fly_back_speed=4.5,
    )

    taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(100.0, 0.0, 400.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=42.0,
        mount_display_id=6851,
    )
    session._taxi_last_tick_at = 100.0

    assert taxi_runtime.taxi_tick(session, now=101.0) is True

    assert session.x > 0.0
    assert session.z == taxi_runtime.TAXI_MAX_Z_SPEED
    assert sent[-1][2] == taxi_runtime.TAXI_MAX_Z_SPEED


def test_taxi_completion_waits_for_continuous_z_correction(monkeypatch):
    sent = []
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(taxi_runtime, "_send_self_movement", lambda session: sent.append((session.x, session.y, session.z)))
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: None)

    session = SimpleNamespace(
        char_guid=7,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
        can_fly=False,
        is_flying=False,
        is_mounted=False,
        mount_spell=None,
        mount_display_id=0,
        unit_flags=0,
        run_speed=7.0,
        fly_speed=7.0,
        fly_back_speed=4.5,
    )

    taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(1.0, 0.0, 100.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=1000.0,
        mount_display_id=6851,
    )
    session._taxi_last_tick_at = 100.0

    assert taxi_runtime.taxi_tick(session, now=101.0) is True

    assert session.taxi_state is not None
    assert session.x == 1.0
    assert session.z == taxi_runtime.TAXI_MAX_Z_SPEED
    assert sent[-1][2] == taxi_runtime.TAXI_MAX_Z_SPEED


def test_taxi_real_tick_limits_extreme_z_delta(monkeypatch):
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(taxi_runtime, "_send_self_movement", lambda session: None)
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: None)

    session = SimpleNamespace(
        char_guid=7,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
        can_fly=False,
        is_flying=False,
        is_mounted=False,
        mount_spell=None,
        mount_display_id=0,
        unit_flags=0,
        run_speed=7.0,
        fly_speed=7.0,
        fly_back_speed=4.5,
    )

    taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(100.0, 0.0, 400.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=42.0,
        mount_display_id=6851,
    )
    state = session.taxi_state
    state.started_at = 100.0
    state.last_tick_at = 100.0
    session._taxi_last_tick_at = 100.0

    assert taxi_runtime.taxi_tick(session, now=100.05) is True

    assert session.z <= taxi_runtime.TAXI_MAX_Z_DELTA_PER_TICK


def test_taxi_runtime_tick_bounds_real_delayed_progress(monkeypatch):
    monkeypatch.setattr(taxi_runtime, "_start_taxi_thread", lambda session, generation: None)
    monkeypatch.setattr(taxi_runtime, "_build_mount_visual_responses", lambda session, display_id: [])
    monkeypatch.setattr(taxi_runtime, "_broadcast_mount_visual", lambda session, display_id: None)
    monkeypatch.setattr(taxi_runtime, "_send_self_movement", lambda session: None)
    monkeypatch.setattr(taxi_runtime, "broadcast_player_state_update", lambda session, force=False: None)

    session = SimpleNamespace(
        char_guid=7,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
        can_fly=False,
        is_flying=False,
        is_mounted=False,
        mount_spell=None,
        mount_display_id=0,
        unit_flags=0,
        run_speed=7.0,
        fly_speed=7.0,
        fly_back_speed=4.5,
    )

    taxi_runtime.start_taxi_flight(
        session,
        [
            taxi_runtime.TaxiPathPoint(0.0, 0.0, 0.0),
            taxi_runtime.TaxiPathPoint(1000.0, 0.0, 0.0),
        ],
        destination_map=1,
        destination_node=2,
        speed=100.0,
        mount_display_id=6851,
    )
    state = session.taxi_state
    state.started_at = 100.0
    state.last_tick_at = 100.0
    session._taxi_last_tick_at = 100.0

    elapsed = taxi_runtime._taxi_tick_delta_seconds(session, state, 101.0, clamp_delta=True)

    assert elapsed == taxi_runtime.TAXI_MAX_RUNTIME_DT_SECONDS
