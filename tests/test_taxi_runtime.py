#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from types import SimpleNamespace

from server.modules.handlers.world import taxi_runtime
from server.session.world_session import MovementState


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
