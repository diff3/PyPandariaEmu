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
