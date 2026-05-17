#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

replay_module = types.ModuleType("server.modules.handlers.world.bootstrap.replay")
replay_module.build_database_gameobject_responses = lambda *args, **kwargs: []
replay_module.build_multi_u32_update_object_payload = lambda *args, **kwargs: b""
replay_module.build_single_u32_update_object_payload = lambda *args, **kwargs: b""
sys.modules.setdefault("server.modules.handlers.world.bootstrap.replay", replay_module)

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type("DatabaseConnection", (), {})
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

from server.modules.handlers.world import transport_runtime
from server.modules.handlers.world.opcodes import movement


def _reset_transport_states() -> None:
    states = getattr(transport_runtime._runtime_transport_states, "_states", None)
    if isinstance(states, dict):
        states.clear()


def test_thunder_bluff_elevator_uses_transport_runtime_route(monkeypatch):
    _reset_transport_states()
    now = 100.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)

    session = SimpleNamespace()
    entry = {
        "guid": 897,
        "world_guid": 0xF110000000000381,
        "entry": 4171,
        "map": 1,
        "type": 11,
        "display_id": 360,
        "x": -1308.37,
        "y": 185.29,
        "z": 68.586,
        "orientation": 0.0,
        "size": 1.0,
    }

    assert transport_runtime.is_runtime_transport_entry(entry) is True
    prepared = transport_runtime.prepare_runtime_transport_entry(entry)

    assert prepared["type"] == transport_runtime.GAMEOBJECT_TYPE_TRANSPORT
    assert prepared["original_type"] == transport_runtime.GAMEOBJECT_TYPE_TRANSPORT
    assert prepared["use_transport_guid"] is True
    assert prepared["transport_period"] == int(
        transport_runtime._THUNDER_BLUFF_ELEVATOR_PERIOD_SECONDS * 1000.0
    )
    assert transport_runtime.is_runtime_transport_entry(prepared) is True
    assert transport_runtime.is_thunder_bluff_elevator_entry(prepared) is True

    moved = transport_runtime.apply_transport_runtime_position(session, prepared)

    assert moved["z"] == transport_runtime._THUNDER_BLUFF_ELEVATOR_LOW_Z

    now = 101.0
    transport_runtime.apply_transport_runtime_position(session, prepared)
    now = 103.0
    moved = transport_runtime.apply_transport_runtime_position(session, prepared)

    assert moved["z"] > transport_runtime._THUNDER_BLUFF_ELEVATOR_LOW_Z
    assert moved["transport_path_progress"] > 0
    assert moved["transport_period"] == int(
        transport_runtime._THUNDER_BLUFF_ELEVATOR_PERIOD_SECONDS * 1000.0
    )
    state = transport_runtime._runtime_transport_states()[prepared["world_guid"]]
    assert len(state.route) == 2
    assert round(state.speed, 3) == round(
        (
            transport_runtime._THUNDER_BLUFF_ELEVATOR_HIGH_Z
            - transport_runtime._THUNDER_BLUFF_ELEVATOR_LOW_Z
        )
        / 16.0,
        3,
    )


def test_runtime_elevator_without_lift_support_leaves_z_unchanged(monkeypatch):
    calls = []
    session = SimpleNamespace(
        supported_lift_guid=0,
        loaded_transport_entries={
            0xF110000000000381: {
                "guid": 897,
                "world_guid": 0xF110000000000381,
                "entry": 4171,
                "map": 1,
                "type": 11,
                "x": -1308.37,
                "y": 185.29,
                "z": 68.586,
            }
        },
    )

    monkeypatch.setattr(
        movement,
        "_clear_lift_support_state",
        lambda *args, **kwargs: calls.append(kwargs.get("reason")),
    )

    z, lift = movement._apply_loaded_lift_support(
        session,
        opcode_name="MSG_MOVE_HEARTBEAT",
        x=0.0,
        y=0.0,
        z=70.0,
        previous_z=70.0,
        movement_flags=0,
    )

    assert z == 70.0
    assert lift is None
    assert calls == ["outside_xy"]


def test_runtime_elevator_jump_keeps_attachment(monkeypatch):
    now = 500.0
    monkeypatch.setattr(movement.time, "time", lambda: now)
    monkeypatch.setattr(movement, "_start_lift_transport_thread", lambda session: None)
    monkeypatch.setattr(movement, "_is_teleporting", lambda session: False)
    monkeypatch.setattr(movement, "_capture_persist_position_from_session", lambda session: None)
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda session: None)

    guid = 0x1FC0000000000381
    session = SimpleNamespace(
        attached_elevator_guid=guid,
        elevator_local_offset_x=1.0,
        elevator_local_offset_y=2.0,
        elevator_local_offset_z=0.0,
        orientation=0.0,
        x=-1307.37,
        y=187.29,
        z=69.0,
        runtime_elevator_states={
            guid: {
                "guid": guid,
                "entry": 4171,
                "map_id": 1,
                "base_x": -1308.37,
                "base_y": 185.29,
                "low_z": 68.586,
                "high_z": 130.080,
                "current_z": 68.586,
                "direction": 1.0,
                "period": 32.0,
                "speed": 3.843,
                "last_tick": now,
            }
        },
    )

    handled, x, y, z, state = movement._runtime_elevator_support(
        session,
        opcode_name="MSG_MOVE_JUMP",
        x=-1307.37,
        y=187.29,
        z=73.0,
        previous_z=69.0,
        movement_flags=0,
    )

    assert handled is True
    assert state is session.runtime_elevator_states[guid]
    assert session.attached_elevator_guid == guid
    assert x == -1307.37
    assert y == 187.29
    assert z == 73.0
    assert session.elevator_local_offset_z > 0.0
