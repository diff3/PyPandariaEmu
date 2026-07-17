#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import copy
import sys
import struct
import types
import math
from types import SimpleNamespace

import pytest

from server.modules.protocol.packet_batch import PacketBatch

replay_module = types.ModuleType("server.modules.handlers.world.bootstrap.replay")
replay_module.build_database_gameobject_responses = lambda *args, **kwargs: []
replay_module.build_multi_u32_update_object_payload = lambda *args, **kwargs: b""
replay_module.build_single_u32_update_object_payload = lambda *args, **kwargs: b""
sys.modules.setdefault("server.modules.handlers.world.bootstrap.replay", replay_module)
creatures_module = types.ModuleType("server.modules.handlers.world.bootstrap.creatures")
creatures_module.build_database_creature_responses = lambda *args, **kwargs: []
sys.modules.setdefault("server.modules.handlers.world.bootstrap.creatures", creatures_module)

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type(
    "DatabaseConnection",
    (),
    {
        "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
        "get_creatures_near": staticmethod(lambda *args, **kwargs: []),
    },
)
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

chat_opcode_module = types.ModuleType("server.modules.handlers.world.opcodes.chat")


def _test_apply_player_state_change(
    session,
    *,
    position=None,
    map_id=None,
    suppress_worldport_cleanup=False,
    **_kwargs,
):
    if position is not None:
        if not suppress_worldport_cleanup:
            from server.modules.handlers.world.transport_runtime import (
                clear_player_transport_state,
            )

            clear_player_transport_state(
                session,
                reason="teleport",
                opcode_name="test_chat_teleport",
            )
        loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
        if isinstance(loaded_gameobjects, set):
            loaded_gameobjects.clear()
        loaded_transport_entries = getattr(session, "loaded_transport_entries", None)
        if isinstance(loaded_transport_entries, dict):
            loaded_transport_entries.clear()
        x, y, z, orientation = position
        session.x = float(x)
        session.y = float(y)
        session.z = float(z)
        session.orientation = float(orientation)
        if map_id is not None:
            session.map_id = int(map_id)
        movement_state = getattr(session, "movement_state", None)
        if movement_state is not None:
            movement_state.x = float(x)
            movement_state.y = float(y)
            movement_state.z = float(z)
            movement_state.orientation = float(orientation)
            movement_state.flags = 0
            movement_state.flags2 = 0
    return [("SMSG_TRANSFER_PENDING", b"normal"), ("SMSG_NEW_WORLD", b"normal")]


chat_opcode_module.apply_player_state_change = _test_apply_player_state_change
sys.modules.setdefault("server.modules.handlers.world.opcodes.chat", chat_opcode_module)

from server.modules.handlers.world import transport_runtime
from server.modules.handlers.world.bootstrap import gameobjects
from server.modules.handlers.world.movements import manager as movement_manager_module
from server.modules.handlers.world.movements import evaluator
from server.modules.handlers.world.movements.types import (
    MovementInstance,
    MovementLifecycleEvent,
    MovementLifecycleEventType,
    MovementRuntimeState,
)
from server.modules.handlers.world.opcodes import movement
from server.modules.handlers.world.runtime.runtime_object import RuntimeObject
from server.modules.handlers.world.runtime.elevator import Elevator
from server.modules.handlers.world.runtime.elevator_store import (
    ElevatorRuntimeStore,
    get_elevator_runtime_store,
    resolve_elevator_runtime,
)
from server.modules.handlers.world.runtime.transport import Transport
from server.modules.handlers.world.runtime.world_object import WorldObject
from server.modules.handlers.world.runtime.world_attachment import (
    persist_session_world_attachment,
    prepare_login_world_attachment,
)
from server.session.world_session import MovementState


def _reset_transport_states() -> None:
    transport_runtime.reset_world_transport_manager_for_tests()


def _tick_transport_entry(entry: dict) -> None:
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    transport_runtime.get_world_transport_manager()._tick_transport_state(
        int(state.guid),
        state,
    )


def _payload_update_type(response: tuple[str, bytes]) -> int:
    _opcode, payload = response
    return int(payload[6])


def _loaded_mo_transport_entry(world_guid: int = 0x1FC00000000186A7) -> dict:
    return {
        "guid": 100007,
        "world_guid": int(world_guid),
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "x": 0.0,
        "y": 0.0,
        "z": 0.0,
        "orientation": 0.0,
        "size": 1.0,
        "flags": 40,
        "state": 1,
        "animprogress": 255,
        "transport_period": 1000,
        "transport_path_progress": 0,
    }


def _install_runtime_update_test_transport(monkeypatch, entry: dict):
    world_guid = int(entry["world_guid"])
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=int(entry["entry"]),
        spawn_guid=int(entry["guid"]),
        display_id=int(entry["display_id"]),
        route=[
            transport_runtime.TransportRouteNode(1, 0.0, 0.0, 0.0, 0.0, 0),
            transport_runtime.TransportRouteNode(1, 10.0, 0.0, 0.0, 0.0, 1000),
        ],
        node_index=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=1,
        path_progress_ms=0,
        timed_route=True,
        route_period_ms=1000,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state

    monkeypatch.setattr(transport_runtime, "_sync_transport_state_from_movement_cache", lambda _state: None)
    monkeypatch.setattr(
        transport_runtime.get_world_transport_manager(),
        "is_visible",
        lambda _guid: True,
    )
    monkeypatch.setattr(
        transport_runtime.get_world_transport_manager(),
        "visibility_state_for_guid",
        lambda _guid: transport_runtime.TRANSPORT_VISIBILITY_ACTIVE,
    )

    def moved_entry(_session, current_entry):
        moved = dict(current_entry)
        moved.update(
            {
                "map": int(state.map_id),
                "x": float(state.x),
                "y": float(state.y),
                "z": float(state.z),
                "orientation": float(state.orientation),
                "transport_path_progress": int(state.path_progress_ms),
                "transport_period": int(state.route_period_ms),
                "_transport_create_source_path": "runtime",
                "_transport_runtime_state_found": True,
            }
        )
        return moved

    monkeypatch.setattr(transport_runtime, "cached_transport_runtime_entry", moved_entry)
    return state


def _registered_runtime_transport() -> tuple[
    dict,
    transport_runtime.RuntimeTransportState,
    Transport,
]:
    entry = {
        **_loaded_mo_transport_entry(),
        "map_id": 1,
        "home_map": 1,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 0.0, 0),
            (1, 10.0, 0.0, 0.0, 0.0, 1000),
        ],
    }
    manager = transport_runtime.get_world_transport_manager()
    state = manager.register_transport(entry, source="test")
    assert state is not None
    transport = manager.transport_for_guid(int(entry["world_guid"]))
    assert transport is not None
    return entry, state, transport


def _runtime_elevator_animation(entry_id: int = 999010):
    return transport_runtime.TransportAnimationPath(
        entry=int(entry_id),
        nodes=(
            transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
            transport_runtime.TransportAnimationNode(5000, 0.0, 0.0, 10.0),
            transport_runtime.TransportAnimationNode(10000, 0.0, 0.0, 0.0),
        ),
        period_ms=10000,
    )


def _registered_runtime_elevator(monkeypatch):
    entry_id = 999010
    animation = _runtime_elevator_animation(entry_id)
    monkeypatch.setattr(
        transport_runtime,
        "_transport_animation_for_entry",
        lambda candidate: animation if int(candidate) == entry_id else None,
    )
    entry = transport_runtime.prepare_runtime_transport_entry(
        {
            "guid": 9010,
            "world_guid": int(transport_runtime.MoTransportGuid.from_spawn_guid(9010)),
            "entry": entry_id,
            "map": 1,
            "map_id": 1,
            "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
            "original_type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
            "display_id": 360,
            "x": 10.0,
            "y": 20.0,
            "z": 30.0,
            "orientation": 0.75,
            "rotation0": 0.0,
            "rotation1": 0.0,
            "rotation2": 0.25,
            "rotation3": 0.9682458,
            "size": 1.25,
        }
    )
    manager = transport_runtime.get_world_transport_manager()
    state = manager.register_transport(entry, source="elevator-runtime-test")
    assert state is not None
    elevator = manager.elevator_for_guid(int(entry["world_guid"]))
    assert elevator is not None
    return entry, state, elevator


def test_transport_runtime_object_has_stable_shared_identity():
    _reset_transport_states()
    entry, state, transport = _registered_runtime_transport()
    manager = transport_runtime.get_world_transport_manager()

    assert isinstance(transport, Transport)
    assert isinstance(transport, WorldObject)
    assert isinstance(transport, RuntimeObject)
    assert transport.runtime_state is state
    assert state.transport is transport
    assert transport.runtime_guid == int(entry["world_guid"])
    assert transport.entry == int(entry["entry"])
    assert transport.spawn_id == int(entry["guid"])
    assert manager.transport_for_guid(int(entry["world_guid"])) is transport

    duplicate = manager.register_transport(entry, source="duplicate-test")

    assert duplicate is state
    assert manager.transport_for_guid(int(entry["world_guid"])) is transport
    assert state.transport is transport


def test_elevator_runtime_store_uses_runtime_guid_as_its_only_index():
    mapping = {
        "entry": 999010,
        "map": 1,
        "instance_id": 3,
        "x": 10.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 0.75,
        "rotation2": 0.25,
        "rotation3": 0.9682458,
        "size": 1.25,
    }
    elevator = Elevator.from_mapping(mapping, runtime_guid=12345)
    store = ElevatorRuntimeStore()

    assert isinstance(elevator, WorldObject)
    assert isinstance(elevator, RuntimeObject)
    assert elevator.runtime_guid == 12345
    assert elevator.entry == 999010
    assert elevator.map_id == 1
    assert elevator.instance_id == 3
    assert elevator.world_position == (10.0, 20.0, 30.0)
    assert elevator.orientation == 0.75
    assert elevator.rotation == (0.0, 0.0, 0.25, 0.9682458)
    assert elevator.scale == 1.25

    assert store.add(elevator) is elevator
    assert store.get(12345) is elevator
    assert store.contains(12345) is True
    assert list(store) == [elevator]
    assert store.remove(12345) is elevator
    assert store.contains(12345) is False
    store.add(elevator)
    store.clear()
    assert list(store) == []


def test_elevator_runtime_object_has_stable_shared_identity(monkeypatch):
    _reset_transport_states()
    entry, state, elevator = _registered_runtime_elevator(monkeypatch)
    manager = transport_runtime.get_world_transport_manager()
    store = get_elevator_runtime_store()

    assert state.elevator is elevator
    assert state.transport is None
    assert manager.world_object_for_guid(int(entry["world_guid"])) is elevator
    assert manager.transport_for_guid(int(entry["world_guid"])) is None
    assert store.get(int(entry["world_guid"])) is elevator

    duplicate = manager.register_transport(entry, source="duplicate-elevator-test")

    assert duplicate is state
    assert manager.elevator_for_guid(int(entry["world_guid"])) is elevator
    assert state.elevator is elevator


def _attachment_restore_session(spawn_id: int, **overrides):
    values = {
        "char_guid": 42,
        "realm_id": 1,
        "map_id": 1,
        "instance_id": 0,
        "x": -10.0,
        "y": -20.0,
        "z": -30.0,
        "orientation": 0.25,
        "movement_state": MovementState(),
        "transport_attach_state": transport_runtime.ATTACH_STATE_DETACHED,
        "transport_attached_guid": 0,
        "pending_world_attachment_restore": {
            "spawn_id": int(spawn_id),
            "local_x": 2.0,
            "local_y": 3.0,
            "local_z": 4.0,
            "local_o": 0.5,
            "safe_map": 1,
            "safe_instance_id": 0,
            "safe_x": -10.0,
            "safe_y": -20.0,
            "safe_z": -30.0,
            "safe_o": 0.25,
            "status": "LOADED",
        },
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_login_attachment_restores_elevator_world_object(monkeypatch):
    _reset_transport_states()
    entry, state, elevator = _registered_runtime_elevator(monkeypatch)
    session = _attachment_restore_session(int(state.spawn_guid))

    assert prepare_login_world_attachment(session) is True

    assert session.transport_attached_guid == elevator.runtime_guid
    assert session.movement_state.transport_guid == elevator.runtime_guid
    assert session.pending_world_attachment_restore["status"] == "PREPARED"
    assert transport_runtime.transport_passenger_attachment(
        elevator.runtime_guid,
        42,
    ) is not None
    assert session._player_bootstrap_runtime_transport["transport_guid"] == int(
        entry["world_guid"]
    )
    expected_x = float(state.x) + math.cos(float(state.orientation)) * 2.0 - math.sin(float(state.orientation)) * 3.0
    expected_y = float(state.y) + math.sin(float(state.orientation)) * 2.0 + math.cos(float(state.orientation)) * 3.0
    assert session.x == pytest.approx(expected_x)
    assert session.y == pytest.approx(expected_y)
    assert session.z == pytest.approx(float(state.z) + 4.0)
    assert (session.x, session.y, session.z) != (-10.0, -20.0, -30.0)


def test_login_attachment_prepare_is_idempotent_across_elevator_ticks(monkeypatch):
    _reset_transport_states()
    _entry, state, elevator = _registered_runtime_elevator(monkeypatch)
    session = _attachment_restore_session(int(state.spawn_guid))

    assert prepare_login_world_attachment(session) is True
    first_position = (session.x, session.y, session.z, session.orientation)
    first_attachment = transport_runtime.transport_passenger_attachment(
        elevator.runtime_guid,
        42,
    )
    first_bootstrap = dict(session._player_bootstrap_runtime_transport)

    state.z += 25.0
    state.path_progress_ms += 5000

    assert prepare_login_world_attachment(session) is True
    assert (session.x, session.y, session.z, session.orientation) == first_position
    assert transport_runtime.transport_passenger_attachment(
        elevator.runtime_guid,
        42,
    ) is first_attachment
    assert session._player_bootstrap_runtime_transport == first_bootstrap


def test_repeated_elevator_relog_never_changes_runtime_transform(monkeypatch):
    _reset_transport_states()
    _entry, state, _elevator = _registered_runtime_elevator(monkeypatch)
    expected_transform = (
        state.x,
        state.y,
        state.z,
        state.orientation,
        state.path_progress_ms,
    )

    for _cycle in range(4):
        session = _attachment_restore_session(int(state.spawn_guid))
        assert prepare_login_world_attachment(session) is True
        assert (
            state.x,
            state.y,
            state.z,
            state.orientation,
            state.path_progress_ms,
        ) == expected_transform
        transport_runtime.detach_session_transport_passenger(
            session,
            reason="disconnect",
        )
        assert (
            state.x,
            state.y,
            state.z,
            state.orientation,
            state.path_progress_ms,
        ) == expected_transform


def test_login_attachment_uses_current_boat_transform_after_movement():
    _reset_transport_states()
    _entry, state, transport = _registered_runtime_transport()
    old_runtime_identity = id(transport)
    state.x = 500.0
    state.y = 600.0
    state.z = 20.0
    state.orientation = math.pi / 2.0
    state.path_progress_ms = 3210
    transport_runtime.get_world_transport_manager().update_entry_transform_from_state(
        state
    )
    session = _attachment_restore_session(int(state.spawn_guid))

    assert prepare_login_world_attachment(session) is True

    assert id(
        transport_runtime.get_world_transport_manager().transport_for_guid(
            transport.runtime_guid
        )
    ) == old_runtime_identity
    assert session.x == pytest.approx(497.0)
    assert session.y == pytest.approx(602.0)
    assert session.z == pytest.approx(24.0)
    assert session.x != -10.0
    assert session.movement_state.transport_time == 3210


def test_login_attachment_missing_runtime_falls_back_to_safe_position():
    _reset_transport_states()
    session = _attachment_restore_session(
        999999,
        map_id=0,
        x=100.0,
        y=200.0,
        z=300.0,
    )

    assert prepare_login_world_attachment(session) is False

    assert session.pending_world_attachment_restore is None
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_DETACHED
    assert session.movement_state.has_transport_data is False
    assert (session.map_id, session.x, session.y, session.z) == (
        1,
        -10.0,
        -20.0,
        -30.0,
    )


def test_login_attachment_resolves_replaced_runtime_identity_after_restart():
    _reset_transport_states()
    entry, state, old_transport = _registered_runtime_transport()
    spawn_id = int(state.spawn_guid)
    old_runtime_guid = int(old_transport.runtime_guid)

    _reset_transport_states()
    replacement_entry = dict(entry)
    replacement_entry["world_guid"] = old_runtime_guid + 1000
    replacement_state = (
        transport_runtime.get_world_transport_manager().register_transport(
            replacement_entry,
            source="restart-test",
        )
    )
    assert replacement_state is not None
    session = _attachment_restore_session(spawn_id)

    assert prepare_login_world_attachment(session) is True
    assert session.transport_attached_guid == old_runtime_guid + 1000
    assert session.transport_attached_guid != old_runtime_guid


def test_login_attachment_rejects_transferring_world_object():
    _reset_transport_states()
    _entry, state, _transport = _registered_runtime_transport()
    state.transfer_active = True
    state.transfer_destination_map = 0
    session = _attachment_restore_session(
        int(state.spawn_guid),
        map_id=0,
        x=100.0,
        y=200.0,
        z=300.0,
    )

    assert prepare_login_world_attachment(session) is False
    assert session.pending_world_attachment_restore is None
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_DETACHED
    assert (session.map_id, session.x, session.y, session.z) == (
        1,
        -10.0,
        -20.0,
        -30.0,
    )


def test_logout_attachment_persists_spawn_identity_and_local_offset():
    _reset_transport_states()
    _entry, state, transport = _registered_runtime_transport()
    session = _attachment_restore_session(int(state.spawn_guid))
    session.transport_attach_state = transport_runtime.ATTACH_STATE_ATTACHED
    session.transport_attached_guid = transport.runtime_guid
    session.movement_state.has_transport_data = True
    session.movement_state.transport_guid = transport.runtime_guid
    session.movement_state.transport_x = 7.0
    session.movement_state.transport_y = 8.0
    session.movement_state.transport_z = 9.0
    session.movement_state.transport_orientation = 0.75
    saved = []

    class DbApi:
        @staticmethod
        def save_character_world_attachment(char_guid, realm_id, **values):
            saved.append((char_guid, realm_id, values))
            return True

    assert persist_session_world_attachment(session, db_api=DbApi) is True
    assert saved == [
        (
            42,
            1,
            {
                "spawn_id": int(state.spawn_guid),
                "local_x": 7.0,
                "local_y": 8.0,
                "local_z": 9.0,
                "local_o": 0.75,
            },
        )
    ]


def test_attached_logout_preserves_absolute_safe_position(monkeypatch):
    session = _attachment_restore_session(7)
    session.transport_attach_state = transport_runtime.ATTACH_STATE_ATTACHED
    position_saves = []
    online_saves = []
    monkeypatch.setattr(
        movement.DatabaseConnection,
        "save_character_position",
        lambda *args, **kwargs: position_saves.append((args, kwargs)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        movement.DatabaseConnection,
        "save_character_online_state",
        lambda *args, **kwargs: online_saves.append((args, kwargs)) or True,
        raising=False,
    )

    assert movement._save_session_position(
        session,
        reason="disconnect",
        online=0,
        force=True,
    ) is True
    assert position_saves == []
    assert len(online_saves) == 1
    assert online_saves[0][0] == (42, 1)
    assert online_saves[0][1]["online"] == 0
    assert int(online_saves[0][1]["logout_time"]) > 0


def test_login_attachment_rejects_invalid_saved_offset():
    _reset_transport_states()
    _entry, state, _transport = _registered_runtime_transport()
    session = _attachment_restore_session(int(state.spawn_guid))
    session.pending_world_attachment_restore["local_x"] = float("inf")

    assert prepare_login_world_attachment(session) is False
    assert session.pending_world_attachment_restore is None
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_DETACHED


def test_elevator_movement_publishes_transform_without_owning_simulation(monkeypatch):
    _reset_transport_states()
    _entry, state, elevator = _registered_runtime_elevator(monkeypatch)
    manager = transport_runtime.get_world_transport_manager()
    route = state.route
    state.path_progress_ms = 2500
    state.map_id = 530
    state.x = 101.25
    state.y = -202.5
    state.z = 44.75
    state.orientation = 1.25

    synchronized = manager.sync_transport_object(state)

    assert synchronized is elevator
    assert elevator.map_id == 530
    assert elevator.world_position == (101.25, -202.5, 44.75)
    assert elevator.orientation == 1.25
    assert state.route is route
    assert not hasattr(elevator, "runtime_state")
    assert not hasattr(elevator, "path_progress_ms")
    assert not hasattr(elevator, "route")


def test_elevator_resolution_fallback_is_unregistered(monkeypatch):
    _reset_transport_states()
    entry, state, elevator = _registered_runtime_elevator(monkeypatch)
    store = get_elevator_runtime_store()
    world_guid = int(entry["world_guid"])

    assert resolve_elevator_runtime(
        entry,
        runtime_guid=world_guid,
        state=state,
    ) is elevator

    assert store.remove(world_guid) is elevator
    fallback = resolve_elevator_runtime(
        entry,
        runtime_guid=world_guid,
        state=state,
    )

    assert isinstance(fallback, Elevator)
    assert fallback is not elevator
    assert fallback.world_position == (state.x, state.y, state.z)
    assert store.contains(world_guid) is False


def test_elevator_packet_and_visibility_paths_reuse_runtime_object(monkeypatch):
    _reset_transport_states()
    entry, state, elevator = _registered_runtime_elevator(monkeypatch)
    manager = transport_runtime.get_world_transport_manager()
    world_guid = int(entry["world_guid"])
    state.x = 13.5
    state.y = 24.5
    state.z = 35.5
    state.orientation = 0.875
    manager.sync_transport_object(state)
    moved_entry = {
        **entry,
        "map": state.map_id,
        "map_id": state.map_id,
        "x": state.x,
        "y": state.y,
        "z": state.z,
        "orientation": state.orientation,
    }
    observer = SimpleNamespace(
        char_guid=1,
        map_id=state.map_id,
        x=state.x,
        y=state.y,
        z=state.z,
    )
    retained_visibility = manager.entries_near(
        observer,
        radius=1.0,
    )

    retained_payload = gameobjects._build_gameobject_update_payload(
        map_id=state.map_id,
        entry=moved_entry,
        realm_id=1,
        transport=elevator,
    )
    get_elevator_runtime_store().remove(world_guid)
    fallback = manager.resolve_world_object(world_guid, moved_entry)
    fallback_payload = gameobjects._build_gameobject_update_payload(
        map_id=state.map_id,
        entry=moved_entry,
        realm_id=1,
        transport=fallback,
    )

    assert isinstance(fallback, Elevator)
    assert fallback is not elevator
    assert get_elevator_runtime_store().contains(world_guid) is False
    assert fallback_payload == retained_payload

    fallback_visibility = manager.entries_near(
        observer,
        radius=1.0,
    )
    assert fallback_visibility == retained_visibility
    assert [candidate["world_guid"] for candidate in fallback_visibility] == [world_guid]


def test_elevator_visibility_reuses_manager_runtime_object(monkeypatch):
    _reset_transport_states()
    entry, _state, elevator = _registered_runtime_elevator(monkeypatch)
    world_guid = int(entry["world_guid"])
    captured: list[WorldObject | None] = []

    monkeypatch.setattr(
        transport_runtime,
        "_sync_transport_state_from_movement_cache",
        lambda _state: None,
    )

    def capture_create(*, transport=None, **_kwargs):
        captured.append(transport)
        return b"elevator-create"

    monkeypatch.setattr(
        transport_runtime,
        "_build_gameobject_update_payload",
        capture_create,
    )
    session = SimpleNamespace(
        char_guid=31,
        gameobjects_visible=True,
        map_id=1,
        x=10.0,
        y=20.0,
        z=30.0,
        realm_id=1,
        loaded_gameobjects=set(),
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        {world_guid: dict(entry)},
        force=True,
    )

    assert len(responses) == 1
    assert captured == [elevator]
    assert world_guid in session.loaded_gameobjects


def test_elevator_despawn_unregisters_runtime_object(monkeypatch):
    _reset_transport_states()
    entry, state, elevator = _registered_runtime_elevator(monkeypatch)
    manager = transport_runtime.get_world_transport_manager()
    world_guid = int(entry["world_guid"])

    assert manager.elevator_for_guid(world_guid) is elevator
    state.lifecycle_state = transport_runtime.TRANSPORT_STATE_DESPAWNED

    assert manager.sync_transport_object(state) is None
    assert manager.elevator_for_guid(world_guid) is None
    assert state.elevator is None


def test_transport_runtime_object_publishes_transform_without_owning_clocks():
    _reset_transport_states()
    _entry, state, transport = _registered_runtime_transport()
    manager = transport_runtime.get_world_transport_manager()
    original_route = state.route
    state.path_progress_ms = 375
    state.map_id = 0
    state.x = 101.25
    state.y = -202.5
    state.z = 33.75
    state.orientation = 1.25

    synchronized = manager.sync_transport_object(state)

    assert synchronized is transport
    assert transport.map_id == 0
    assert transport.world_position == (101.25, -202.5, 33.75)
    assert transport.orientation == 1.25
    assert transport.runtime_state.path_progress_ms == 375
    assert transport.runtime_state.route is original_route
    assert not hasattr(transport, "path_progress_ms")
    assert not hasattr(transport, "route")


def test_transport_visibility_reuses_manager_runtime_object(monkeypatch):
    _reset_transport_states()
    entry, _state, transport = _registered_runtime_transport()
    world_guid = int(entry["world_guid"])
    captured: list[Transport | None] = []

    monkeypatch.setattr(
        transport_runtime,
        "_sync_transport_state_from_movement_cache",
        lambda _state: None,
    )

    def capture_create(*, transport=None, **_kwargs):
        captured.append(transport)
        return b"transport-create"

    monkeypatch.setattr(
        transport_runtime,
        "_build_gameobject_update_payload",
        capture_create,
    )
    session = SimpleNamespace(
        char_guid=30,
        gameobjects_visible=True,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        realm_id=1,
        loaded_gameobjects=set(),
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        {world_guid: dict(entry)},
        force=True,
    )

    assert len(responses) == 1
    assert captured == [transport]
    assert world_guid in session.loaded_gameobjects


def test_transport_packet_path_is_byte_identical(monkeypatch):
    _reset_transport_states()
    entry, state, transport = _registered_runtime_transport()
    state.x = 3.5
    state.y = 4.5
    state.z = 5.5
    state.orientation = 0.75
    state.path_progress_ms = 250
    transport_runtime.get_world_transport_manager().sync_transport_object(state)
    moved_entry = {
        **entry,
        "map": state.map_id,
        "map_id": state.map_id,
        "x": state.x,
        "y": state.y,
        "z": state.z,
        "orientation": state.orientation,
        "transport_path_progress": state.path_progress_ms,
    }
    monkeypatch.setattr(
        gameobjects,
        "_manager_transport_for_guid",
        lambda _world_guid: None,
    )

    mapping_payload = gameobjects._build_gameobject_update_payload(
        map_id=state.map_id,
        entry=moved_entry,
        realm_id=1,
    )
    runtime_payload = gameobjects._build_gameobject_update_payload(
        map_id=state.map_id,
        entry=moved_entry,
        realm_id=1,
        transport=transport,
    )
    mapping_values_payload = gameobjects._build_gameobject_values_update_payload(
        map_id=state.map_id,
        entry=moved_entry,
        realm_id=1,
    )
    runtime_values_payload = gameobjects._build_gameobject_values_update_payload(
        map_id=state.map_id,
        entry=moved_entry,
        realm_id=1,
        transport=transport,
    )

    assert runtime_payload == mapping_payload
    assert runtime_values_payload == mapping_values_payload


def test_runtime_transport_lifecycle_create_values_destroy_create(monkeypatch):
    _reset_transport_states()
    entry = _loaded_mo_transport_entry()
    world_guid = int(entry["world_guid"])
    state = _install_runtime_update_test_transport(monkeypatch, entry)
    session = SimpleNamespace(
        char_guid=30,
        gameobjects_visible=True,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        realm_id=1,
        loaded_gameobjects=set(),
    )
    entries = {world_guid: dict(entry)}

    first = transport_runtime._build_visible_transport_updates(session, entries)

    assert len(first) == 1
    assert _payload_update_type(first[0]) == 1
    assert world_guid in session.loaded_gameobjects

    state.x = 3.0
    state.path_progress_ms = 300
    second = transport_runtime._build_visible_transport_updates(session, entries)

    assert len(second) == 1
    assert _payload_update_type(second[0]) == 0

    destroyed = transport_runtime._despawn_loaded_transport(
        session,
        entries,
        world_guid,
        map_id=1,
        reason="test",
    )

    assert len(destroyed) == 1
    assert _payload_update_type(destroyed[0]) == 3
    assert world_guid not in session.loaded_gameobjects
    assert world_guid not in entries

    entries[world_guid] = dict(entry)
    state.x = 6.0
    state.path_progress_ms = 600
    recreated = transport_runtime._build_visible_transport_updates(session, entries)

    assert len(recreated) == 1
    assert _payload_update_type(recreated[0]) == 1


def test_runtime_transport_values_update_is_suppressed_during_world_bootstrap(monkeypatch):
    _reset_transport_states()
    entry = _loaded_mo_transport_entry()
    world_guid = int(entry["world_guid"])
    state = _install_runtime_update_test_transport(monkeypatch, entry)
    state.x = 3.0
    state.path_progress_ms = 300
    session = SimpleNamespace(
        char_guid=30,
        gameobjects_visible=True,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        realm_id=1,
        login_state="WORLD_BOOTSTRAP",
        teleport_pending=False,
        worldport_ack_pending=False,
        loading_screen_visible=False,
        loaded_gameobjects={world_guid},
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        {world_guid: dict(entry)},
        force=True,
    )

    assert responses == []


def test_runtime_transport_map_mismatch_destroy_is_suppressed_during_worldport(monkeypatch):
    _reset_transport_states()
    entry = _loaded_mo_transport_entry()
    world_guid = int(entry["world_guid"])
    session = SimpleNamespace(
        char_guid=30,
        gameobjects_visible=True,
        map_id=0,
        x=0.0,
        y=0.0,
        z=0.0,
        realm_id=1,
        login_state="IN_WORLD",
        teleport_pending=True,
        worldport_ack_pending=True,
        loading_screen_visible=False,
        loaded_gameobjects={world_guid},
    )
    entries = {world_guid: dict(entry)}
    suppressed: list[tuple[str, int]] = []

    monkeypatch.setattr(
        transport_runtime,
        "_log_suppressed_runtime_transport_update",
        lambda _session, guid, *, session_state, operation="update": suppressed.append(
            (operation, int(guid))
        ),
    )

    responses = transport_runtime._build_visible_transport_updates(session, entries)

    assert responses == []
    assert suppressed == [("destroy", world_guid)]
    assert world_guid in session.loaded_gameobjects
    assert world_guid in entries


def test_map_transfer_clears_transport_by_default(monkeypatch):
    from server.modules.handlers.world.teleport import map_transfer

    session = SimpleNamespace(
        map_id=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
    )
    session.movement_state.has_transport_data = True
    session.movement_state.transport_guid = 9
    session.movement_state.transport_x = 1.0
    session.movement_state.transport_y = 2.0
    session.movement_state.transport_z = 3.0
    session.movement_state.transport_orientation = 0.25
    session.movement_state.transport_time = 123
    session.movement_state.transport_time2 = 456
    session.movement_state.transport_time3 = 789
    session.movement_state.transport_seat = 2
    session.movement_state.transport_vehicle_id = 77
    session.transport_transfer_pending = True
    session.pending_transport_transfer = {
        "source_guid": 9,
        "destination_guid": 10,
    }
    session.post_bootstrap_transport_reattach_request = {
        "destination_guid": 10,
    }
    session._player_bootstrap_runtime_transport = {
        "transport_guid": 9,
        "x": 91.0,
        "y": 92.0,
        "z": 93.0,
    }

    map_transfer.apply_map_transfer(
        session,
        map_transfer.TeleportDestination(1, 10.0, 20.0, 30.0, 0.5),
        reason="unit-test",
    )

    assert bool(getattr(session.movement_state, "has_transport_data", False)) is False
    assert session.movement_state.transport_guid == 0
    assert session.movement_state.transport_x == 0.0
    assert session.movement_state.transport_y == 0.0
    assert session.movement_state.transport_z == 0.0
    assert session.movement_state.transport_orientation == 0.0
    assert session.movement_state.transport_time == 0
    assert session.movement_state.transport_time2 == 0
    assert session.movement_state.transport_time3 == 0
    assert session.movement_state.transport_seat == -1
    assert session.movement_state.transport_vehicle_id == 0
    assert session.transport_transfer_pending is False
    assert session.pending_transport_transfer is None
    assert session.post_bootstrap_transport_reattach_request is None
    assert session._player_bootstrap_runtime_transport is None
    assert (session.map_id, session.x, session.y, session.z, session.orientation) == (
        1,
        10.0,
        20.0,
        30.0,
        0.5,
    )
    assert (
        session.movement_state.x,
        session.movement_state.y,
        session.movement_state.z,
        session.movement_state.orientation,
    ) == (10.0, 20.0, 30.0, 0.5)


def test_map_transfer_keep_transport_preserves_transport_state(monkeypatch):
    from server.modules.handlers.world.teleport import map_transfer

    session = SimpleNamespace(
        map_id=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
    )
    session.movement_state.has_transport_data = True
    session.movement_state.transport_guid = 9
    session.movement_state.transport_x = 1.0
    session.movement_state.transport_y = 2.0
    session.movement_state.transport_z = 3.0
    session.movement_state.transport_orientation = 0.25
    session.movement_state.transport_time = 123

    map_transfer.apply_map_transfer(
        session,
        map_transfer.TeleportDestination(1, 10.0, 20.0, 30.0, 0.5),
        reason="transport",
        keep_transport=True,
    )

    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == 9
    assert session.movement_state.transport_x == pytest.approx(1.0)
    assert session.movement_state.transport_y == pytest.approx(2.0)
    assert session.movement_state.transport_z == pytest.approx(3.0)
    assert session.movement_state.transport_orientation == pytest.approx(0.25)
    assert session.movement_state.transport_time == 123


def test_canonical_transport_detach_clears_runtime_and_movement_state():
    _reset_transport_states()
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=7,
        display_id=3015,
        route=[],
        node_index=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=1,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    session = SimpleNamespace(
        char_guid=1,
        map_id=1,
        movement_state=MovementState(),
    )
    session.movement_state.has_transport_data = True
    session.movement_state.transport_guid = world_guid
    session.movement_state.transport_x = 2.0
    session.movement_state.transport_y = 3.0
    session.movement_state.transport_z = 4.0
    session.movement_state.transport_orientation = 0.5
    session.movement_state.transport_time = 123
    session.movement_state.transport_time2 = 456
    session.movement_state.transport_time3 = 789

    assert transport_runtime.attach_transport_passenger(
        world_guid,
        1,
        local_x=2.0,
        local_y=3.0,
        local_z=4.0,
        local_o=0.5,
        source_map=1,
    ) is True
    session.transport_attach_state = transport_runtime.ATTACH_STATE_ATTACHED
    session.transport_attached_guid = world_guid

    assert transport_runtime.detach_session_transport_passenger(
        session,
        reason="unit-test",
    ) is True

    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is None
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_DETACHED
    assert session.transport_attached_guid == 0
    assert session.movement_state.has_transport_data is False
    assert session.movement_state.transport_guid == 0
    assert session.movement_state.transport_x == 0.0
    assert session.movement_state.transport_y == 0.0
    assert session.movement_state.transport_z == 0.0
    assert session.movement_state.transport_orientation == 0.0
    assert session.movement_state.transport_time == 0
    assert session.movement_state.transport_time2 == 0
    assert session.movement_state.transport_time3 == 0


def test_map_transfer_finds_stale_runtime_passenger_membership():
    from server.modules.handlers.world.teleport import map_transfer

    _reset_transport_states()
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(17))
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=17,
        display_id=3015,
        route=[],
        node_index=0,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.5,
        map_id=1,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    assert transport_runtime.attach_transport_passenger(
        world_guid,
        42,
        local_x=4.0,
        local_y=5.0,
        local_z=6.0,
        local_o=0.25,
        source_map=1,
    ) is True
    state.pending_transfers = {
        42: SimpleNamespace(destination_instance_id=world_guid),
    }
    legacy_state = MovementRuntimeState(
        instance=MovementInstance(world_guid, "legacy-test"),
        pending_transfers={
            42: SimpleNamespace(destination_instance_id=world_guid),
        },
    )
    transport_runtime.get_movement_manager().instances[world_guid] = legacy_state
    session = SimpleNamespace(
        char_guid=42,
        map_id=1,
        x=104.0,
        y=205.0,
        z=16.0,
        orientation=0.75,
        movement_state=MovementState(),
        transport_attached_guid=0,
        transport_transfer_pending=True,
        pending_transport_transfer=None,
        post_bootstrap_transport_reattach_request={
            "destination_guid": world_guid,
        },
    )

    map_transfer.apply_map_transfer(
        session,
        map_transfer.TeleportDestination(0, 10.0, 20.0, 30.0, 1.25),
        reason="teleport",
    )

    assert transport_runtime.transport_passenger_attachment(world_guid, 42) is None
    assert 42 not in (state.pending_transfers or {})
    assert 42 not in (legacy_state.pending_transfers or {})
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_DETACHED
    assert session.transport_attached_guid == 0
    assert session.transport_transfer_pending is False
    assert session.pending_transport_transfer is None
    assert session.post_bootstrap_transport_reattach_request is None
    assert (session.map_id, session.x, session.y, session.z, session.orientation) == (
        0,
        10.0,
        20.0,
        30.0,
        1.25,
    )


def test_teleport_transport_reset_is_idempotent():
    session = SimpleNamespace(
        char_guid=42,
        map_id=1,
        movement_state=MovementState(),
        transport_transfer_pending=False,
        pending_transport_transfer=None,
        post_bootstrap_transport_reattach_request=None,
    )

    transport_runtime.clear_player_transport_state(session, reason="teleport")
    transport_runtime.clear_player_transport_state(session, reason="teleport")

    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_DETACHED
    assert session.transport_attached_guid == 0
    assert session.movement_state.has_transport_data is False
    assert session.movement_state.transport_guid == 0


def test_stale_boundary_passenger_snapshot_cannot_supersede_ordinary_teleport():
    _reset_transport_states()
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(17))
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=17,
        display_id=3015,
        route=[],
        node_index=0,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.5,
        map_id=1,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    attachment = transport_runtime.PassengerAttachment(
        passenger_id=42,
        local_x=4.0,
        local_y=5.0,
        local_z=6.0,
        local_o=0.25,
        source_map=1,
    )
    session = SimpleNamespace(
        char_guid=42,
        map_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.25,
        movement_state=MovementState(),
        teleport_pending=True,
        worldport_ack_pending=True,
        near_teleport_pending=False,
        transport_transfer_pending=False,
        pending_transport_transfer=None,
        transport_attach_state=transport_runtime.ATTACH_STATE_DETACHED,
    )

    started = transport_runtime._start_boundary_worldport_for_passenger(
        session,
        state,
        attachment,
        from_map=1,
        to_map=0,
        transfer_id="stale-boundary",
    )

    assert started is False
    assert session.pending_transport_transfer is None
    assert bool(getattr(session.movement_state, "has_transport_data", False)) is False
    assert (session.map_id, session.x, session.y, session.z) == (
        0,
        10.0,
        20.0,
        30.0,
    )


def test_record_attach_detaches_previous_transport_before_new_transport():
    _reset_transport_states()
    first_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    second_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(8))
    for guid in (first_guid, second_guid):
        transport_runtime._runtime_transport_states()[guid] = transport_runtime.RuntimeTransportState(
            guid=guid,
            entry=20808,
            spawn_guid=guid & 0xFFFFFFFF,
            display_id=3015,
            route=[],
            node_index=0,
            x=0.0,
            y=0.0,
            z=0.0,
            orientation=0.0,
            map_id=1,
        )
    session = SimpleNamespace(char_guid=1, map_id=1, movement_state=MovementState())
    session.movement_state.has_transport_data = True
    session.movement_state.transport_guid = first_guid

    transport_runtime.record_transport_attach(session, first_guid, opcode_name="TEST_ATTACH_1")
    assert transport_runtime.transport_passenger_attachment(first_guid, 1) is not None

    session.movement_state.transport_guid = second_guid
    session.movement_state.transport_x = 9.0
    transport_runtime.record_transport_attach(session, second_guid, opcode_name="TEST_ATTACH_2")

    assert transport_runtime.transport_passenger_attachment(first_guid, 1) is None
    assert transport_runtime.transport_passenger_attachment(second_guid, 1) is not None
    assert session.transport_attached_guid == second_guid
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_ATTACHED


def test_map_transfer_detaches_transport_by_default_from_runtime_passengers(monkeypatch):
    from server.modules.handlers.world.teleport import map_transfer

    _reset_transport_states()
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    transport_runtime._runtime_transport_states()[world_guid] = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=7,
        display_id=3015,
        route=[],
        node_index=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=1,
    )
    session = SimpleNamespace(
        char_guid=1,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
    )
    session.movement_state.has_transport_data = True
    session.movement_state.transport_guid = world_guid
    session.transport_attach_state = transport_runtime.ATTACH_STATE_ATTACHED
    session.transport_attached_guid = world_guid
    transport_runtime.attach_transport_passenger(world_guid, 1, source_map=1)

    map_transfer.apply_map_transfer(
        session,
        map_transfer.TeleportDestination(0, 10.0, 20.0, 30.0, 0.5),
        reason="unit-test",
    )

    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is None
    assert session.movement_state.has_transport_data is False
    assert session.movement_state.transport_guid == 0
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_DETACHED


def test_transfer_pending_builder_uses_map_only_payload_for_normal_teleport():
    from server.modules.handlers.world.login.packets import build_login_packet

    payload = build_login_packet(
        "SMSG_TRANSFER_PENDING",
        SimpleNamespace(map_id=1),
    )

    assert payload == struct.pack("<I", 1)


@pytest.mark.parametrize(
    ("source_map_id", "destination_map_id", "expected_hex"),
    (
        (0, 1, "40000000004851000001000000"),
        (1, 0, "40010000004851000000000000"),
    ),
)
def test_path_241_transfer_pending_transport_wire_layout_both_directions(
    source_map_id,
    destination_map_id,
    expected_hex,
):
    from server.modules.handlers.world.login.packets import build_login_packet

    payload = build_login_packet(
        "SMSG_TRANSFER_PENDING",
        SimpleNamespace(
            map_id=destination_map_id,
            has_transport=True,
            source_map_id=source_map_id,
            transport_entry=20808,
        ),
    )

    assert len(payload) == 13
    assert payload[0] == 0x40
    assert payload.hex() == expected_hex
    assert payload[1:] == struct.pack(
        "<III",
        source_map_id,
        20808,
        destination_map_id,
    )
    transport_map_id, transport_entry, map_id = struct.unpack("<III", payload[1:])
    assert transport_map_id == source_map_id
    assert transport_entry == 20808
    assert map_id == destination_map_id
    assert map_id in {0, 1}
    assert map_id != transport_entry


def test_map_transfer_keep_transport_replaces_transfer_pending_with_transport_payload(monkeypatch):
    from server.modules.handlers.world.teleport import map_transfer

    session = SimpleNamespace(
        map_id=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        movement_state=MovementState(),
    )
    session.movement_state.has_transport_data = True
    session.movement_state.transport_guid = 9

    responses = map_transfer.apply_map_transfer(
        session,
        map_transfer.TeleportDestination(1, 10.0, 20.0, 30.0, 0.5),
        reason="transport",
        keep_transport=True,
        source_map_id=0,
        transport_entry=20808,
    )

    assert [name for name, _payload in responses] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert len(responses[0][1]) == 13
    assert responses[0][1][1:] == struct.pack("<III", 0, 20808, 1)


def test_transport_worldport_uses_map_transfer_keep_transport(monkeypatch):
    from server.modules.handlers.world.teleport import map_transfer

    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    captured = {}
    monkeypatch.setattr(
        map_transfer,
        "apply_map_transfer",
        lambda _session, _destination, *, reason, keep_transport=False, **kwargs: captured.update(
            destination=_destination,
            reason=reason,
            keep_transport=keep_transport,
            kwargs=kwargs,
        )
        or [
            ("SMSG_TRANSFER_PENDING", b"normal"),
            ("SMSG_NEW_WORLD", b"normal"),
        ],
    )
    _add_boundary_event(state, destination_map=0)
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is True

    assert ("SMSG_TRANSFER_PENDING", b"normal") in sent
    assert ("SMSG_NEW_WORLD", b"normal") in sent
    assert captured["reason"] == "transport"
    assert captured["keep_transport"] is True
    assert captured["kwargs"]["source_map_id"] == 1
    assert captured["kwargs"]["transport_entry"] == 20808
    assert captured["destination"].map_id == 0
    assert session.transport_transfer_pending is True
    assert session.pending_transport_transfer["destination_guid"] == world_guid
    assert 1 in (state.passengers or {})
    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == world_guid
    assert session.movement_state.transport_x == pytest.approx(2.0)
    assert session.movement_state.transport_y == pytest.approx(3.0)
    assert session.movement_state.transport_z == pytest.approx(4.0)
    assert session.movement_state.transport_orientation == pytest.approx(0.5)


def test_transport_create_uses_same_pinned_runtime_transform_as_player_bootstrap():
    entry = _loaded_mo_transport_entry()
    world_guid = int(entry["world_guid"])
    session = SimpleNamespace(
        _player_bootstrap_runtime_transport={
            "transport_guid": world_guid,
            "map_id": 0,
            "x": 101.25,
            "y": 202.5,
            "z": 12.75,
            "orientation": 1.125,
            "route_phase": 9876,
        }
    )

    packet_entry = transport_runtime.cached_transport_runtime_entry(session, entry)
    assert packet_entry["x"] == pytest.approx(101.25)
    assert packet_entry["y"] == pytest.approx(202.5)
    assert packet_entry["z"] == pytest.approx(12.75)
    assert packet_entry["orientation"] == pytest.approx(1.125)
    assert packet_entry["transport_path_progress"] == 9876
    assert packet_entry["_bootstrap_runtime_transform_pinned"] is True
    assert packet_entry["_runtime_transport_orientation_authoritative"] is True
    assert session._player_bootstrap_runtime_transport["transport_create_transform_matched"] is True

    # The packet builder's normal runtime overlay must not replace the transform
    # sampled for the player in this same bootstrap.
    assert gameobjects._transport_runtime_packet_entry(packet_entry) is packet_entry
    expected_rotation = (0.0, 0.0, math.sin(1.125 / 2.0), math.cos(1.125 / 2.0))
    assert gameobjects._rotation_components(packet_entry) == pytest.approx(expected_rotation)
    assert gameobjects._gameobject_rotation_packed(packet_entry) == gameobjects._gameobject_rotation_packed(
        {"orientation": 1.125}
    )


def test_login_reattachment_transport_create_serializes_one_t1_orientation(monkeypatch):
    entry = {
        **_loaded_mo_transport_entry(),
        "orientation": 0.0,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
    }
    world_guid = int(entry["world_guid"])
    session = SimpleNamespace(
        _player_bootstrap_runtime_transport={
            "transport_guid": world_guid,
            "map_id": 0,
            "x": 101.25,
            "y": 202.5,
            "z": 12.75,
            "orientation": 1.125,
            "route_phase": 9876,
        }
    )
    packet_entry = transport_runtime.cached_transport_runtime_entry(session, entry)
    captured_fields = {}
    monkeypatch.setattr(gameobjects.EncoderHandler, "encode_packet", lambda _name, fields: fields)

    def capture_fields(fields, *, mask_blocks=1):
        captured_fields.update(fields)
        return (b"\x00" * (int(mask_blocks) * 4), b"")

    monkeypatch.setattr(gameobjects, "_build_fixed_u32_field_block", capture_fields)
    payload = gameobjects._build_gameobject_update_payload(
        map_id=0,
        entry=packet_entry,
        realm_id=1,
    )

    expected_z = math.sin(1.125 / 2.0)
    expected_w = math.cos(1.125 / 2.0)
    rotation_start = gameobjects._GAMEOBJECT_FIELD_ROTATION_START
    assert payload["stationary_orientation"] == pytest.approx(1.125)
    assert payload["gameobject_rotation_packed"] == gameobjects._gameobject_rotation_packed(
        {"orientation": 1.125}
    )
    assert struct.unpack("<f", struct.pack("<I", captured_fields[rotation_start + 2]))[0] == pytest.approx(expected_z)
    assert struct.unpack("<f", struct.pack("<I", captured_fields[rotation_start + 3]))[0] == pytest.approx(expected_w)
    assert payload["movement_block_uint32"] == 9876


def test_runtime_transport_values_update_is_suppressed_while_worldport_pending(monkeypatch):
    _reset_transport_states()
    entry = _loaded_mo_transport_entry()
    world_guid = int(entry["world_guid"])
    _install_runtime_update_test_transport(monkeypatch, entry)
    session = SimpleNamespace(
        char_guid=30,
        gameobjects_visible=True,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        realm_id=1,
        login_state="IN_WORLD",
        teleport_pending=True,
        worldport_ack_pending=True,
        loading_screen_visible=False,
        loaded_gameobjects={world_guid},
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        {world_guid: dict(entry)},
        force=True,
    )

    assert responses == []


def test_runtime_transport_values_update_resumes_after_in_world(monkeypatch):
    _reset_transport_states()
    entry = _loaded_mo_transport_entry()
    world_guid = int(entry["world_guid"])
    state = _install_runtime_update_test_transport(monkeypatch, entry)
    state.x = 3.0
    state.path_progress_ms = 300
    session = SimpleNamespace(
        char_guid=30,
        gameobjects_visible=True,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        realm_id=1,
        login_state="IN_WORLD",
        teleport_pending=False,
        worldport_ack_pending=False,
        loading_screen_visible=False,
        loaded_gameobjects={world_guid},
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        {world_guid: dict(entry)},
        force=True,
    )

    assert len(responses) == 1
    assert _payload_update_type(responses[0]) == 0


def test_transport_passenger_attach_detach_lookup_owned_by_runtime_state(monkeypatch):
    _reset_transport_states()
    entry = _loaded_mo_transport_entry(world_guid=0x1FC0000000018801)
    state = _install_runtime_update_test_transport(monkeypatch, entry)
    manager = transport_runtime.get_movement_manager()

    assert manager.attach_passenger(
        int(state.guid),
        42,
        local_x=1.0,
        local_y=2.0,
        local_z=3.0,
        local_o=0.25,
        source_map=1,
    ) is True

    attachment = manager.passenger_attachment(int(state.guid), 42)
    assert attachment is not None
    assert attachment.local_x == 1.0
    assert attachment.local_y == 2.0
    assert attachment.local_z == 3.0
    assert attachment.local_o == 0.25
    assert state.passengers is not None
    assert 42 in state.passengers
    assert manager.get_state(int(state.guid)) is None

    assert manager.detach_passenger(int(state.guid), 42) is True
    assert manager.passenger_attachment(int(state.guid), 42) is None
    assert state.passengers == {}


def test_transport_pending_transfer_owned_by_runtime_state(monkeypatch):
    _reset_transport_states()
    source_entry = _loaded_mo_transport_entry(world_guid=0x1FC0000000018802)
    destination_entry = _loaded_mo_transport_entry(world_guid=0x1FC0000000018803)
    source_state = _install_runtime_update_test_transport(monkeypatch, source_entry)
    destination_state = transport_runtime.RuntimeTransportState(
        guid=int(destination_entry["world_guid"]),
        entry=int(destination_entry["entry"]),
        spawn_guid=int(destination_entry["guid"]),
        display_id=int(destination_entry["display_id"]),
        route=list(source_state.route),
        node_index=0,
        x=10.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=0,
        path_progress_ms=0,
        timed_route=True,
        route_period_ms=1000,
    )
    transport_runtime._runtime_transport_states()[int(destination_state.guid)] = destination_state
    manager = transport_runtime.get_movement_manager()

    assert manager.attach_passenger(
        int(source_state.guid),
        42,
        local_x=1.0,
        local_y=2.0,
        local_z=3.0,
        local_o=0.25,
        source_map=1,
    ) is True
    transfer = manager.begin_passenger_transfer(
        int(source_state.guid),
        int(destination_state.guid),
        42,
        target_map_id=0,
    )

    assert transfer is not None
    assert source_state.passengers is not None
    assert 42 in source_state.passengers
    assert source_state.pending_transfers is not None
    assert source_state.pending_transfers[42] is transfer

    completed = manager.complete_passenger_transfer(int(source_state.guid), 42)

    assert completed is transfer
    assert source_state.passengers == {}
    assert source_state.pending_transfers == {}
    assert destination_state.passengers is not None
    assert 42 in destination_state.passengers
    assert manager.passenger_attachment(int(destination_state.guid), 42) is not None


def _animation_for_thunder_bluff(entry_id: int):
    animations = {
        4170: transport_runtime.TransportAnimationPath(
            entry=4170,
            nodes=(
                transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
                transport_runtime.TransportAnimationNode(15000, 0.0, 0.0, -61.244),
                transport_runtime.TransportAnimationNode(30000, 0.0, 0.0, 0.0),
            ),
            period_ms=30000,
        ),
        4171: transport_runtime.TransportAnimationPath(
            entry=4171,
            nodes=(
                transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
                transport_runtime.TransportAnimationNode(15000, 0.0, 0.0, 61.498),
                transport_runtime.TransportAnimationNode(30000, 0.0, 0.0, 0.0),
            ),
            period_ms=30000,
        ),
    }
    return animations.get(int(entry_id))


def test_thunder_bluff_elevator_uses_transport_runtime_route(monkeypatch):
    _reset_transport_states()
    now = 100.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)
    monkeypatch.setattr(transport_runtime, "_transport_animation_for_entry", _animation_for_thunder_bluff)
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda _clock_key, period_ms: int((now - 100.0) * 1000.0) % int(period_ms),
    )

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
        30000
    )
    assert transport_runtime.is_runtime_transport_entry(prepared) is True
    assert transport_runtime._has_transport_animation(prepared) is True
    assert prepared["client_driven_transport_animation"] is True
    assert prepared["client_animation_base_z"] == entry["z"]

    _tick_transport_entry(prepared)
    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)

    assert moved["x"] == entry["x"]
    assert moved["y"] == entry["y"]
    assert moved["z"] != entry["z"]

    monkeypatch.setattr(
        gameobjects.EncoderHandler,
        "encode_packet",
        lambda _name, payload: payload,
    )
    payload = gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=moved,
        realm_id=1,
    )
    assert payload["stationary_x"] == entry["x"]
    assert payload["stationary_y"] == entry["y"]
    assert payload["stationary_z"] == entry["z"]

    now = 101.0
    _tick_transport_entry(prepared)
    transport_runtime.cached_transport_runtime_entry(session, prepared)
    now = 111.0
    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)

    assert moved["z"] > entry["z"]
    assert moved["x"] == entry["x"]
    assert moved["y"] == entry["y"]
    assert moved["transport_path_progress"] > 0
    assert moved["transport_period"] == int(
        30000
    )
    state = transport_runtime._runtime_transport_states()[prepared["world_guid"]]
    assert len(state.route) == 3
    assert state.timed_route is True

    state.x += 12.5
    state.y -= 4.0
    now = 120.0
    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)

    assert moved["x"] == entry["x"]
    assert moved["y"] == entry["y"]
    assert moved["z"] > entry["z"]

    now = 130.0
    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)

    assert moved["x"] == entry["x"]
    assert moved["y"] == entry["y"]
    assert moved["transport_path_progress"] >= 0


def test_thunder_bluff_elevator_high_spawn_uses_authoritative_runtime(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime, "_transport_animation_for_entry", _animation_for_thunder_bluff)

    entry = {
        "guid": 898,
        "world_guid": 0xF110000000000382,
        "entry": 4170,
        "map": 1,
        "type": 11,
        "display_id": 360,
        "x": -1286.24,
        "y": 189.72,
        "z": 130.080,
        "orientation": 0.0,
        "size": 1.0,
    }
    prepared = transport_runtime.prepare_runtime_transport_entry(entry)

    assert transport_runtime.is_runtime_transport_entry(prepared) is True
    assert transport_runtime._has_transport_animation(prepared) is True


def test_thunder_bluff_duplicate_spawn_reuses_authoritative_runtime(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime, "_transport_animation_for_entry", _animation_for_thunder_bluff)
    manager = transport_runtime.get_world_transport_manager()
    first = transport_runtime.prepare_runtime_transport_entry(
        {
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
        }
    )
    duplicate = transport_runtime.prepare_runtime_transport_entry(
        {
            "guid": 898,
            "world_guid": 0xF110000000000382,
            "entry": 4171,
            "map": 1,
            "type": 11,
            "display_id": 360,
            "x": -1308.36,
            "y": 185.31,
            "z": 68.586,
            "orientation": 0.0,
        }
    )

    first_state = manager.register_transport(first, source="test")
    duplicate_state = manager.register_transport(duplicate, source="test")

    assert first_state is not None
    assert duplicate_state is first_state
    assert set(manager.entries) == {first["world_guid"]}


def test_type11_transport_animation_uses_dbc_timed_route(monkeypatch):
    _reset_transport_states()
    now = 11.5
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)

    animation = transport_runtime.TransportAnimationPath(
        entry=999001,
        nodes=(
            transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
            transport_runtime.TransportAnimationNode(5000, 0.0, 0.0, 10.0),
            transport_runtime.TransportAnimationNode(10000, 0.0, 0.0, 0.0),
        ),
        period_ms=10000,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_transport_animation_for_entry",
        lambda entry_id: animation if int(entry_id) == 999001 else None,
    )

    session = SimpleNamespace()
    entry = {
        "guid": 9001,
        "world_guid": 0xF110000000099001,
        "entry": 999001,
        "map": 1,
        "type": 11,
        "display_id": 360,
        "x": 10.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 0.75,
        "size": 1.0,
    }

    assert transport_runtime.is_runtime_transport_entry(entry) is True
    prepared = transport_runtime.prepare_runtime_transport_entry(entry)

    assert prepared["use_transport_guid"] is True
    assert prepared["transport_period"] == 10000
    assert prepared["client_driven_transport_animation"] is True
    assert prepared["client_animation_base_z"] == 30.0

    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)
    assert moved["z"] == 30.0

    now = 13.5
    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)

    assert round(moved["z"], 3) == 34.0
    assert moved["orientation"] == 0.75
    assert moved["transport_path_progress"] == 2000
    state = transport_runtime._runtime_transport_states()[prepared["world_guid"]]
    assert state.timed_route is True
    assert state.route_period_ms == 10000


def test_world_db_elevator_preload_registers_type11_animation_runtime(monkeypatch):
    _reset_transport_states()
    now = 250.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)
    animation = transport_runtime.TransportAnimationPath(
        entry=999002,
        nodes=(
            transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
            transport_runtime.TransportAnimationNode(5000, 0.0, 0.0, 12.0),
            transport_runtime.TransportAnimationNode(10000, 0.0, 0.0, 0.0),
        ),
        period_ms=10000,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_transport_animation_for_entry",
        lambda entry_id: animation if int(entry_id) == 999002 else None,
    )
    monkeypatch.setattr(transport_runtime, "_load_world_db_transports", lambda: ())
    monkeypatch.setattr(
        transport_runtime,
        "_load_world_db_elevator_entries",
        lambda: (
            {
                "guid": 9002,
                "entry": 999002,
                "map": 530,
                "map_id": 530,
                "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
                "original_type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
                "display_id": 360,
                "x": -10.0,
                "y": 20.0,
                "z": 30.0,
                "orientation": 0.0,
                "size": 1.0,
                "name": "Generic Runtime Elevator",
            },
        ),
    )
    manager = transport_runtime.get_world_transport_manager()
    manager.start()

    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(9002))
    state = transport_runtime._runtime_transport_states()[world_guid]
    movement_state = transport_runtime.get_movement_manager().get_state(world_guid)
    assert state.entry == 999002
    assert state.map_id == 530
    assert state.timed_route is True
    assert state.route_period_ms == 10000
    assert movement_state is not None
    template = transport_runtime.get_movement_manager().templates[
        str(movement_state.instance.template_id)
    ]
    assert template.kind == transport_runtime.MovementKind.ELEVATOR
    elevator = manager.elevator_for_guid(world_guid)
    assert isinstance(elevator, Elevator)
    assert state.elevator is elevator
    assert get_elevator_runtime_store().get(world_guid) is elevator

    manager.stop()

    assert manager.elevator_for_guid(world_guid) is None
    assert state.elevator is None


def test_world_db_elevator_loader_includes_thunder_bluff_entries(monkeypatch):
    monkeypatch.delattr(transport_runtime._load_world_db_elevator_entries, "_entries", raising=False)
    monkeypatch.setitem(
        sys.modules,
        "sqlalchemy",
        SimpleNamespace(text=lambda query: query),
    )
    animation = transport_runtime.TransportAnimationPath(
        entry=999003,
        nodes=(
            transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
            transport_runtime.TransportAnimationNode(1000, 0.0, 0.0, 1.0),
        ),
        period_ms=1000,
    )
    thunder_bluff_animation = transport_runtime.TransportAnimationPath(
        entry=4170,
        nodes=(
            transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
            transport_runtime.TransportAnimationNode(1000, 0.0, 0.0, 1.0),
        ),
        period_ms=1000,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_transport_animation_paths",
        lambda: {
            999003: animation,
            4170: thunder_bluff_animation,
            219175: animation,
            20651: animation,
        },
    )

    class FakeSession:
        def execute(self, _query, _params):
            return SimpleNamespace(
                mappings=lambda: (
                    {
                        "guid": 9003,
                        "entry": 999003,
                        "map": 530,
                        "x": 1.0,
                        "y": 2.0,
                        "z": 3.0,
                        "orientation": 0.0,
                        "name": "Generic Elevator",
                        "display_id": 360,
                        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
                        "faction": 0,
                        "flags": 0,
                        "size": 1.0,
                        "data0": 0,
                        "data1": 0,
                        "data2": 0,
                        "data3": 0,
                    },
                    {
                        "guid": 897,
                        "entry": 4170,
                        "map": 1,
                        "x": -1286.24,
                        "y": 189.72,
                        "z": 130.08,
                        "orientation": 0.0,
                        "name": "Mesa Elevator",
                        "display_id": 360,
                        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
                        "faction": 0,
                        "flags": 0,
                        "size": 1.0,
                        "data0": 0,
                        "data1": 0,
                        "data2": 0,
                        "data3": 0,
                    },
                    {
                        "guid": 100430,
                        "entry": 219175,
                        "map": 1136,
                        "x": 1704.78,
                        "y": -4265.96,
                        "z": 34.88,
                        "orientation": 0.0,
                        "name": "Doodad_Orgrimmar_Elevator_01",
                        "display_id": 9542,
                        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
                        "faction": 0,
                        "flags": 0,
                        "size": 1.0,
                        "data0": 0,
                        "data1": 0,
                        "data2": 0,
                        "data3": 0,
                    },
                    {
                        "guid": 1235,
                        "entry": 20651,
                        "map": 0,
                        "x": 1596.21,
                        "y": 302.401,
                        "z": -40.6645,
                        "orientation": 1.56207,
                        "name": "lowerLdoor",
                        "display_id": 462,
                        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
                        "faction": 0,
                        "flags": 0,
                        "size": 1.0,
                        "data0": 0,
                        "data1": 0,
                        "data2": 0,
                        "data3": 0,
                    },
                )
            )

    monkeypatch.setattr(
        database_module.DatabaseConnection,
        "world",
        staticmethod(lambda: FakeSession()),
        raising=False,
    )

    entries = transport_runtime._load_world_db_elevator_entries()

    assert [entry["entry"] for entry in entries] == [999003, 4170, 219175]
    assert entries[0]["original_type"] == transport_runtime.GAMEOBJECT_TYPE_TRANSPORT
    assert entries[1]["map"] == 1
    assert entries[1]["map_id"] == 1
    assert entries[2]["map"] == 1
    assert entries[2]["map_id"] == 1


def test_mo_transport_without_dbc_does_not_generate_fallback_route(monkeypatch):
    _reset_transport_states()
    now = 300.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)
    monkeypatch.setattr(transport_runtime, "_transport_animation_for_entry", lambda entry_id: None)

    session = SimpleNamespace()
    entry = {
        "guid": 444,
        "world_guid": 0x1FC00000000001BC,
        "entry": 175354,
        "map": 1,
        "type": 15,
        "display_id": 3015,
        "x": 1000.0,
        "y": 2000.0,
        "z": 12.0,
        "orientation": 0.0,
        "size": 1.0,
        "data0": 0,
    }

    assert transport_runtime.is_runtime_transport_entry(entry) is True
    prepared = transport_runtime.prepare_runtime_transport_entry(entry)

    assert prepared["use_transport_guid"] is True
    assert prepared["transport_period"] == transport_runtime._DEFAULT_MO_TRANSPORT_PERIOD_MS

    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)
    assert moved["map"] == 1
    assert moved["x"] == 1000.0

    now = 305.0
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)

    assert moved["map"] == 1
    assert moved["x"] == 1000.0
    assert moved["z"] == 12.0
    assert prepared["world_guid"] not in transport_runtime._runtime_transport_states()


def test_world_db_transport_spawns_from_same_map_taxi_nodes(monkeypatch):
    _reset_transport_states()
    now = 400.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)
    monkeypatch.setattr(movement_manager_module, "transport_time_ms", lambda: 0)
    monkeypatch.setattr(transport_runtime, "_shared_route_phase_ms", lambda *_args: 11500)
    monkeypatch.setattr(
        transport_runtime,
        "_load_world_db_transports",
        lambda: (
            {
                "guid": 7,
                "entry": 20808,
                "name": "The Maiden's Fancy",
                "period": 231236,
                "display_id": 3015,
                "faction": 0,
                "flags": 0,
                "size": 1.0,
                "path_id": 241,
                "data1": 30,
                "data2": 1,
                "data3": 0,
            },
        ),
    )
    monkeypatch.setattr(
        transport_runtime,
        "_build_skyfire_taxi_transport_route",
        lambda *_args, **_kwargs: [
            transport_runtime.TransportRouteNode(1, -1370.0, -4266.0, 0.0, time_ms=0),
            transport_runtime.TransportRouteNode(1, -1265.0, -4140.0, 0.0, time_ms=1000),
            transport_runtime.TransportRouteNode(0, -14123.0, 852.0, 0.0, time_ms=1001),
            transport_runtime.TransportRouteNode(0, -14268.0, 964.0, 0.0, time_ms=2000),
        ],
    )
    transport_runtime.get_world_transport_manager().start()

    canonical_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    clone_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100007))
    for world_guid, state in transport_runtime._runtime_transport_states().items():
        transport_runtime.get_movement_manager().tick_instance(
            int(world_guid),
            server_time_ms=transport_runtime._transport_server_time_ms(state),
        )
        transport_runtime._commit_transport_state_from_movement_cache(state)

    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}
    assert clone_guid not in transport_runtime._runtime_transport_states()
    assert clone_guid not in transport_runtime.get_movement_manager().instances

    session = SimpleNamespace(
        gameobjects_visible=True,
        map_id=1,
        x=-1372.0,
        y=-4268.0,
        realm_id=1,
    )

    entries = transport_runtime.synthetic_transport_entries_near(session, loaded_guids=set())

    assert len(entries) == 1
    entry = entries[0]
    assert entry["entry"] == 20808
    assert entry["map"] == 1
    assert entry["guid"] == 7
    assert entry["world_guid"] == canonical_guid
    assert entry["world_db_transport"] is True
    state = transport_runtime._runtime_transport_states()[entry["world_guid"]]
    assert len(state.route) == 4
    assert {node.map_id for node in state.route} == {0, 1}
    assert state.timed_route is True
    assert state.shared_clock_key == "world-db-transport:7"


def test_world_db_transport_canonical_runtime_progresses(monkeypatch):
    _reset_transport_states()
    server_time = {"ms": 11500}
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 400.0)
    monkeypatch.setattr(movement_manager_module, "transport_time_ms", lambda: 0)
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda *_args: int(server_time["ms"]),
    )
    monkeypatch.setattr(
        transport_runtime,
        "_load_world_db_transports",
        lambda: (
            {
                "guid": 7,
                "entry": 20808,
                "name": "The Maiden's Fancy",
                "period": 1000,
                "display_id": 3015,
                "faction": 0,
                "flags": 0,
                "size": 1.0,
                "path_id": 241,
                "data1": 30,
                "data2": 1,
                "data3": 0,
            },
        ),
    )
    monkeypatch.setattr(
        transport_runtime,
        "_build_skyfire_taxi_transport_route",
        lambda *_args, **_kwargs: [
            transport_runtime.TransportRouteNode(1, 0.0, 0.0, 0.0, time_ms=0),
            transport_runtime.TransportRouteNode(1, 100.0, 0.0, 0.0, time_ms=1000),
        ],
    )

    transport_runtime.get_world_transport_manager().start()

    canonical_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    clone_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100007))
    state = transport_runtime._runtime_transport_states()[canonical_guid]
    start_x = float(state.x)

    server_time["ms"] = 12000
    transport_runtime.get_movement_manager().tick_instance(
        canonical_guid,
        server_time_ms=transport_runtime._transport_server_time_ms(state),
    )
    transport_runtime._commit_transport_state_from_movement_cache(state)

    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}
    assert clone_guid not in transport_runtime._runtime_transport_states()
    assert float(state.x) != start_x
    assert int(state.path_progress_ms) == 500


def test_canonical_world_db_transport_publishes_coherent_cross_map_transform(monkeypatch):
    _reset_transport_states()
    server_time = {"ms": 11500}
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 400.0)
    monkeypatch.setattr(movement_manager_module, "transport_time_ms", lambda: 0)
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda *_args: int(server_time["ms"]),
    )

    canonical_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    clone_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100007))
    entry = {
        "guid": 7,
        "transport_db_guid": 7,
        "world_guid": canonical_guid,
        "entry": 20808,
        "map": 1,
        "map_id": 1,
        "home_map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (1, 20.0, 20.0, 5.0, 0.0, 500),
            (0, 100.0, 200.0, 10.0, 0.0, 1000),
            (0, 150.0, 200.0, 10.0, 0.0, 2000),
        ],
        "shared_route_clock_key": "world-db-transport:7",
        "transport_period": 2000,
        "world_db_transport": True,
        "use_transport_guid": True,
    }
    state = transport_runtime.get_world_transport_manager().register_transport(
        entry,
        source="test",
    )
    assert state is not None
    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}

    server_time["ms"] = 12250
    transport_runtime.get_movement_manager().tick_instance(
        canonical_guid,
        server_time_ms=transport_runtime._transport_server_time_ms(state),
    )
    transport_runtime._commit_transport_state_from_movement_cache(state)

    assert state.guid == canonical_guid
    assert state.spawn_guid == 7
    assert state.map_id == 1
    assert (state.x, state.y, state.z) == (20.0, 20.0, 5.0)
    assert state.transfer_destination_map == 0
    assert state.lifecycle_state == transport_runtime.TRANSPORT_STATE_TRANSFER_PENDING
    assert int(state.path_progress_ms) == 750
    transport = transport_runtime.get_world_transport_manager().transport_for_guid(
        canonical_guid
    )
    assert transport is not None
    assert transport.map_id == 1
    assert transport.world_position == (20.0, 20.0, 5.0)
    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}
    assert clone_guid not in transport_runtime._runtime_transport_states()
    assert clone_guid not in transport_runtime.get_movement_manager().instances

    server_time["ms"] = 13000
    transport_runtime.get_movement_manager().tick_instance(
        canonical_guid,
        server_time_ms=transport_runtime._transport_server_time_ms(state),
    )
    transport_runtime._commit_transport_state_from_movement_cache(state)

    assert state.guid == canonical_guid
    assert state.map_id == 0
    assert (state.x, state.y, state.z) == (125.0, 200.0, 10.0)
    assert transport.map_id == 0
    assert transport.world_position == (125.0, 200.0, 10.0)
    assert int(state.path_progress_ms) == 1500
    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}

    server_time["ms"] = 13500
    transport_runtime.get_movement_manager().tick_instance(
        canonical_guid,
        server_time_ms=transport_runtime._transport_server_time_ms(state),
    )
    transport_runtime._commit_transport_state_from_movement_cache(state)

    assert state.guid == canonical_guid
    assert state.map_id == 1
    assert (state.x, state.y, state.z) == (10.0, 20.0, 5.0)
    assert transport.map_id == 1
    assert transport.world_position == (10.0, 20.0, 5.0)
    assert int(state.path_progress_ms) == 0
    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}


def test_canonical_world_db_transport_visible_only_on_current_map(monkeypatch):
    _reset_transport_states()
    server_time = {"ms": 11500}
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 400.0)
    monkeypatch.setattr(movement_manager_module, "transport_time_ms", lambda: 0)
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda *_args: int(server_time["ms"]),
    )

    canonical_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    clone_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100007))
    entry = {
        "guid": 7,
        "transport_db_guid": 7,
        "world_guid": canonical_guid,
        "entry": 20808,
        "map": 1,
        "map_id": 1,
        "home_map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (1, 20.0, 20.0, 5.0, 0.0, 500),
            (0, 100.0, 200.0, 10.0, 0.0, 1000),
            (0, 150.0, 200.0, 10.0, 0.0, 2000),
        ],
        "shared_route_clock_key": "world-db-transport:7",
        "transport_period": 2000,
        "world_db_transport": True,
        "use_transport_guid": True,
    }
    state = transport_runtime.get_world_transport_manager().register_transport(
        entry,
        source="test",
    )
    assert state is not None

    server_time["ms"] = 12250
    transport_runtime.get_movement_manager().tick_instance(
        canonical_guid,
        server_time_ms=transport_runtime._transport_server_time_ms(state),
    )
    transport_runtime._commit_transport_state_from_movement_cache(state)

    old_map_session = SimpleNamespace(
        gameobjects_visible=True,
        map_id=1,
        x=10.0,
        y=20.0,
        z=5.0,
        realm_id=1,
    )
    new_map_session = SimpleNamespace(
        gameobjects_visible=True,
        map_id=0,
        x=100.0,
        y=200.0,
        z=10.0,
        realm_id=1,
    )

    entries = transport_runtime.synthetic_transport_entries_near(
        old_map_session,
        loaded_guids=set(),
    )
    assert len(entries) == 1
    assert entries[0]["world_guid"] == canonical_guid
    assert entries[0]["map"] == 1
    assert transport_runtime.synthetic_transport_entries_near(
        new_map_session,
        loaded_guids=set(),
    ) == []

    server_time["ms"] = 13000
    transport_runtime.get_movement_manager().tick_instance(
        canonical_guid,
        server_time_ms=transport_runtime._transport_server_time_ms(state),
    )
    transport_runtime._commit_transport_state_from_movement_cache(state)
    entries = transport_runtime.synthetic_transport_entries_near(
        new_map_session,
        loaded_guids=set(),
    )

    assert len(entries) == 1
    assert entries[0]["world_guid"] == canonical_guid
    assert entries[0]["guid"] == 7
    assert entries[0]["map"] == 0
    assert clone_guid not in transport_runtime._runtime_transport_states()
    assert clone_guid not in transport_runtime.get_movement_manager().instances


def test_cross_map_transport_route_keeps_departure_hold(monkeypatch):
    monkeypatch.setattr(
        transport_runtime,
        "_transport_taxi_path_nodes_by_path",
        lambda: {
            999: (
                transport_runtime.TransportTaxiPathNode(999, 0, 0, 0.0, 0.0, 0.0),
                transport_runtime.TransportTaxiPathNode(999, 1, 0, 100.0, 0.0, 0.0),
                transport_runtime.TransportTaxiPathNode(999, 2, 1, 200.0, 0.0, 0.0),
            )
        },
    )

    route = transport_runtime._build_timed_taxi_transport_route(999, period_ms=10_000)

    assert len(route) == 3
    same_map_segment_ms = route[1].time_ms - route[0].time_ms
    cross_map_segment_ms = route[2].time_ms - route[1].time_ms
    assert cross_map_segment_ms <= same_map_segment_ms
    assert cross_map_segment_ms <= 2


def test_ratchet_booty_route_uses_skyfire_keyframes_and_timing(monkeypatch):
    if hasattr(transport_runtime._transport_taxi_path_nodes_by_path, "_paths"):
        monkeypatch.delattr(
            transport_runtime._transport_taxi_path_nodes_by_path,
            "_paths",
        )

    raw_nodes = transport_runtime._transport_taxi_path_nodes_by_path()[241]
    keyframes = transport_runtime._skyfire_transport_keyframes(
        raw_nodes,
        can_be_stopped=False,
    )
    observed_section_maps = []
    original_lengths = transport_runtime._catmull_rom_section_lengths

    def _record_section(section):
        observed_section_maps.append({int(node.map_id) for node in section})
        return original_lengths(section)

    monkeypatch.setattr(
        transport_runtime,
        "_catmull_rom_section_lengths",
        _record_section,
    )
    route = transport_runtime._build_skyfire_taxi_transport_route(
        241,
        move_speed=30.0,
        acceleration=1.0,
        can_be_stopped=False,
    )

    assert len(route) == 18
    assert [node.source_node_index for node in route] == [
        *range(1, 11),
        *range(13, 21),
    ]
    assert [
        (node.source_node_index, node.transfer_destination_node_index)
        for node in route
        if node.transfer
    ] == [(10, 13), (20, 1)]
    assert observed_section_maps == [{1}, {0}]
    assert [
        (
            node.source_node_index,
            node.wait_time,
            node.arrival_event_id,
            node.departure_event_id,
        )
        for node in route
        if node.wait_time > 0.0
    ] == [
        (6, 60.0, 16398, 0),
        (16, 60.0, 16397, 0),
    ]
    assert route[-1].time_ms == 231111
    assert route[-1].time_ms > 21
    assert route[10].time_ms - route[9].time_ms == 1


def test_ratchet_booty_route_has_symmetric_cross_map_lifecycle_boundaries():
    nodes = transport_runtime._transport_taxi_path_nodes_by_path()[241]
    keyframes = transport_runtime._skyfire_transport_keyframes(
        nodes,
        can_be_stopped=False,
    )
    boundaries = transport_runtime._transport_boundary_destinations(keyframes)

    forward_source = keyframes[9]
    forward_destination = keyframes[boundaries[9]]
    reverse_source = keyframes[17]
    reverse_destination = keyframes[boundaries[17]]

    assert (
        forward_source.node_index,
        forward_source.map_id,
        forward_destination.node_index,
        forward_destination.map_id,
    ) == (10, 1, 13, 0)
    assert (
        reverse_source.node_index,
        reverse_source.map_id,
        reverse_destination.node_index,
        reverse_destination.map_id,
    ) == (20, 0, 1, 1)


def test_ratchet_booty_runtime_keeps_eighteen_executable_keyframes(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda *_args: 0,
    )
    route = transport_runtime._build_skyfire_taxi_transport_route(
        241,
        move_speed=30.0,
        acceleration=1.0,
        can_be_stopped=False,
    )
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    entry = transport_runtime._entry_from_world_db_transport_spec(
        {
            "guid": 7,
            "entry": 20808,
            "name": "The Maiden's Fancy",
            "display_id": 3015,
            "faction": 0,
            "flags": 40,
            "size": 1.0,
            "path_id": 241,
            "data1": 30,
            "data2": 1,
            "data3": 0,
            "data8": 0,
        },
        world_guid=world_guid,
        route=route,
        start_index=0,
    )

    state = transport_runtime.get_world_transport_manager().register_transport(
        entry,
        source="test",
    )
    assert state is not None
    assert len(state.route) == 18
    assert state.route_period_ms == 231112
    assert [
        (node.source_node_index, node.arrival_event_id)
        for node in state.route
        if node.arrival_event_id
    ] == [(6, 16398), (16, 16397)]
    template = transport_runtime._movement_template_for_state(state)
    assert template is not None
    assert len(template.nodes) == 20
    assert template.period_ms == 231112
    assert template.transfer_nodes == (10, 19)
    assert template.station_nodes == (5, 14)

    transport_runtime.get_movement_manager().unregister_instance(world_guid)
    transport_runtime._ensure_movement_instance_for_state(state)
    restored_template = transport_runtime._movement_template_for_state(state)
    assert restored_template is not None
    assert restored_template.map_local_splines is True
    assert len(restored_template.nodes) == 20


def test_path_241_station_lifecycle_is_symmetric_across_two_cycles(monkeypatch):
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda *_args: 0,
    )
    route = transport_runtime._build_skyfire_taxi_transport_route(
        241,
        move_speed=30.0,
        acceleration=1.0,
        can_be_stopped=False,
    )
    entry = {
        "entry": 20808,
        "world_guid": 241,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "skyfire_transport_route": True,
    }
    template = transport_runtime._movement_template_from_route(entry, route)

    assert template is not None
    assert template.station_nodes == (5, 14)
    assert template.transfer_nodes == (10, 19)
    assert route[5].source_node_index == 6
    assert route[5].arrival_event_id == 16398
    assert route[13].source_node_index == 16
    assert route[13].arrival_event_id == 16397

    manager = movement_manager_module.MovementManager()
    instance = MovementInstance(
        instance_id=241,
        template_id=template.template_id,
        started_at_ms=0,
    )
    state = MovementRuntimeState(
        instance=instance,
        spawned=True,
    )
    manager.templates[template.template_id] = template
    manager.instances[241] = state

    emitted = []

    def tick_phase(absolute_phase_ms):
        before = tuple(state.lifecycle_events)
        transform = manager.tick_instance(
            241,
            server_time_ms=int(absolute_phase_ms) + 11500,
        )
        after = tuple(state.lifecycle_events)
        overlap = 0
        for size in range(min(len(before), len(after)), -1, -1):
            if before[len(before) - size:] == after[:size]:
                overlap = size
                break
        emitted.extend(after[overlap:])
        return transform

    tick_phase(0)
    node_times = sorted(
        {
            int(node.time_ms)
            for node in template.nodes
            if int(node.time_ms) > 0
        }
    )
    station_samples = {5: [], 14: []}
    for cycle in range(2):
        cycle_start = cycle * int(template.period_ms)
        for phase_ms in node_times:
            transform = tick_phase(cycle_start + phase_ms)
            if int(transform.node_index) in station_samples:
                station_samples[int(transform.node_index)].append(transform)
        tick_phase((cycle + 1) * int(template.period_ms))

    for station_index in (5, 14):
        arrivals = [
            event
            for event in emitted
            if event.event_type == MovementLifecycleEventType.ARRIVED
            and int(event.node_index) == station_index
        ]
        departures = [
            event
            for event in emitted
            if event.event_type == MovementLifecycleEventType.DEPARTED
            and int(event.node_index) == station_index
        ]
        assert len(arrivals) == 2
        assert len(departures) == 2
        assert len(station_samples[station_index]) == 2
        assert all(
            str(transform.state) == evaluator.STATE_DOCKED
            for transform in station_samples[station_index]
        )

    cyclic_begins = [
        event
        for event in emitted
        if event.event_type == MovementLifecycleEventType.TRANSFER_BEGIN
        and int(event.node_index) == 19
        and int(event.target_map_id) == 1
    ]
    assert len(cyclic_begins) == 2

    cyclic_source = evaluator.evaluate_template(
        template,
        int(template.period_ms) - 1 + 11500,
    )
    cyclic_destination = evaluator.evaluate_template(
        template,
        int(template.period_ms) + 11500,
    )
    assert (
        cyclic_source.phase_ms,
        cyclic_source.node_index,
        cyclic_source.next_node_index,
        cyclic_source.map_id,
        cyclic_source.state,
    ) == (
        231111,
        19,
        0,
        0,
        evaluator.STATE_TRANSFER_PENDING,
    )
    assert (
        cyclic_destination.phase_ms,
        cyclic_destination.node_index,
        cyclic_destination.map_id,
        cyclic_destination.state,
    ) == (0, 0, 1, evaluator.STATE_ACTIVE)

    ratchet_wait_end = int(template.nodes[6].time_ms)
    booty_wait_end = int(template.nodes[15].time_ms)
    for cycle in range(2):
        cycle_start = cycle * int(template.period_ms)
        for wait_end, wait_node in ((ratchet_wait_end, 6), (booty_wait_end, 15)):
            waiting = evaluator.evaluate_template(
                template,
                cycle_start + wait_end + 11499,
            )
            departed = evaluator.evaluate_template(
                template,
                cycle_start + wait_end + 11500,
            )
            moving = evaluator.evaluate_template(
                template,
                cycle_start + wait_end + 11501,
            )
            assert waiting.node_index == wait_node - 1
            assert waiting.state == evaluator.STATE_DOCKED
            assert departed.node_index == wait_node
            assert departed.state == evaluator.STATE_ACTIVE
            assert (departed.x, departed.y, departed.z) == (
                waiting.x,
                waiting.y,
                waiting.z,
            )
            assert moving.node_index == wait_node
            assert (moving.x, moving.y, moving.z) != (
                departed.x,
                departed.y,
                departed.z,
            )


def test_next_station_distance_completes_no_station_synthetic_cycle():
    distance = transport_runtime._distance_to_next_station(
        0,
        (0,),
        (10.0, 20.0, 30.0),
    )

    assert distance == 60.0


def test_next_station_distance_completes_one_real_station_cycle():
    distance = transport_runtime._distance_to_next_station(
        1,
        (1,),
        (10.0, 20.0, 30.0),
    )

    assert distance == 60.0


def test_next_station_distance_stops_at_next_of_multiple_stations():
    distance = transport_runtime._distance_to_next_station(
        0,
        (0, 2),
        (10.0, 20.0, 30.0),
    )

    assert distance == 30.0


def test_next_station_distance_from_between_stations():
    distance = transport_runtime._distance_to_next_station(
        1,
        (0, 2),
        (10.0, 20.0, 30.0),
    )

    assert distance == 20.0


def test_next_station_distance_rejects_unreachable_station():
    with pytest.raises(ValueError, match="no reachable station"):
        transport_runtime._distance_to_next_station(
            0,
            (9,),
            (10.0, 20.0, 30.0),
        )


def test_skyfire_transport_timeline_accumulates_every_station_delay(monkeypatch):
    def _nodes(delays):
        return tuple(
            transport_runtime.TransportTaxiPathNode(
                1002,
                index,
                1,
                float(index * 100),
                0.0,
                0.0,
                flags=2 if index in (0, 2, 4) else 0,
                delay=int(delays.get(index, 0)),
            )
            for index in range(5)
        )

    monkeypatch.setattr(
        transport_runtime,
        "_transport_taxi_path_nodes_by_path",
        lambda: {1002: _nodes({})},
    )
    route_without_delays = transport_runtime._build_skyfire_taxi_transport_route(
        1002,
        move_speed=10.0,
        acceleration=1.0,
        can_be_stopped=True,
    )

    monkeypatch.setattr(
        transport_runtime,
        "_transport_taxi_path_nodes_by_path",
        lambda: {1002: _nodes({0: 2, 2: 3, 4: 4})},
    )
    route = transport_runtime._build_skyfire_taxi_transport_route(
        1002,
        move_speed=10.0,
        acceleration=1.0,
        can_be_stopped=True,
    )

    assert [
        node.time_ms - baseline.time_ms
        for node, baseline in zip(route, route_without_delays)
    ] == [0, 2000, 2000, 5000, 5000]

    entry = {
        "entry": 1002,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "skyfire_transport_route": True,
    }
    template = transport_runtime._movement_template_from_route(entry, route)

    assert template is not None
    times = [int(node.time_ms) for node in template.nodes]
    assert all(later > earlier for earlier, later in zip(times, times[1:]))
    for route_node in route:
        delay_ms = int(round(float(route_node.wait_time) * 1000.0))
        if delay_ms <= 0:
            continue
        assert int(route_node.time_ms) + delay_ms in times
    assert template.period_ms == route[-1].time_ms + 4000
    assert transport_runtime._route_period_with_waits_ms(route) == template.period_ms


def test_entry_186371_builds_a_monotonic_skyfire_transport_template(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda *_args: 0,
    )
    route = transport_runtime._build_skyfire_taxi_transport_route(
        727,
        move_speed=10.0,
        acceleration=1.0,
        can_be_stopped=False,
    )

    assert route[0].source_node_index == 1
    assert route[0].time_ms == 0
    assert route[0].wait_time == 60.0
    assert route[1].source_node_index == 2
    assert route[1].time_ms == 69_240

    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(13))
    entry = transport_runtime._entry_from_world_db_transport_spec(
        {
            "guid": 13,
            "entry": 186371,
            "name": 'Westguard Keep bombardment ("Zeppelin")',
            "display_id": 3031,
            "faction": 0,
            "flags": 0,
            "size": 1.0,
            "path_id": 727,
            "data1": 10,
            "data2": 1,
            "data3": 0,
            "data8": 0,
        },
        world_guid=world_guid,
        route=route,
        start_index=0,
    )
    try:
        state = transport_runtime.get_world_transport_manager().register_transport(
            entry,
            source="test",
        )

        assert state is not None
        template = transport_runtime._movement_template_for_state(state)
        assert template is not None
        times = [int(node.time_ms) for node in template.nodes]
        assert all(later > earlier for earlier, later in zip(times, times[1:]))
        assert template.period_ms == times[-1]
        assert state.route_period_ms == template.period_ms
    finally:
        _reset_transport_states()


def test_path_2600_registers_without_station_nodes(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda *_args: 0,
    )
    route = transport_runtime._build_skyfire_taxi_transport_route(
        2600,
        move_speed=15.0,
        acceleration=8.0,
        can_be_stopped=False,
    )
    assert len(route) == 10
    assert all(node.wait_time == 0.0 for node in route)

    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(26))
    entry = transport_runtime._entry_from_world_db_transport_spec(
        {
            "guid": 26,
            "entry": 207227,
            "name": "Krazzworks Attack Zeppelin",
            "display_id": 3031,
            "faction": 0,
            "flags": 40,
            "size": 1.0,
            "path_id": 2600,
            "data1": 15,
            "data2": 8,
            "data3": 0,
            "data8": 0,
        },
        world_guid=world_guid,
        route=route,
        start_index=0,
    )

    try:
        state = transport_runtime.get_world_transport_manager().register_transport(
            entry,
            source="test",
        )
        assert state is not None
        template = transport_runtime._movement_template_for_state(state)
        assert template is not None
        times = [int(node.time_ms) for node in template.nodes]
        assert all(later > earlier for earlier, later in zip(times, times[1:]))
    finally:
        _reset_transport_states()


@pytest.mark.parametrize(
    ("entry", "path_id", "speed", "acceleration"),
    (
        (20808, 241, 30, 1),
        (164871, 302, 30, 1),
        (175080, 285, 30, 1),
        (176231, 292, 30, 1),
        (176310, 967, 30, 1),
        (176495, 301, 30, 1),
        (177233, 777, 30, 1),
        (181646, 503, 30, 1),
        (181688, 964, 15, 1),
        (181689, 737, 30, 1),
        (186238, 712, 30, 1),
        (186371, 727, 10, 1),
        (187038, 778, 20, 1),
        (187568, 799, 30, 1),
        (188511, 1079, 30, 1),
        (190536, 965, 21, 1),
        (190549, 1221, 30, 1),
        (192241, 1095, 2, 1),
        (192242, 1094, 2, 1),
        (197195, 1368, 30, 8),
        (203428, 2338, 15, 10),
        (203466, 2204, 30, 8),
        (203626, 2265, 30, 5),
        (204018, 2222, 7, 10),
        (206328, 2477, 20, 8),
        (206329, 2480, 20, 8),
        (207227, 2600, 15, 8),
    ),
)
def test_all_world_db_type15_route_builders_terminate(
    entry,
    path_id,
    speed,
    acceleration,
):
    route = transport_runtime._build_skyfire_taxi_transport_route(
        path_id,
        move_speed=float(speed),
        acceleration=float(acceleration),
        can_be_stopped=False,
    )

    assert len(route) >= 2, f"entry={entry} path={path_id}"
    times = [int(node.time_ms) for node in route]
    assert all(later > earlier for earlier, later in zip(times, times[1:]))


def test_ratchet_booty_owner_tick_starts_worldport_in_both_directions(monkeypatch):
    _reset_transport_states()
    phase = {"value": 115557}
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda *_args: 11500 + int(phase["value"]),
    )
    route = transport_runtime._build_skyfire_taxi_transport_route(
        241,
        move_speed=30.0,
        acceleration=1.0,
        can_be_stopped=False,
    )
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    entry = transport_runtime._entry_from_world_db_transport_spec(
        {
            "guid": 7,
            "entry": 20808,
            "name": "The Maiden's Fancy",
            "display_id": 3015,
            "faction": 0,
            "flags": 40,
            "size": 1.0,
            "path_id": 241,
            "data1": 30,
            "data2": 1,
            "data3": 0,
            "data8": 0,
        },
        world_guid=world_guid,
        route=route,
        start_index=0,
    )
    state = transport_runtime.get_world_transport_manager().register_transport(
        entry,
        source="test",
    )
    assert state is not None
    worldports = []
    monkeypatch.setattr(
        transport_runtime,
        "transport_crossed_map_boundary",
        lambda guid, *, previous_map_id, boundary_event: worldports.append(
            (
                int(guid),
                int(previous_map_id),
                int(boundary_event.target_map_id),
            )
        ) or True,
    )

    phase["value"] = 115559
    assert transport_runtime.get_world_transport_manager()._tick_transport_state(
        world_guid,
        state,
    ) is True
    assert state.map_id == 0

    phase["value"] = 231110
    transport_runtime.get_world_transport_manager()._tick_transport_state(
        world_guid,
        state,
    )
    phase["value"] = 0
    assert transport_runtime.get_world_transport_manager()._tick_transport_state(
        world_guid,
        state,
    ) is True
    assert state.map_id == 1
    assert worldports == [
        (world_guid, 1, 0),
        (world_guid, 0, 1),
    ]


def test_transport_manager_ticks_each_shared_clock_independently(monkeypatch):
    _reset_transport_states()
    phases = {
        "world-db-transport:7": 250,
        "world-db-transport:8": 750,
    }
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda clock_key, _period_ms: phases[str(clock_key)],
    )
    entries = [
        {
            "guid": 120007,
            "world_guid": 0xF120000000120007,
            "entry": 20808,
            "map": 1,
            "home_map": 1,
            "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
            "display_id": 3015,
            "runtime_route": [
                (1, 0.0, 0.0, 0.0, 0.0, 0),
                (1, 100.0, 0.0, 0.0, 0.0, 1000),
            ],
            "shared_route_clock_key": "world-db-transport:7",
            "transport_period": 1000,
        },
        {
            "guid": 120008,
            "world_guid": 0xF120000000120008,
            "entry": 20808,
            "map": 1,
            "home_map": 1,
            "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
            "display_id": 3015,
            "runtime_route": [
                (1, 0.0, 10.0, 0.0, 0.0, 0),
                (1, 100.0, 10.0, 0.0, 0.0, 1000),
            ],
            "shared_route_clock_key": "world-db-transport:8",
            "transport_period": 1000,
        },
    ]
    for entry in entries:
        assert transport_runtime._transport_state_for_entry(entry) is not None

    states = list(transport_runtime._runtime_transport_states().items())
    for world_guid, state in states:
        transport_runtime.get_movement_manager().tick_instance(
            world_guid,
            server_time_ms=transport_runtime._transport_server_time_ms(state),
        )
        transport_runtime._commit_transport_state_from_movement_cache(state)

    first = transport_runtime._runtime_transport_states()[entries[0]["world_guid"]]
    second = transport_runtime._runtime_transport_states()[entries[1]["world_guid"]]

    assert int(first.path_progress_ms) == 250
    assert int(second.path_progress_ms) == 750
    assert round(first.x, 3) == 25.0
    assert round(second.x, 3) == 75.0


def test_cross_map_destination_clone_visible_during_transfer(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(
        transport_runtime,
        "_shared_route_phase_ms",
        lambda _clock_key, _period_ms: 500,
    )
    source_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(
        transport_runtime._same_map_transport_spawn_guid(77, map_id=1)
    ))
    destination_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(
        transport_runtime._same_map_transport_spawn_guid(77, map_id=0)
    ))
    base_entry = {
        "transport_db_guid": 77,
        "entry": 20808,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (0, 100.0, 200.0, 10.0, 0.0, 1000),
            (0, 150.0, 200.0, 10.0, 0.0, 2000),
        ],
        "shared_route_clock_key": "world-db-transport:77",
        "transport_period": 2000,
        "world_db_transport": True,
        "use_transport_guid": True,
    }
    source_entry = {
        **base_entry,
        "guid": transport_runtime._same_map_transport_spawn_guid(77, map_id=1),
        "world_guid": source_guid,
        "map": 1,
        "map_id": 1,
        "home_map": 1,
    }
    destination_entry = {
        **base_entry,
        "guid": transport_runtime._same_map_transport_spawn_guid(77, map_id=0),
        "world_guid": destination_guid,
        "map": 0,
        "map_id": 0,
        "home_map": 0,
    }
    manager = transport_runtime.get_world_transport_manager()
    assert manager.register_transport(source_entry, source="test") is not None
    assert manager.register_transport(destination_entry, source="test") is not None
    for world_guid, state in list(transport_runtime._runtime_transport_states().items()):
        transport_runtime.get_movement_manager().tick_instance(
            world_guid,
            server_time_ms=transport_runtime._transport_server_time_ms(state),
        )
        transport_runtime._commit_transport_state_from_movement_cache(state)

    assert manager.is_visible(source_guid) is False
    assert manager.visibility_state_for_guid(source_guid) == "TRANSFERRING"
    assert manager.is_visible(destination_guid) is True
    assert manager.visibility_state_for_guid(destination_guid) == "ACTIVE"

    session = SimpleNamespace(
        char_guid=1,
        gameobjects_visible=True,
        map_id=0,
        x=101.0,
        y=201.0,
        realm_id=1,
    )
    entries = transport_runtime.synthetic_transport_entries_near(session, loaded_guids=set())

    assert any(int(entry["world_guid"]) == destination_guid for entry in entries)
    destination_state = transport_runtime._runtime_transport_states()[destination_guid]
    assert destination_state.map_id == 0
    assert (destination_state.x, destination_state.y, destination_state.z) == (100.0, 200.0, 10.0)


def test_transport_route_builder_converts_taxi_delay_to_wait_segment(monkeypatch):
    monkeypatch.setattr(
        transport_runtime,
        "_transport_taxi_path_nodes_by_path",
        lambda: {
            1001: (
                transport_runtime.TransportTaxiPathNode(1001, 0, 1, 0.0, 0.0, 0.0, flags=2, delay=2),
                transport_runtime.TransportTaxiPathNode(1001, 1, 1, 100.0, 0.0, 0.0),
                transport_runtime.TransportTaxiPathNode(1001, 2, 1, 200.0, 0.0, 0.0),
            )
        },
    )

    route = transport_runtime._build_timed_taxi_transport_route(1001, period_ms=10_000)

    assert len(route) == 4
    assert route[0].wait_time == 2.0
    assert route[1].map_id == route[0].map_id
    assert (route[1].x, route[1].y, route[1].z) == (route[0].x, route[0].y, route[0].z)
    assert route[1].time_ms - route[0].time_ms == 2000
    assert route[-1].time_ms == 10_000


def test_timed_transport_evaluation_uses_movement_manager(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.25)
    entry = {
        "guid": 100777,
        "world_guid": 0xF120000000000777,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "x": 0.0,
        "y": 0.0,
        "z": 0.0,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 0.0, 0),
            (1, 10.0, 0.0, 0.0, 0.0, 500),
            (1, 20.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }

    _tick_transport_entry(entry)
    moved = transport_runtime.cached_transport_runtime_entry(SimpleNamespace(), entry)

    assert moved["map"] == 1
    assert 0.0 < moved["x"] < 20.0
    assert hasattr(transport_runtime, "_apply_timed_route_position") is False


def test_transport_lifecycle_transfer_pending_on_explicit_transfer_event(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.5)
    entry = {
        "guid": 100778,
        "world_guid": 0xF120000000000778,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 0.0, 0),
            (0, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    destination = transport_runtime.transport_transfer_destination_map_for_guid(int(entry["world_guid"]))
    manager_state = transport_runtime.get_movement_manager().get_state(int(entry["world_guid"]))

    assert manager_state is not None
    assert manager_state.lifecycle_state == transport_runtime.TRANSPORT_STATE_TRANSFER_PENDING
    assert destination == 0
    events = transport_runtime.get_movement_manager().latest_events(int(entry["world_guid"]))
    assert events[-1].event_type == MovementLifecycleEventType.TRANSFER_BEGIN
    assert events[-1].target_map_id == 0


def test_commit_transport_dynamic_state_copies_lifecycle_metadata(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.5)
    world_guid = 0xF120000000000779
    entry = {
        "guid": 100779,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 0.0, 0),
            (0, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    movement_state = transport_runtime.get_movement_manager().get_state(world_guid)

    assert state is not None
    assert movement_state is not None
    assert state.lifecycle_state == transport_runtime.TRANSPORT_STATE_TRANSFER_PENDING
    assert state.previous_lifecycle_state == movement_state.previous_lifecycle_state
    assert state.visibility_state == "TRANSFERRING"
    assert state.previous_visibility_state == movement_state.previous_visibility_state
    assert state.last_event == "transfer"
    assert state.transfer_active is True
    assert state.transfer_destination_map == 0
    assert state.last_node_index == 0
    assert state.lifecycle_events[-1].event_type == MovementLifecycleEventType.TRANSFER_BEGIN
    assert state.lifecycle_events[-1].target_map_id == 0


def test_transport_lifecycle_and_visibility_helpers_prefer_runtime_state(monkeypatch):
    _reset_transport_states()
    entry = _loaded_mo_transport_entry(world_guid=0x1FC0000000018701)
    state = _install_runtime_update_test_transport(monkeypatch, entry)
    movement_state = transport_runtime.get_movement_manager().get_state(int(state.guid))
    if movement_state is not None:
        movement_state.lifecycle_state = transport_runtime.TRANSPORT_STATE_ACTIVE
        movement_state.visibility_state = "ACTIVE"
    state.lifecycle_state = "DOCKED"
    state.visibility_state = "WAITING"

    assert transport_runtime._movement_lifecycle_state(int(state.guid)) == "DOCKED"
    assert transport_runtime._movement_visibility_state(int(state.guid)) == "WAITING"


def test_transfer_destination_prefers_runtime_state(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.5)
    world_guid = 0xF12000000000077A
    entry = {
        "guid": 100780,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 0.0, 0),
            (0, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    movement_state = transport_runtime.get_movement_manager().get_state(world_guid)
    assert movement_state is not None
    movement_state.lifecycle_events = ()
    movement_state.transfer_destination_map = None
    monkeypatch.setattr(transport_runtime, "_sync_transport_state_from_movement_cache", lambda _state: None)

    assert transport_runtime.transport_transfer_destination_map_for_guid(world_guid) == 0


def test_transfer_destination_uses_runtime_state_before_sync_for_map_zero(monkeypatch):
    _reset_transport_states()
    world_guid = 0xF12000000000077B
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=100781,
        display_id=3015,
        route=[],
        node_index=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=1,
        transfer_active=True,
        transfer_destination_map=0,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state

    def _fail_sync(_state):
        raise AssertionError("runtime-state destination should be read before sync")

    monkeypatch.setattr(transport_runtime, "_sync_transport_state_from_movement_cache", _fail_sync)

    assert transport_runtime.transport_transfer_destination_map_for_guid(world_guid) == 0


def test_transfer_destination_uses_runtime_state_for_map_one(monkeypatch):
    _reset_transport_states()
    world_guid = 0xF12000000000077C
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=100782,
        display_id=3015,
        route=[],
        node_index=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=0,
        transfer_active=True,
        transfer_destination_map=1,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state

    def _fail_sync(_state):
        raise AssertionError("runtime-state destination should be read before sync")

    monkeypatch.setattr(transport_runtime, "_sync_transport_state_from_movement_cache", _fail_sync)

    assert transport_runtime.transport_transfer_destination_map_for_guid(world_guid) == 1


def test_transfer_pending_transport_is_not_streamed(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.5)
    world_guid = 0xF120000000000780
    entry = {
        "guid": 100780,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 0.0, 0),
            (0, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    session = SimpleNamespace(
        char_guid=10,
        gameobjects_visible=True,
        map_id=1,
        x=0.0,
        y=0.0,
        realm_id=1,
        loaded_gameobjects={world_guid},
    )
    loaded = {world_guid: entry}

    responses = transport_runtime._build_visible_transport_updates(session, loaded)

    assert responses
    assert loaded == {}
    assert world_guid not in session.loaded_gameobjects
    assert transport_runtime.get_movement_manager().visibility_state(world_guid).value == "TRANSFERRING"


def test_transfer_pending_transport_auto_worldports_attached_passenger(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.5)
    monkeypatch.setattr(movement, "_is_teleporting", lambda _session: False)
    monkeypatch.setattr(movement, "_clear_loaded_world_objects_for_transfer", lambda _session: [])

    source_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100782))
    entry = {
        "guid": 100782,
        "transport_db_guid": 7,
        "world_guid": source_guid,
        "entry": 20808,
        "map": 1,
        "map_id": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "use_transport_guid": True,
        "world_db_transport": True,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        "shared_route_clock_key": "world-db-transport:7",
        "transport_period": 1000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None

    movement_state = SimpleNamespace(
        has_transport_data=True,
        transport_guid=source_guid,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.5,
        transport_time=0,
        transport_time2=0,
        transport_time3=0,
        transport_seat=-1,
        transport_vehicle_id=0,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        pitch=0.0,
        last_valid_orientation=0.0,
    )
    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        gameobjects_visible=True,
        map_id=1,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        movement_state=movement_state,
        loaded_gameobjects={source_guid},
        loaded_transport_entries={source_guid: entry},
    )
    transport_runtime.get_movement_manager().attach_passenger(
        source_guid,
        1,
        local_x=2.0,
        local_y=3.0,
        local_z=4.0,
        local_o=0.5,
        source_map=1,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.worldport_ack_pending is True
    assert session.transport_transfer_pending is True
    assert session.map_id == 0
    assert session.x == 102.0
    assert session.y == 203.0
    assert session.z == 14.0
    linked_destination_guid = transport_runtime.linked_transport_world_guid(entry, map_id=0)
    assert movement_state.transport_guid == source_guid
    assert session.pending_transport_transfer["destination_guid"] == source_guid
    assert transport_runtime.runtime_transport_state_for_guid(linked_destination_guid) is None


def test_waiting_transport_remains_visible(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.0)
    world_guid = 0xF120000000000781
    entry = {
        "guid": 100781,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 4.0, 0),
            (1, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    session = SimpleNamespace(
        char_guid=11,
        gameobjects_visible=True,
        map_id=1,
        x=0.0,
        y=0.0,
        realm_id=1,
        loaded_gameobjects={world_guid},
    )
    loaded = {world_guid: entry}

    responses = transport_runtime._build_visible_transport_updates(session, loaded)

    assert responses
    assert world_guid in loaded
    assert transport_runtime.get_movement_manager().visibility_state(world_guid).value == "WAITING"


def test_transport_dock_delay_freezes_position_and_distance(monkeypatch):
    _reset_transport_states()
    now = 0.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)
    world_guid = 0xF120000000000A01
    entry = {
        "guid": 110001,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 2.0, 0),
            (1, 100.0, 0.0, 0.0, 0.0, 1000),
            (1, 200.0, 0.0, 0.0, 0.0, 2000),
        ],
        "transport_period": 2000,
    }

    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    manager = transport_runtime.get_movement_manager()
    template = manager.templates[manager.get_state(world_guid).instance.template_id]

    manager.tick_instance(world_guid, server_time_ms=500)
    at_500 = manager.get_transform(world_guid)
    distance_500 = evaluator._distance_for_phase(template, 500)

    manager.tick_instance(world_guid, server_time_ms=1500)
    at_1500 = manager.get_transform(world_guid)
    distance_1500 = evaluator._distance_for_phase(template, 1500)

    assert at_500.phase_ms == 500
    assert at_1500.phase_ms == 1500
    assert (at_500.x, at_500.y, at_500.z) == (0.0, 0.0, 0.0)
    assert (at_1500.x, at_1500.y, at_1500.z) == (0.0, 0.0, 0.0)
    assert distance_1500 == distance_500 == 0.0
    assert at_1500.state == "DOCKED"
    assert at_1500.event == "station"

    manager.tick_instance(world_guid, server_time_ms=2500)
    after_dock = manager.get_transform(world_guid)

    assert after_dock.state == "ACTIVE"
    assert after_dock.x > 0.0
    assert after_dock.phase_ms == 2500
    assert evaluator._distance_for_phase(template, 2500) > distance_1500


def test_cross_map_transfer_waits_at_departure_position(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.0)
    world_guid = 0xF120000000000A02
    entry = {
        "guid": 110002,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 2.0, 0),
            (0, 500.0, 600.0, 8.0, 0.0, 1000),
            (0, 550.0, 600.0, 8.0, 0.0, 2000),
        ],
        "transport_period": 2000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    manager = transport_runtime.get_movement_manager()

    manager.tick_instance(world_guid, server_time_ms=13000)
    waiting = manager.get_transform(world_guid)
    assert waiting.map_id == 1
    assert (waiting.x, waiting.y, waiting.z) == (10.0, 20.0, 5.0)
    assert waiting.state == "DOCKED"
    assert transport_runtime.transport_transfer_destination_map_for_guid(world_guid) is None

    manager.tick_instance(world_guid, server_time_ms=13500)
    transfer = manager.get_transform(world_guid)
    assert transfer.map_id == 1
    assert (transfer.x, transfer.y, transfer.z) == (10.0, 20.0, 5.0)
    assert transfer.state == transport_runtime.TRANSPORT_STATE_TRANSFER_PENDING
    assert transfer.event == "transfer"
    assert transport_runtime.transport_transfer_destination_map_for_guid(world_guid) == 0


def test_cached_transport_entry_keeps_source_map_during_transfer_frame(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.0)
    world_guid = 0xF120000000000A03
    entry = {
        "guid": 110003,
        "transport_db_guid": 110003,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (0, 500.0, 600.0, 8.0, 0.0, 1000),
            (0, 550.0, 600.0, 8.0, 0.0, 2000),
        ],
        "shared_route_clock_key": "world-db-transport:110003",
        "world_db_transport": True,
        "transport_period": 2000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    manager = transport_runtime.get_movement_manager()

    manager.tick_instance(world_guid, server_time_ms=13500)
    transfer = manager.get_transform(world_guid)
    assert transfer.event == "transfer"
    assert (transfer.x, transfer.y, transfer.z) == (10.0, 20.0, 5.0)
    transport_runtime._commit_transport_state_from_movement_cache(state)

    moved = transport_runtime.cached_transport_runtime_entry(
        SimpleNamespace(map_id=0, x=500.0, y=600.0, z=8.0),
        entry,
    )

    assert (moved["x"], moved["y"], moved["z"]) == (10.0, 20.0, 5.0)
    assert moved["map"] == 1
    assert moved["transport_path_progress"] == transfer.phase_ms


def test_cached_transport_entry_reads_committed_runtime_transport_state(monkeypatch):
    _reset_transport_states()
    world_guid = 0xF120000000000B01
    entry = {
        "guid": 120001,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 0.0, 0),
            (1, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None

    state.map_id = 1
    state.x = 12.0
    state.y = 34.0
    state.z = 56.0
    state.orientation = 1.25
    state.path_progress_ms = 789

    monkeypatch.setattr(
        transport_runtime.get_movement_manager(),
        "get_transform",
        lambda _world_guid: SimpleNamespace(
            map_id=0,
            x=999.0,
            y=999.0,
            z=999.0,
            orientation=9.0,
            phase_ms=999,
            event="",
            next_node_index=0,
        ),
    )

    moved = transport_runtime.cached_transport_runtime_entry(
        SimpleNamespace(map_id=1, x=0.0, y=0.0, z=0.0),
        entry,
    )

    assert moved["map"] == 1
    assert (moved["x"], moved["y"], moved["z"]) == (12.0, 34.0, 56.0)
    assert moved["orientation"] == 1.25
    assert moved["transport_path_progress"] == 789


def test_gameobject_create_reads_runtime_transport_state(monkeypatch):
    _reset_transport_states()
    captured_fields = {}
    world_guid = 0xF120000000000B02
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=120002,
        display_id=3015,
        route=[],
        node_index=0,
        x=12.0,
        y=34.0,
        z=56.0,
        orientation=1.25,
        map_id=0,
        path_progress_ms=789,
        route_period_ms=2000,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    stale_entry = {
        "guid": 120002,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "x": 1.0,
        "y": 2.0,
        "z": 3.0,
        "orientation": 0.5,
        "transport_path_progress": 100,
        "transport_period": 2000,
    }

    monkeypatch.setattr(
        gameobjects.EncoderHandler,
        "encode_packet",
        lambda _name, payload: payload,
    )

    def capture_fields(fields, *, mask_blocks=1):
        captured_fields.clear()
        captured_fields.update(fields)
        return (b"\x00" * (int(mask_blocks) * 4), b"")

    monkeypatch.setattr(gameobjects, "_build_fixed_u32_field_block", capture_fields)

    payload = gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=stale_entry,
        realm_id=1,
    )

    assert payload["map_id"] == 0
    assert payload["guid"] == {"guid": world_guid}
    assert payload["stationary_x"] == 12.0
    assert payload["stationary_y"] == 34.0
    assert payload["stationary_z"] == 56.0
    assert payload["stationary_orientation"] == 1.25
    assert payload["gameobject_rotation_packed"] == gameobjects._gameobject_rotation_packed(
        {"orientation": 1.25}
    )
    assert payload["movement_block_uint32"] == 789
    rotation_start = gameobjects._GAMEOBJECT_FIELD_ROTATION_START
    assert struct.unpack("<f", struct.pack("<I", captured_fields[rotation_start + 2]))[0] == pytest.approx(math.sin(1.25 / 2.0))
    assert struct.unpack("<f", struct.pack("<I", captured_fields[rotation_start + 3]))[0] == pytest.approx(math.cos(1.25 / 2.0))
    dynamic_flags = captured_fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS]
    assert dynamic_flags == (25853 << 16)


def test_gameobject_values_update_reads_runtime_transport_state(monkeypatch):
    _reset_transport_states()
    captured_fields = {}
    world_guid = 0xF120000000000B03
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=120003,
        display_id=3015,
        route=[],
        node_index=0,
        x=12.0,
        y=34.0,
        z=56.0,
        orientation=1.25,
        map_id=0,
        path_progress_ms=500,
        route_period_ms=2000,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    stale_entry = {
        "guid": 120003,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "x": 1.0,
        "y": 2.0,
        "z": 3.0,
        "orientation": 0.5,
        "transport_path_progress": 100,
        "transport_period": 2000,
    }

    def capture_fields(fields, *, mask_blocks=1):
        captured_fields.clear()
        captured_fields.update(fields)
        return (b"\x00" * (int(mask_blocks) * 4), b"")

    monkeypatch.setattr(gameobjects, "_build_fixed_u32_field_block", capture_fields)

    payload = gameobjects._build_gameobject_values_update_payload(
        map_id=1,
        entry=stale_entry,
        realm_id=1,
    )

    assert struct.unpack_from("<H", payload, 0)[0] == 0
    dynamic_flags = captured_fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS]
    assert dynamic_flags == (16383 << 16)


def test_type11_gameobject_create_reads_runtime_elevator_state(monkeypatch):
    _reset_transport_states()
    captured_fields = {}
    world_guid = 0xF120000000000E11
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=999011,
        spawn_guid=9011,
        display_id=360,
        route=[],
        node_index=0,
        x=111.0,
        y=222.0,
        z=333.0,
        orientation=1.75,
        map_id=530,
        path_progress_ms=4321,
        route_period_ms=10000,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    stale_entry = {
        "guid": 9011,
        "world_guid": world_guid,
        "entry": 999011,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "display_id": 360,
        "x": 1.0,
        "y": 2.0,
        "z": 3.0,
        "orientation": 0.5,
        "transport_path_progress": 100,
        "transport_period": 2000,
    }

    monkeypatch.setattr(
        gameobjects.EncoderHandler,
        "encode_packet",
        lambda _name, payload: payload,
    )

    def capture_fields(fields, *, mask_blocks=1):
        captured_fields.clear()
        captured_fields.update(fields)
        return (b"\x00" * (int(mask_blocks) * 4), b"")

    monkeypatch.setattr(gameobjects, "_build_fixed_u32_field_block", capture_fields)

    payload = gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=stale_entry,
        realm_id=1,
    )

    assert payload["map_id"] == 530
    assert payload["guid"] == {"guid": world_guid}
    assert payload["stationary_x"] == 111.0
    assert payload["stationary_y"] == 222.0
    assert payload["stationary_z"] == 333.0
    assert payload["stationary_orientation"] == 1.75
    assert payload["gameobject_rotation_packed"] == gameobjects._gameobject_rotation_packed(
        {"orientation": 1.75}
    )
    assert payload["movement_block_uint32"] == 4321
    rotation_start = gameobjects._GAMEOBJECT_FIELD_ROTATION_START
    assert struct.unpack("<f", struct.pack("<I", captured_fields[rotation_start + 2]))[0] == pytest.approx(math.sin(1.75 / 2.0))
    assert struct.unpack("<f", struct.pack("<I", captured_fields[rotation_start + 3]))[0] == pytest.approx(math.cos(1.75 / 2.0))
    dynamic_flags = captured_fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS]
    assert dynamic_flags == 0


def test_generic_type11_runtime_elevator_counts_as_real_runtime_elevator(monkeypatch):
    animation = transport_runtime.TransportAnimationPath(
        entry=999012,
        nodes=(
            transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
            transport_runtime.TransportAnimationNode(1000, 0.0, 0.0, 10.0),
        ),
        period_ms=1000,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_transport_animation_for_entry",
        lambda entry_id: animation if int(entry_id) == 999012 else None,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.elevators_enabled",
        lambda: True,
    )

    entry = {
        "guid": 9012,
        "world_guid": 0xF120000000000E12,
        "entry": 999012,
        "map": 530,
        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "original_type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "display_id": 360,
    }

    assert movement._is_real_runtime_elevator_entry(entry) is True


def test_client_driven_type11_create_uses_base_position_with_runtime_progress(monkeypatch):
    _reset_transport_states()
    captured_fields = {}
    world_guid = 0xF120000000000E13
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=999013,
        spawn_guid=9013,
        display_id=360,
        route=[],
        node_index=0,
        x=111.0,
        y=222.0,
        z=333.0,
        orientation=1.75,
        map_id=530,
        path_progress_ms=4321,
        route_period_ms=10000,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    entry = {
        "guid": 9013,
        "world_guid": world_guid,
        "entry": 999013,
        "map": 530,
        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "original_type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "display_id": 360,
        "x": 1.0,
        "y": 2.0,
        "z": 3.0,
        "orientation": 0.5,
        "client_driven_transport_animation": True,
        "client_animation_base_map": 530,
        "client_animation_base_x": 1.0,
        "client_animation_base_y": 2.0,
        "client_animation_base_z": 3.0,
        "client_animation_base_orientation": 0.5,
    }

    monkeypatch.setattr(
        gameobjects.EncoderHandler,
        "encode_packet",
        lambda _name, payload: payload,
    )

    def capture_fields(fields, *, mask_blocks=1):
        captured_fields.clear()
        captured_fields.update(fields)
        return (b"\x00" * (int(mask_blocks) * 4), b"")

    monkeypatch.setattr(gameobjects, "_build_fixed_u32_field_block", capture_fields)

    payload = gameobjects._build_gameobject_update_payload(
        map_id=530,
        entry=entry,
        realm_id=1,
    )

    assert payload["map_id"] == 530
    assert payload["stationary_x"] == 1.0
    assert payload["stationary_y"] == 2.0
    assert payload["stationary_z"] == 3.0
    assert payload["stationary_orientation"] == 0.5
    assert payload["movement_block_uint32"] == 4321
    dynamic_flags = captured_fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS]
    assert dynamic_flags == (28317 << 16)


def test_cached_transport_entry_keeps_database_position_when_runtime_missing():
    _reset_transport_states()
    entry = {
        "guid": 110004,
        "world_guid": 0xF120000000000A04,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "x": 10.0,
        "y": 20.0,
        "z": 5.0,
        "orientation": 1.25,
        "transport_period": 2000,
    }

    moved = transport_runtime.cached_transport_runtime_entry(
        SimpleNamespace(map_id=1, x=10.0, y=20.0, z=5.0),
        entry,
    )

    assert (moved["x"], moved["y"], moved["z"]) == (10.0, 20.0, 5.0)
    assert moved["orientation"] == 1.25
    assert moved["_transport_create_source_path"] == "database"
    assert moved["_transport_runtime_state_found"] is False


def test_cross_map_lifecycle_despawns_source_and_spawns_destination(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        transport_runtime,
        "_build_gameobject_update_payload",
        lambda **kwargs: b"create:%016X" % int(kwargs["entry"]["world_guid"]),
    )
    monkeypatch.setattr(
        transport_runtime,
        "make_update_object_response",
        lambda payload: ("SMSG_UPDATE_OBJECT", payload),
    )

    base_guid = 77
    source_guid = int(
        transport_runtime.MoTransportGuid.from_spawn_guid(
            transport_runtime._same_map_transport_spawn_guid(base_guid, map_id=1)
        )
    )
    destination_guid = int(
        transport_runtime.MoTransportGuid.from_spawn_guid(
            transport_runtime._same_map_transport_spawn_guid(base_guid, map_id=0)
        )
    )
    route = [
        (1, 10.0, 20.0, 5.0, 0.0, 0),
        (0, 100.0, 200.0, 10.0, 0.0, 1000),
        (0, 150.0, 200.0, 10.0, 0.0, 2000),
    ]
    base_entry = {
        "transport_db_guid": base_guid,
        "entry": 20808,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": route,
        "transport_period": 2000,
        "world_db_transport": True,
        "use_transport_guid": True,
    }
    source_entry = {
        **base_entry,
        "guid": transport_runtime._same_map_transport_spawn_guid(base_guid, map_id=1),
        "world_guid": source_guid,
        "map": 1,
        "map_id": 1,
        "home_map": 1,
    }
    destination_entry = {
        **base_entry,
        "guid": transport_runtime._same_map_transport_spawn_guid(base_guid, map_id=0),
        "world_guid": destination_guid,
        "map": 0,
        "map_id": 0,
        "home_map": 0,
    }
    manager = transport_runtime.get_world_transport_manager()
    assert manager.register_transport(source_entry, source="test") is not None
    assert manager.register_transport(destination_entry, source="test") is not None
    for world_guid, state in list(transport_runtime._runtime_transport_states().items()):
        transport_runtime.get_movement_manager().tick_instance(
            world_guid,
            server_time_ms=12000,
        )
        transport_runtime._commit_transport_state_from_movement_cache(state)

    session = SimpleNamespace(
        char_guid=44,
        gameobjects_visible=True,
        map_id=0,
        x=100.0,
        y=200.0,
        z=10.0,
        realm_id=1,
        loaded_gameobjects={source_guid},
        loaded_transport_entries={source_guid: dict(source_entry)},
    )
    loaded_entries = session.loaded_transport_entries

    responses = transport_runtime._build_visible_transport_updates(
        session,
        loaded_entries,
        force=True,
        context="test_lifecycle",
    )

    assert source_guid not in loaded_entries
    assert source_guid not in session.loaded_gameobjects
    assert destination_guid in loaded_entries
    assert destination_guid in session.loaded_gameobjects
    assert ("SMSG_UPDATE_OBJECT", b"create:%016X" % destination_guid) in responses


def test_runtime_snapshot_uses_authoritative_transport_transform(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 0.0)
    world_guid = 0xF120000000000A03
    entry = {
        "guid": 110003,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 2.0, 0),
            (1, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    transport_runtime.get_movement_manager().attach_passenger(
        world_guid,
        42,
        source_map=1,
    )
    transport_runtime.get_movement_manager().tick_instance(world_guid, server_time_ms=1500)
    transport_runtime._commit_transport_state_from_movement_cache(state)

    row = transport_runtime.runtime_transport_snapshot_rows([(world_guid, state)])[0]

    assert row["phase_ms"] == 1500
    assert row["x"] == 0.0
    assert row["y"] == 0.0
    assert row["z"] == 0.0
    assert row["node_index"] == 0
    assert row["next_node_index"] == 1
    assert row["lifecycle_state"] == "DOCKED"
    assert row["visibility_state"] == "WAITING"
    assert row["event"] == "station"
    assert row["passenger_count"] == 1


def test_runtime_snapshot_reports_runtime_lifecycle_metadata(monkeypatch):
    _reset_transport_states()
    entry = _loaded_mo_transport_entry(world_guid=0x1FC0000000018702)
    state = _install_runtime_update_test_transport(monkeypatch, entry)
    movement_state = transport_runtime.get_movement_manager().get_state(int(state.guid))
    if movement_state is not None:
        movement_state.lifecycle_state = transport_runtime.TRANSPORT_STATE_ACTIVE
        movement_state.visibility_state = "ACTIVE"
        movement_state.last_event = ""
        movement_state.transfer_active = False
        movement_state.transfer_destination_map = None
    state.lifecycle_state = transport_runtime.TRANSPORT_STATE_TRANSFER_PENDING
    state.visibility_state = "TRANSFERRING"
    state.last_event = "transfer"
    state.transfer_active = True
    state.transfer_destination_map = 0
    state.passengers = {
        42: transport_runtime.PassengerAttachment(passenger_id=42),
    }
    state.pending_transfers = {
        43: transport_runtime.PassengerTransferState(
            passenger_id=43,
            source_instance_id=int(state.guid),
            destination_instance_id=int(state.guid) + 1,
            target_map_id=0,
        ),
    }

    row = transport_runtime.runtime_transport_snapshot_rows([(int(state.guid), state)])[0]

    assert row["lifecycle_state"] == transport_runtime.TRANSPORT_STATE_TRANSFER_PENDING
    assert row["visibility_state"] == "TRANSFERRING"
    assert row["event"] == "transfer"
    assert row["transfer_active"] is True
    assert row["transfer_destination_map"] == 0
    assert row["passenger_count"] == 1
    assert row["pending_transfer_count"] == 1


def test_bootstrap_transport_entry_prefers_authoritative_runtime_guid(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 12.0)
    canonical_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    clone_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100007))
    route = [
        transport_runtime.TransportRouteNode(1, 0.0, 0.0, 0.0, 0.0, 0),
        transport_runtime.TransportRouteNode(1, 100.0, 0.0, 0.0, 0.0, 1000),
    ]
    clone_entry = {
        "guid": 100007,
        "world_guid": clone_guid,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": route,
        "transport_period": 1000,
        "use_transport_guid": True,
    }
    transport_runtime._runtime_transport_states()[canonical_guid] = transport_runtime.RuntimeTransportState(
        guid=canonical_guid,
        entry=20808,
        spawn_guid=7,
        display_id=3015,
        route=route,
        node_index=0,
        x=50.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=1,
        path_progress_ms=500.0,
        timed_route=True,
        route_period_ms=1000,
        affinity_map_id=1,
    )
    transport_runtime._runtime_transport_states()[clone_guid] = transport_runtime.RuntimeTransportState(
        guid=clone_guid,
        entry=20808,
        spawn_guid=100007,
        display_id=3015,
        route=route,
        node_index=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=1,
        path_progress_ms=0.0,
        timed_route=True,
        route_period_ms=1000,
        affinity_map_id=1,
    )

    session = SimpleNamespace(map_id=1, x=50.0, y=0.0, z=0.0)
    moved_entry = transport_runtime.cached_transport_runtime_entry(session, clone_entry)

    assert moved_entry["world_guid"] == canonical_guid
    assert moved_entry["x"] == 50.0
    assert moved_entry["y"] == 0.0
    assert moved_entry["transport_path_progress"] == 500


def test_movement_manager_emits_spawn_and_despawn_events(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 10.0)
    entry = {
        "guid": 100779,
        "world_guid": 0xF120000000000779,
        "entry": 20808,
        "map": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "runtime_route": [
            (1, 0.0, 0.0, 0.0, 0.0, 0),
            (1, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }

    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    manager = transport_runtime.get_movement_manager()

    events = manager.latest_events(int(entry["world_guid"]))
    assert events[0].event_type == MovementLifecycleEventType.SPAWN

    manager.unregister_instance(int(entry["world_guid"]))
    events = manager.latest_events(int(entry["world_guid"]))
    assert events[-1].event_type == MovementLifecycleEventType.DESPAWN


def test_transport_manager_attach_requires_same_authoritative_map():
    _reset_transport_states()
    manager = transport_runtime.get_world_transport_manager()
    state = transport_runtime.RuntimeTransportState(
        guid=0xF120000000000779,
        entry=20808,
        spawn_guid=100779,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(1, 0.0, 0.0, 0.0, 0.0, 0),
            transport_runtime.TransportRouteNode(1, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        node_index=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=1,
        timed_route=True,
        route_period_ms=1000,
        shared_clock_key="world-db-transport:7",
    )
    transport_runtime._runtime_transport_states()[state.guid] = state
    transport_runtime._ensure_movement_instance_for_state(state)
    transport_runtime._commit_transport_state_from_movement_cache(state)

    assert manager.can_attach(SimpleNamespace(char_guid=1, map_id=1), state.guid) is True
    assert manager.can_attach(SimpleNamespace(char_guid=1, map_id=0), state.guid) is False












def test_unknown_static_gameobject_attachment_is_rejected():
    _reset_transport_states()
    world_guid = 0xF11000000007A123
    session = SimpleNamespace(
        char_guid=16,
        map_id=369,
        loaded_gameobjects=set(),
        loaded_gameobject_entries={},
    )

    assert transport_runtime.can_attach_transport(session, world_guid) is False




def _loaded_canonical_world_db_transport_after_map_change(
    monkeypatch,
    *,
    entry_id: int,
    transport_db_guid: int,
):
    _reset_transport_states()
    monkeypatch.setattr(
        transport_runtime,
        "_sync_transport_state_from_movement_cache",
        lambda _state: None,
    )

    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(transport_db_guid))
    entry = {
        "guid": transport_db_guid,
        "transport_db_guid": transport_db_guid,
        "world_guid": world_guid,
        "entry": entry_id,
        "map": 1,
        "map_id": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "name": "Map Change Visibility",
        "use_transport_guid": True,
        "world_db_transport": True,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        "shared_route_clock_key": f"world-db-transport:{transport_db_guid}",
        "transport_period": 1000,
    }
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=entry_id,
        spawn_guid=transport_db_guid,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(1, 10.0, 20.0, 5.0, 0.0, 0),
            transport_runtime.TransportRouteNode(0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        node_index=1,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.25,
        map_id=0,
        last_sent_x=100.0,
        last_sent_y=200.0,
        last_sent_z=10.0,
        last_sent_map_id=0,
        path_progress_ms=1000,
        timed_route=True,
        route_period_ms=1000,
        shared_clock_key=f"world-db-transport:{transport_db_guid}",
        transport_db_guid=transport_db_guid,
        world_db_transport=True,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        gameobjects_visible=True,
        map_id=1,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        loaded_gameobjects={world_guid},
        loaded_transport_entries={world_guid: dict(entry)},
    )
    return session, entry, state, world_guid


def test_20808_map_change_invalidates_old_map_loaded_transport(monkeypatch):
    session, _entry, _state, world_guid = _loaded_canonical_world_db_transport_after_map_change(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in responses] == ["SMSG_UPDATE_OBJECT"]
    assert _payload_update_type(responses[0]) == 3
    assert world_guid not in session.loaded_gameobjects
    assert world_guid not in session.loaded_transport_entries


def test_164871_map_change_invalidates_old_map_loaded_transport(monkeypatch):
    session, _entry, _state, world_guid = _loaded_canonical_world_db_transport_after_map_change(
        monkeypatch,
        entry_id=164871,
        transport_db_guid=6,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in responses] == ["SMSG_UPDATE_OBJECT"]
    assert _payload_update_type(responses[0]) == 3
    assert world_guid not in session.loaded_gameobjects
    assert world_guid not in session.loaded_transport_entries


def test_transport_map_change_invalidation_is_idempotent(monkeypatch):
    session, _entry, _state, world_guid = _loaded_canonical_world_db_transport_after_map_change(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
    )

    first = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )
    second = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert len(first) == 1
    assert _payload_update_type(first[0]) == 3
    assert second == []
    assert world_guid not in session.loaded_gameobjects
    assert world_guid not in session.loaded_transport_entries


def test_transport_new_map_visibility_can_create_after_map_change(monkeypatch):
    old_session, entry, state, world_guid = _loaded_canonical_world_db_transport_after_map_change(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
    )
    new_session = SimpleNamespace(
        char_guid=2,
        realm_id=1,
        gameobjects_visible=True,
        map_id=0,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.0,
        loaded_gameobjects=set(),
        loaded_transport_entries={world_guid: dict(entry)},
    )
    state.last_sent_map_id = int(state.map_id)

    responses = transport_runtime._build_visible_transport_updates(
        new_session,
        new_session.loaded_transport_entries,
        force=True,
    )

    assert old_session.map_id == 1
    assert [name for name, _payload in responses] == ["SMSG_UPDATE_OBJECT"]
    assert _payload_update_type(responses[0]) == 1
    assert world_guid in new_session.loaded_gameobjects
    assert world_guid in new_session.loaded_transport_entries


def _transport_boundary_transfer_session(
    monkeypatch,
    *,
    source_map: int,
    destination_map: int,
    passenger: bool,
    transfer_active: bool = True,
):
    _reset_transport_states()
    monkeypatch.setattr(
        transport_runtime,
        "_sync_transport_state_from_movement_cache",
        lambda _state: None,
    )
    monkeypatch.setattr(movement, "_is_teleporting", lambda _session: False)
    monkeypatch.setattr(movement, "_clear_loaded_world_objects_for_transfer", lambda _session: [])
    monkeypatch.setattr(
        movement,
        "_capture_persist_position_from_session",
        lambda _session: None,
    )
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_post_teleport_multiplayer_resync", lambda *args, **kwargs: [])

    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    entry = {
        "guid": 7,
        "transport_db_guid": 7,
        "world_guid": world_guid,
        "entry": 20808,
        "map": source_map,
        "map_id": source_map,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "use_transport_guid": True,
        "world_db_transport": True,
        "runtime_route": [
            (source_map, 10.0, 20.0, 5.0, 0.0, 0),
            (destination_map, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        "shared_route_clock_key": "world-db-transport:7",
        "transport_period": 1000,
    }
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=7,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(source_map, 10.0, 20.0, 5.0, 0.0, 0),
            transport_runtime.TransportRouteNode(destination_map, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        node_index=1,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.25,
        map_id=destination_map,
        path_progress_ms=1000,
        timed_route=True,
        route_period_ms=1000,
        shared_clock_key="world-db-transport:7",
        transfer_active=transfer_active,
        transfer_destination_map=destination_map,
        transport_db_guid=7,
        world_db_transport=True,
    )
    transport_runtime._runtime_transport_states()[world_guid] = state
    movement_state = SimpleNamespace(
        has_transport_data=passenger,
        transport_guid=world_guid if passenger else 0,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.5,
        transport_time=1000,
        transport_time2=0,
        transport_time3=0,
        transport_seat=-1,
        transport_vehicle_id=0,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        pitch=0.0,
        last_valid_orientation=0.0,
    )
    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        gameobjects_visible=True,
        map_id=source_map,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        movement_state=movement_state,
        loaded_gameobjects={world_guid},
        loaded_transport_entries={world_guid: entry},
    )
    if passenger:
        transport_runtime.attach_transport_passenger(
            world_guid,
            1,
            local_x=2.0,
            local_y=3.0,
            local_z=4.0,
            local_o=0.5,
            source_map=source_map,
        )
    return session, state, world_guid


def _add_boundary_event(state, *, destination_map: int, phase_ms: int = 1000) -> None:
    state.lifecycle_events = (
        MovementLifecycleEvent(
            event_type=MovementLifecycleEventType.TRANSFER_BEGIN,
            instance_id=int(state.guid),
            phase_ms=int(phase_ms),
            node_index=int(getattr(state, "node_index", 0) or 0),
            target_map_id=int(destination_map),
        ),
    )


def test_transport_boundary_event_worldports_attached_passenger_once(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    _add_boundary_event(state, destination_map=0)
    sent: list[tuple[str, bytes]] = []
    sent_batches = []

    def capture_batch(responses):
        sent_batches.append(responses)
        sent.extend(responses)

    session.send_response = capture_batch
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is True
    assert [name for name, _payload in sent][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.transport_transfer_pending is True
    assert session.map_id == 0
    assert session.movement_state.transport_guid == world_guid
    assert session.world_transition_owner == "transport_worldport"
    assert isinstance(sent_batches[-1], PacketBatch)
    assert sent_batches[-1].transition_bound is True
    assert sent_batches[-1].transition_owner == "transport_worldport"
    assert sent_batches[-1].transition_generation == (
        session.world_transition_generation
    )
    assert session.pending_transport_transfer["world_transition_generation"] == (
        session.world_transition_generation
    )
    pending = session.pending_transport_transfer
    assert pending["destination_map"] == 0
    assert (pending["base_x"], pending["base_y"], pending["base_z"]) == (
        state.x,
        state.y,
        state.z,
    )
    assert pending["destination_entry"]["map"] == state.map_id
    assert (
        pending["destination_entry"]["x"],
        pending["destination_entry"]["y"],
        pending["destination_entry"]["z"],
    ) == (state.x, state.y, state.z)
    boundary_key = tuple(
        session.pending_transport_transfer["boundary_event_key"]
    )
    assert boundary_key in state.active_boundary_events
    assert boundary_key not in state.handled_boundary_events

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is False
    assert [name for name, _payload in sent].count("SMSG_TRANSFER_PENDING") == 1


def test_transport_boundary_starts_again_after_bootstrap_completion(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    _add_boundary_event(state, destination_map=0, phase_ms=1000)
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is True
    boundary_key = tuple(
        session.pending_transport_transfer["boundary_event_key"]
    )
    assert boundary_key in state.active_boundary_events
    assert boundary_key not in state.handled_boundary_events
    assert movement.complete_pending_transport_transfer(session) is True
    assert boundary_key not in state.active_boundary_events
    assert boundary_key in state.handled_boundary_events
    assert session.transport_transfer_pending is False
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_ATTACHED
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None

    state.map_id = 1
    _add_boundary_event(state, destination_map=1, phase_ms=2000)
    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=0,
    ) is True
    assert [name for name, _payload in sent].count("SMSG_TRANSFER_PENDING") == 2
    assert [name for name, _payload in sent].count("SMSG_NEW_WORLD") == 2


def test_failed_boundary_handling_restores_event_for_retry(monkeypatch):
    _session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    _add_boundary_event(state, destination_map=0, phase_ms=1000)
    event = state.lifecycle_events[0]
    event_key = transport_runtime._boundary_event_key(event)
    state.active_boundary_events.add(event_key)
    pending = {
        "source_guid": world_guid,
        "destination_guid": world_guid,
        "boundary_event_key": event_key,
    }

    assert transport_runtime.restore_transport_boundary_event(
        pending,
        reason="safe_fallback_rejected",
    ) is True
    assert event_key not in state.active_boundary_events
    assert event_key not in state.handled_boundary_events
    assert transport_runtime._latest_unhandled_boundary_event(state) is event


def test_transport_boundary_owns_one_transition_for_all_attached_passengers(monkeypatch):
    first, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    second = copy.deepcopy(first)
    second.char_guid = 2
    second.x = -50000.0
    second.y = 50000.0
    transport_runtime.attach_transport_passenger(
        world_guid,
        2,
        local_x=-20.0,
        local_y=18.0,
        local_z=7.0,
        local_o=1.0,
        source_map=1,
    )
    _add_boundary_event(state, destination_map=0)
    sent = {1: [], 2: []}
    first.send_response = lambda responses: sent[1].extend(responses)
    second.send_response = lambda responses: sent[2].extend(responses)
    sessions = {1: first, 2: second}
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: sessions.get(int(passenger_id)),
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is True
    assert [name for name, _payload in sent[1]][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert [name for name, _payload in sent[2]][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert first.pending_transport_transfer["transfer_id"] == (
        second.pending_transport_transfer["transfer_id"]
    )


@pytest.mark.parametrize(
    ("local_x", "local_y", "local_z"),
    ((0.0, 0.0, 0.0), (25.0, -14.0, 8.0), (-31.0, 19.0, 12.0)),
)
def test_transport_boundary_participation_depends_only_on_attachment(
    monkeypatch,
    local_x,
    local_y,
    local_z,
):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    state.passengers[1] = transport_runtime.PassengerAttachment(
        passenger_id=1,
        local_x=local_x,
        local_y=local_y,
        local_z=local_z,
        local_o=0.25,
        source_map=1,
    )
    session.x = 100000.0
    session.y = -100000.0
    session.transport_transfer_pending = True
    session.teleport_pending = True
    session.worldport_ack_pending = True
    session.transport_attach_state = transport_runtime.ATTACH_STATE_TRANSFERRING
    _add_boundary_event(state, destination_map=0)
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is True
    assert [name for name, _payload in sent][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.pending_transport_transfer["local_x"] == local_x
    assert session.pending_transport_transfer["local_y"] == local_y
    assert session.pending_transport_transfer["local_z"] == local_z


def test_transport_boundary_adopts_legacy_manager_passenger_container(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=False,
    )
    _add_boundary_event(state, destination_map=0)
    transport_runtime._ensure_movement_instance_for_state(state)
    manager_state = transport_runtime.get_movement_manager().get_state(world_guid)
    assert manager_state is not None
    manager_state.passengers = {
        1: transport_runtime.PassengerAttachment(
            passenger_id=1,
            local_x=2.0,
            local_y=3.0,
            local_z=4.0,
            local_o=0.5,
            source_map=1,
        )
    }
    assert not (state.passengers or {})
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is True

    assert state.passengers is not None
    assert 1 in state.passengers
    assert manager_state.passengers == {}
    assert [name for name, _payload in sent][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.transport_transfer_pending is True


def test_runtime_map_transition_triggers_boundary_worldport_once(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime._trigger_boundary_on_runtime_map_transition(
        state,
        previous_transform=(1, 10.0, 20.0, 5.0, 0.0),
    ) is True

    assert [name for name, _payload in sent][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.transport_transfer_pending is True
    assert session.map_id == 0
    assert session.movement_state.transport_guid == world_guid

    assert transport_runtime._trigger_boundary_on_runtime_map_transition(
        state,
        previous_transform=(1, 10.0, 20.0, 5.0, 0.0),
    ) is False
    assert [name for name, _payload in sent].count("SMSG_TRANSFER_PENDING") == 1


def test_runtime_same_map_movement_does_not_trigger_boundary(monkeypatch):
    _session, state, _world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=1,
        passenger=True,
    )
    called = False

    def fail_boundary(*_args, **_kwargs):
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(
        transport_runtime,
        "transport_crossed_map_boundary",
        fail_boundary,
    )

    assert transport_runtime._trigger_boundary_on_runtime_map_transition(
        state,
        previous_transform=(1, 10.0, 20.0, 5.0, 0.0),
    ) is False
    assert called is False


def test_runtime_boundary_visibility_cleanup_excludes_passenger_before_worldport(monkeypatch):
    session, state, _world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )

    removed_visibility_for_passenger = False

    def record_visibility(**_kwargs):
        nonlocal removed_visibility_for_passenger
        passenger_ids = set(_kwargs.get("passenger_ids", set()) or set())
        removed_visibility_for_passenger = 1 not in passenger_ids
        return 1

    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        record_visibility,
    )
    assert transport_runtime._trigger_boundary_on_runtime_map_transition(
        state,
        previous_transform=(1, 10.0, 20.0, 5.0, 0.0),
    ) is True

    assert removed_visibility_for_passenger is False
    assert [name for name, _payload in sent][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]


def test_visible_transport_updates_do_not_initiate_cross_map_transfer(monkeypatch):
    session, _state, _world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert not any(name == "SMSG_TRANSFER_PENDING" for name, _payload in responses)
    assert not any(name == "SMSG_NEW_WORLD" for name, _payload in responses)
    assert not bool(getattr(session, "transport_transfer_pending", False))


def test_visibility_cannot_commit_transport_boundary_state(monkeypatch):
    _reset_transport_states()
    entry, state, _transport = _registered_runtime_transport()
    original = (
        int(state.map_id),
        float(state.x),
        float(state.y),
        float(state.z),
        float(state.orientation),
    )
    monkeypatch.setattr(
        transport_runtime,
        "_commit_transport_dynamic_state",
        lambda _state: pytest.fail("visibility committed movement-cache state"),
    )
    session = SimpleNamespace(
        char_guid=30,
        gameobjects_visible=True,
        map_id=int(state.map_id),
        x=float(state.x),
        y=float(state.y),
        z=float(state.z),
        orientation=float(state.orientation),
        realm_id=1,
        loaded_gameobjects=set(),
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        {int(state.guid): dict(entry)},
        force=True,
    )

    assert responses
    assert (
        int(state.map_id),
        float(state.x),
        float(state.y),
        float(state.z),
        float(state.orientation),
    ) == original


def test_transport_owner_tick_alone_starts_boundary_worldport(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    state.map_id = 1
    _add_boundary_event(state, destination_map=0)
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(
        transport_runtime.get_movement_manager(),
        "tick_instance",
        lambda *_args, **_kwargs: None,
    )

    def commit_boundary(committed_state):
        committed_state.map_id = 0
        committed_state.x = 100.0
        committed_state.y = 200.0
        committed_state.z = 10.0

    monkeypatch.setattr(
        transport_runtime,
        "_commit_transport_state_from_movement_cache",
        commit_boundary,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime.get_world_transport_manager()._tick_transport_state(
        world_guid,
        state,
    ) is True
    pending = session.pending_transport_transfer
    assert pending["destination_map"] == 0
    assert (pending["base_x"], pending["base_y"], pending["base_z"]) == (
        100.0,
        200.0,
        10.0,
    )
    assert [name for name, _payload in sent][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]


def test_20808_boundary_active_pending_still_blocks_duplicate_transfer(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
        transfer_active=False,
    )
    session.transport_transfer_pending = True
    session.teleport_pending = True
    session.worldport_ack_pending = True
    session.pending_transport_transfer = {
        "source_guid": world_guid,
        "destination_guid": world_guid,
        "source_map": 1,
        "destination_map": 0,
    }

    responses = movement._maybe_start_transport_route_transfer(
        session,
        "MSG_MOVE_HEARTBEAT",
        forced_destination_map=1,
    )

    assert responses == []
    assert session.transport_transfer_pending is True
    assert session.pending_transport_transfer["destination_map"] == 0


def test_movement_after_boundary_cannot_wake_or_restart_worldport(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    _add_boundary_event(state, destination_map=0)
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is True
    movement._store_transport_state_from_parsed(
        session,
        "MSG_MOVE_HEARTBEAT",
        {
            "has_transport_data": True,
            "transport_guid": world_guid,
            "transport_x": 20.0,
            "transport_y": -15.0,
            "transport_z": 8.0,
            "transport_orientation": 0.75,
        },
    )
    visibility_responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert movement._maybe_start_transport_route_transfer(
        session,
        "MSG_MOVE_HEARTBEAT",
    ) == []
    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is False
    assert not any(
        opcode in {"SMSG_TRANSFER_PENDING", "SMSG_NEW_WORLD"}
        for opcode, _payload in visibility_responses
    )
    assert [name for name, _payload in sent].count("SMSG_TRANSFER_PENDING") == 1
    assert [name for name, _payload in sent].count("SMSG_NEW_WORLD") == 1


def test_20808_client_clear_cannot_half_cancel_pending_transport_transition(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
    )
    session.transport_transfer_pending = True
    session.teleport_pending = False
    session.worldport_ack_pending = False
    session.pending_transport_transfer = {
        "source_guid": world_guid,
        "destination_guid": world_guid,
        "source_map": 1,
        "destination_map": 0,
    }

    movement._store_transport_state_from_parsed(
        session,
        "MSG_MOVE_HEARTBEAT",
        {"has_transport_data": False},
    )

    assert session.transport_transfer_pending is True
    assert session.pending_transport_transfer is not None
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None

    movement._store_transport_state_from_parsed(
        session,
        "MSG_MOVE_HEARTBEAT",
        {"has_transport_data": False},
    )

    assert session.transport_transfer_pending is True
    assert session.pending_transport_transfer is not None
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None


def test_missing_transport_metadata_during_boundary_cannot_detach_passenger(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    session.transport_transfer_pending = True
    session.teleport_pending = True
    session.worldport_ack_pending = True
    session.pending_transport_transfer = {
        "source_guid": world_guid,
        "destination_guid": world_guid,
        "source_map": 1,
        "destination_map": 0,
    }

    for _index in range(3):
        movement._store_transport_state_from_parsed(
            session,
            "MSG_MOVE_HEARTBEAT",
            {"has_transport_data": False},
        )

    assert session.transport_transfer_pending is True
    assert session.pending_transport_transfer is not None
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None


def test_20808_client_clear_preserves_active_transport_transfer_pending(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
    )
    session.transport_transfer_pending = True
    session.teleport_pending = False
    session.worldport_ack_pending = True
    session.pending_transport_transfer = {
        "source_guid": world_guid,
        "destination_guid": world_guid,
        "source_map": 0,
        "destination_map": 1,
    }

    movement._store_transport_state_from_parsed(
        session,
        "MSG_MOVE_HEARTBEAT",
        {"has_transport_data": False},
    )

    assert session.transport_transfer_pending is True
    assert session.pending_transport_transfer["destination_map"] == 1
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None


def test_one_packet_without_transport_metadata_does_not_detach(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
    )

    movement._store_transport_state_from_parsed(
        session,
        "MSG_MOVE_HEARTBEAT",
        {"has_transport_data": False},
    )

    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None


def test_repeated_missing_transport_metadata_confirms_detach(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
    )

    for _index in range(2):
        movement._store_transport_state_from_parsed(
            session,
            "MSG_MOVE_HEARTBEAT",
            {"has_transport_data": False},
        )

    assert session.movement_state.has_transport_data is False
    assert session.movement_state.transport_guid == 0
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is None


def test_attached_player_parsed_transport_yes_preserves_attachment(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
    )

    movement._store_transport_state_from_parsed(
        session,
        "MSG_MOVE_HEARTBEAT",
        {
            "has_transport_data": True,
            "transport_guid": world_guid,
            "transport_x": 5.0,
            "transport_y": 6.0,
            "transport_z": 7.0,
            "transport_orientation": 0.75,
            "transport_time": 100,
            "transport_time2": 0,
            "transport_time3": 0,
            "transport_seat": -1,
            "transport_vehicle_id": 0,
        },
    )

    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None


def test_attached_player_no_skyfire_parse_preserves_attachment(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
    )
    monkeypatch.setattr(movement, "_parse_skyfire_flying_movement_info", lambda *_args, **_kwargs: None)

    movement._record_movement_packet_state(
        session,
        "MSG_MOVE_START_STRAFE_RIGHT",
        b"\x00" * 8,
    )

    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None


def test_repeated_no_skyfire_parse_still_worldports_at_boundary(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
    )
    _add_boundary_event(state, destination_map=1)
    sent: list[tuple[str, bytes]] = []
    session.send_response = lambda responses: sent.extend(responses)
    monkeypatch.setattr(movement, "_parse_skyfire_flying_movement_info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    for _ in range(3):
        movement._record_movement_packet_state(
            session,
            "MSG_MOVE_START_STRAFE_RIGHT",
            b"\x00" * 8,
        )

    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None
    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=0,
    ) is True
    assert [name for name, _payload in sent][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=0,
    ) is False
    assert [name for name, _payload in sent].count("SMSG_TRANSFER_PENDING") == 1


def test_unattached_player_no_skyfire_parse_does_not_attach(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=False,
    )
    monkeypatch.setattr(movement, "_parse_skyfire_flying_movement_info", lambda *_args, **_kwargs: None)

    movement._record_movement_packet_state(
        session,
        "MSG_MOVE_START_STRAFE_RIGHT",
        b"\x00" * 8,
    )

    assert session.movement_state.has_transport_data is False
    assert session.movement_state.transport_guid == 0
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is None


def test_20808_boundary_passenger_reattaches_same_guid_after_ack(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    _add_boundary_event(state, destination_map=0)
    session.send_response = lambda _responses: None
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda passenger_id: session if int(passenger_id) == 1 else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_remove_previous_map_transport_visibility",
        lambda **_kwargs: 1,
    )

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is True
    session.worldport_ack_pending = True

    movement.handle_move_worldport_ack(session, SimpleNamespace())

    assert session.transport_transfer_pending is False
    assert session.movement_state.transport_guid == world_guid
    assert (
        transport_runtime.transport_passenger_attachment(world_guid, 1)
        is not None
    )


def test_visibility_does_not_wake_boundary_when_movement_metadata_is_missing(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    session.movement_state.has_transport_data = False
    session.movement_state.transport_guid = 0
    session.movement_state.transport_x = 0.0
    session.movement_state.transport_y = 0.0
    session.movement_state.transport_z = 0.0
    session.movement_state.transport_orientation = 0.0

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert not any(name == "SMSG_TRANSFER_PENDING" for name, _payload in responses)
    assert not any(name == "SMSG_NEW_WORLD" for name, _payload in responses)
    assert not bool(getattr(session, "transport_transfer_pending", False))
    assert session.movement_state.transport_guid == 0
    assert session.movement_state.has_transport_data is False
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None


def test_20808_boundary_non_passenger_receives_out_of_range(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=False,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in responses] == ["SMSG_UPDATE_OBJECT"]
    assert _payload_update_type(responses[0]) == 3
    assert world_guid not in session.loaded_gameobjects
    assert world_guid not in session.loaded_transport_entries


def _run_canonical_transport_transfer(
    monkeypatch,
    *,
    entry_id: int,
    transport_db_guid: int,
    source_map: int,
    destination_map: int,
    runtime_map: int | None = None,
    runtime_base: tuple[float, float, float, float] = (100.0, 200.0, 10.0, 0.25),
    route_base: tuple[float, float, float] = (100.0, 200.0, 10.0),
    expected_base_source: str | None = None,
    freeze_runtime_state: bool = False,
    runtime_transfer_metadata: bool = False,
    completion_via_loading_screen: bool = False,
):
    _reset_transport_states()
    now = 500.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)
    monkeypatch.setattr(movement, "_is_teleporting", lambda _session: False)

    def _clear_loaded_for_transfer(_session):
        loaded_gameobjects = getattr(_session, "loaded_gameobjects", None)
        if isinstance(loaded_gameobjects, set):
            loaded_gameobjects.clear()
        loaded_transport_entries = getattr(_session, "loaded_transport_entries", None)
        if isinstance(loaded_transport_entries, dict):
            loaded_transport_entries.clear()
        return []

    monkeypatch.setattr(movement, "_clear_loaded_world_objects_for_transfer", _clear_loaded_for_transfer)
    monkeypatch.setattr(
        movement,
        "_capture_persist_position_from_session",
        lambda _session: None,
    )
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_post_teleport_multiplayer_resync", lambda *args, **kwargs: [])

    source_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(transport_db_guid))
    runtime_x, runtime_y, runtime_z, runtime_o = runtime_base
    route_x, route_y, route_z = route_base
    route = [
        (source_map, 10.0, 20.0, 5.0, 0.0, 0),
        (destination_map, route_x, route_y, route_z, 0.0, 1000),
    ]
    entry = {
        "guid": transport_db_guid,
        "transport_db_guid": transport_db_guid,
        "world_guid": source_guid,
        "entry": entry_id,
        "map": source_map,
        "map_id": source_map,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "name": "Canonical Transfer",
        "use_transport_guid": True,
        "world_db_transport": True,
        "runtime_route": route,
        "shared_route_clock_key": f"world-db-transport:{transport_db_guid}",
        "transport_period": 1000,
    }
    state = transport_runtime.RuntimeTransportState(
        guid=source_guid,
        entry=entry_id,
        spawn_guid=transport_db_guid,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(source_map, 10.0, 20.0, 5.0, 0.0, 0),
            transport_runtime.TransportRouteNode(destination_map, route_x, route_y, route_z, 0.0, 1000),
        ],
        node_index=1,
        x=runtime_x,
        y=runtime_y,
        z=runtime_z,
        orientation=runtime_o,
        map_id=destination_map if runtime_map is None else runtime_map,
        path_progress_ms=1000,
        timed_route=True,
        route_period_ms=1000,
        shared_clock_key=f"world-db-transport:{transport_db_guid}",
        transport_db_guid=transport_db_guid,
        world_db_transport=True,
    )
    transport_runtime._runtime_transport_states()[source_guid] = state
    if freeze_runtime_state:
        monkeypatch.setattr(
            transport_runtime,
            "_sync_transport_state_from_movement_cache",
            lambda _state: None,
        )
        monkeypatch.setattr(
            transport_runtime,
            "transport_transfer_destination_map_for_guid",
            lambda _world_guid: int(destination_map),
        )

    movement_state = SimpleNamespace(
        has_transport_data=True,
        transport_guid=source_guid,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.5,
        transport_time=1000,
        transport_time2=0,
        transport_time3=0,
        transport_seat=-1,
        transport_vehicle_id=0,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        pitch=0.0,
        last_valid_orientation=0.0,
    )
    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        map_id=source_map,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        movement_state=movement_state,
        loaded_gameobjects={source_guid},
        loaded_transport_entries={source_guid: entry},
    )
    transport_runtime._ensure_movement_instance_for_state(state)
    if runtime_transfer_metadata:
        state.transfer_active = True
        state.transfer_destination_map = int(destination_map)
        manager_state = transport_runtime.get_movement_manager().get_state(source_guid)
        assert manager_state is not None
        manager_state.transfer_active = False
        manager_state.transfer_destination_map = None
        manager_state.lifecycle_events = ()
    transport_runtime.get_movement_manager().attach_passenger(
        source_guid,
        1,
        local_x=2.0,
        local_y=3.0,
        local_z=4.0,
        local_o=0.5,
        source_map=source_map,
    )
    linked_destination_guid = transport_runtime.linked_transport_world_guid(
        entry,
        map_id=destination_map,
    )
    if linked_destination_guid != source_guid:
        assert transport_runtime.runtime_transport_state_for_guid(linked_destination_guid) is None

    responses = movement._maybe_start_transport_route_transfer(session, "MSG_MOVE_HEARTBEAT")

    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.worldport_ack_pending is True
    assert session.map_id == destination_map
    assert movement_state.transport_guid == source_guid
    assert movement_state.transport_x == 2.0
    pending = session.pending_transport_transfer
    if expected_base_source is not None:
        assert pending["base_source"] == expected_base_source
    if expected_base_source == "runtime_state":
        assert (
            pending["base_x"],
            pending["base_y"],
            pending["base_z"],
            pending["base_o"],
        ) == runtime_base
    assert session.x == pending["final_x"]
    assert session.y == pending["final_y"]
    assert session.z == pending["final_z"]
    assert session.pending_transport_transfer["source_guid"] == source_guid
    assert session.pending_transport_transfer["destination_guid"] == source_guid
    if linked_destination_guid != source_guid:
        assert transport_runtime.runtime_transport_state_for_guid(linked_destination_guid) is None

    if completion_via_loading_screen:
        assert movement.queue_pending_transport_transfer_post_bootstrap(session) is True
        post_bootstrap_responses = (
            movement.complete_queued_post_bootstrap_transport_reattach(session)
        )
        assert "SMSG_PLAYER_MOVE" in [name for name, _payload in post_bootstrap_responses]
    else:
        movement.handle_move_worldport_ack(session, SimpleNamespace())

    assert session.transport_transfer_pending is False
    assert movement_state.has_transport_data is True
    assert movement_state.transport_guid == source_guid
    assert source_guid in session.loaded_transport_entries
    assert source_guid not in session.loaded_gameobjects
    if linked_destination_guid != source_guid:
        assert linked_destination_guid not in session.loaded_transport_entries
        assert linked_destination_guid not in session.loaded_gameobjects
        assert transport_runtime.runtime_transport_state_for_guid(linked_destination_guid) is None
    assert (
        transport_runtime.get_movement_manager().passenger_attachment(
            source_guid,
            1,
        )
        is not None
    )
    return source_guid, linked_destination_guid, session


def test_cross_map_boat_transfer_emits_correlated_diagnostics(monkeypatch):
    captured = []
    monkeypatch.setattr(
        movement.Logger,
        "info",
        lambda message, *args, **_kwargs: captured.append(message % args if args else message),
    )

    _run_canonical_transport_transfer(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
        source_map=1,
        destination_map=0,
        freeze_runtime_state=True,
    )

    transfer_id = "1-500000"
    expected_stages = (
        "start",
        "before_new_world",
        "worldport_ack",
        "verify",
        "before_post_worldport_update",
    )
    for stage in expected_stages:
        assert any(
            f"[TransportTransferDiag] {stage} transfer_id={transfer_id}" in line
            for line in captured
        ), (stage, captured)
    for event in ("transfer_begin", "worldport_ack", "reattach"):
        assert any(
            f"[TransportTransfer] {event} transfer_id={transfer_id}" in line
            for line in captured
        ), (event, captured)
    assert not any(
        f"[TransportTransfer] fallback transfer_id={transfer_id}" in line
        for line in captured
    )


def test_post_bootstrap_completes_pending_boat_transfer_without_worldport_ack(monkeypatch):
    captured = []
    monkeypatch.setattr(
        movement.Logger,
        "info",
        lambda message, *args, **_kwargs: captured.append(message % args if args else message),
    )

    source_guid, _linked_guid, session = _run_canonical_transport_transfer(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
        source_map=1,
        destination_map=0,
        runtime_base=(120.0, 230.0, 15.0, 0.75),
        freeze_runtime_state=True,
        completion_via_loading_screen=True,
    )

    assert session.pending_transport_transfer is None
    assert session.transport_transfer_pending is False
    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == source_guid
    assert (session.movement_state.transport_x, session.movement_state.transport_y) == (2.0, 3.0)
    expected_x = 120.0 + (math.cos(0.75) * 2.0 - math.sin(0.75) * 3.0)
    expected_y = 230.0 + (math.sin(0.75) * 2.0 + math.cos(0.75) * 3.0)
    assert session.x == pytest.approx(expected_x)
    assert session.y == pytest.approx(expected_y)
    assert session.z == pytest.approx(19.0)
    assert session.orientation == pytest.approx(1.25)
    assert transport_runtime.transport_passenger_attachment(source_guid, 1) is not None
    assert any("[TransportTransfer] post_bootstrap_reattach_queued" in line for line in captured)
    assert any("[TransportTransfer] post_bootstrap_reattach_attempt" in line for line in captured)
    assert any("[TransportTransfer] post_bootstrap_reattach_success" in line for line in captured)
    assert any(
        "runtime_transport_world=(120.000 230.000 15.000)" in line
        and "runtime_rotation=0.750000" in line
        and "rotated_offset=" in line
        for line in captured
    )
    assert not any("[TransportTransfer] worldport_ack" in line for line in captured)


def test_post_bootstrap_transport_queue_is_noop_without_pending_transfer():
    session = SimpleNamespace(pending_transport_transfer=None, transport_transfer_pending=False)

    assert movement.queue_pending_transport_transfer_post_bootstrap(session) is False
    assert movement.complete_queued_post_bootstrap_transport_reattach(session) == []
    assert session.pending_transport_transfer is None
    assert session.transport_transfer_pending is False


def test_post_bootstrap_clears_pending_transfer_when_transport_not_ready():
    _reset_transport_states()
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(77))
    pending = {
        "transfer_id": "1-wait",
        "destination_guid": world_guid,
        "destination_entry": {
            "entry": 20808,
            "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
            "world_db_transport": True,
            "name": "The Maiden's Fancy",
        },
    }
    session = SimpleNamespace(
        char_guid=1,
        pending_transport_transfer=pending,
        transport_transfer_pending=True,
    )

    assert movement.queue_pending_transport_transfer_post_bootstrap(session) is True
    responses = movement.complete_queued_post_bootstrap_transport_reattach(session)
    assert all(name == "SMSG_MESSAGECHAT" for name, _payload in responses)
    assert session.pending_transport_transfer is None
    assert session.transport_transfer_pending is False


def test_20808_passenger_transfer_preserves_guid_map_1_to_0(monkeypatch):
    _run_canonical_transport_transfer(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
        source_map=1,
        destination_map=0,
    )


def test_20808_transfer_worldport_uses_live_runtime_base(monkeypatch):
    _run_canonical_transport_transfer(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
        source_map=1,
        destination_map=0,
        runtime_base=(123.0, 234.0, 12.0, 0.75),
        route_base=(100.0, 200.0, 10.0),
        expected_base_source="runtime_state",
        freeze_runtime_state=True,
    )


def test_20808_transfer_route_uses_runtime_state_destination_map_zero(monkeypatch):
    _run_canonical_transport_transfer(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
        source_map=1,
        destination_map=0,
        runtime_transfer_metadata=True,
    )


def test_20808_transfer_worldport_falls_back_to_route_node(monkeypatch):
    _reset_transport_states()
    now = 520.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)
    monkeypatch.setattr(movement, "_is_teleporting", lambda _session: False)
    monkeypatch.setattr(movement, "_clear_loaded_world_objects_for_transfer", lambda _session: [])
    monkeypatch.setattr(
        movement,
        "_capture_persist_position_from_session",
        lambda _session: None,
    )
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_post_teleport_multiplayer_resync", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        transport_runtime,
        "_sync_transport_state_from_movement_cache",
        lambda _state: None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "transport_transfer_destination_map_for_guid",
        lambda _world_guid: 0,
    )

    source_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    entry = {
        "guid": 7,
        "transport_db_guid": 7,
        "world_guid": source_guid,
        "entry": 20808,
        "map": 1,
        "map_id": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "use_transport_guid": True,
        "world_db_transport": True,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        "shared_route_clock_key": "world-db-transport:7",
        "transport_period": 1000,
    }
    state = transport_runtime.RuntimeTransportState(
        guid=source_guid,
        entry=20808,
        spawn_guid=7,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(1, 10.0, 20.0, 5.0, 0.0, 0),
            transport_runtime.TransportRouteNode(0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        node_index=0,
        x=123.0,
        y=234.0,
        z=12.0,
        orientation=0.75,
        map_id=1,
        path_progress_ms=1000,
        timed_route=True,
        route_period_ms=1000,
        shared_clock_key="world-db-transport:7",
        transport_db_guid=7,
        world_db_transport=True,
    )
    transport_runtime._runtime_transport_states()[source_guid] = state
    movement_state = SimpleNamespace(
        has_transport_data=True,
        transport_guid=source_guid,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.5,
        transport_time=1000,
        transport_time2=0,
        transport_time3=0,
        transport_seat=-1,
        transport_vehicle_id=0,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        pitch=0.0,
        last_valid_orientation=0.0,
    )
    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        map_id=1,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        movement_state=movement_state,
        loaded_gameobjects={source_guid},
        loaded_transport_entries={source_guid: entry},
    )
    transport_runtime._ensure_movement_instance_for_state(state)
    transport_runtime.get_movement_manager().attach_passenger(
        source_guid,
        1,
        local_x=2.0,
        local_y=3.0,
        local_z=4.0,
        local_o=0.5,
        source_map=1,
    )

    movement._maybe_start_transport_route_transfer(session, "MSG_MOVE_HEARTBEAT")

    pending = session.pending_transport_transfer
    assert pending["base_source"] == "route_node_fallback"
    assert (pending["base_x"], pending["base_y"], pending["base_z"]) == (100.0, 200.0, 10.0)
    assert (session.x, session.y, session.z) == (102.0, 203.0, 14.0)


def test_20808_passenger_transfer_preserves_guid_map_0_to_1(monkeypatch):
    source_guid, linked_destination_guid, _session = _run_canonical_transport_transfer(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
        source_map=0,
        destination_map=1,
    )

    assert linked_destination_guid != source_guid


def test_verify_pending_boat_transfer_attachment_noop_when_already_attached(monkeypatch):
    _reset_transport_states()
    captured = []
    monkeypatch.setattr(
        movement.Logger,
        "info",
        lambda message, *args: captured.append(message % args if args else message),
    )
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    entry = {
        "guid": 7,
        "transport_db_guid": 7,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 0,
        "map_id": 0,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "name": "The Maiden's Fancy",
        "use_transport_guid": True,
        "world_db_transport": True,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (0, 120.0, 230.0, 15.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    transport_runtime._runtime_transport_states()[world_guid] = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=7,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(1, 10.0, 20.0, 5.0, 0.0, 0),
            transport_runtime.TransportRouteNode(0, 120.0, 230.0, 15.0, 0.0, 1000),
        ],
        node_index=1,
        x=120.0,
        y=230.0,
        z=15.0,
        orientation=0.75,
        map_id=0,
        path_progress_ms=1000,
        timed_route=True,
        route_period_ms=1000,
        world_db_transport=True,
        transport_db_guid=7,
    )
    transport_runtime.attach_transport_passenger(
        world_guid,
        1,
        local_x=2.0,
        local_y=3.0,
        local_z=4.0,
        local_o=0.5,
        source_map=0,
    )
    movement_state = SimpleNamespace(
        has_transport_data=True,
        transport_guid=world_guid,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.5,
        transport_time=1000,
        x=122.0,
        y=233.0,
        z=19.0,
        orientation=1.25,
    )
    session = SimpleNamespace(
        char_guid=1,
        map_id=0,
        x=122.0,
        y=233.0,
        z=19.0,
        orientation=1.25,
        movement_state=movement_state,
        loaded_transport_entries={world_guid: dict(entry)},
    )
    pending = {
        "transfer_id": "1-500000",
        "destination_guid": world_guid,
        "destination_map": 0,
        "destination_entry": dict(entry),
        "local_x": 2.0,
        "local_y": 3.0,
        "local_z": 4.0,
        "local_o": 0.5,
        "route_phase": 1000,
    }

    movement._verify_pending_boat_transfer_attachment(session, pending)

    assert session.x == 122.0
    assert session.y == 233.0
    assert session.z == 19.0
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None
    assert any(
        "[TransportTransferDiag] verify transfer_id=1-500000" in line
        and "return_reason=already_attached" in line
        and "early_return=true" in line
        and "rebase=false" in line
        for line in captured
    )


def test_cross_map_ship_diagnostics_exclude_elevators_and_identify_zeppelin():
    zeppelin = {
        "entry": 176495,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "world_db_transport": True,
        "name": "Zeppelin",
    }
    elevator = {
        "entry": 219175,
        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "world_db_transport": False,
        "name": "Orgrimmar Elevator",
    }

    assert transport_runtime.is_cross_map_zeppelin_entry(zeppelin) is True
    assert transport_runtime.is_cross_map_boat_entry(zeppelin) is False
    assert transport_runtime.is_cross_map_zeppelin_entry(elevator) is False
    assert transport_runtime.is_cross_map_boat_entry(elevator) is False


def test_verify_pending_boat_transfer_attachment_restores_missing_attachment_from_live_runtime_position(monkeypatch):
    _reset_transport_states()
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    entry = {
        "guid": 7,
        "transport_db_guid": 7,
        "world_guid": world_guid,
        "entry": 20808,
        "map": 0,
        "map_id": 0,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "name": "The Maiden's Fancy",
        "use_transport_guid": True,
        "world_db_transport": True,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        "transport_period": 1000,
    }
    transport_runtime._runtime_transport_states()[world_guid] = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=7,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(1, 10.0, 20.0, 5.0, 0.0, 0),
            transport_runtime.TransportRouteNode(0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        node_index=1,
        x=150.0,
        y=260.0,
        z=18.0,
        orientation=0.9,
        map_id=0,
        path_progress_ms=1300,
        timed_route=True,
        route_period_ms=1000,
        world_db_transport=True,
        transport_db_guid=7,
    )
    movement_state = SimpleNamespace(
        has_transport_data=False,
        transport_guid=0,
        transport_x=0.0,
        transport_y=0.0,
        transport_z=0.0,
        transport_orientation=0.0,
        transport_time=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.0,
    )
    session = SimpleNamespace(
        char_guid=1,
        map_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.0,
        movement_state=movement_state,
        loaded_transport_entries={world_guid: dict(entry)},
    )
    pending = {
        "destination_guid": world_guid,
        "destination_map": 0,
        "destination_entry": dict(entry),
        "local_x": 2.0,
        "local_y": 3.0,
        "local_z": 4.0,
        "local_o": 0.5,
        "base_x": 100.0,
        "base_y": 200.0,
        "base_z": 10.0,
        "base_o": 0.25,
        "route_phase": 1300,
    }

    movement._verify_pending_boat_transfer_attachment(session, pending)

    assert session.x == 152.0
    assert session.y == 263.0
    assert session.z == 22.0
    assert session.orientation == 1.4
    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None


def test_164871_passenger_transfer_preserves_guid_map_1_to_0(monkeypatch):
    _run_canonical_transport_transfer(
        monkeypatch,
        entry_id=164871,
        transport_db_guid=6,
        source_map=1,
        destination_map=0,
    )


def test_first_movement_after_ack_preserves_matching_transport_guid(monkeypatch):
    source_guid, _linked_destination_guid, session = _run_canonical_transport_transfer(
        monkeypatch,
        entry_id=20808,
        transport_db_guid=7,
        source_map=1,
        destination_map=0,
    )
    movement_state = session.movement_state

    movement._store_transport_state_from_parsed(
        session,
        "MSG_MOVE_HEARTBEAT",
        {
            "has_transport_data": True,
            "transport_guid": source_guid,
            "transport_x": 2.0,
            "transport_y": 3.0,
            "transport_z": 4.0,
            "transport_orientation": 0.5,
            "transport_time": 1000,
            "transport_time2": 0,
            "transport_time3": 0,
            "transport_seat": -1,
            "transport_vehicle_id": 0,
        },
    )

    assert movement_state.has_transport_data is True
    assert movement_state.transport_guid == source_guid
    assert (
        transport_runtime.get_movement_manager().passenger_attachment(
            source_guid,
            1,
        )
        is not None
    )


def test_legacy_transport_transfer_registers_missing_destination_instance(monkeypatch):
    _reset_transport_states()
    now = 510.0
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: now)
    monkeypatch.setattr(movement, "_is_teleporting", lambda _session: False)
    monkeypatch.setattr(movement, "_clear_loaded_world_objects_for_transfer", lambda _session: [])
    monkeypatch.setattr(
        movement,
        "_capture_persist_position_from_session",
        lambda _session: None,
    )
    monkeypatch.setattr(movement, "_mark_position_dirty", lambda _session: None)
    monkeypatch.setattr(movement, "_save_session_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(movement, "_post_teleport_multiplayer_resync", lambda *args, **kwargs: [])

    source_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100107))
    entry = {
        "guid": 100107,
        "transport_db_guid": 107,
        "world_guid": source_guid,
        "entry": 20808,
        "map": 1,
        "map_id": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "name": "Route Stability",
        "use_transport_guid": True,
        "world_db_transport": False,
        "runtime_route": [
            (1, 10.0, 20.0, 5.0, 0.0, 0),
            (0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        "shared_route_clock_key": "world-db-transport:107",
        "transport_period": 1000,
    }
    source_state = transport_runtime.RuntimeTransportState(
        guid=source_guid,
        entry=20808,
        spawn_guid=100107,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(1, 10.0, 20.0, 5.0, 0.0, 0),
            transport_runtime.TransportRouteNode(0, 100.0, 200.0, 10.0, 0.0, 1000),
        ],
        node_index=1,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.25,
        map_id=0,
        path_progress_ms=1000,
        timed_route=True,
        route_period_ms=1000,
        shared_clock_key="world-db-transport:107",
    )
    transport_runtime._runtime_transport_states()[source_guid] = source_state
    transport_runtime._ensure_movement_instance_for_state(source_state)
    transport_runtime.get_movement_manager().attach_passenger(
        source_guid,
        1,
        local_x=2.0,
        local_y=3.0,
        local_z=4.0,
        local_o=0.5,
        source_map=1,
    )

    movement_state = SimpleNamespace(
        has_transport_data=True,
        transport_guid=source_guid,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.5,
        transport_time=1000,
        transport_time2=0,
        transport_time3=0,
        transport_seat=-1,
        transport_vehicle_id=0,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        flags=0,
        flags2=0,
        timestamp_ms=0,
        client_timestamp_ms=0,
        server_movement_timestamp_ms=0,
        pitch=0.0,
        last_valid_orientation=0.0,
    )
    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        map_id=1,
        x=12.0,
        y=23.0,
        z=9.0,
        orientation=0.0,
        movement_state=movement_state,
        loaded_transport_entries={source_guid: entry},
    )
    destination_guid = transport_runtime.linked_transport_world_guid(entry, map_id=0)
    assert transport_runtime.runtime_transport_state_for_guid(destination_guid) is None

    responses = movement._maybe_start_transport_route_transfer(session, "MSG_MOVE_HEARTBEAT")

    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert transport_runtime.runtime_transport_state_for_guid(destination_guid) is not None

    movement.handle_move_worldport_ack(session, SimpleNamespace())

    assert (
        transport_runtime.get_movement_manager().passenger_attachment(
            destination_guid,
            1,
        )
        is not None
    )


def test_transport_rehydrate_preserves_shared_clock_phase(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime, "_shared_route_phase_ms", lambda _key, _period: 750)
    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100108))
    state = transport_runtime.RuntimeTransportState(
        guid=world_guid,
        entry=20808,
        spawn_guid=100108,
        display_id=3015,
        route=[
            transport_runtime.TransportRouteNode(1, 0.0, 0.0, 0.0, 0.0, 0),
            transport_runtime.TransportRouteNode(1, 100.0, 0.0, 0.0, 0.0, 1000),
        ],
        node_index=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        map_id=1,
        path_progress_ms=0,
        timed_route=True,
        route_period_ms=1000,
        shared_clock_key="world-db-transport:108",
    )

    transport_runtime._ensure_movement_instance_for_state(state)
    transport_runtime._commit_transport_state_from_movement_cache(state)

    assert int(state.path_progress_ms) == 750
    assert state.x == 75.0








def test_autonomous_transport_visibility_creates_then_updates_stationary_player(monkeypatch):
    from server.modules.handlers.world.state import runtime as world_runtime

    world_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    state = SimpleNamespace(
        guid=world_guid,
        map_id=1,
        x=10.0,
        y=20.0,
        z=5.0,
        orientation=0.25,
        path_progress_ms=1000,
        route_period_ms=2000,
        last_sent_x=float("inf"),
        last_sent_y=float("inf"),
        last_sent_z=float("inf"),
        last_sent_map_id=-1,
    )
    entry = {
        "guid": 7,
        "world_guid": world_guid,
        "entry": 20808,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "map": 1,
        "phase_mask": 1,
        "world_db_transport": True,
        "runtime_route": [(1, 0.0, 0.0, 0.0), (0, 100.0, 100.0, 0.0)],
    }
    sent = []
    session = SimpleNamespace(
        char_guid=16,
        realm_id=1,
        map_id=1,
        phase_mask=1,
        x=10.0,
        y=20.0,
        z=5.0,
        login_state="IN_WORLD",
        gameobjects_visible=True,
        loaded_gameobjects=set(),
        loaded_transport_entries={},
        loaded_gameobject_entries={},
        send_response=lambda _responses: None,
    )
    monkeypatch.setattr(world_runtime, "iter_in_world_sessions", lambda **_kwargs: [session])
    monkeypatch.setattr(
        transport_runtime,
        "_build_gameobject_update_payload",
        lambda **_kwargs: b"create",
    )
    monkeypatch.setattr(
        transport_runtime,
        "_build_gameobject_values_update_payload",
        lambda **_kwargs: b"values",
    )
    monkeypatch.setattr(
        transport_runtime,
        "make_update_object_response",
        lambda payload: ("SMSG_UPDATE_OBJECT", payload),
    )
    monkeypatch.setattr(
        transport_runtime,
        "_send_responses",
        lambda target, responses: sent.append((target, responses)),
    )

    transport_runtime._push_autonomous_transport_visibility(state, entry)
    transport_runtime._push_autonomous_transport_visibility(state, entry)

    assert [responses for _target, responses in sent] == [
        [("SMSG_UPDATE_OBJECT", b"create")],
        [("SMSG_UPDATE_OBJECT", b"values")],
    ]
    assert world_guid in session.loaded_gameobjects
    assert world_guid in session.loaded_transport_entries
    assert world_guid in session.loaded_gameobject_entries


def test_autonomous_transport_visibility_excludes_elevators():
    elevator = {
        "entry": 219175,
        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "world_db_transport": True,
        "runtime_route": [(1, 0.0, 0.0, 0.0), (1, 0.0, 0.0, 10.0)],
    }

    assert transport_runtime._supports_autonomous_transport_visibility(elevator) is False


def _mount_test_session_on_runtime_transport(state, *, player_guid: int = 77):
    movement_state = MovementState()
    movement_state.has_transport_data = True
    movement_state.transport_guid = int(state.guid)
    movement_state.transport_x = 1.25
    movement_state.transport_y = -2.5
    movement_state.transport_z = 3.75
    movement_state.transport_orientation = 0.375
    movement_state.transport_time = 4321
    movement_state.transport_time2 = 123
    movement_state.transport_time3 = 456
    movement_state.transport_seat = -1
    movement_state.transport_vehicle_id = 0
    cos_o = math.cos(float(state.orientation))
    sin_o = math.sin(float(state.orientation))
    world_x = float(state.x) + cos_o * movement_state.transport_x - sin_o * movement_state.transport_y
    world_y = float(state.y) + sin_o * movement_state.transport_x + cos_o * movement_state.transport_y
    world_z = float(state.z) + movement_state.transport_z
    world_o = float(state.orientation) + movement_state.transport_orientation
    movement_state.x = world_x
    movement_state.y = world_y
    movement_state.z = world_z
    movement_state.orientation = world_o
    session = SimpleNamespace(
        char_guid=int(player_guid),
        realm_id=1,
        map_id=int(state.map_id),
        instance_id=0,
        x=world_x,
        y=world_y,
        z=world_z,
        orientation=world_o,
        movement_state=movement_state,
        transport_attach_state=transport_runtime.ATTACH_STATE_ATTACHED,
        transport_attached_guid=int(state.guid),
        transport_attach_source_map=int(state.map_id),
        mount_spell=None,
        mount_display_id=0,
        is_mounted=False,
        is_flying=False,
        can_fly=False,
        unit_flags=0,
        active_mount_aura_spell_id=None,
        active_mount_aura_slot=0,
        active_fly_aura_spell_id=None,
        run_speed=7.0,
        fly_speed=7.0,
    )
    assert transport_runtime.attach_transport_passenger(
        int(state.guid),
        int(player_guid),
        local_x=movement_state.transport_x,
        local_y=movement_state.transport_y,
        local_z=movement_state.transport_z,
        local_o=movement_state.transport_orientation,
        source_map=int(state.map_id),
    )
    return session


def _assert_mount_did_not_change_attachment(session, state, expected):
    attachment = transport_runtime.transport_passenger_attachment(
        int(state.guid), int(session.char_guid)
    )
    assert attachment is not None
    assert attachment.attached_at_ms == expected.attached_at_ms
    movement_state = session.movement_state
    assert movement_state.has_transport_data is True
    assert movement_state.transport_guid == int(state.guid)
    assert (
        movement_state.transport_x,
        movement_state.transport_y,
        movement_state.transport_z,
        movement_state.transport_orientation,
    ) == pytest.approx((1.25, -2.5, 3.75, 0.375))
    assert (
        movement_state.transport_time,
        movement_state.transport_time2,
        movement_state.transport_time3,
    ) == (4321, 123, 456)
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_ATTACHED
    assert session.transport_attached_guid == int(state.guid)


@pytest.mark.parametrize("runtime_kind", ["boat", "elevator"])
def test_mount_and_dismount_preserve_runtime_transport_attachment(monkeypatch, runtime_kind):
    from server.modules.handlers.world.opcodes import spells as spells_handlers

    _reset_transport_states()
    if runtime_kind == "boat":
        _entry, state, _transport = _registered_runtime_transport()
    else:
        _entry, state, _elevator = _registered_runtime_elevator(monkeypatch)
    session = _mount_test_session_on_runtime_transport(state)
    expected_attachment = transport_runtime.transport_passenger_attachment(
        int(state.guid), int(session.char_guid)
    )

    monkeypatch.setattr(spells_handlers, "get_mount_display_id", lambda _spell_id: 2404)
    monkeypatch.setattr(spells_handlers, "is_flying_mount_spell", lambda _spell_id: False)
    monkeypatch.setattr(spells_handlers, "_broadcast_mount_visual_to_visible_peers", lambda *_args: None)
    monkeypatch.setattr(spells_handlers, "build_mount_visual_responses", lambda target, display_id: setattr(target, "mount_display_id", int(display_id)) or [])
    monkeypatch.setattr(spells_handlers, "_build_run_speed_update_response", lambda _target: ("SMSG_MOVE_SET_RUN_SPEED", b""))
    monkeypatch.setattr(spells_handlers, "build_move_set_flight_speed_payload", lambda _target: b"")
    monkeypatch.setattr(spells_handlers, "_build_movement_speed_update_responses", lambda _target: [])
    monkeypatch.setattr(spells_handlers, "_notification_response", lambda _message: [])
    monkeypatch.setattr(spells_handlers, "_persist_current_mount_state", lambda _target: None)
    monkeypatch.setattr(spells_handlers, "clear_persisted_mount_state", lambda _target: None)

    world_before = (session.x, session.y, session.z, session.orientation)
    spells_handlers.handle_mount(session, 59535)
    _assert_mount_did_not_change_attachment(session, state, expected_attachment)
    assert (session.x, session.y, session.z, session.orientation) == pytest.approx(world_before)
    spells_handlers.dismount(session)
    _assert_mount_did_not_change_attachment(session, state, expected_attachment)
    assert (session.x, session.y, session.z, session.orientation) == pytest.approx(world_before)


def test_mount_after_runtime_phase_change_preserves_world_position_before_refresh(monkeypatch):
    from server.modules.handlers.world.opcodes import spells as spells_handlers

    _reset_transport_states()
    _entry, state, _transport = _registered_runtime_transport()
    session = _mount_test_session_on_runtime_transport(state)
    refresh_snapshots = []

    monkeypatch.setattr(spells_handlers, "get_mount_display_id", lambda _spell_id: 2404)
    monkeypatch.setattr(spells_handlers, "is_flying_mount_spell", lambda _spell_id: False)
    monkeypatch.setattr(spells_handlers, "_broadcast_mount_visual_to_visible_peers", lambda *_args: None)
    monkeypatch.setattr(spells_handlers, "_persist_current_mount_state", lambda _target: None)
    monkeypatch.setattr(spells_handlers, "clear_persisted_mount_state", lambda _target: None)

    def advance_transport_and_build_mount(_target, _spell_id):
        state.x += 6.0
        state.y -= 2.0
        return [("SMSG_MOVE_SET_RUN_SPEED", b"mount")]

    def advance_transport_and_build_dismount(_target):
        state.x -= 3.0
        state.y += 5.0
        return [("SMSG_MOVE_SET_RUN_SPEED", b"dismount")]

    def capture_refresh(target):
        refresh_snapshots.append(
            (
                target.x,
                target.y,
                target.z,
                target.orientation,
                target.movement_state.transport_guid,
            )
        )
        return [("SMSG_PLAYER_MOVE", b"refresh")]

    monkeypatch.setattr(spells_handlers, "send_mount_update", advance_transport_and_build_mount)
    monkeypatch.setattr(spells_handlers, "send_dismount_update", advance_transport_and_build_dismount)
    monkeypatch.setattr(spells_handlers, "resync_movement", capture_refresh)
    world_before_mount = (session.x, session.y, session.z, session.orientation)

    mount_responses = spells_handlers.handle_mount(session, 59535)
    assert mount_responses[-1] == ("SMSG_PLAYER_MOVE", b"refresh")
    assert refresh_snapshots[-1][:4] == pytest.approx(world_before_mount)
    assert refresh_snapshots[-1][4] == int(state.guid)

    world_before_dismount = (session.x, session.y, session.z, session.orientation)
    dismount_responses = spells_handlers.dismount(session)
    assert dismount_responses[-1] == ("SMSG_PLAYER_MOVE", b"refresh")
    assert refresh_snapshots[-1][:4] == pytest.approx(world_before_dismount)
    assert refresh_snapshots[-1][4] == int(state.guid)
    assert transport_runtime.transport_passenger_attachment(state.guid, session.char_guid) is not None


def test_mount_speed_ack_preserves_transport_guid_and_refreshed_local_offset(monkeypatch):
    from server.modules.handlers.world.opcodes import movement as movement_handlers
    from server.modules.handlers.world.opcodes import spells as spells_handlers

    _reset_transport_states()
    _entry, state, _transport = _registered_runtime_transport()
    session = _mount_test_session_on_runtime_transport(state)
    session.x += 4.0
    session.y -= 1.5
    world_before = (session.x, session.y, session.z, session.orientation)
    monkeypatch.setattr(spells_handlers, "send_mount_update", lambda *_args: [])
    monkeypatch.setattr(spells_handlers, "_persist_current_mount_state", lambda *_args: None)
    monkeypatch.setattr(movement_handlers, "build_smsg_player_move_payload", lambda *_args: b"move")

    spells_handlers.handle_mount(session, 59535)
    attachment = transport_runtime.transport_passenger_attachment(state.guid, session.char_guid)
    local_before_ack = (
        attachment.local_x,
        attachment.local_y,
        attachment.local_z,
        attachment.local_o,
    )
    _count, responses = movement_handlers.handle_move_force_run_speed_change_ack(session, None)

    assert responses == [("SMSG_PLAYER_MOVE", b"move")]
    assert session.movement_state.transport_guid == int(state.guid)
    assert (
        session.movement_state.transport_x,
        session.movement_state.transport_y,
        session.movement_state.transport_z,
        session.movement_state.transport_orientation,
    ) == pytest.approx(local_before_ack)
    assert (session.x, session.y, session.z, session.orientation) == pytest.approx(world_before)


def test_mount_rebuild_missing_transport_guard_is_bounded_and_genuine_departure_detaches(monkeypatch):
    from server.modules.handlers.world.opcodes import movement as movement_handlers

    _reset_transport_states()
    _entry, state, _transport = _registered_runtime_transport()
    session = _mount_test_session_on_runtime_transport(state)
    monkeypatch.setattr(transport_runtime.time, "monotonic", lambda: 10.0)
    assert transport_runtime.prepare_attached_movement_rebuild(session, reason="test")
    missing = {"has_transport_data": False}

    movement_handlers._store_transport_state_from_parsed(session, "MSG_MOVE_HEARTBEAT", missing)
    movement_handlers._store_transport_state_from_parsed(session, "MSG_MOVE_HEARTBEAT", missing)
    assert transport_runtime.transport_passenger_attachment(state.guid, session.char_guid) is not None
    assert session.movement_state.transport_guid == int(state.guid)

    movement_handlers._store_transport_state_from_parsed(session, "MSG_MOVE_HEARTBEAT", missing)
    assert transport_runtime.transport_passenger_attachment(state.guid, session.char_guid) is not None
    movement_handlers._store_transport_state_from_parsed(session, "MSG_MOVE_HEARTBEAT", missing)
    assert transport_runtime.transport_passenger_attachment(state.guid, session.char_guid) is None
    assert session.movement_state.transport_guid == 0


def _accepted_transport_sample(session, state, *, local_x, local_y, local_z, has_transport=True, guid=None):
    cos_o = math.cos(float(state.orientation))
    sin_o = math.sin(float(state.orientation))
    return {
        "has_transport_data": bool(has_transport),
        "transport_guid": int(state.guid if guid is None else guid),
        "transport_x": float(local_x),
        "transport_y": float(local_y),
        "transport_z": float(local_z),
        "transport_orientation": 0.0,
        "transport_time": 100,
        "transport_time2": 0,
        "transport_time3": 0,
        "transport_seat": -1,
        "transport_vehicle_id": 0,
        "x": float(state.x) + cos_o * float(local_x) - sin_o * float(local_y),
        "y": float(state.y) + sin_o * float(local_x) + cos_o * float(local_y),
        "z": float(state.z) + float(local_z),
    }


@pytest.mark.parametrize("runtime_kind", ["boat", "elevator"])
def test_geometric_departure_bypasses_mount_rebuild_guard_on_first_packet(monkeypatch, runtime_kind):
    _reset_transport_states()
    if runtime_kind == "boat":
        _entry, state, _runtime = _registered_runtime_transport()
    else:
        _entry, state, _runtime = _registered_runtime_elevator(monkeypatch)
    session = _mount_test_session_on_runtime_transport(state)
    assert transport_runtime.prepare_attached_movement_rebuild(session, reason="mount")
    attachment_before = transport_runtime.transport_passenger_attachment(state.guid, session.char_guid)
    sample = _accepted_transport_sample(
        session,
        state,
        local_x=attachment_before.local_x,
        local_y=attachment_before.local_y,
        local_z=attachment_before.local_z,
        has_transport=False,
    )
    sample["x"] += 40.0

    movement._store_transport_state_from_parsed(session, "MSG_MOVE_HEARTBEAT", sample)

    assert transport_runtime.transport_passenger_attachment(state.guid, session.char_guid) is None
    assert session.movement_state.transport_guid == 0
    assert getattr(session, "_movement_rebuild_transport_guard", None) is None
    assert transport_runtime._start_boundary_worldport_for_passenger(
        session,
        state,
        attachment_before,
        from_map=int(state.map_id),
        to_map=int(state.map_id) + 1,
        transfer_id="detached-test",
    ) is False


def test_same_guid_implausible_local_offset_detaches_instead_of_replacing_attachment():
    _reset_transport_states()
    _entry, state, _runtime = _registered_runtime_transport()
    session = _mount_test_session_on_runtime_transport(state)
    sample = _accepted_transport_sample(
        session,
        state,
        local_x=200.0,
        local_y=0.0,
        local_z=0.0,
    )

    movement._store_transport_state_from_parsed(session, "MSG_MOVE_HEARTBEAT", sample)

    assert transport_runtime.transport_passenger_attachment(state.guid, session.char_guid) is None
    assert session.movement_state.transport_guid == 0


def test_normal_deck_movement_jump_and_small_jitter_preserve_attachment():
    _reset_transport_states()
    _entry, state, _runtime = _registered_runtime_transport()
    session = _mount_test_session_on_runtime_transport(state)

    for opcode, local_x, local_y, local_z, jitter in (
        ("MSG_MOVE_START_FORWARD", 2.0, -2.5, 3.75, 0.03),
        ("MSG_MOVE_HEARTBEAT", 7.0, -1.0, 3.75, -0.04),
        ("MSG_MOVE_JUMP", 8.0, 0.0, 6.0, 0.02),
    ):
        sample = _accepted_transport_sample(
            session,
            state,
            local_x=local_x,
            local_y=local_y,
            local_z=local_z,
        )
        sample["x"] += jitter
        movement._store_transport_state_from_parsed(session, opcode, sample)
        attachment = transport_runtime.transport_passenger_attachment(state.guid, session.char_guid)
        assert attachment is not None
        assert (attachment.local_x, attachment.local_y, attachment.local_z) == pytest.approx(
            (local_x, local_y, local_z)
        )
        assert session.movement_state.transport_guid == int(state.guid)


def test_changed_transport_guid_keeps_existing_new_transport_detach_path(monkeypatch):
    _reset_transport_states()
    _entry, first, _runtime = _registered_runtime_transport()
    session = _mount_test_session_on_runtime_transport(first)
    second_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(808080))
    second = copy.copy(first)
    second.guid = second_guid
    second.spawn_guid = 808080
    second.passengers = {}
    second.x = float(first.x) + 5.0
    transport_runtime._runtime_transport_states()[second_guid] = second
    reasons = []
    original_detach = transport_runtime.detach_session_transport_passenger

    def _capture_detach(target, **kwargs):
        reasons.append(str(kwargs.get("reason", "")))
        return original_detach(target, **kwargs)

    monkeypatch.setattr(transport_runtime, "detach_session_transport_passenger", _capture_detach)
    sample = _accepted_transport_sample(
        session,
        second,
        local_x=1.0,
        local_y=1.0,
        local_z=1.0,
        guid=second_guid,
    )

    movement._store_transport_state_from_parsed(session, "MSG_MOVE_HEARTBEAT", sample)

    assert "new_transport" in reasons
    assert transport_runtime.transport_passenger_attachment(first.guid, session.char_guid) is None
    assert transport_runtime.transport_passenger_attachment(second_guid, session.char_guid) is not None
    assert session.movement_state.transport_guid == second_guid


def test_repeated_mount_cycles_preserve_attachment_while_transport_moves(monkeypatch):
    from server.modules.handlers.world.opcodes import spells as spells_handlers

    _reset_transport_states()
    _entry, state, _transport = _registered_runtime_transport()
    session = _mount_test_session_on_runtime_transport(state)
    expected_attachment = transport_runtime.transport_passenger_attachment(
        int(state.guid), int(session.char_guid)
    )

    monkeypatch.setattr(spells_handlers, "send_mount_update", lambda _target, _spell_id: [])
    monkeypatch.setattr(spells_handlers, "send_dismount_update", lambda _target: [])
    monkeypatch.setattr(spells_handlers, "_persist_current_mount_state", lambda _target: None)
    monkeypatch.setattr(spells_handlers, "clear_persisted_mount_state", lambda _target: None)

    for path_progress_ms in (100, 250, 500, 750):
        state.path_progress_ms = path_progress_ms
        state.x += 2.0
        state.y -= 0.75
        attachment = transport_runtime.transport_passenger_attachment(state.guid, session.char_guid)
        from server.modules.handlers.world.position.publication import publish_transport

        publish_transport(session, state, attachment)
        world_before = (session.x, session.y, session.z, session.orientation)
        spells_handlers.handle_mount(session, 59535)
        _assert_mount_did_not_change_attachment(session, state, expected_attachment)
        assert (session.x, session.y, session.z, session.orientation) == pytest.approx(world_before)
        spells_handlers.dismount(session)
        _assert_mount_did_not_change_attachment(session, state, expected_attachment)
        assert (session.x, session.y, session.z, session.orientation) == pytest.approx(world_before)


def test_transport_tick_runs_normal_incremental_visibility_for_stationary_passenger(
    monkeypatch,
):
    from server.modules.handlers.world import world_refresh

    _reset_transport_states()
    _entry, state, _transport = _registered_runtime_transport()
    session = _mount_test_session_on_runtime_transport(state)
    attachment = transport_runtime.transport_passenger_attachment(
        state.guid,
        session.char_guid,
    )
    sent = []
    session.send_response = lambda responses: sent.extend(responses)
    calls = []

    class _Refresh:
        def refresh_after_movement(self, target, *, context):
            calls.append((target, context, target.x, target.y, target.z))
            return [("SMSG_UPDATE_OBJECT", b"visibility")]

    monkeypatch.setattr(world_refresh, "get_world_refresh_service", lambda: _Refresh())
    monkeypatch.setattr(
        transport_runtime,
        "_canonical_runtime_passengers",
        lambda *_args, **_kwargs: {session.char_guid: attachment},
    )
    monkeypatch.setattr(
        transport_runtime,
        "_find_transport_passenger_session",
        lambda player_guid: session if int(player_guid) == session.char_guid else None,
    )
    monkeypatch.setattr(
        transport_runtime.get_movement_manager(),
        "tick_instance",
        lambda *_args, **_kwargs: None,
    )

    def move_transport(runtime_state):
        runtime_state.x += 5.0
        transport_runtime.get_world_transport_manager().sync_transport_object(runtime_state)

    monkeypatch.setattr(
        transport_runtime,
        "_commit_transport_state_from_movement_cache",
        move_transport,
    )

    transport_runtime.get_world_transport_manager()._tick_transport_state(
        state.guid,
        state,
    )

    assert len(calls) == 1
    assert calls[0][0] is session
    assert calls[0][1] == "movement:transport-passenger"
    assert session.x == pytest.approx(calls[0][2])
    assert sent == [("SMSG_UPDATE_OBJECT", b"visibility")]
