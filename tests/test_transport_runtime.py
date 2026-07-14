#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
import struct
import types
import math
from types import SimpleNamespace

import pytest

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
from server.modules.handlers.world.runtime.transport import Transport
from server.modules.handlers.world.runtime.world_object import WorldObject
from server.session.world_session import MovementState


def _reset_transport_states() -> None:
    transport_runtime.reset_world_transport_manager_for_tests()


def _tick_transport_entry(entry: dict) -> None:
    state = transport_runtime._transport_state_for_entry(entry)
    assert state is not None
    transport_runtime.get_movement_manager().tick(
        transport_runtime._transport_server_time_ms(state)
    )
    transport_runtime._sync_transport_state_from_movement_cache(state)


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

    monkeypatch.setattr(
        map_transfer,
        "_POST_TRANSFER_AREA_TRIGGER_SUPPRESS_SECONDS",
        0.0,
    )
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

    assert session.movement_state.has_transport_data is False
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

    monkeypatch.setattr(
        map_transfer,
        "_POST_TRANSFER_AREA_TRIGGER_SUPPRESS_SECONDS",
        0.0,
    )
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

    monkeypatch.setattr(
        map_transfer,
        "_POST_TRANSFER_AREA_TRIGGER_SUPPRESS_SECONDS",
        0.0,
    )
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


def test_transfer_pending_builder_uses_transport_payload_for_transport_worldport():
    from server.modules.handlers.world.login.packets import build_login_packet

    payload = build_login_packet(
        "SMSG_TRANSFER_PENDING",
        SimpleNamespace(
            map_id=1,
            has_transport=True,
            source_map_id=0,
            transport_entry=20808,
        ),
    )

    assert len(payload) == 13
    assert payload[0] == 0x40
    assert payload[1:] == struct.pack("<III", 1, 0, 20808)


def test_map_transfer_keep_transport_replaces_transfer_pending_with_transport_payload(monkeypatch):
    from server.modules.handlers.world.teleport import map_transfer

    monkeypatch.setattr(
        map_transfer,
        "_POST_TRANSFER_AREA_TRIGGER_SUPPRESS_SECONDS",
        0.0,
    )
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
    assert responses[0][1][1:] == struct.pack("<III", 1, 0, 20808)


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
    assert session._player_bootstrap_runtime_transport["transport_create_transform_matched"] is True

    # The packet builder's normal runtime overlay must not replace the transform
    # sampled for the player in this same bootstrap.
    assert gameobjects._transport_runtime_packet_entry(packet_entry) is packet_entry


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
    transport_runtime.get_world_transport_manager().start()

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
        "_transport_taxi_path_nodes_by_path",
        lambda: {
            241: (
                transport_runtime.TransportTaxiPathNode(241, 0, 1, -1370.0, -4266.0, 0.0),
                transport_runtime.TransportTaxiPathNode(241, 1, 1, -1265.0, -4140.0, 0.0),
                transport_runtime.TransportTaxiPathNode(241, 20, 0, -14123.0, 852.0, 0.0),
                transport_runtime.TransportTaxiPathNode(241, 21, 0, -14268.0, 964.0, 0.0),
            )
        },
    )
    transport_runtime.get_world_transport_manager().start()

    canonical_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(7))
    clone_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100007))
    for world_guid, state in transport_runtime._runtime_transport_states().items():
        transport_runtime.get_movement_manager().tick_instance(
            int(world_guid),
            server_time_ms=transport_runtime._transport_server_time_ms(state),
        )
        transport_runtime._sync_transport_state_from_movement_cache(state)

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
        "_transport_taxi_path_nodes_by_path",
        lambda: {
            241: (
                transport_runtime.TransportTaxiPathNode(241, 0, 1, 0.0, 0.0, 0.0),
                transport_runtime.TransportTaxiPathNode(241, 1, 1, 100.0, 0.0, 0.0),
            )
        },
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
    transport_runtime._sync_transport_state_from_movement_cache(state)

    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}
    assert clone_guid not in transport_runtime._runtime_transport_states()
    assert float(state.x) != start_x
    assert int(state.path_progress_ms) == 500


def test_canonical_world_db_transport_changes_map_at_transfer(monkeypatch):
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
    transport_runtime._sync_transport_state_from_movement_cache(state)

    assert state.guid == canonical_guid
    assert state.spawn_guid == 7
    assert state.map_id == 0
    assert (state.x, state.y, state.z) == (100.0, 200.0, 10.0)
    assert int(state.path_progress_ms) == 750
    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}
    assert clone_guid not in transport_runtime._runtime_transport_states()
    assert clone_guid not in transport_runtime.get_movement_manager().instances

    server_time["ms"] = 13000
    transport_runtime.get_movement_manager().tick_instance(
        canonical_guid,
        server_time_ms=transport_runtime._transport_server_time_ms(state),
    )
    transport_runtime._sync_transport_state_from_movement_cache(state)

    assert state.guid == canonical_guid
    assert state.map_id == 0
    assert int(state.path_progress_ms) == 1500
    assert set(transport_runtime._runtime_transport_states()) == {canonical_guid}
    assert set(transport_runtime.get_movement_manager().instances) == {canonical_guid}

    server_time["ms"] = 13500
    transport_runtime.get_movement_manager().tick_instance(
        canonical_guid,
        server_time_ms=transport_runtime._transport_server_time_ms(state),
    )
    transport_runtime._sync_transport_state_from_movement_cache(state)

    assert state.guid == canonical_guid
    assert state.map_id == 1
    assert (state.x, state.y, state.z) == (10.0, 20.0, 5.0)
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
    transport_runtime._sync_transport_state_from_movement_cache(state)

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

    assert transport_runtime.synthetic_transport_entries_near(
        old_map_session,
        loaded_guids=set(),
    ) == []
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
        transport_runtime._sync_transport_state_from_movement_cache(state)

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
        transport_runtime._sync_transport_state_from_movement_cache(state)

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


def test_cached_transport_entry_uses_runtime_position_during_transfer_frame(monkeypatch):
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
    transport_runtime._sync_transport_state_from_movement_cache(state)

    moved = transport_runtime.cached_transport_runtime_entry(
        SimpleNamespace(map_id=0, x=500.0, y=600.0, z=8.0),
        entry,
    )

    assert (moved["x"], moved["y"], moved["z"]) == (10.0, 20.0, 5.0)
    assert moved["map"] == 0
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
    assert payload["movement_block_uint32"] == 789
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
    assert payload["movement_block_uint32"] == 4321
    dynamic_flags = captured_fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS]
    assert dynamic_flags == (28317 << 16)


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
        transport_runtime._sync_transport_state_from_movement_cache(state)

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
    transport_runtime._sync_transport_state_from_movement_cache(state)

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
    transport_runtime._sync_transport_state_from_movement_cache(state)

    assert manager.can_attach(SimpleNamespace(char_guid=1, map_id=1), state.guid) is True
    assert manager.can_attach(SimpleNamespace(char_guid=1, map_id=0), state.guid) is False


def _static_type11_session(world_guid: int, *, go_type: int = 11, map_id: int = 369):
    return SimpleNamespace(
        char_guid=16,
        map_id=map_id,
        loaded_gameobjects={world_guid},
        loaded_gameobject_entries={
            world_guid: {
                "guid": 500001,
                "world_guid": world_guid,
                "entry": 176082,
                "map": 369,
                "type": go_type,
            }
        },
    )


def test_static_type11_gameobject_attachment_is_accepted_without_runtime_state():
    _reset_transport_states()
    world_guid = 0xF11000000007A121
    session = _static_type11_session(world_guid)

    assert transport_runtime.can_attach_transport(session, world_guid) is True
    assert transport_runtime.runtime_transport_state_for_guid(world_guid) is None


def test_static_type11_movement_keeps_transport_guid():
    _reset_transport_states()
    world_guid = 0xF11000000007A125
    session = _static_type11_session(world_guid)
    session.movement_state = SimpleNamespace(transport_guid=0)

    movement._store_transport_state_from_parsed(
        session,
        "CMSG_MOVE_HEARTBEAT",
        {
            "has_transport_data": True,
            "transport_guid": world_guid,
            "transport_x": 1.0,
            "transport_y": 2.0,
            "transport_z": 3.0,
            "transport_orientation": 0.25,
            "transport_time": 100,
            "transport_seat": -1,
        },
    )

    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.runtime_transport_state_for_guid(world_guid) is None


def test_static_type11_gameobject_attachment_requires_same_map():
    _reset_transport_states()
    world_guid = 0xF11000000007A126

    assert transport_runtime.can_attach_transport(
        _static_type11_session(world_guid, map_id=0),
        world_guid,
    ) is False


def test_static_non_type11_gameobject_attachment_is_rejected():
    _reset_transport_states()
    world_guid = 0xF11000000007A122

    assert transport_runtime.can_attach_transport(
        _static_type11_session(world_guid, go_type=5),
        world_guid,
    ) is False


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


def test_static_type11_gameobject_does_not_start_cross_map_transfer():
    _reset_transport_states()
    world_guid = 0xF11000000007A124
    session = _static_type11_session(world_guid)
    session.transport_transfer_pending = False
    session.teleport_pending = False
    session.worldport_ack_pending = False
    session.near_teleport_pending = False
    session.movement_state = SimpleNamespace(transport_guid=world_guid)

    assert movement._maybe_start_transport_route_transfer(session, "CMSG_MOVE_HEARTBEAT") == []
    assert transport_runtime.runtime_transport_state_for_guid(world_guid) is None


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
    assert session.transport_transfer_pending is True
    assert session.map_id == 0
    assert session.movement_state.transport_guid == world_guid

    assert transport_runtime.transport_crossed_map_boundary(
        world_guid,
        previous_map_id=1,
    ) is False
    assert [name for name, _payload in sent].count("SMSG_TRANSFER_PENDING") == 1


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


def test_20808_boundary_passenger_worldports_before_despawn_ratchet_to_booty(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert not any(name == "SMSG_MESSAGECHAT" for name, _payload in responses)
    update_responses = [response for response in responses if response[0] == "SMSG_UPDATE_OBJECT"]
    assert not any(_payload_update_type(response) == 3 for response in update_responses)
    assert session.transport_transfer_pending is True
    assert session.map_id == 0
    assert session.movement_state.transport_guid == world_guid


def test_20808_boundary_passenger_worldports_before_despawn_booty_to_ratchet(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert not any(name == "SMSG_MESSAGECHAT" for name, _payload in responses)
    update_responses = [response for response in responses if response[0] == "SMSG_UPDATE_OBJECT"]
    assert not any(_payload_update_type(response) == 3 for response in update_responses)
    assert session.transport_transfer_pending is True
    assert session.map_id == 1
    assert session.movement_state.transport_guid == world_guid


def test_20808_boundary_forced_map_zero_succeeds_after_transfer_window(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
        transfer_active=False,
    )
    monkeypatch.setattr(
        transport_runtime,
        "transport_transfer_destination_map_for_guid",
        lambda _world_guid: None,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert state.transfer_active is False
    assert state.transfer_destination_map == 0
    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.transport_transfer_pending is True
    assert session.map_id == 0
    assert session.movement_state.transport_guid == world_guid


def test_20808_boundary_forced_map_one_succeeds_after_transfer_window(monkeypatch):
    session, state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
        transfer_active=False,
    )
    monkeypatch.setattr(
        transport_runtime,
        "transport_transfer_destination_map_for_guid",
        lambda _world_guid: None,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert state.transfer_active is False
    assert state.transfer_destination_map == 1
    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.transport_transfer_pending is True
    assert session.map_id == 1
    assert session.movement_state.transport_guid == world_guid


def test_20808_boundary_forced_map_duplicate_tick_does_not_duplicate_transfer(monkeypatch):
    session, _state, _world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
        transfer_active=False,
    )
    monkeypatch.setattr(
        transport_runtime,
        "transport_transfer_destination_map_for_guid",
        lambda _world_guid: None,
    )

    first = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )
    second = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in first][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert [name for name, _payload in second].count("SMSG_TRANSFER_PENDING") == 0
    assert [name for name, _payload in second].count("SMSG_NEW_WORLD") == 0


def test_20808_boundary_stale_pending_does_not_block_next_transfer(monkeypatch):
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=0,
        destination_map=1,
        passenger=True,
        transfer_active=False,
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
    monkeypatch.setattr(
        transport_runtime,
        "transport_transfer_destination_map_for_guid",
        lambda _world_guid: None,
    )

    responses = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.transport_transfer_pending is True
    assert session.worldport_ack_pending is True
    assert session.pending_transport_transfer["source_map"] == 0
    assert session.pending_transport_transfer["destination_map"] == 1
    assert session.movement_state.transport_guid == world_guid


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


def test_20808_client_clear_clears_stale_transport_transfer_pending(monkeypatch):
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

    assert session.transport_transfer_pending is False
    assert session.pending_transport_transfer is None
    assert session.movement_state.transport_guid == 0


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
    assert session.movement_state.transport_guid == 0


def test_attached_player_parsed_transport_no_detaches(monkeypatch):
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
    captured: list[str] = []

    def _capture(message, *args):
        captured.append(message % args if args else message)

    monkeypatch.setattr(movement, "_parse_skyfire_flying_movement_info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(movement.Logger, "info", _capture)
    monkeypatch.setattr(transport_runtime.Logger, "info", _capture)

    movement._record_movement_packet_state(
        session,
        "MSG_MOVE_START_STRAFE_RIGHT",
        b"\x00" * 8,
    )

    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == world_guid
    assert transport_runtime.transport_passenger_attachment(world_guid, 1) is not None
    assert any("event=MOVEMENT_PARSE_UNKNOWN" in line for line in captured)
    assert any("action=preserve_attachment" in line for line in captured)
    assert not any("event=VALIDATION_DETACH" in line for line in captured)


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
    session, _state, world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )
    transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    movement.handle_move_worldport_ack(session, SimpleNamespace())

    assert session.transport_transfer_pending is False
    assert session.movement_state.transport_guid == world_guid
    assert (
        transport_runtime.transport_passenger_attachment(world_guid, 1)
        is not None
    )


def test_20808_boundary_runtime_passenger_starts_transfer_when_movement_state_missing(monkeypatch):
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

    assert [name for name, _payload in responses][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.transport_transfer_pending is True
    assert session.movement_state.transport_guid == world_guid
    assert session.movement_state.has_transport_data is True


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


def test_20808_boundary_duplicate_tick_does_not_duplicate_transfer(monkeypatch):
    session, _state, _world_guid = _transport_boundary_transfer_session(
        monkeypatch,
        source_map=1,
        destination_map=0,
        passenger=True,
    )

    first = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )
    second = transport_runtime._build_visible_transport_updates(
        session,
        session.loaded_transport_entries,
    )

    assert [name for name, _payload in first][-2:] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert [name for name, _payload in second].count("SMSG_TRANSFER_PENDING") == 0
    assert [name for name, _payload in second].count("SMSG_NEW_WORLD") == 0


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
    transport_runtime._sync_transport_state_from_movement_cache(state)

    assert int(state.path_progress_ms) == 750
    assert state.x == 75.0


def test_deeprun_tram_without_dbc_template_does_not_spawn(monkeypatch):
    _reset_transport_states()
    monkeypatch.setattr(transport_runtime, "_load_world_db_transports", lambda: ())
    monkeypatch.setattr(transport_runtime, "_shared_route_phase_ms", lambda *_args: 0)
    transport_runtime.get_world_transport_manager().start()

    deeprun_session = SimpleNamespace(
        gameobjects_visible=True,
        map_id=transport_runtime._DEEPRUN_TRAM_MAP_ID,
        x=23.0,
        y=20.0,
        realm_id=1,
    )
    entries = transport_runtime.synthetic_transport_entries_near(deeprun_session, loaded_guids=set())

    assert entries == []

    ironforge_session = SimpleNamespace(
        gameobjects_visible=True,
        map_id=transport_runtime._DEEPRUN_TRAM_MAP_ID,
        x=-20.0,
        y=2488.0,
        realm_id=1,
    )
    ironforge_entries = transport_runtime.synthetic_transport_entries_near(ironforge_session, loaded_guids=set())
    assert ironforge_entries == []

    instance_session = SimpleNamespace(
        gameobjects_visible=True,
        map_id=603,
        x=2307.0,
        y=284.0,
        realm_id=1,
    )
    assert transport_runtime.synthetic_transport_entries_near(instance_session, loaded_guids=set()) == []


def test_deeprun_runtime_registration_is_silent(monkeypatch):
    logged: list[str] = []

    def _capture(message, *args, **kwargs):
        logged.append(str(message) % args if args else str(message))

    monkeypatch.setattr(transport_runtime.Logger, "warning", _capture)

    transport_runtime.get_world_transport_manager()._register_deeprun_trams_locked()

    assert logged == []


def test_uld_instance_tram_entry_is_not_deeprun_special_case(monkeypatch):
    _reset_transport_states()
    animation = transport_runtime.TransportAnimationPath(
        entry=transport_runtime._DEEPRUN_TRAM_ENTRY,
        nodes=(
            transport_runtime.TransportAnimationNode(0, 0.0, 0.0, 0.0),
            transport_runtime.TransportAnimationNode(66000, 0.0, 10.0, 0.0),
        ),
        period_ms=66000,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_transport_animation_for_entry",
        lambda entry_id: animation if int(entry_id) == transport_runtime._DEEPRUN_TRAM_ENTRY else None,
    )

    entry = {
        "guid": 34057,
        "world_guid": 0xF110000000008509,
        "entry": transport_runtime._DEEPRUN_TRAM_ENTRY,
        "map": 603,
        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "display_id": transport_runtime._DEEPRUN_TRAM_DISPLAY_ID,
        "x": 2307.0,
        "y": 284.632,
        "z": 424.288,
        "orientation": 0.0,
    }

    prepared = transport_runtime.prepare_runtime_transport_entry(entry)
    assert transport_runtime.is_deeprun_tram_entry(prepared) is False
    assert prepared.get("deeprun_tram") is None
    assert prepared["transport_period"] == 66000


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
