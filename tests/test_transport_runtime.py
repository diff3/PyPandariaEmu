#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
import struct
import types
from types import SimpleNamespace

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

from server.modules.handlers.world import transport_runtime
from server.modules.handlers.world.bootstrap import gameobjects
from server.modules.handlers.world.movements import manager as movement_manager_module
from server.modules.handlers.world.movements import evaluator
from server.modules.handlers.world.movements.types import MovementLifecycleEventType
from server.modules.handlers.world.opcodes import movement


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
    assert source_state.passengers == {}
    assert source_state.pending_transfers is not None
    assert source_state.pending_transfers[42] is transfer

    completed = manager.complete_passenger_transfer(int(source_state.guid), 42)

    assert completed is transfer
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

    assert [name for name, _payload in responses][-3:-1] == [
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

    assert [name for name, _payload in responses][-3:-1] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
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

    assert [name for name, _payload in responses][-3:-1] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
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
    assert [name for name, _payload in responses][-3:-1] == [
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
    assert [name for name, _payload in responses][-3:-1] == [
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

    assert [name for name, _payload in first][-3:-1] == [
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

    assert [name for name, _payload in responses][-3:-1] == [
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

    assert [name for name, _payload in first][-3:-1] == [
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

    assert [name for name, _payload in responses][-3:-1] == [
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

    assert [name for name, _payload in responses][-3:-1] == [
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
