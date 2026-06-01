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
    assert transport_runtime.is_thunder_bluff_elevator_entry(prepared) is True

    _tick_transport_entry(prepared)
    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)

    assert moved["z"] == entry["z"]
    assert moved["x"] == entry["x"]
    assert moved["y"] == entry["y"]

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
    assert moved["z"] == entry["z"]


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
    assert transport_runtime.is_thunder_bluff_elevator_entry(prepared) is True


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
    now = 200.0
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
        "orientation": 0.0,
        "size": 1.0,
    }

    assert transport_runtime.is_runtime_transport_entry(entry) is True
    prepared = transport_runtime.prepare_runtime_transport_entry(entry)

    assert prepared["use_transport_guid"] is True
    assert prepared["transport_period"] == 10000

    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)
    assert moved["z"] == 30.0

    now = 202.0
    _tick_transport_entry(prepared)
    moved = transport_runtime.cached_transport_runtime_entry(session, prepared)

    assert round(moved["z"], 3) == 34.0
    assert moved["transport_path_progress"] == 2000
    state = transport_runtime._runtime_transport_states()[prepared["world_guid"]]
    assert state.timed_route is True
    assert state.route_period_ms == 10000


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
    monkeypatch.setattr(transport_runtime, "_shared_route_phase_ms", lambda *_args: 0)
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
    monkeypatch.setattr(transport_runtime, "_load_thunder_bluff_elevator_entries", lambda: ())
    transport_runtime.get_world_transport_manager().start()
    transport_runtime.get_movement_manager().tick(0)
    for state in transport_runtime._runtime_transport_states().values():
        transport_runtime._sync_transport_state_from_movement_cache(state)

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
    assert entry["guid"] == transport_runtime._same_map_transport_spawn_guid(7, map_id=1)
    assert entry["world_guid"] == transport_runtime.MoTransportGuid.from_spawn_guid(entry["guid"])
    assert entry["world_db_transport"] is True
    state = transport_runtime._runtime_transport_states()[entry["world_guid"]]
    assert len(state.route) == 4
    assert {node.map_id for node in state.route} == {0, 1}
    assert state.timed_route is True
    assert state.shared_clock_key == "world-db-transport:7"


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
    assert movement_state.transport_guid == transport_runtime.linked_transport_world_guid(entry, map_id=0)


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

    manager.tick_instance(world_guid, server_time_ms=1500)
    waiting = manager.get_transform(world_guid)
    assert waiting.map_id == 1
    assert (waiting.x, waiting.y, waiting.z) == (10.0, 20.0, 5.0)
    assert waiting.state == "DOCKED"
    assert transport_runtime.transport_transfer_destination_map_for_guid(world_guid) is None

    manager.tick_instance(world_guid, server_time_ms=2500)
    transfer = manager.get_transform(world_guid)
    assert transfer.map_id == 1
    assert (transfer.x, transfer.y, transfer.z) == (10.0, 20.0, 5.0)
    assert transfer.state == transport_runtime.TRANSPORT_STATE_TRANSFER_PENDING
    assert transfer.event == "transfer"
    assert transport_runtime.transport_transfer_destination_map_for_guid(world_guid) == 0


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


def test_transport_route_transfer_worldports_attached_passenger(monkeypatch):
    _reset_transport_states()
    now = 500.0
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

    source_guid = int(transport_runtime.MoTransportGuid.from_spawn_guid(100007))
    entry = {
        "guid": 100007,
        "transport_db_guid": 7,
        "world_guid": source_guid,
        "entry": 20808,
        "map": 1,
        "map_id": 1,
        "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
        "display_id": 3015,
        "name": "The Maiden's Fancy",
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
        spawn_guid=100007,
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
        shared_clock_key="world-db-transport:7",
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

    responses = movement._maybe_start_transport_route_transfer(session, "MSG_MOVE_HEARTBEAT")

    assert [name for name, _payload in responses][-3:-1] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.worldport_ack_pending is True
    assert session.map_id == 0
    assert movement_state.transport_guid == transport_runtime.linked_transport_world_guid(entry, map_id=0)
    assert movement_state.transport_x == 2.0
    assert session.x == 102.0
    assert session.y == 203.0
    assert session.z == 14.0

    movement.handle_move_worldport_ack(session, SimpleNamespace())

    assert session.transport_transfer_pending is False
    assert movement_state.has_transport_data is True
    assert movement_state.transport_guid in session.loaded_transport_entries
    assert (
        transport_runtime.get_movement_manager().passenger_attachment(
            movement_state.transport_guid,
            1,
        )
        is not None
    )


def test_transport_transfer_registers_missing_destination_instance(monkeypatch):
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
        "world_db_transport": True,
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
    monkeypatch.setattr(transport_runtime, "_load_thunder_bluff_elevator_entries", lambda: ())
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
