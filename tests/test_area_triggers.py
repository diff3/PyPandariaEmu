#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from types import SimpleNamespace

from server.modules.handlers.world.teleport import area_trigger
from server.modules.handlers.world.teleport.map_transfer import TeleportDestination


def test_movement_segment_crossing_activates_area_trigger(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=60.0,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=500,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=1.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    captured = {}

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {500: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {500: {"id": 500}})
    monkeypatch.setattr(
        area_trigger.DatabaseConnection,
        "get_areatrigger_teleport",
        lambda trigger_id: {
            "id": trigger_id,
            "target_map": 2,
            "target_position_x": 100.0,
            "target_position_y": 200.0,
            "target_position_z": 30.0,
            "target_orientation": 1.5,
        },
    )

    def fake_transfer(target_session, destination, *, reason):
        captured["session"] = target_session
        captured["destination"] = destination
        captured["reason"] = reason
        return [("SMSG_NEW_WORLD", b"area")]

    monkeypatch.setattr(area_trigger, "apply_map_transfer", fake_transfer)

    responses = area_trigger.check_movement_segment_for_area_triggers(
        session,
        (40.0, 0.0, 0.0),
        (60.0, 0.0, 0.0),
    )

    assert responses == [("SMSG_NEW_WORLD", b"area")]
    assert captured["session"] is session
    assert captured["reason"] == "areatrigger"
    assert captured["destination"] == TeleportDestination(
        map_id=2,
        x=100.0,
        y=200.0,
        z=30.0,
        orientation=1.5,
        name="areatrigger:500",
    )


def test_client_areatrigger_outside_dbc_bounds_is_rejected(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=50.0,
        y=50.0,
        z=0.0,
        taxi_in_flight=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=600,
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {600: definition})
    monkeypatch.setattr(
        area_trigger.DatabaseConnection,
        "get_areatrigger_teleport",
        lambda trigger_id: {
            "id": trigger_id,
            "target_map": 2,
            "target_position_x": 100.0,
            "target_position_y": 200.0,
            "target_position_z": 30.0,
            "target_orientation": 1.5,
        },
    )
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"bad")],
    )

    assert area_trigger.activate_area_trigger(session, 600, source="client") == []


def test_movement_segment_inside_trigger_does_not_reactivate(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=51.0,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=700,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=4.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {700: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {700: {"id": 700}})
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"bad")],
    )

    assert area_trigger.check_movement_segment_for_area_triggers(
        session,
        (50.5, 0.0, 0.0),
        (51.0, 0.0, 0.0),
    ) is None


def test_movement_segment_exiting_trigger_does_not_activate(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=70.0,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=701,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=4.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {701: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {701: {"id": 701}})
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"bad")],
    )

    assert area_trigger.check_movement_segment_for_area_triggers(
        session,
        (50.5, 0.0, 0.0),
        (70.0, 0.0, 0.0),
    ) is None


def test_recent_map_transfer_suppresses_movement_scan(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=60.0,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
        _area_trigger_suppressed_until=time.monotonic() + 10.0,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=702,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=1.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {702: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {702: {"id": 702}})
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"bad")],
    )

    assert area_trigger.check_movement_segment_for_area_triggers(
        session,
        (40.0, 0.0, 0.0),
        (60.0, 0.0, 0.0),
    ) is None


def test_movement_scan_uses_exact_dbc_bounds(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=45.0,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=703,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=1.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {703: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {703: {"id": 703, "target_map": 2}})
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"bad")],
    )

    assert not area_trigger._point_inside_trigger(definition, 45.0, 0.0, 0.0)
    assert area_trigger.check_movement_segment_for_area_triggers(
        session,
        (40.0, 0.0, 0.0),
        (45.0, 0.0, 0.0),
    ) is None


def test_movement_scan_blocks_immediate_return_to_previous_map(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=0,
        x=60.0,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
        _area_trigger_return_block_map=33,
        _area_trigger_return_block_until=time.monotonic() + 10.0,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=704,
        map_id=0,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=1.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {704: definition})
    monkeypatch.setattr(
        area_trigger,
        "_teleport_trigger_rows",
        lambda: {
            704: {
                "id": 704,
                "target_map": 33,
                "target_position_x": 1.0,
                "target_position_y": 2.0,
                "target_position_z": 3.0,
                "target_orientation": 4.0,
            }
        },
    )
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"bad")],
    )

    assert area_trigger.check_movement_segment_for_area_triggers(
        session,
        (40.0, 0.0, 0.0),
        (60.0, 0.0, 0.0),
    ) is None


def test_movement_scan_uses_tight_instance_padding(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=0,
        x=47.5,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=705,
        map_id=0,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=1.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {705: definition})
    monkeypatch.setattr(
        area_trigger,
        "_teleport_trigger_rows",
        lambda: {
            705: {
                "id": 705,
                "target_map": 33,
                "target_position_x": 1.0,
                "target_position_y": 2.0,
                "target_position_z": 3.0,
                "target_orientation": 4.0,
            }
        },
    )
    monkeypatch.setattr(area_trigger, "_map_is_instanceable", lambda map_id: int(map_id) == 33)
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"bad")],
    )

    assert area_trigger.check_movement_segment_for_area_triggers(
        session,
        (40.0, 0.0, 0.0),
        (47.5, 0.0, 0.0),
    ) is None


def test_movement_scan_allows_instanceable_target_at_actual_volume(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=0,
        x=50.5,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=706,
        map_id=0,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=1.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    row = {
        "id": 706,
        "target_map": 33,
        "target_position_x": 1.0,
        "target_position_y": 2.0,
        "target_position_z": 3.0,
        "target_orientation": 4.0,
    }

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {706: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {706: row})
    monkeypatch.setattr(area_trigger, "_map_is_instanceable", lambda map_id: int(map_id) == 33)
    monkeypatch.setattr(area_trigger.DatabaseConnection, "get_areatrigger_teleport", lambda trigger_id: row)
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"instance")],
    )

    assert area_trigger.check_movement_segment_for_area_triggers(
        session,
        (40.0, 0.0, 0.0),
        (50.5, 0.0, 0.0),
    ) == [("SMSG_NEW_WORLD", b"instance")]


def test_client_areatrigger_can_use_nearby_teleport_mapping(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        taxi_in_flight=False,
    )
    original = area_trigger.AreaTriggerDefinition(
        trigger_id=800,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    mapped = area_trigger.AreaTriggerDefinition(
        trigger_id=801,
        map_id=1,
        x=52.0,
        y=0.0,
        z=0.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    captured = {}

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {800: original, 801: mapped})
    monkeypatch.setattr(
        area_trigger,
        "_teleport_trigger_rows",
        lambda: {
            801: {
                "id": 801,
                "target_map": 2,
                "target_position_x": 100.0,
                "target_position_y": 200.0,
                "target_position_z": 30.0,
                "target_orientation": 1.5,
            }
        },
    )
    monkeypatch.setattr(area_trigger.DatabaseConnection, "get_areatrigger_teleport", lambda trigger_id: None)

    def fake_transfer(target_session, destination, *, reason):
        captured["destination"] = destination
        return [("SMSG_NEW_WORLD", b"fallback")]

    monkeypatch.setattr(area_trigger, "apply_map_transfer", fake_transfer)

    responses = area_trigger.activate_area_trigger(session, 800, source="client")

    assert responses == [("SMSG_NEW_WORLD", b"fallback")]
    assert captured["destination"].name == "areatrigger:801"


def test_area_trigger_fires_once_until_player_leaves_and_reenters(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=900,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    row = {
        "id": 900,
        "target_map": 1,
        "target_position_x": 50.0,
        "target_position_y": 0.0,
        "target_position_z": 0.0,
        "target_orientation": 0.0,
    }
    activations = []

    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {900: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {900: row})
    monkeypatch.setattr(
        area_trigger.DatabaseConnection,
        "get_areatrigger_teleport",
        lambda trigger_id: row if int(trigger_id) == 900 else None,
    )
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *_args, **_kwargs: activations.append(900)
        or [("SMSG_MOVE_TELEPORT", b"area")],
    )

    assert area_trigger.check_movement_segment_for_area_triggers(
        session, (40.0, 0.0, 0.0), (50.0, 0.0, 0.0)
    ) == [("SMSG_MOVE_TELEPORT", b"area")]
    session.x = 51.0
    assert area_trigger.check_movement_segment_for_area_triggers(
        session, (50.0, 0.0, 0.0), (51.0, 0.0, 0.0)
    ) is None
    assert activations == [900]

    session.x = 60.0
    assert area_trigger.check_movement_segment_for_area_triggers(
        session, (51.0, 0.0, 0.0), (60.0, 0.0, 0.0)
    ) is None
    assert session.active_area_triggers == set()

    # This test covers enter/leave state independently of the temporary
    # AreaTrigger teleport cooldown.
    session.area_trigger_teleport_cooldown_until = 0.0
    session.x = 50.0
    assert area_trigger.check_movement_segment_for_area_triggers(
        session, (60.0, 0.0, 0.0), (50.0, 0.0, 0.0)
    ) == [("SMSG_MOVE_TELEPORT", b"area")]
    assert activations == [900, 900]


def test_position_discontinuity_seeds_destination_trigger_without_firing(monkeypatch):
    session = SimpleNamespace(map_id=2, x=100.0, y=0.0, z=0.0)
    destination = area_trigger.AreaTriggerDefinition(
        trigger_id=901,
        map_id=2,
        x=100.0,
        y=0.0,
        z=0.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {901: destination})

    assert area_trigger.synchronize_area_trigger_state(session) == {901}
    assert area_trigger.activate_area_trigger(session, 901, source="client") == []


def test_client_only_trigger_leave_clears_active_state(monkeypatch):
    session = SimpleNamespace(
        map_id=2,
        x=110.0,
        y=0.0,
        z=0.0,
        near_teleport_pending=False,
        teleport_pending=False,
        active_area_triggers={902},
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=902,
        map_id=2,
        x=100.0,
        y=0.0,
        z=0.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {902: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {})

    assert area_trigger.check_movement_segment_for_area_triggers(
        session,
        (100.0, 0.0, 0.0),
        (110.0, 0.0, 0.0),
    ) is None
    assert session.active_area_triggers == set()


def test_map_transfer_reconciles_active_state_to_destination_volume(monkeypatch):
    from server.modules.handlers.world.teleport import lifecycle, map_transfer

    session = SimpleNamespace(
        map_id=1,
        instance_id=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        active_area_triggers={910},
    )
    destination_trigger = area_trigger.AreaTriggerDefinition(
        trigger_id=911,
        map_id=2,
        x=100.0,
        y=200.0,
        z=30.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    class _Lifecycle:
        def teleport(self, target, destination, **_kwargs):
            target.map_id = destination.map_id
            target.x = destination.x
            target.y = destination.y
            target.z = destination.z
            target.orientation = destination.orientation
            return [("SMSG_NEW_WORLD", b"destination")]

    monkeypatch.setattr(lifecycle, "get_teleport_lifecycle", lambda: _Lifecycle())
    monkeypatch.setattr(map_transfer, "_reset_movement_for_teleport", lambda *_args: None)
    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {911: destination_trigger})

    responses = map_transfer.apply_map_transfer(
        session,
        TeleportDestination(2, 100.0, 200.0, 30.0, 0.5),
        reason="test",
    )

    assert responses == [("SMSG_NEW_WORLD", b"destination")]
    assert session.active_area_triggers == {911}


def test_movement_evaluates_published_world_position_not_transport_local(monkeypatch):
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=100.0,
        y=200.0,
        z=30.0,
        movement_state=SimpleNamespace(
            transport_guid=0x1234,
            transport_x=1.0,
            transport_y=2.0,
            transport_z=3.0,
        ),
        near_teleport_pending=False,
        teleport_pending=False,
    )
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=920,
        map_id=1,
        x=100.0,
        y=200.0,
        z=30.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    row = {
        "id": 920,
        "target_map": 2,
        "target_position_x": 5.0,
        "target_position_y": 6.0,
        "target_position_z": 7.0,
        "target_orientation": 0.0,
    }
    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {920: definition})
    monkeypatch.setattr(area_trigger, "_teleport_trigger_rows", lambda: {920: row})
    monkeypatch.setattr(
        area_trigger.DatabaseConnection,
        "get_areatrigger_teleport",
        lambda _trigger_id: row,
        raising=False,
    )
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda *_args, **_kwargs: [("SMSG_NEW_WORLD", b"transport-trigger")],
    )

    responses = area_trigger.check_movement_segment_for_area_triggers(
        session,
        (97.0, 200.0, 30.0),
        (1.0, 2.0, 3.0),
    )

    assert responses == [("SMSG_NEW_WORLD", b"transport-trigger")]


def test_trigger_bounds_have_no_implicit_position_padding():
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=921,
        map_id=1,
        x=50.0,
        y=0.0,
        z=0.0,
        radius=1.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )

    assert not area_trigger._point_inside_trigger(definition, 45.0, 0.0, 0.0)
    assert area_trigger._point_inside_trigger(definition, 49.0, 0.0, 0.0)


def test_area_trigger_teleport_cooldown_is_per_player_and_expires(monkeypatch):
    clock = {"now": 100.0}
    transfers = []
    definitions = {
        trigger_id: area_trigger.AreaTriggerDefinition(
            trigger_id=trigger_id,
            map_id=1,
            x=10.0,
            y=20.0,
            z=30.0,
            radius=2.0,
            box_x=0.0,
            box_y=0.0,
            box_z=0.0,
            box_orientation=0.0,
        )
        for trigger_id in (930, 931, 932)
    }
    rows = {
        trigger_id: {
            "id": trigger_id,
            "target_map": 2,
            "target_position_x": 1.0,
            "target_position_y": 2.0,
            "target_position_z": 3.0,
            "target_orientation": 0.0,
        }
        for trigger_id in definitions
    }
    session = SimpleNamespace(
        char_guid=1001,
        map_id=1,
        x=10.0,
        y=20.0,
        z=30.0,
        active_area_triggers=set(),
        area_trigger_teleport_cooldown_until=0.0,
    )

    monkeypatch.setattr(area_trigger.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: definitions)
    monkeypatch.setattr(
        area_trigger.DatabaseConnection,
        "get_areatrigger_teleport",
        lambda trigger_id: rows.get(trigger_id),
    )
    monkeypatch.setattr(
        area_trigger,
        "apply_map_transfer",
        lambda _session, destination, **_kwargs: transfers.append(destination) or [
            ("SMSG_NEW_WORLD", b"ok")
        ],
    )

    assert area_trigger.activate_area_trigger(session, 930, source="test")
    assert session.area_trigger_teleport_cooldown_until == 130.0

    clock["now"] = 110.0
    assert area_trigger.activate_area_trigger(session, 931, source="test") == []
    assert len(transfers) == 1

    clock["now"] = 130.0
    assert area_trigger.activate_area_trigger(session, 932, source="test")
    assert len(transfers) == 2


def test_failed_area_trigger_transfer_does_not_start_cooldown(monkeypatch):
    definition = area_trigger.AreaTriggerDefinition(
        trigger_id=933,
        map_id=1,
        x=10.0,
        y=20.0,
        z=30.0,
        radius=2.0,
        box_x=0.0,
        box_y=0.0,
        box_z=0.0,
        box_orientation=0.0,
    )
    row = {
        "id": 933,
        "target_map": 2,
        "target_position_x": 1.0,
        "target_position_y": 2.0,
        "target_position_z": 3.0,
        "target_orientation": 0.0,
    }
    session = SimpleNamespace(
        char_guid=1002,
        map_id=1,
        x=10.0,
        y=20.0,
        z=30.0,
        active_area_triggers=set(),
        area_trigger_teleport_cooldown_until=0.0,
    )
    monkeypatch.setattr(area_trigger.time, "monotonic", lambda: 200.0)
    monkeypatch.setattr(area_trigger, "_area_trigger_definitions", lambda: {933: definition})
    monkeypatch.setattr(
        area_trigger.DatabaseConnection,
        "get_areatrigger_teleport",
        lambda trigger_id: row,
    )
    monkeypatch.setattr(area_trigger, "apply_map_transfer", lambda *args, **kwargs: [])

    assert area_trigger.activate_area_trigger(session, 933, source="test") == []
    assert session.area_trigger_teleport_cooldown_until == 0.0
