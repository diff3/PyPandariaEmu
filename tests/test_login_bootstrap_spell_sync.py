#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
import math
from types import SimpleNamespace
import types

import pytest

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type(
    "DatabaseConnection",
    (),
    {
        "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
        "get_creatures_near": staticmethod(lambda *args, **kwargs: []),
        "get_areatrigger_teleport": staticmethod(lambda *args, **kwargs: None),
    },
)
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

inventory_module = types.ModuleType("server.modules.game.inventory")
inventory_module.refresh_session_inventory = lambda session: None
inventory_module.persist_session_inventory = lambda session, **kwargs: None
sys.modules.setdefault("server.modules.game.inventory", inventory_module)

characters_module = types.ModuleType("server.modules.handlers.world.characters.characters")
characters_module.handle_CMSG_CHAR_CREATE = lambda *args, **kwargs: (0, None)
characters_module.handle_CMSG_CHAR_DELETE = lambda *args, **kwargs: (0, None)
characters_module.handle_CMSG_REORDER_CHARACTERS = lambda *args, **kwargs: (0, None)
sys.modules.setdefault("server.modules.handlers.world.characters.characters", characters_module)

from server.modules.handlers.world.opcodes import login as login_handlers
from server.modules.handlers.world.runtime.player_store import (
    get_player_runtime_store,
)
from server.session.world_session import LoginState
from server.session.world_session import MovementState


def _pending_worldport_session(
    *,
    generation: int = 7,
    owner: str = "transport_worldport",
    source_map: int = 0,
    destination_map: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        char_guid=42,
        world_guid=42,
        login_state=LoginState.IN_WORLD,
        map_id=destination_map,
        instance_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.5,
        teleport_pending=True,
        worldport_ack_pending=True,
        near_teleport_pending=False,
        teleport_destination=f"transport:{source_map}->{destination_map}",
        loading_screen_visible=True,
        loading_screen_done=False,
        post_loading_sent=False,
        world_transition_generation=generation,
        world_transition_loading_generation=generation,
        world_transition_bootstrap_generation=0,
        world_transition_bootstrap_status="IDLE",
        world_transition_owner=owner,
        world_transition_ignore_worldport_ack=False,
        pending_transport_transfer={
            "world_transition_generation": generation,
            "source_map": source_map,
            "destination_map": destination_map,
            "destination_guid": 7,
        },
        transport_transfer_pending=True,
    )


@pytest.mark.parametrize(
    "signals,source_map,destination_map",
    (
        (("loading_screen_notify", "worldport_ack"), 0, 1),
        (("worldport_ack", "loading_screen_notify"), 1, 0),
    ),
)
def test_ratchet_booty_worldport_bootstrap_signal_order_is_idempotent(
    monkeypatch,
    signals,
    source_map,
    destination_map,
) -> None:
    from server.modules.handlers.world.teleport.transition import (
        complete_world_transition,
    )

    session = _pending_worldport_session(
        source_map=source_map,
        destination_map=destination_map,
    )
    calls = []
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda target: SimpleNamespace(map_id=target.map_id),
    )

    def queue(target, ctx):
        calls.append((target.map_id, ctx.map_id))
        target.teleport_pending = False
        target.worldport_ack_pending = False
        target.post_loading_sent = True
        complete_world_transition(target)
        return [("SMSG_UPDATE_OBJECT", b"destination-bootstrap")]

    monkeypatch.setattr(login_handlers, "_queue_teleport_world_transition", queue)
    monkeypatch.setattr(
        login_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )

    first = login_handlers.ensure_worldport_bootstrap_started(
        session,
        signals[0],
        expected_generation=7,
        expected_owner="transport_worldport",
    )
    second = login_handlers.ensure_worldport_bootstrap_started(
        session,
        signals[1],
        expected_generation=7,
        expected_owner="transport_worldport",
    )

    assert first[-1] == ("SMSG_UPDATE_OBJECT", b"destination-bootstrap")
    assert second == []
    assert calls == [(destination_map, destination_map)]
    assert session.world_transition_bootstrap_generation == 7
    assert session.world_transition_bootstrap_status == "COMPLETED"


def test_stale_post_loading_sent_cannot_block_new_transport_bootstrap(
    monkeypatch,
) -> None:
    from server.modules.handlers.world.teleport.transition import (
        complete_world_transition,
    )

    session = _pending_worldport_session()
    session.post_loading_sent = True
    calls = []
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _target: SimpleNamespace(),
    )

    def queue(target, _ctx):
        calls.append(target.world_transition_generation)
        target.teleport_pending = False
        target.worldport_ack_pending = False
        complete_world_transition(target)
        return [("SMSG_UPDATE_OBJECT", b"bootstrap")]

    monkeypatch.setattr(login_handlers, "_queue_teleport_world_transition", queue)
    monkeypatch.setattr(
        login_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )

    responses = login_handlers.ensure_worldport_bootstrap_started(
        session,
        "worldport_ack",
        expected_generation=7,
        expected_owner="transport_worldport",
    )

    assert responses[-1] == ("SMSG_UPDATE_OBJECT", b"bootstrap")
    assert calls == [7]
    assert session.world_transition_bootstrap_generation == 7
    assert session.world_transition_bootstrap_status == "COMPLETED"


def test_stale_loading_notification_cannot_start_bootstrap_during_near_teleport(
    monkeypatch,
) -> None:
    session = _pending_worldport_session(owner="ordinary_teleport")
    session.teleport_pending = False
    session.worldport_ack_pending = False
    session.near_teleport_pending = True
    session.near_teleport_generation = 7
    session.loading_screen_visible = False
    ctx = SimpleNamespace(
        name="CMSG_LOADING_SCREEN_NOTIFY",
        payload=b"",
        decoded={},
    )
    monkeypatch.setattr(login_handlers, "log_cmsg", lambda _ctx: {})
    monkeypatch.setattr(
        login_handlers,
        "_decode_loading_screen_showing",
        lambda _decoded, _payload: 0,
    )
    monkeypatch.setattr(login_handlers, "_resolve_session_ids", lambda _target: None)
    monkeypatch.setattr(
        login_handlers,
        "_queue_world_bootstrap_transition",
        lambda *_args: pytest.fail("stale loading started login bootstrap"),
    )
    monkeypatch.setattr(
        login_handlers,
        "ensure_worldport_bootstrap_started",
        lambda *_args, **_kwargs: pytest.fail(
            "stale loading started worldport bootstrap"
        ),
    )

    assert login_handlers.handle_loading_screen_notify(session, ctx) == (0, None)
    assert session.near_teleport_pending is True
    assert session.world_transition_owner == "ordinary_teleport"
    assert session.world_transition_generation == 7
    assert session.loading_screen_visible is False


def test_bootstrap_state_tombstones_completion_and_resets_other_terminal_paths() -> None:
    from server.modules.handlers.world.teleport.transition import (
        begin_ordinary_teleport_transition,
        complete_world_transition,
        fail_world_transition,
    )

    completed = _pending_worldport_session()
    completed.world_transition_bootstrap_generation = 7
    completed.world_transition_bootstrap_status = "STARTING"
    complete_world_transition(completed)
    assert completed.world_transition_bootstrap_generation == 7
    assert completed.world_transition_bootstrap_status == "COMPLETED"

    failed = _pending_worldport_session()
    failed.world_transition_bootstrap_generation = 7
    failed.world_transition_bootstrap_status = "STARTING"
    assert fail_world_transition(
        failed,
        expected_generation=7,
        expected_owner="transport_worldport",
        reason="test failure",
    ) is True
    assert failed.world_transition_bootstrap_generation == 0
    assert failed.world_transition_bootstrap_status == "IDLE"

    superseded = _pending_worldport_session()
    superseded.world_transition_bootstrap_generation = 7
    superseded.world_transition_bootstrap_status = "STARTING"
    assert begin_ordinary_teleport_transition(superseded) == 8
    assert superseded.world_transition_bootstrap_generation == 0
    assert superseded.world_transition_bootstrap_status == "IDLE"


@pytest.mark.parametrize("signal", ("worldport_ack", "loading_screen_notify"))
def test_duplicate_worldport_bootstrap_signal_is_ignored(monkeypatch, signal) -> None:
    session = _pending_worldport_session()
    session.world_transition_bootstrap_generation = 7
    session.world_transition_bootstrap_status = "STARTING"
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _target: pytest.fail("duplicate rebuilt login context"),
    )

    assert login_handlers.ensure_worldport_bootstrap_started(
        session,
        signal,
        expected_generation=7,
        expected_owner="transport_worldport",
    ) == []


@pytest.mark.parametrize("signal", ("worldport_ack", "loading_screen_notify"))
def test_completed_generation_tombstone_rejects_late_bootstrap_signal(
    monkeypatch,
    signal,
) -> None:
    session = _pending_worldport_session()
    session.world_transition_bootstrap_generation = 7
    session.world_transition_bootstrap_status = "COMPLETED"
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _target: pytest.fail("completed generation restarted bootstrap"),
    )

    assert login_handlers.ensure_worldport_bootstrap_started(
        session,
        signal,
        expected_generation=7,
        expected_owner="transport_worldport",
    ) == []
    assert session.world_transition_bootstrap_generation == 7
    assert session.world_transition_bootstrap_status == "COMPLETED"


def test_two_bidirectional_cycles_build_one_bootstrap_batch_per_generation(
    monkeypatch,
) -> None:
    from server.modules.handlers.world.teleport.transition import (
        begin_transport_worldport_transition,
        complete_world_transition,
    )

    session = _pending_worldport_session(source_map=0, destination_map=1)
    built_destinations = []
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda target: SimpleNamespace(map_id=target.map_id),
    )

    def queue(target, _ctx):
        built_destinations.append(target.map_id)
        target.teleport_pending = False
        target.worldport_ack_pending = False
        complete_world_transition(target)
        return [("SMSG_UPDATE_OBJECT", b"bootstrap")]

    monkeypatch.setattr(login_handlers, "_queue_teleport_world_transition", queue)
    monkeypatch.setattr(
        login_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )

    for cycle_index, destination_map in enumerate((1, 0, 1, 0)):
        if cycle_index:
            begin_transport_worldport_transition(session)
        generation = int(session.world_transition_generation)
        session.map_id = destination_map
        session.teleport_pending = True
        session.worldport_ack_pending = True
        session.pending_transport_transfer = {
            "world_transition_generation": generation,
            "source_map": 1 - destination_map,
            "destination_map": destination_map,
        }
        first_signal = (
            "loading_screen_notify" if cycle_index % 2 == 0 else "worldport_ack"
        )
        late_signal = (
            "worldport_ack" if first_signal == "loading_screen_notify"
            else "loading_screen_notify"
        )

        assert login_handlers.ensure_worldport_bootstrap_started(
            session,
            first_signal,
            expected_generation=generation,
            expected_owner="transport_worldport",
        )
        assert login_handlers.ensure_worldport_bootstrap_started(
            session,
            late_signal,
            expected_generation=generation,
            expected_owner="transport_worldport",
        ) == []
        assert session.world_transition_bootstrap_generation == generation
        assert session.world_transition_bootstrap_status == "COMPLETED"

    assert built_destinations == [1, 0, 1, 0]


def test_stale_worldport_ack_generation_cannot_start_bootstrap(monkeypatch) -> None:
    session = _pending_worldport_session(generation=8)
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _target: pytest.fail("stale ACK built login context"),
    )

    assert login_handlers.ensure_worldport_bootstrap_started(
        session,
        "worldport_ack",
        expected_generation=7,
        expected_owner="transport_worldport",
    ) == []
    assert session.teleport_pending is True
    assert session.world_transition_bootstrap_status == "IDLE"


def test_ack_triggered_bootstrap_failure_uses_terminal_failure_path(
    monkeypatch,
) -> None:
    session = _pending_worldport_session()
    pending = session.pending_transport_transfer
    failures = []
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _target: SimpleNamespace(),
    )
    monkeypatch.setattr(
        login_handlers,
        "_queue_teleport_world_transition",
        lambda _target, _ctx: (_ for _ in ()).throw(
            RuntimeError("ACK bootstrap failed")
        ),
    )
    monkeypatch.setattr(
        login_handlers,
        "_fail_transport_worldport_bootstrap",
        lambda target, target_pending, *, reason: failures.append(
            (target, target_pending, reason)
        )
        or [("SMSG_NEW_WORLD", b"safe-fallback")],
    )

    responses = login_handlers.ensure_worldport_bootstrap_started(
        session,
        "worldport_ack",
        expected_generation=7,
        expected_owner="transport_worldport",
    )

    assert responses == [("SMSG_NEW_WORLD", b"safe-fallback")]
    assert failures == [(session, pending, "ACK bootstrap failed")]
    assert session.world_transition_bootstrap_generation == 7
    assert session.world_transition_bootstrap_status == "FAILED"


def test_pending_boat_sync_preserves_attachment_before_bootstrap(monkeypatch) -> None:
    from server.modules.handlers.world import transport_runtime
    from server.modules.handlers.world.runtime.player import Player
    from server.modules.handlers.world.runtime.player_store import (
        get_player_runtime_store,
    )

    transport_guid = 0x1FC0000000000007
    runtime = SimpleNamespace(
        guid=transport_guid,
        map_id=0,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=math.pi / 2.0,
        path_progress_ms=4321,
    )
    monkeypatch.setattr(transport_runtime, "is_cross_map_boat_entry", lambda _entry: True)
    monkeypatch.setattr(transport_runtime, "is_cross_map_zeppelin_entry", lambda _entry: False)
    monkeypatch.setattr(
        transport_runtime,
        "current_runtime_transport_state_for_guid",
        lambda guid: runtime if guid == transport_guid else None,
    )
    session = SimpleNamespace(
        char_guid=91,
        world_guid=91,
        instance_id=0,
        map_id=0,
        x=-500.0,
        y=-600.0,
        z=-10.0,
        orientation=0.0,
        movement_state=MovementState(),
        pending_transport_transfer={
            "transfer_id": "16-pre-bootstrap",
            "destination_guid": transport_guid,
            "destination_map": 0,
            "destination_entry": {"entry": 20808},
            "base_x": -1000.0,
            "base_y": -2000.0,
            "local_x": 2.0,
            "local_y": 3.0,
            "local_z": 4.0,
            "local_o": 0.25,
        },
    )

    player_store = get_player_runtime_store()
    player_store.clear()
    player = player_store.add(Player.from_session(session))
    try:
        synced = login_handlers._sync_pending_transport_before_player_bootstrap(
            session
        )
    finally:
        player_store.clear()

    assert synced is True
    assert session.x == pytest.approx(97.0)
    assert session.y == pytest.approx(202.0)
    assert session.z == pytest.approx(14.0)
    assert session.orientation == pytest.approx((math.pi / 2.0) + 0.25)
    assert (player.map_id, player.x, player.y, player.z, player.orientation) == (
        pytest.approx(0),
        pytest.approx(97.0),
        pytest.approx(202.0),
        pytest.approx(14.0),
        pytest.approx((math.pi / 2.0) + 0.25),
    )
    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == transport_guid
    assert session.movement_state.transport_x == pytest.approx(2.0)
    assert session.movement_state.transport_y == pytest.approx(3.0)
    assert session.movement_state.transport_z == pytest.approx(4.0)
    assert session.movement_state.transport_orientation == pytest.approx(0.25)
    assert session.movement_state.transport_time == 4321
    assert session._player_bootstrap_runtime_transport == {
        "transport_guid": transport_guid,
        "map_id": 0,
        "x": 100.0,
        "y": 200.0,
        "z": 10.0,
        "orientation": math.pi / 2.0,
        "route_phase": 4321,
        "local_x": 2.0,
        "local_y": 3.0,
        "local_z": 4.0,
        "local_o": 0.25,
        "rotated_x": pytest.approx(-3.0),
        "rotated_y": pytest.approx(2.0),
        "rotated_z": pytest.approx(4.0),
    }


def test_pending_boat_sync_missing_runtime_keeps_snapshot_and_does_not_block(monkeypatch) -> None:
    from server.modules.handlers.world import transport_runtime

    monkeypatch.setattr(transport_runtime, "is_cross_map_boat_entry", lambda _entry: True)
    monkeypatch.setattr(transport_runtime, "is_cross_map_zeppelin_entry", lambda _entry: False)
    monkeypatch.setattr(
        transport_runtime,
        "current_runtime_transport_state_for_guid",
        lambda _guid: None,
    )
    state = MovementState()
    session = SimpleNamespace(
        map_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.5,
        movement_state=state,
        pending_transport_transfer={
            "transfer_id": "16-fallback",
            "destination_guid": 7,
            "destination_map": 0,
            "destination_entry": {"entry": 20808},
            "local_x": 2.0,
        },
    )

    assert login_handlers._sync_pending_transport_before_player_bootstrap(session) is False
    assert (session.x, session.y, session.z, session.orientation) == (10.0, 20.0, 30.0, 0.5)
    assert getattr(state, "has_transport_data", False) is False


def test_normal_bootstrap_has_no_transport_sync_side_effects() -> None:
    state = MovementState()
    session = SimpleNamespace(
        map_id=1,
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.4,
        movement_state=state,
        pending_transport_transfer=None,
    )

    assert login_handlers._sync_pending_transport_before_player_bootstrap(session) is False
    assert (session.x, session.y, session.z, session.orientation) == (1.0, 2.0, 3.0, 0.4)
    assert getattr(state, "has_transport_data", False) is False


def test_replacement_worldport_loading_completion_bootstraps_manual_destination(
    monkeypatch,
) -> None:
    from server.modules.handlers.world.teleport.transition import (
        complete_world_transition,
    )
    from server.modules.handlers.world.state.runtime import is_player_world_active

    session = SimpleNamespace(
        char_guid=1,
        world_guid=0x1000000000000001,
        login_state=LoginState.IN_WORLD,
        map_id=530,
        instance_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.5,
        teleport_pending=True,
        worldport_ack_pending=True,
        near_teleport_pending=False,
        teleport_destination="manual:530:10:20:30:1.5",
        loading_screen_visible=False,
        loading_screen_done=False,
        post_loading_sent=False,
        world_transition_generation=2,
        world_transition_owner="ordinary_teleport",
        world_transition_ignore_worldport_ack=True,
        world_transition_loading_generation=2,
        pending_transport_transfer=None,
        transport_transfer_pending=False,
    )
    ctx = SimpleNamespace(
        name="CMSG_LOADING_SCREEN_NOTIFY",
        payload=b"",
        decoded={},
    )
    showing_values = iter((0,))
    bootstrap_calls = []

    monkeypatch.setattr(login_handlers, "log_cmsg", lambda _ctx: {})
    monkeypatch.setattr(
        login_handlers,
        "_decode_loading_screen_showing",
        lambda _decoded, _payload: next(showing_values),
    )
    monkeypatch.setattr(login_handlers, "_resolve_session_ids", lambda _session: None)
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _session: SimpleNamespace(),
    )

    def queue_manual_destination(target, _ctx):
        assert is_player_world_active(target) is False
        bootstrap_calls.append(
            (
                target.map_id,
                target.instance_id,
                target.x,
                target.y,
                target.z,
                target.orientation,
            )
        )
        target.teleport_pending = False
        target.worldport_ack_pending = False
        target.teleport_destination = None
        complete_world_transition(target)
        return [("SMSG_UPDATE_OBJECT", b"manual-destination-visible")]

    monkeypatch.setattr(
        login_handlers,
        "_queue_teleport_world_transition",
        queue_manual_destination,
    )
    monkeypatch.setattr(
        login_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )

    complete_status, complete_responses = login_handlers.handle_loading_screen_notify(
        session,
        ctx,
    )
    assert complete_status == 0
    assert bootstrap_calls == [(530, 0, 10.0, 20.0, 30.0, 1.5)]
    assert complete_responses[-1] == (
        "SMSG_UPDATE_OBJECT",
        b"manual-destination-visible",
    )
    assert session.teleport_pending is False
    assert session.worldport_ack_pending is False
    assert session.pending_transport_transfer is None
    assert session.transport_transfer_pending is False
    assert session.world_transition_owner is None
    assert session.world_transition_ignore_worldport_ack is False
    assert is_player_world_active(session) is True
    assert (session.map_id, session.instance_id) == (530, 0)
    assert (session.x, session.y, session.z, session.orientation) == (
        10.0,
        20.0,
        30.0,
        1.5,
    )


def test_superseded_transport_snapshot_cannot_enter_player_bootstrap() -> None:
    state = MovementState()
    session = SimpleNamespace(
        world_transition_generation=2,
        transport_transfer_pending=True,
        pending_transport_transfer={
            "world_transition_generation": 1,
            "destination_guid": 77,
            "destination_entry": {"entry": 20808},
            "local_x": 4.0,
            "local_y": 5.0,
            "local_z": 6.0,
            "local_o": 0.7,
        },
        movement_state=state,
    )

    assert login_handlers._sync_pending_transport_before_player_bootstrap(session) is False
    assert session.pending_transport_transfer is None
    assert session.transport_transfer_pending is False
    assert getattr(state, "has_transport_data", False) is False
    assert int(getattr(state, "transport_guid", 0) or 0) == 0


def test_transport_bootstrap_player_create_uses_runtime_position_with_transport_block(
    monkeypatch,
) -> None:
    transport_guid = 0x1FC0000000000007
    pending = {"transfer_id": "16-wire-baseline", "destination_guid": transport_guid}
    movement_state = MovementState()
    movement_state.has_transport_data = True
    movement_state.transport_guid = transport_guid
    movement_state.transport_x = 2.0
    movement_state.transport_y = 3.0
    movement_state.transport_z = 4.0
    movement_state.transport_orientation = 0.25
    session = SimpleNamespace(
        x=97.0,
        y=202.0,
        z=14.0,
        orientation=1.75,
        movement_state=movement_state,
        pending_transport_transfer=pending,
        _player_bootstrap_runtime_transport={
            "transport_guid": transport_guid,
            "route_phase": 4321,
            "x": 100.0,
            "y": 200.0,
            "z": 10.0,
            "orientation": 1.5,
            "local_x": 2.0,
            "local_y": 3.0,
            "local_z": 4.0,
            "local_o": 0.25,
            "rotated_x": -3.0,
            "rotated_y": 2.0,
            "rotated_z": 4.0,
            "transport_create_transform_matched": True,
        },
    )
    captured = {}
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _session: SimpleNamespace(
            x=_session.x,
            y=_session.y,
            z=_session.z,
            orientation=_session.orientation,
            has_transport_data=True,
            transport_guid=_session.movement_state.transport_guid,
            transport_x=_session.movement_state.transport_x,
            transport_y=_session.movement_state.transport_y,
            transport_z=_session.movement_state.transport_z,
            transport_orientation=_session.movement_state.transport_orientation,
            transport_time=1234,
        ),
    )
    monkeypatch.setattr(
        login_handlers,
        "build_login_packet",
        lambda opcode, ctx: captured.update(
            {
                opcode: (
                    ctx.x,
                    ctx.y,
                    ctx.z,
                    ctx.orientation,
                    ctx.has_transport_data,
                    getattr(ctx, "transport_guid", 0),
                )
            }
        )
        or b"packet",
    )
    monkeypatch.setattr(
        login_handlers,
        "build_database_gameobject_responses",
        lambda _session: [("SMSG_UPDATE_OBJECT", b"transport-create")],
    )

    responses = login_handlers.build_player_bootstrap_packets(session)

    assert captured["SMSG_UPDATE_OBJECT_1773613176_0002"] == (
        97.0,
        202.0,
        14.0,
        1.75,
        True,
        transport_guid,
    )
    assert responses[1] == ("SMSG_UPDATE_OBJECT", b"transport-create")
    assert responses[2] == ("SMSG_UPDATE_OBJECT", b"packet")
    assert movement_state.has_transport_data is True
    assert movement_state.transport_guid == transport_guid
    assert session.pending_transport_transfer is pending


@pytest.mark.parametrize(
    ("variant", "expected"),
    (
        ("A", ["SMSG_MOVE_SET_ACTIVE_MOVER", "transport", "player"]),
        ("B", ["SMSG_MOVE_SET_ACTIVE_MOVER", "player", "transport"]),
        (
            "C",
            [
                "SMSG_MOVE_SET_ACTIVE_MOVER",
                "transport",
                "player",
                "SMSG_MOVE_SET_ACTIVE_MOVER",
            ],
        ),
        ("D", ["SMSG_MOVE_SET_ACTIVE_MOVER", "transport", "player"]),
    ),
)
def test_transport_worldport_bootstrap_variants_change_only_targeted_create_order(
    monkeypatch,
    variant,
    expected,
) -> None:
    session = SimpleNamespace(
        _worldport_bootstrap_variant=variant,
        _player_bootstrap_runtime_transport={
            "transport_guid": 9,
            "route_phase": 10,
            "x": 1.0,
            "y": 2.0,
            "z": 3.0,
            "orientation": 0.0,
            "local_x": 0.0,
            "local_y": 0.0,
            "local_z": 0.0,
            "local_o": 0.0,
            "rotated_x": 0.0,
            "rotated_y": 0.0,
            "rotated_z": 0.0,
            "transport_create_transform_matched": True,
        },
        movement_state=MovementState(),
        player_object_sent=False,
    )
    ctx = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.0,
        has_transport_data=True,
        transport_guid=9,
        transport_x=0.0,
        transport_y=0.0,
        transport_z=0.0,
        transport_orientation=0.0,
        transport_time=10,
    )
    monkeypatch.setattr(login_handlers, "_build_world_login_context", lambda _session: ctx)
    monkeypatch.setattr(login_handlers, "resolve_player_runtime", lambda _session: None)
    monkeypatch.setattr(
        login_handlers,
        "build_login_packet",
        lambda opcode, _ctx: b"active" if opcode == "SMSG_MOVE_SET_ACTIVE_MOVER" else b"player",
    )
    monkeypatch.setattr(
        login_handlers,
        "build_database_gameobject_responses",
        lambda _session: [("transport", b"create")],
    )
    monkeypatch.setattr(login_handlers, "log_transport_packet_snapshot", lambda *args, **kwargs: None)

    responses = login_handlers.build_player_bootstrap_packets(session)

    labels = [
        "player"
        if opcode == "SMSG_UPDATE_OBJECT" and payload == b"player"
        else opcode
        for opcode, payload in responses
    ]
    assert labels == expected
    assert labels.count("player") == 1


def test_transport_worldport_variant_d_resets_and_replays_visibility_once(monkeypatch) -> None:
    from server.modules.handlers.world.opcodes import movement as movement_handlers

    session = SimpleNamespace(
        _worldport_bootstrap_variant="D",
        loaded_gameobjects={1},
        loaded_gameobject_entries={1: {}},
        loaded_transport_entries={1: {}},
        loaded_npcs={2},
        npc_flags_by_guid={2: 0},
    )
    contexts = []
    monkeypatch.setattr(
        movement_handlers,
        "stream_world_objects_after_teleport",
        lambda target, *, context: contexts.append(
            (context, set(getattr(target, "loaded_gameobjects", set())))
        ) or [("SMSG_UPDATE_OBJECT", context.encode())],
    )
    monkeypatch.setattr(login_handlers, "gameobjects_enabled", lambda: True)
    monkeypatch.setattr(login_handlers, "npcs_enabled", lambda: True)
    monkeypatch.setattr(login_handlers, "npc_auto_stream_enabled", lambda: True)

    login_handlers._reset_loaded_world_object_state(session)
    replay = movement_handlers.stream_world_objects_after_teleport(
        session,
        context="worldport-variant-d-visibility-replay",
    )

    assert contexts == [("worldport-variant-d-visibility-replay", set())]
    assert replay == [("SMSG_UPDATE_OBJECT", b"worldport-variant-d-visibility-replay")]


def test_build_player_bootstrap_packets_uses_native_builders(monkeypatch) -> None:
    session = SimpleNamespace()
    calls: list[str] = []

    monkeypatch.setattr(login_handlers, "_build_world_login_context", lambda _session: SimpleNamespace())
    monkeypatch.setattr(
        login_handlers,
        "build_login_packet",
        lambda opcode_name, _ctx: calls.append(opcode_name)
        or {
            "SMSG_MOVE_SET_ACTIVE_MOVER": b"active-mover",
            "SMSG_UPDATE_OBJECT_1773613176_0002": b"player-create",
        }.get(opcode_name),
    )
    monkeypatch.setattr(
        login_handlers,
        "build_database_gameobject_responses",
        lambda _session: [("SMSG_UPDATE_OBJECT", b"gameobject-create")],
    )

    assert login_handlers.build_player_bootstrap_packets(session) == [
        ("SMSG_MOVE_SET_ACTIVE_MOVER", b"active-mover"),
        ("SMSG_UPDATE_OBJECT", b"player-create"),
        ("SMSG_UPDATE_OBJECT", b"gameobject-create"),
    ]
    assert calls == ["SMSG_MOVE_SET_ACTIVE_MOVER", "SMSG_UPDATE_OBJECT_1773613176_0002"]
    assert session.player_object_sent is True


def test_pending_transport_transfer_syncs_before_player_bootstrap(monkeypatch) -> None:
    from server.modules.handlers.world import transport_runtime

    transport_guid = 0x1FC0000000000007
    runtime_state = SimpleNamespace(
        guid=transport_guid,
        map_id=1,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=math.pi / 2.0,
        path_progress_ms=4321,
    )
    monkeypatch.setattr(
        transport_runtime,
        "current_runtime_transport_state_for_guid",
        lambda guid: runtime_state if guid == transport_guid else None,
    )
    session = SimpleNamespace(
        map_id=1,
        x=-1.0,
        y=-2.0,
        z=-3.0,
        orientation=0.0,
        movement_state=MovementState(),
        pending_transport_transfer={
            "transfer_id": "transport-16-test",
            "destination_guid": transport_guid,
            "destination_map": 1,
            "local_x": 2.0,
            "local_y": 3.0,
            "local_z": 4.0,
            "local_o": 0.25,
            "destination_entry": {
                "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
                "world_db_transport": True,
                "entry": 20808,
            },
        },
    )

    assert login_handlers._sync_pending_transport_before_player_bootstrap(session) is True
    assert session.x == pytest.approx(97.0)
    assert session.y == pytest.approx(202.0)
    assert session.z == pytest.approx(14.0)
    assert session.orientation == pytest.approx((math.pi / 2.0) + 0.25)
    assert session.movement_state.has_transport_data is True
    assert session.movement_state.transport_guid == transport_guid
    assert session.movement_state.transport_time == 4321


def test_character_login_bootstrap_keeps_verify_world_and_existing_order(monkeypatch) -> None:
    """Keep the initial-login pre-create bundle and its ordering unchanged."""
    from server.modules.handlers.world.opcodes import movement as movement_handlers

    session = SimpleNamespace(
        post_loading_sent=False,
        player_object_sent=False,
        loading_screen_done=False,
        login_state=LoginState.PLAYER_LOGIN,
    )
    ctx = SimpleNamespace()
    state_changes: list[LoginState] = []

    monkeypatch.setattr(
        login_handlers,
        "_set_login_state",
        lambda _session, state: state_changes.append(state),
    )
    monkeypatch.setattr(
        login_handlers,
        "build_pre_update_object_packets",
        lambda _ctx: [
            ("SMSG_LOGIN_VERIFY_WORLD", b"verify"),
            ("SMSG_LOGIN_SET_TIME_SPEED", b"time"),
            ("SMSG_BIND_POINT_UPDATE", b"bind"),
        ],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_player_bootstrap_packets",
        lambda _session: [("SMSG_UPDATE_OBJECT", b"create")],
    )
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_active_mover_spell_sync_responses",
        lambda _session: [("SMSG_SEND_KNOWN_SPELLS", b"known-spells")],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_login_inventory_sync_responses",
        lambda _session: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "trigger_inventory_activation",
        lambda _session: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_explored_zones_update_response",
        lambda _session: None,
    )
    monkeypatch.setattr(
        login_handlers,
        "build_post_update_object_packets",
        lambda _ctx: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_world_bootstrap_packets",
        lambda _ctx: [
            ("SMSG_MOVE_SET_ACTIVE_MOVER", b"active-mover"),
            ("BOOT", b"boot"),
        ],
    )
    monkeypatch.setattr(
        movement_handlers,
        "stream_world_objects_after_teleport",
        lambda _session, *, context: [],
    )

    responses = login_handlers._queue_world_bootstrap_transition(session, ctx)

    assert state_changes == [LoginState.WORLD_BOOTSTRAP]
    assert responses == [
        ("SMSG_LOGIN_VERIFY_WORLD", b"verify"),
        ("SMSG_LOGIN_SET_TIME_SPEED", b"time"),
        ("SMSG_BIND_POINT_UPDATE", b"bind"),
        ("SMSG_UPDATE_OBJECT", b"create"),
        ("SMSG_SEND_KNOWN_SPELLS", b"known-spells"),
        ("BOOT", b"boot"),
    ]
    assert session.loading_screen_done is True
    assert session.post_loading_sent is True


def test_world_bootstrap_refreshes_weather_before_weather_packet(monkeypatch) -> None:
    """Use current session weather when the initial SMSG_WEATHER is built."""
    from server.modules.handlers.world.opcodes import movement as movement_handlers

    session = SimpleNamespace(
        post_loading_sent=False,
        player_object_sent=True,
        loading_screen_done=False,
        login_state=LoginState.PLAYER_LOGIN,
        weather={"weather_type": 0, "density": 0.0, "abrupt": 0},
    )
    ctx = SimpleNamespace(weather={})
    captured_weather = {}

    monkeypatch.setattr(login_handlers, "_set_login_state", lambda _session, _state: None)
    monkeypatch.setattr(login_handlers, "build_pre_update_object_packets", lambda _ctx: [])
    monkeypatch.setattr(login_handlers, "build_post_update_object_packets", lambda _ctx: [])
    monkeypatch.setattr(
        login_handlers,
        "refresh_region_weather",
        lambda current_session: setattr(
            current_session,
            "weather",
            {"weather_type": 5, "density": 0.75, "abrupt": 0},
        ),
    )
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_active_mover_spell_sync_responses",
        lambda _session: [],
    )
    monkeypatch.setattr(login_handlers, "build_login_inventory_sync_responses", lambda _session: [])
    monkeypatch.setattr(login_handlers, "trigger_inventory_activation", lambda _session: [])
    monkeypatch.setattr(login_handlers, "build_explored_zones_update_response", lambda _session: None)

    def build_bootstrap(current_ctx):
        captured_weather.update(current_ctx.weather)
        return [("SMSG_WEATHER", b"weather")]

    monkeypatch.setattr(login_handlers, "build_world_bootstrap_packets", build_bootstrap)
    monkeypatch.setattr(
        movement_handlers,
        "stream_world_objects_after_teleport",
        lambda _session, *, context: [],
    )

    responses = login_handlers._queue_world_bootstrap_transition(session, ctx)

    assert captured_weather == {"weather_type": 5, "density": 0.75, "abrupt": 0}
    assert ctx.weather == {"weather_type": 5, "density": 0.75, "abrupt": 0}
    assert responses == [("SMSG_WEATHER", b"weather")]


def test_world_bootstrap_streams_world_objects_immediately(monkeypatch) -> None:
    from server.modules.handlers.world.opcodes import movement as movement_handlers

    session = SimpleNamespace(
        post_loading_sent=False,
        player_object_sent=True,
        loading_screen_done=False,
        login_state=LoginState.PLAYER_LOGIN,
        loaded_gameobjects=set(),
        loaded_transport_entries={},
        loaded_npcs=set(),
    )
    ctx = SimpleNamespace()
    calls: list[str] = []

    monkeypatch.setattr(login_handlers, "_set_login_state", lambda _session, _state: None)
    monkeypatch.setattr(login_handlers, "refresh_region_weather", lambda _session: None)
    monkeypatch.setattr(login_handlers, "build_pre_update_object_packets", lambda _ctx: [])
    monkeypatch.setattr(login_handlers, "build_post_update_object_packets", lambda _ctx: [])
    monkeypatch.setattr(login_handlers, "build_world_bootstrap_packets", lambda _ctx: [])
    monkeypatch.setattr(login_handlers.spells_handlers, "build_active_mover_spell_sync_responses", lambda _session: [])
    monkeypatch.setattr(login_handlers, "build_login_inventory_sync_responses", lambda _session: [])
    monkeypatch.setattr(login_handlers, "trigger_inventory_activation", lambda _session: [])
    monkeypatch.setattr(login_handlers, "build_explored_zones_update_response", lambda _session: None)
    monkeypatch.setattr(
        movement_handlers,
        "stream_world_objects_after_teleport",
        lambda _session, *, context: calls.append(context)
        or _session.loaded_gameobjects.add(11)
        or _session.loaded_npcs.add(22)
        or [("SMSG_UPDATE_OBJECT", b"login-visible")],
    )

    responses = login_handlers._queue_world_bootstrap_transition(session, ctx)

    assert calls == ["login-bootstrap-complete"]
    assert session.loaded_gameobjects == {11}
    assert session.loaded_npcs == {22}
    assert responses == [("SMSG_UPDATE_OBJECT", b"login-visible")]


def test_cinematic_only_triggers_for_pending_state() -> None:
    assert login_handlers._resolve_pending_cinematic_id(1, 0) == 0
    assert login_handlers._resolve_pending_cinematic_id(1, 1) == 0
    assert login_handlers._resolve_pending_cinematic_id(1, 2) == 81


def test_pending_cinematic_response_marks_character_played(monkeypatch) -> None:
    saved = {}
    encoded = {}
    session = SimpleNamespace(
        pending_cinematic_id=259,
        char_guid=24,
        realm_id=1,
        race=26,
    )

    monkeypatch.setattr(
        login_handlers.EncoderHandler,
        "encode_packet",
        lambda name, fields: encoded.update(packet=(name, fields)) or b"cinematic",
    )
    monkeypatch.setattr(
        login_handlers.DatabaseConnection,
        "save_character_cinematic_state",
        lambda guid, realm_id, cinematic: saved.update(
            guid=guid,
            realm_id=realm_id,
            cinematic=cinematic,
        ) or True,
        raising=False,
    )

    responses = login_handlers._build_pending_cinematic_response(session)

    assert responses == [("SMSG_TRIGGER_CINEMATIC", b"cinematic")]
    assert encoded["packet"] == ("SMSG_TRIGGER_CINEMATIC", {"cinematic_id": 259})
    assert saved == {"guid": 24, "realm_id": 1, "cinematic": 1}
    assert session.pending_cinematic_id == 0
    assert session.cinematic_played == 1


def test_active_mover_sends_mount_restore_after_known_spells(monkeypatch) -> None:
    session = SimpleNamespace(
        login_state=LoginState.WORLD_BOOTSTRAP,
        player_object_sent=True,
        char_guid=7,
        world_guid=7,
        map_id=1,
        instance_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.5,
        motd="",
        chat_motd_sent=False,
        account_settings_sent=False,
        pending_world_attachment_restore={
            "status": "PREPARED",
            "runtime_guid": 7,
        },
    )
    calls: list[str] = []

    monkeypatch.setattr(login_handlers, "sync_player_visibility", lambda _session: None)
    monkeypatch.setattr(login_handlers, "sync_all_players_on_map", lambda _map_id: None)
    monkeypatch.setattr(login_handlers, "_build_world_login_context", lambda _session: SimpleNamespace(motd=""))
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_active_mover_spell_sync_responses",
        lambda _session: calls.append("known") or [("SMSG_SEND_KNOWN_SPELLS", b"known")],
    )
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_login_mount_restore_responses",
        lambda _session: calls.append("mount") or [("SMSG_MOVE_SET_CAN_FLY", b"fly")],
    )

    store = get_player_runtime_store()
    store.clear()
    try:
        status, responses = login_handlers.handle_set_active_mover(
            session,
            SimpleNamespace(),
        )
        player = store.get(7)
        assert player is not None
        assert player.runtime_guid == 7
        assert session.pending_world_attachment_restore is None
        assert player.world_position == (10.0, 20.0, 30.0)
        assert list(store) == [player]

        duplicate_status, duplicate_responses = (
            login_handlers.handle_set_active_mover(session, SimpleNamespace())
        )

        assert duplicate_status == 0
        assert duplicate_responses is None
        assert store.get(7) is player
        assert list(store) == [player]
    finally:
        store.clear()

    assert status == 0
    assert session.login_state == LoginState.IN_WORLD
    assert calls == ["known", "mount"]
    assert responses == [
        ("SMSG_SEND_KNOWN_SPELLS", b"known"),
        ("SMSG_MOVE_SET_CAN_FLY", b"fly"),
    ]


def test_far_worldport_active_mover_does_not_replay_known_spells(monkeypatch) -> None:
    session = SimpleNamespace(
        login_state=LoginState.WORLD_BOOTSTRAP,
        player_object_sent=True,
        char_guid=8,
        world_guid=8,
        map_id=1,
        instance_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.5,
        motd="",
        chat_motd_sent=False,
        account_settings_sent=False,
        pending_world_attachment_restore=None,
        _far_worldport_known_spells_sent=True,
    )
    calls: list[str] = []

    monkeypatch.setattr(login_handlers, "sync_player_visibility", lambda _session: None)
    monkeypatch.setattr(login_handlers, "sync_all_players_on_map", lambda _map_id: None)
    monkeypatch.setattr(login_handlers, "_build_world_login_context", lambda _session: SimpleNamespace(motd=""))
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_active_mover_spell_sync_responses",
        lambda _session: calls.append("known") or [("SMSG_SEND_KNOWN_SPELLS", b"known")],
    )
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_login_mount_restore_responses",
        lambda _session: calls.append("mount") or [("SMSG_MOVE_SET_CAN_FLY", b"fly")],
    )

    store = get_player_runtime_store()
    store.clear()
    try:
        status, responses = login_handlers.handle_set_active_mover(session, SimpleNamespace())
    finally:
        store.clear()

    assert status == 0
    assert calls == ["mount"]
    assert responses == [("SMSG_MOVE_SET_CAN_FLY", b"fly")]
    assert session._far_worldport_known_spells_sent is False


def test_far_transport_worldport_omits_verify_world_and_keeps_bootstrap_order(monkeypatch) -> None:
    """Exclude login-only verification without changing the far-worldport sequence."""
    from server.modules.handlers.world import transport_runtime
    from server.modules.handlers.world.opcodes import movement as movement_handlers

    session = SimpleNamespace(
        loading_screen_done=False,
        post_loading_sent=False,
        teleport_pending=True,
        worldport_ack_pending=True,
        near_teleport_pending=False,
        teleport_destination="test",
        loaded_gameobjects={0x1FC00000000186A7},
        loaded_transport_entries={0x1FC00000000186A7: 176495},
        loaded_npcs={1234},
        npc_flags_by_guid={1234: 0},
    )
    ctx = SimpleNamespace()
    state_changes: list[LoginState] = []
    player_bootstrap_loaded_state: list[tuple[set[int], dict[int, int]]] = []
    transport_refresh_state: list[tuple[set[int], dict[int, int]]] = []
    bootstrap_order: list[str] = []

    monkeypatch.setattr(
        login_handlers,
        "_set_login_state",
        lambda _session, state: state_changes.append(state),
    )
    monkeypatch.setattr(
        login_handlers,
        "build_login_packet",
        lambda opcode_name, _ctx: {
            "SMSG_LOGIN_VERIFY_WORLD": b"verify",
            "SMSG_LOGIN_SET_TIME_SPEED": b"time",
            "SMSG_BIND_POINT_UPDATE": b"bind",
            "SMSG_TIME_SYNC_REQUEST": b"sync",
            "SMSG_PHASE_SHIFT_CHANGE": b"phase",
            "SMSG_INIT_WORLD_STATES": b"states",
            "SMSG_WEATHER": b"weather",
            "SMSG_QUERY_TIME_RESPONSE": b"query-time",
        }.get(opcode_name),
    )
    monkeypatch.setattr(
        login_handlers,
        "build_player_bootstrap_packets",
        lambda _session: bootstrap_order.append("player_bootstrap")
        or player_bootstrap_loaded_state.append(
            (set(_session.loaded_gameobjects), dict(_session.loaded_transport_entries))
        )
        or _session.loaded_gameobjects.add(0x1FC00000000186A7)
        or _session.loaded_transport_entries.update({0x1FC00000000186A7: {"entry": 176495}})
        or [
            ("SMSG_MOVE_SET_ACTIVE_MOVER", b"active-mover"),
            ("SMSG_UPDATE_OBJECT", b"transport-create"),
            ("SMSG_UPDATE_OBJECT", b"player-create"),
        ],
    )
    monkeypatch.setattr(
        login_handlers,
        "_sync_pending_transport_before_player_bootstrap",
        lambda _session: bootstrap_order.append("transport_sync") or False,
    )
    monkeypatch.setattr(
        transport_runtime,
        "build_bootstrap_transport_value_updates",
        lambda _session: transport_refresh_state.append(
            (set(_session.loaded_gameobjects), dict(_session.loaded_transport_entries))
        )
        or [("SMSG_UPDATE_OBJECT", b"transport-values")],
    )
    monkeypatch.setattr(
        movement_handlers,
        "stream_world_objects_after_teleport",
        lambda _session, *, context: [("SMSG_UPDATE_OBJECT", f"visible:{context}".encode("ascii"))],
    )
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_active_mover_spell_sync_responses",
        lambda _session: [("SMSG_SEND_KNOWN_SPELLS", b"known-spells")],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_login_inventory_sync_responses",
        lambda _session: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "trigger_inventory_activation",
        lambda _session: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_explored_zones_update_response",
        lambda _session: None,
    )

    responses = login_handlers._queue_teleport_world_transition(session, ctx)

    assert state_changes == [LoginState.WORLD_BOOTSTRAP]
    assert bootstrap_order == ["transport_sync", "player_bootstrap"]
    assert player_bootstrap_loaded_state == [(set(), {})]
    assert transport_refresh_state == [
        ({0x1FC00000000186A7}, {0x1FC00000000186A7: {"entry": 176495}})
    ]
    assert ("SMSG_LOGIN_VERIFY_WORLD", b"verify") not in responses
    assert responses[:6] == [
        ("SMSG_BIND_POINT_UPDATE", b"bind"),
        ("SMSG_SEND_KNOWN_SPELLS", b"known-spells"),
        ("SMSG_LOGIN_SET_TIME_SPEED", b"time"),
        ("SMSG_MOVE_SET_ACTIVE_MOVER", b"active-mover"),
        ("SMSG_UPDATE_OBJECT", b"transport-create"),
        ("SMSG_UPDATE_OBJECT", b"player-create"),
    ]
    assert ("SMSG_UPDATE_OBJECT", b"transport-values") in responses
    assert ("SMSG_UPDATE_OBJECT", b"visible:worldport-loading-complete") in responses
    assert responses.count(("SMSG_SEND_KNOWN_SPELLS", b"known-spells")) == 1
    assert responses.index(("SMSG_UPDATE_OBJECT", b"transport-values")) > responses.index(
        ("SMSG_QUERY_TIME_RESPONSE", b"query-time")
    )
    assert responses.index(("SMSG_UPDATE_OBJECT", b"visible:worldport-loading-complete")) > responses.index(
        ("SMSG_UPDATE_OBJECT", b"transport-values")
    )
    assert session.loading_screen_done is True
    assert session.post_loading_sent is True
    assert session.teleport_pending is False
    assert session.worldport_ack_pending is False
    assert session.teleport_destination is None


def test_worldport_loading_completion_streams_world_objects_immediately(monkeypatch) -> None:
    from server.modules.handlers.world import transport_runtime
    from server.modules.handlers.world.opcodes import movement as movement_handlers
    from server.modules.handlers.world.state.runtime import is_player_world_active

    session = SimpleNamespace(
        loading_screen_done=False,
        post_loading_sent=False,
        teleport_pending=True,
        worldport_ack_pending=True,
        teleport_destination="test",
        char_guid=1,
        world_guid=1,
        player_guid=1,
        instance_id=0,
        map_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.5,
        loaded_gameobjects=set(),
        loaded_transport_entries={},
        loaded_npcs=set(),
        transport_transfer_pending=True,
        login_state=LoginState.IN_WORLD,
        world_transition_generation=1,
        world_transition_loading_generation=1,
        world_transition_owner="transport_worldport",
        world_transition_ignore_worldport_ack=False,
        pending_transport_transfer={
            "transfer_id": "1-post-bootstrap",
            "destination_guid": 0x1FC0000000000007,
            "world_transition_generation": 1,
            "destination_map": 0,
            "local_x": 2.0,
            "local_y": 3.0,
            "local_z": 4.0,
            "local_o": 0.25,
            "destination_entry": {
                "entry": 20808,
                "type": transport_runtime.GAMEOBJECT_TYPE_MO_TRANSPORT,
                "world_db_transport": True,
                "name": "The Maiden's Fancy",
            },
        },
        movement_state=MovementState(),
    )
    ctx = SimpleNamespace()
    calls: list[str] = []
    runtime_state = SimpleNamespace(
        map_id=0,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=math.pi / 2.0,
        path_progress_ms=4321,
    )

    monkeypatch.setattr(login_handlers, "_set_login_state", lambda _session, state: None)
    monkeypatch.setattr(login_handlers, "refresh_region_weather", lambda _session: None)
    monkeypatch.setattr(login_handlers, "build_login_packet", lambda opcode_name, _ctx: None)
    monkeypatch.setattr(login_handlers, "build_player_bootstrap_packets", lambda _session: [])
    monkeypatch.setattr(
        login_handlers,
        "resolve_player_runtime",
        lambda target: SimpleNamespace(
            map_id=target.map_id,
            x=target.x,
            y=target.y,
            z=target.z,
            orientation=target.orientation,
        ),
    )
    monkeypatch.setattr(
        transport_runtime,
        "current_runtime_transport_state_for_guid",
        lambda _guid: runtime_state,
    )
    monkeypatch.setattr(login_handlers.spells_handlers, "build_active_mover_spell_sync_responses", lambda _session: [])
    monkeypatch.setattr(login_handlers, "build_login_inventory_sync_responses", lambda _session: [])
    monkeypatch.setattr(login_handlers, "trigger_inventory_activation", lambda _session: [])
    monkeypatch.setattr(login_handlers, "build_explored_zones_update_response", lambda _session: None)
    monkeypatch.setattr(transport_runtime, "build_bootstrap_transport_value_updates", lambda _session: [])
    def stream_during_bootstrap(target, *, context):
        assert is_player_world_active(target) is False
        assert (target.x, target.y, target.z) == pytest.approx(
            (97.0, 202.0, 14.0)
        )
        calls.append(context)
        return [("SMSG_UPDATE_OBJECT", b"visible-now")]

    monkeypatch.setattr(
        movement_handlers,
        "stream_world_objects_after_teleport",
        stream_during_bootstrap,
    )
    responses = login_handlers._queue_teleport_world_transition(session, ctx)

    assert calls == ["worldport-loading-complete"]
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"visible-now")
    assert (session.x, session.y, session.z, session.orientation) == pytest.approx(
        (97.0, 202.0, 14.0, (math.pi / 2.0) + 0.25)
    )
    assert (ctx.map_id, ctx.x, ctx.y, ctx.z, ctx.orientation) == pytest.approx(
        (0, 97.0, 202.0, 14.0, (math.pi / 2.0) + 0.25)
    )
    assert session.pending_transport_transfer is None
    assert session.transport_transfer_pending is False
    assert session.transport_attach_state == transport_runtime.ATTACH_STATE_ATTACHED
    assert session.transport_attached_guid == 0x1FC0000000000007
    assert is_player_world_active(session) is True
    assert not hasattr(session, "post_bootstrap_transport_reattach_request")

    before_late_ack = dict(vars(session))
    assert movement_handlers.handle_move_worldport_ack(session, SimpleNamespace()) == (0, None)
    assert vars(session) == before_late_ack


def test_failed_worldport_bootstrap_enters_terminal_failure_and_fallback(
    monkeypatch,
) -> None:
    from server.modules.handlers.world import transport_runtime
    from server.modules.handlers.world.opcodes import movement as movement_handlers
    from server.modules.handlers.world.teleport import map_transfer
    from server.modules.handlers.world.teleport.transition import (
        begin_ordinary_teleport_transition,
        complete_world_transition,
    )
    from server.modules.handlers.world.state.runtime import is_player_world_active

    pending = {
        "transfer_id": "1-fail",
        "world_transition_generation": 1,
        "source_map": 1,
        "safe_map": 1,
        "safe_x": 10.0,
        "safe_y": 20.0,
        "safe_z": 30.0,
        "safe_o": 0.5,
        "destination_guid": 7,
    }
    session = SimpleNamespace(
        char_guid=42,
        map_id=0,
        x=100.0,
        y=200.0,
        z=300.0,
        orientation=1.0,
        loading_screen_done=False,
        loading_screen_visible=True,
        post_loading_sent=False,
        teleport_pending=True,
        worldport_ack_pending=True,
        teleport_destination="test",
        loaded_gameobjects=set(),
        loaded_transport_entries={},
        loaded_npcs=set(),
        pending_transport_transfer=pending,
        transport_transfer_pending=True,
        login_state=LoginState.IN_WORLD,
        world_transition_generation=1,
        world_transition_loading_generation=1,
        world_transition_owner="transport_worldport",
        world_transition_ignore_worldport_ack=False,
        transport_attach_state="TRANSFERRING",
        transport_attached_guid=7,
        post_bootstrap_transport_reattach_request={"transport_guid": 7},
        movement_state=MovementState(),
    )
    session.movement_state.has_transport_data = True
    session.movement_state.transport_guid = 7
    session.movement_state.transport_x = 1.0
    session.movement_state.transport_y = 2.0
    session.movement_state.transport_z = 3.0
    fallback_calls = []
    finalized = []

    def apply_fallback(target, destination, *, reason):
        assert target.teleport_pending is False
        assert target.worldport_ack_pending is False
        assert target.near_teleport_pending is False
        assert target.teleport_destination is None
        assert target.pending_transport_transfer is None
        assert target.transport_transfer_pending is False
        assert target.post_bootstrap_transport_reattach_request is None
        assert target.transport_attach_state != "TRANSFERRING"
        fallback_calls.append((destination, reason))
        begin_ordinary_teleport_transition(target)
        target.map_id = destination.map_id
        target.x = destination.x
        target.y = destination.y
        target.z = destination.z
        target.orientation = destination.orientation
        target.teleport_pending = True
        target.worldport_ack_pending = True
        target.teleport_destination = destination.name
        return [("SMSG_NEW_WORLD", b"safe-fallback")]

    monkeypatch.setattr(map_transfer, "apply_map_transfer", apply_fallback)
    monkeypatch.setattr(
        transport_runtime,
        "finalize_transport_boundary_event",
        lambda target, *, outcome: finalized.append((target, outcome)) or True,
    )

    responses = login_handlers._fail_transport_worldport_bootstrap(
        session,
        pending,
        reason="bootstrap failed",
    )

    assert responses == [("SMSG_NEW_WORLD", b"safe-fallback")]
    assert session.world_transition_terminal_state == "FAILED"
    assert session.world_transition_terminal_generation == 1
    assert session.world_transition_terminal_owner == "transport_worldport"
    assert session.world_transition_failure_reason == "bootstrap failed"
    assert session.world_transition_owner == "ordinary_teleport"
    assert session.world_transition_generation == 3
    assert session.pending_transport_transfer is None
    assert session.transport_transfer_pending is False
    assert session.transport_attach_state != "TRANSFERRING"
    assert session.movement_state.has_transport_data is False
    assert fallback_calls[0][1] == "transport_worldport_failure"
    assert finalized == [(pending, "failed_fallback")]
    assert movement_handlers.complete_pending_transport_transfer(session) is False
    assert (session.map_id, session.x, session.y, session.z) == (
        1,
        10.0,
        20.0,
        30.0,
    )
    assert is_player_world_active(session) is False

    session.teleport_pending = False
    session.worldport_ack_pending = False
    session.login_state = LoginState.IN_WORLD
    complete_world_transition(session)
    assert is_player_world_active(session) is True


def test_stale_transport_failure_cannot_replace_manual_teleport(
    monkeypatch,
) -> None:
    from server.modules.handlers.world.teleport import map_transfer

    stale_pending = {
        "world_transition_generation": 1,
        "safe_map": 1,
        "safe_x": 10.0,
        "safe_y": 20.0,
        "safe_z": 30.0,
        "safe_o": 0.5,
    }
    manual_destination = object()
    session = SimpleNamespace(
        char_guid=42,
        world_transition_generation=2,
        world_transition_loading_generation=2,
        world_transition_owner="ordinary_teleport",
        world_transition_status="ACTIVE",
        teleport_pending=True,
        worldport_ack_pending=True,
        teleport_destination=manual_destination,
        pending_transport_transfer=None,
        transport_transfer_pending=False,
    )

    monkeypatch.setattr(
        map_transfer,
        "apply_map_transfer",
        lambda *_args, **_kwargs: pytest.fail("stale failure started fallback"),
    )

    assert login_handlers._fail_transport_worldport_bootstrap(
        session,
        stale_pending,
        reason="late bootstrap failure",
    ) == []
    assert session.world_transition_generation == 2
    assert session.world_transition_owner == "ordinary_teleport"
    assert session.world_transition_status == "ACTIVE"
    assert session.teleport_pending is True
    assert session.worldport_ack_pending is True
    assert session.teleport_destination is manual_destination


def test_loading_handler_terminalizes_transport_bootstrap_exception(
    monkeypatch,
) -> None:
    pending = {
        "world_transition_generation": 1,
        "destination_guid": 7,
    }
    session = SimpleNamespace(
        char_guid=42,
        world_guid=42,
        login_state=LoginState.IN_WORLD,
        map_id=0,
        teleport_pending=True,
        worldport_ack_pending=True,
        teleport_destination="boat-destination",
        loading_screen_visible=True,
        world_transition_generation=1,
        world_transition_loading_generation=1,
        world_transition_owner="transport_worldport",
        pending_transport_transfer=pending,
        transport_transfer_pending=True,
    )
    ctx = SimpleNamespace(
        name="CMSG_LOADING_SCREEN_NOTIFY",
        payload=b"",
        decoded={},
    )
    failures = []

    monkeypatch.setattr(login_handlers, "log_cmsg", lambda _ctx: {})
    monkeypatch.setattr(
        login_handlers,
        "_decode_loading_screen_showing",
        lambda _decoded, _payload: 0,
    )
    monkeypatch.setattr(login_handlers, "_resolve_session_ids", lambda _session: None)
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _session: SimpleNamespace(),
    )
    monkeypatch.setattr(
        login_handlers,
        "_queue_teleport_world_transition",
        lambda _session, _ctx: (_ for _ in ()).throw(
            RuntimeError("bootstrap failed")
        ),
    )
    monkeypatch.setattr(
        login_handlers,
        "_fail_transport_worldport_bootstrap",
        lambda target, target_pending, *, reason: failures.append(
            (target, target_pending, reason)
        )
        or [("SMSG_NEW_WORLD", b"fallback")],
    )

    status, responses = login_handlers.handle_loading_screen_notify(session, ctx)

    assert status == 0
    assert responses == [("SMSG_NEW_WORLD", b"fallback")]
    assert failures == [(session, pending, "bootstrap failed")]


def test_login_attachment_bootstrap_failure_aborts_restore(monkeypatch) -> None:
    from server.modules.handlers.world.runtime import world_attachment
    from server.modules.handlers.world.state.runtime import is_player_world_active

    pending = {
        "status": "PREPARED",
        "spawn_id": 7,
    }
    session = SimpleNamespace(
        char_guid=42,
        login_state=LoginState.WORLD_BOOTSTRAP,
        world_transition_owner=None,
        world_transition_loading_generation=0,
        pending_world_attachment_restore=pending,
    )
    aborts = []

    monkeypatch.setattr(
        world_attachment,
        "prepare_login_world_attachment",
        lambda _session: True,
    )
    monkeypatch.setattr(
        world_attachment,
        "abort_login_world_attachment",
        lambda target, *, reason: aborts.append((target, reason)) or True,
    )
    monkeypatch.setattr(
        login_handlers,
        "_build_world_login_context",
        lambda _session: SimpleNamespace(),
    )
    monkeypatch.setattr(
        login_handlers,
        "_queue_world_bootstrap_transition_unchecked",
        lambda _session, _ctx: (_ for _ in ()).throw(
            RuntimeError("bootstrap failed")
        ),
    )

    with pytest.raises(RuntimeError, match="bootstrap failed"):
        login_handlers._queue_world_bootstrap_transition(
            session,
            SimpleNamespace(),
        )

    assert aborts == [(session, "bootstrap_failed")]
    assert is_player_world_active(session) is False
