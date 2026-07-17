from types import SimpleNamespace

import pytest

from server.modules.handlers.world.teleport.lifecycle import TeleportLifecycle
from server.modules.handlers.world.teleport.map_transfer import (
    TeleportDestination,
    apply_map_transfer,
)


def _session():
    return SimpleNamespace(
        map_id=1,
        teleport_destination=None,
        world_transition_generation=0,
        world_transition_owner=None,
        world_transition_loading_generation=0,
        world_transition_bootstrap_generation=0,
        world_transition_bootstrap_status="IDLE",
        world_transition_status="IDLE",
        near_teleport_generation=0,
        teleport_pending=False,
        worldport_ack_pending=False,
        transport_transfer_pending=False,
        pending_transport_transfer=None,
        post_bootstrap_transport_reattach_request=None,
        loading_screen_visible=False,
        world_transition_ignore_worldport_ack=False,
        loading_screen_done=False,
        post_loading_sent=False,
    )


def test_begin_transition_validates_and_classifies_same_map():
    session = _session()
    lifecycle = TeleportLifecycle()

    transition = lifecycle.begin_transition(
        session,
        TeleportDestination(1, 10.0, 20.0, 30.0, 7.0, "same-map"),
        reason="test",
    )

    assert transition.same_map is True
    assert transition.source_map_id == 1
    assert transition.destination.orientation == pytest.approx(7.0 % 6.283185307179586)
    assert session.teleport_destination == "same-map"


def test_begin_transition_rejects_invalid_destination():
    with pytest.raises(ValueError, match="invalid teleport destination"):
        TeleportLifecycle().begin_transition(
            _session(),
            TeleportDestination(-1, 0.0, 0.0, 0.0, 0.0, "invalid"),
            reason="test",
        )


def test_map_transfer_is_compatibility_entry_into_lifecycle(monkeypatch):
    session = _session()
    destination = TeleportDestination(1, 1.0, 2.0, 3.0, 4.0, "delegated")
    calls = []

    from server.modules.handlers.world.teleport import lifecycle as lifecycle_module

    monkeypatch.setattr(
        lifecycle_module._TELEPORT_LIFECYCLE,
        "teleport",
        lambda target, resolved, **kwargs: calls.append(
            (target, resolved, kwargs)
        )
        or [("SMSG_MOVE_TELEPORT", b"canonical")],
    )

    responses = apply_map_transfer(session, destination, reason="delegate-test")

    assert responses == [("SMSG_MOVE_TELEPORT", b"canonical")]
    assert calls == [
        (
            session,
            destination,
            {"reason": "delegate-test", "keep_transport": False},
        )
    ]


def test_deferred_completion_uses_existing_worldport_refresh_flag():
    session = _session()
    lifecycle = TeleportLifecycle()
    lifecycle.begin_owned_transition(session, owner="ordinary_teleport")

    responses = lifecycle.complete_transition(
        session,
        context="test-complete",
        refresh="deferred",
    )

    assert responses == []
    assert session.world_transition_owner is None
    assert session._worldport_destination_visibility_refresh_pending is True
