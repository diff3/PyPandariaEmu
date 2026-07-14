"""State boundary for ordinary teleports that replace an active worldport."""

from __future__ import annotations


def _begin_world_transition(session, owner: str) -> int:
    """Assign a new authoritative owner and generation to a world transition."""
    generation = int(getattr(session, "world_transition_generation", 0) or 0) + 1
    session.world_transition_generation = generation
    session.world_transition_owner = str(owner)
    session.world_transition_loading_generation = generation
    return generation


def begin_ordinary_teleport_transition(session) -> int:
    """Invalidate an older worldport and start a fresh ordinary transition."""
    supersedes_worldport = bool(
        getattr(session, "teleport_pending", False)
        or getattr(session, "worldport_ack_pending", False)
        or getattr(session, "transport_transfer_pending", False)
        or isinstance(getattr(session, "pending_transport_transfer", None), dict)
        or isinstance(
            getattr(session, "post_bootstrap_transport_reattach_request", None),
            dict,
        )
        or getattr(session, "loading_screen_visible", False)
        or getattr(session, "world_transition_ignore_worldport_ack", False)
    )

    generation = _begin_world_transition(session, "ordinary_teleport")
    # CMSG_MOVE_WORLDPORT_ACK has no transition identity. While replacing an
    # unfinished worldport, loading completion is therefore the sole completion
    # boundary and every ACK is deliberately ignored.
    session.world_transition_ignore_worldport_ack = supersedes_worldport
    # Loading notifications are also untagged. The fresh transition immediately
    # owns the active loading lifecycle so its next completion can only bootstrap
    # the new authoritative destination.
    session.loading_screen_done = False
    session.post_loading_sent = False
    return generation


def begin_transport_worldport_transition(session) -> int:
    """Assign ownership and identity to a transport-initiated worldport."""
    generation = _begin_world_transition(session, "transport_worldport")
    session.world_transition_ignore_worldport_ack = False
    return generation


def begin_taxi_worldport_transition(session) -> int:
    """Assign ownership and identity to a taxi-initiated worldport."""
    generation = _begin_world_transition(session, "taxi_worldport")
    session.world_transition_ignore_worldport_ack = False
    return generation


def mark_world_transition_loading_started(session) -> None:
    """Associate a loading-screen start with the active transition generation."""
    if not bool(getattr(session, "teleport_pending", False)):
        return
    if str(getattr(session, "world_transition_owner", "") or "") != "ordinary_teleport":
        return
    session.world_transition_loading_generation = int(
        getattr(session, "world_transition_generation", 0) or 0
    )


def should_ignore_worldport_ack(session) -> bool:
    """Return whether an ACK is ambiguous with a superseded worldport."""
    return bool(getattr(session, "world_transition_ignore_worldport_ack", False))


def pending_transition_is_current(session, pending) -> bool:
    """Validate generation-tagged delayed work against current ownership."""
    if not isinstance(pending, dict):
        return False
    pending_generation = pending.get("world_transition_generation")
    if pending_generation is None:
        return True
    return int(pending_generation) == int(
        getattr(session, "world_transition_generation", 0) or 0
    )


def complete_world_transition(session) -> None:
    """Retire completion guards after the active transition has bootstrapped."""
    session.world_transition_owner = None
    session.world_transition_ignore_worldport_ack = False
    session.world_transition_loading_generation = 0
