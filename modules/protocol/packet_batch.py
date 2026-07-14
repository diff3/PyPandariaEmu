#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Optional ownership metadata for one atomic outgoing packet batch."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from threading import Lock
from typing import Any


class PacketBatch(list):
    """A list-compatible response batch with optional transition ownership."""

    def __init__(
        self,
        responses: Iterable = (),
        *,
        transition_bound: bool = False,
        transition_generation: int | None = None,
        transition_owner: str | None = None,
    ) -> None:
        super().__init__(responses)
        self.transition_bound = bool(transition_bound)
        self.transition_generation = (
            None
            if transition_generation is None
            else int(transition_generation)
        )
        self.transition_owner = (
            None if transition_owner is None else str(transition_owner)
        )


def bind_packet_batch_to_current_transition(session, responses) -> PacketBatch:
    """Bind responses to the transition that currently owns the session."""
    return PacketBatch(
        responses or (),
        transition_bound=True,
        transition_generation=int(
            getattr(session, "world_transition_generation", 0) or 0
        ),
        transition_owner=str(
            getattr(session, "world_transition_owner", "") or ""
        ),
    )


def preserve_packet_batch_metadata(source, responses) -> PacketBatch | list:
    """Copy optional batch ownership while replacing its packet sequence."""
    if not isinstance(source, PacketBatch):
        return list(responses or ())
    return PacketBatch(
        responses or (),
        transition_bound=source.transition_bound,
        transition_generation=source.transition_generation,
        transition_owner=source.transition_owner,
    )


def packet_batch_ownership_matches(session, batch) -> bool:
    """Return whether a transition-bound batch still owns the session."""
    if not isinstance(batch, PacketBatch) or not batch.transition_bound:
        return True
    return (
        batch.transition_generation
        == int(getattr(session, "world_transition_generation", 0) or 0)
        and str(batch.transition_owner or "")
        == str(getattr(session, "world_transition_owner", "") or "")
    )


def send_packet_batch_under_lock(
    session: Any,
    batch,
    send_lock: Lock,
    send_batch: Callable[[], None],
    *,
    on_discard: Callable[[PacketBatch], None] | None = None,
) -> bool:
    """Validate and send one complete batch while holding the socket lock.

    Ownership changes after ``send_batch`` starts are outside the cancellation
    boundary because socket bytes may already have been written.
    """
    with send_lock:
        if not packet_batch_ownership_matches(session, batch):
            if callable(on_discard):
                on_discard(batch)
            return False
        send_batch()
        return True
