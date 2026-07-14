#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive shared runtime representation for a logged-in player."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from server.modules.handlers.world.runtime.world_object import WorldObject


@dataclass(slots=True)
class Player(WorldObject):
    """Long-lived player identity and geometry snapshot.

    The object copies universally shared world identity and geometry from a
    successful ``WorldSession`` login. It does not retain the session and does
    not own movement, visibility, packets, gameplay, persistence, networking,
    login flow, or disconnect behavior.
    """

    character_guid: int

    @classmethod
    def from_session(cls, session: Any) -> Player:
        """Snapshot generic player identity and geometry exactly once."""
        runtime_guid = int(
            getattr(session, "world_guid", 0)
            or getattr(session, "player_guid", 0)
            or 0
        )
        return cls(
            runtime_guid=runtime_guid,
            map_id=int(getattr(session, "map_id", 0) or 0),
            instance_id=int(getattr(session, "instance_id", 0) or 0),
            x=float(getattr(session, "x", 0.0) or 0.0),
            y=float(getattr(session, "y", 0.0) or 0.0),
            z=float(getattr(session, "z", 0.0) or 0.0),
            orientation=float(getattr(session, "orientation", 0.0) or 0.0),
            rotation=(0.0, 0.0, 0.0, 1.0),
            scale=1.0,
            character_guid=int(getattr(session, "char_guid", 0) or 0),
        )
