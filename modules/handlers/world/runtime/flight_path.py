#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Published world-object transform for one active player taxi flight."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from server.modules.handlers.world.runtime.world_object import WorldObject


def flight_path_runtime_guid(session: Any) -> int:
    """Return the existing mover GUID used by taxi spline packets."""
    return int(
        getattr(session, "char_guid", 0)
        or getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )


@dataclass(slots=True)
class FlightPath(WorldObject):
    """Long-lived identity and published transform for an active taxi flight.

    Taxi paths, spline progression, timing, interpolation, node advancement,
    arrival, map transfers, packets, visibility, networking, persistence, and
    gameplay remain in their existing subsystems. This object only exposes the
    world transform already committed by the flight runtime.
    """

    @classmethod
    def from_session(cls, session: Any) -> FlightPath:
        """Snapshot the current taxi mover identity and world transform."""
        return cls(
            runtime_guid=flight_path_runtime_guid(session),
            map_id=int(getattr(session, "map_id", 0) or 0),
            instance_id=int(getattr(session, "instance_id", 0) or 0),
            x=float(getattr(session, "x", 0.0) or 0.0),
            y=float(getattr(session, "y", 0.0) or 0.0),
            z=float(getattr(session, "z", 0.0) or 0.0),
            orientation=float(getattr(session, "orientation", 0.0) or 0.0),
            rotation=(0.0, 0.0, 0.0, 1.0),
            scale=1.0,
        )

    def publish_transform(self, session: Any) -> None:
        """Publish a transform already committed by the taxi runtime."""
        self.runtime_guid = flight_path_runtime_guid(session)
        self.map_id = int(getattr(session, "map_id", self.map_id) or 0)
        self.instance_id = int(
            getattr(session, "instance_id", self.instance_id) or 0
        )
        self.x = float(getattr(session, "x", self.x) or 0.0)
        self.y = float(getattr(session, "y", self.y) or 0.0)
        self.z = float(getattr(session, "z", self.z) or 0.0)
        self.orientation = float(
            getattr(session, "orientation", self.orientation) or 0.0
        )
