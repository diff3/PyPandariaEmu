#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared world-object representation for an active Transport."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)
from server.modules.handlers.world.runtime.world_object import WorldObject


@dataclass(slots=True)
class Transport(WorldObject):
    """Long-lived identity and world transform for an active transport.

    ``RuntimeTransportState`` remains responsible for route evaluation,
    clocks, progress, lifecycle events, and passengers. This object references
    that state while owning the shared runtime identity and published world
    transform consumed by visibility and packet construction. It performs no
    scheduling, movement evaluation, networking, or gameplay work.
    """

    entry: int = 0
    spawn_id: int = 0
    runtime_state: Any = field(default=None, repr=False, compare=False)

    @classmethod
    def from_runtime_state(
        cls,
        state: Any,
        mapping: Mapping[str, Any],
    ) -> Transport:
        """Create one runtime object from existing transport state."""
        return cls(
            runtime_guid=int(getattr(state, "guid", 0) or 0),
            map_id=int(getattr(state, "map_id", 0) or 0),
            instance_id=_mapping_int(mapping, "instance_id"),
            x=float(getattr(state, "x", 0.0) or 0.0),
            y=float(getattr(state, "y", 0.0) or 0.0),
            z=float(getattr(state, "z", 0.0) or 0.0),
            orientation=float(getattr(state, "orientation", 0.0) or 0.0),
            rotation=(
                _mapping_float(mapping, "rotation0"),
                _mapping_float(mapping, "rotation1"),
                _mapping_float(mapping, "rotation2"),
                _mapping_float(mapping, "rotation3"),
            ),
            scale=_mapping_float(mapping, "size", 1.0),
            entry=int(getattr(state, "entry", 0) or 0),
            spawn_id=int(getattr(state, "spawn_guid", 0) or 0),
            runtime_state=state,
        )

    def sync_from_runtime_state(self, state: Any | None = None) -> None:
        """Publish the current simulated identity and transform in place."""
        source = state if state is not None else self.runtime_state
        if source is None:
            return
        self.runtime_state = source
        self.runtime_guid = int(getattr(source, "guid", self.runtime_guid) or 0)
        self.entry = int(getattr(source, "entry", self.entry) or 0)
        self.spawn_id = int(getattr(source, "spawn_guid", self.spawn_id) or 0)
        self.map_id = int(getattr(source, "map_id", self.map_id) or 0)
        self.x = float(getattr(source, "x", self.x) or 0.0)
        self.y = float(getattr(source, "y", self.y) or 0.0)
        self.z = float(getattr(source, "z", self.z) or 0.0)
        self.orientation = float(
            getattr(source, "orientation", self.orientation) or 0.0
        )
