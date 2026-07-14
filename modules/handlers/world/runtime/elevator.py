#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared world-object representation for a runtime elevator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)
from server.modules.handlers.world.runtime.world_object import WorldObject


@dataclass(slots=True)
class Elevator(WorldObject):
    """Long-lived elevator identity and published world transform.

    Movement templates, clocks, interpolation, lifecycle state, passengers,
    visibility, packets, collision, and persistence remain outside this
    object. The existing transport simulation publishes its computed transform
    here without transferring simulation ownership.
    """

    entry: int = 0

    @classmethod
    def from_runtime_state(
        cls,
        state: Any,
        mapping: Mapping[str, Any],
    ) -> Elevator:
        """Create an elevator snapshot from existing simulation output."""
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
        )

    @classmethod
    def from_mapping(
        cls,
        mapping: Mapping[str, Any],
        *,
        runtime_guid: int,
    ) -> Elevator:
        """Construct the unregistered packet/visibility fallback."""
        map_id = _mapping_int(mapping, "map_id", _mapping_int(mapping, "map"))
        return cls(
            runtime_guid=int(runtime_guid),
            map_id=map_id,
            instance_id=_mapping_int(mapping, "instance_id"),
            x=_mapping_float(mapping, "x", _mapping_float(mapping, "position_x")),
            y=_mapping_float(mapping, "y", _mapping_float(mapping, "position_y")),
            z=_mapping_float(mapping, "z", _mapping_float(mapping, "position_z")),
            orientation=_mapping_float(mapping, "orientation"),
            rotation=(
                _mapping_float(mapping, "rotation0"),
                _mapping_float(mapping, "rotation1"),
                _mapping_float(mapping, "rotation2"),
                _mapping_float(mapping, "rotation3"),
            ),
            scale=_mapping_float(mapping, "size", 1.0),
            entry=_mapping_int(mapping, "entry"),
        )

    def publish_transform(self, state: Any) -> None:
        """Publish the transform already computed by the movement runtime."""
        self.runtime_guid = int(getattr(state, "guid", self.runtime_guid) or 0)
        self.entry = int(getattr(state, "entry", self.entry) or 0)
        self.map_id = int(getattr(state, "map_id", self.map_id) or 0)
        self.x = float(getattr(state, "x", self.x) or 0.0)
        self.y = float(getattr(state, "y", self.y) or 0.0)
        self.z = float(getattr(state, "z", self.z) or 0.0)
        self.orientation = float(
            getattr(state, "orientation", self.orientation) or 0.0
        )
