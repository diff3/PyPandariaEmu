#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic identity and geometric state for runtime entities.

``RuntimeObject`` exists to provide a small common representation for state
that is shared by world entities. It provides identity comparisons and basic
geometry derived only from that state.

Ownership, lifecycle, mutation policy, gameplay systems, protocol
serialization, database persistence, visibility, collision, AI, combat, loot,
inventory, and quest behavior do not belong in this base class.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from typing import Any, Mapping


def _mapping_int(
    data: Mapping[str, Any],
    key: str,
    default: int = 0,
) -> int:
    """Read an integer using the existing runtime-entry coercion rules."""
    try:
        return int(data.get(key, default) or default)
    except Exception:
        return int(default)


def _mapping_float(
    data: Mapping[str, Any],
    key: str,
    default: float = 0.0,
) -> float:
    """Read a float using the existing runtime-entry coercion rules."""
    try:
        return float(data.get(key, default) or default)
    except Exception:
        return float(default)


@dataclass(slots=True)
class RuntimeObject:
    """Lightweight runtime identity and world geometry.

    The stored values and helpers are applicable to every positioned runtime
    entity. Geometry helpers belong here because they depend only on these
    generic values and require no knowledge of the owning subsystem. Being a
    ``RuntimeObject`` does not itself imply participation in the game world.

    Entity-specific behavior and subsystem ownership remain in their existing
    modules. This class does not manage lifecycle or updates, send packets,
    persist rows, decide visibility, register collision, or implement gameplay
    behavior.
    """

    runtime_guid: int
    map_id: int
    instance_id: int
    x: float
    y: float
    z: float
    orientation: float
    rotation: tuple[float, float, float, float]
    scale: float

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        runtime_guid: int = 0,
    ) -> RuntimeObject:
        """Build generic runtime state from an existing entry mapping.

        Both ``map_id`` and the established ``map`` alias are accepted so the
        extraction does not require changes to existing database or packet
        dictionaries.
        """
        map_id = _mapping_int(data, "map_id", _mapping_int(data, "map"))
        return cls(
            runtime_guid=int(runtime_guid),
            map_id=map_id,
            instance_id=_mapping_int(data, "instance_id"),
            x=_mapping_float(data, "x"),
            y=_mapping_float(data, "y"),
            z=_mapping_float(data, "z"),
            orientation=_mapping_float(data, "orientation"),
            rotation=(
                _mapping_float(data, "rotation0"),
                _mapping_float(data, "rotation1"),
                _mapping_float(data, "rotation2"),
                _mapping_float(data, "rotation3"),
            ),
            scale=_mapping_float(data, "size", 1.0),
        )

    @property
    def world_position(self) -> tuple[float, float, float]:
        """Return the current world position as an ``(x, y, z)`` tuple."""
        return self.x, self.y, self.z

    @property
    def transform(
        self,
    ) -> tuple[tuple[float, float, float], float, float]:
        """Return position, orientation, and scale as generic geometry."""
        return self.world_position, self.orientation, self.scale

    def distance_squared(self, other: RuntimeObject) -> float:
        """Return squared three-dimensional distance to another object.

        This helper compares coordinates only. Callers remain responsible for
        deciding whether objects from different maps or instances are
        meaningfully comparable.
        """
        delta_x = self.x - other.x
        delta_y = self.y - other.y
        delta_z = self.z - other.z
        return delta_x * delta_x + delta_y * delta_y + delta_z * delta_z

    def distance_to(self, other: RuntimeObject) -> float:
        """Return three-dimensional Euclidean distance to another object."""
        return sqrt(self.distance_squared(other))

    def same_map(self, other: RuntimeObject) -> bool:
        """Return whether both objects have the same map identity."""
        return self.map_id == other.map_id

    def same_instance(self, other: RuntimeObject) -> bool:
        """Return whether both objects share one map-instance identity."""
        return self.same_map(other) and self.instance_id == other.instance_id
