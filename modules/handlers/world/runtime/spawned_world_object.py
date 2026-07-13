#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Common identity for persistent spawned world entities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)
from server.modules.handlers.world.runtime.world_object import WorldObject


@dataclass(slots=True)
class SpawnedWorldObject(WorldObject):
    """A world object associated with a persistent spawn and template entry.

    This layer owns only the identity shared by persistent GameObjects and
    Creatures. It does not own persistence, lifecycle, visibility, networking,
    collision, movement, gameplay, world membership, updates, or registries.
    """

    entry: int
    spawn_id: int

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        runtime_guid: int = 0,
    ) -> SpawnedWorldObject:
        """Build persistent-spawn identity and generic runtime geometry."""
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
            entry=_mapping_int(data, "entry"),
            spawn_id=_mapping_int(data, "guid"),
        )
