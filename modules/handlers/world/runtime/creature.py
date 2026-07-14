#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Runtime representation for a Creature identity and transform."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping

from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)
from server.modules.handlers.world.runtime.spawned_world_object import (
    SpawnedWorldObject,
)


def _normalized_creature_orientation(value: float) -> float:
    """Normalize orientation using the established Creature packet rules."""
    orientation = math.fmod(float(value or 0.0), math.tau)
    if orientation < 0.0:
        orientation += math.tau
    return float(orientation)


def _mapping_creature_display_id(data: Mapping[str, Any]) -> int:
    """Resolve the effective display ID from spawn and template metadata."""
    display_id = _mapping_int(data, "modelid")
    if display_id > 0:
        return display_id
    template = data.get("template")
    if isinstance(template, Mapping):
        for key in ("modelid1", "modelid2", "modelid3", "modelid4"):
            display_id = _mapping_int(template, key)
            if display_id > 0:
                return display_id
    return 15476


def _mapping_creature_npc_flags(data: Mapping[str, Any]) -> int:
    """Resolve effective NPC flags from spawn and template metadata."""
    npc_flags = _mapping_int(data, "npcflag")
    if npc_flags != 0:
        return npc_flags
    template = data.get("template")
    if isinstance(template, Mapping):
        return _mapping_int(template, "npcflag")
    return 0


@dataclass(slots=True)
class Creature(SpawnedWorldObject):
    """A thin world-object representation for a Creature.

    Persistent-spawn identity comes from ``SpawnedWorldObject``. Generic
    runtime identity and geometry come from ``RuntimeObject`` through
    ``WorldObject``. The effective display ID and NPC flags are immutable
    runtime snapshot values already required by CREATE. Other Creature
    metadata, visibility, packet building, persistence, editor behavior,
    gameplay, and lifecycle orchestration remain in their existing
    subsystems.
    """

    display_id: int = 15476
    npc_flags: int = 0

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        runtime_guid: int = 0,
    ) -> Creature:
        """Build a complete Creature runtime snapshot without retaining data."""
        map_id = _mapping_int(data, "map_id", _mapping_int(data, "map"))
        return cls(
            runtime_guid=int(runtime_guid),
            map_id=map_id,
            instance_id=_mapping_int(data, "instance_id"),
            x=_mapping_float(data, "x"),
            y=_mapping_float(data, "y"),
            z=_mapping_float(data, "z"),
            orientation=_normalized_creature_orientation(
                _mapping_float(data, "orientation")
            ),
            rotation=(
                _mapping_float(data, "rotation0"),
                _mapping_float(data, "rotation1"),
                _mapping_float(data, "rotation2"),
                _mapping_float(data, "rotation3"),
            ),
            scale=_mapping_float(data, "size", 1.0),
            entry=_mapping_int(data, "entry"),
            spawn_id=_mapping_int(data, "guid"),
            display_id=_mapping_creature_display_id(data),
            npc_flags=_mapping_creature_npc_flags(data),
        )
