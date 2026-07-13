#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Runtime representation for a Creature identity and transform."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from server.modules.handlers.world.runtime.spawned_world_object import (
    SpawnedWorldObject,
)


@dataclass(slots=True)
class Creature(SpawnedWorldObject):
    """A thin world-object representation for a Creature.

    Persistent-spawn identity comes from ``SpawnedWorldObject``. Generic
    runtime identity and geometry come from ``RuntimeObject`` through
    ``WorldObject``. Creature-specific metadata, visibility, packet building,
    persistence, editor behavior, gameplay, and lifecycle orchestration remain
    in their existing subsystems.
    """

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        runtime_guid: int = 0,
    ) -> Creature:
        """Build a typed Creature from an existing entry mapping."""
        return super().from_mapping(data, runtime_guid=runtime_guid)
