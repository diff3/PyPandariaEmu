#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Runtime representation for an ordinary persistent GameObject."""

from __future__ import annotations

from dataclasses import dataclass

from server.modules.handlers.world.runtime.spawned_world_object import (
    SpawnedWorldObject,
)


@dataclass(slots=True)
class GameObject(SpawnedWorldObject):
    """A world object representing an ordinary persistent GameObject.

    Persistent-spawn identity comes from ``SpawnedWorldObject``. Generic
    runtime identity and geometry come from ``RuntimeObject`` through
    ``WorldObject``. GameObject-specific packet construction, visibility,
    collision, persistence, and gameplay behavior remain in their existing
    modules. This subclass is intentionally empty until an existing
    GameObject-specific responsibility has a behavior-preserving migration.
    """
