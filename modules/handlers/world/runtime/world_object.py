#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Base representation for runtime entities that can exist in the world.

``WorldObject`` marks the boundary between generic runtime identity and
geometry in ``RuntimeObject`` and entity-specific behavior in subclasses.
Future shared map ownership, world lifecycle, and visibility participation
belong at this layer only after common behavior and ownership are established.
"""

from __future__ import annotations

from dataclasses import dataclass

from server.modules.handlers.world.runtime.runtime_object import RuntimeObject


@dataclass(slots=True)
class WorldObject(RuntimeObject):
    """A runtime object capable of participating in the game world.

    This class intentionally adds no state or behavior. It does not currently
    own a map, manage world entry or removal, decide visibility, or coordinate
    updates. Those responsibilities remain in their existing subsystems until
    a shared behavior-preserving abstraction exists.
    """
