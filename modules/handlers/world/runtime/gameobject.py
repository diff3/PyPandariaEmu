#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Runtime representation for an ordinary persistent GameObject."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)
from server.modules.handlers.world.runtime.spawned_world_object import (
    SpawnedWorldObject,
)


@dataclass(slots=True)
class GameObject(SpawnedWorldObject):
    """A world object representing an ordinary persistent GameObject.

    Persistent-spawn identity comes from ``SpawnedWorldObject``. Generic
    runtime identity and geometry come from ``RuntimeObject`` through
    ``WorldObject``. After construction, that inherited transform is the live
    runtime transform; its source mapping remains authoritative for persistent
    data. GameObject-specific packet construction, visibility, collision,
    persistence, and gameplay behavior remain in their existing modules. This
    class owns the runtime fields used by CREATE. Explicit setters mutate only
    this object; they do not update persistence or trigger packets, visibility,
    collision, lifecycle, dirty tracking, or serialization.
    """

    display_id: int = 0
    state: int = 0
    flags: int = 0
    faction: int = 0
    art_kit: int = 0
    animation_progress: int = 0
    gameobject_type: int = 0

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        runtime_guid: int = 0,
    ) -> GameObject:
        """Build a complete runtime snapshot without retaining the mapping."""
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
            display_id=_mapping_int(data, "display_id"),
            state=_mapping_int(data, "state"),
            flags=_mapping_int(data, "flags"),
            faction=_mapping_int(data, "faction"),
            art_kit=_mapping_int(data, "artkit"),
            animation_progress=_mapping_int(data, "animprogress"),
            gameobject_type=_mapping_int(data, "type"),
        )

    def set_position(self, x: float, y: float, z: float) -> None:
        """Set this object's runtime world position only."""
        self.x = float(x)
        self.y = float(y)
        self.z = float(z)

    def set_orientation(self, orientation: float) -> None:
        """Set this object's runtime orientation only."""
        self.orientation = float(orientation)

    def set_rotation(
        self,
        rotation: tuple[float, float, float, float],
    ) -> None:
        """Set this object's four-component runtime rotation only."""
        rotation0, rotation1, rotation2, rotation3 = rotation
        self.rotation = (
            float(rotation0),
            float(rotation1),
            float(rotation2),
            float(rotation3),
        )

    def set_scale(self, scale: float) -> None:
        """Set this object's runtime scale only."""
        self.scale = float(scale)

    def set_state(self, state: int) -> None:
        """Set this object's runtime GameObject state only."""
        self.state = int(state)

    def set_flags(self, flags: int) -> None:
        """Set this object's runtime GameObject flags only."""
        self.flags = int(flags)

    def set_display_id(self, display_id: int) -> None:
        """Set this object's runtime display identity only."""
        self.display_id = int(display_id)

    def set_faction(self, faction: int) -> None:
        """Set this object's runtime faction only."""
        self.faction = int(faction)

    def set_art_kit(self, art_kit: int) -> None:
        """Set this object's runtime art kit only."""
        self.art_kit = int(art_kit)

    def set_animation_progress(self, progress: int) -> None:
        """Set this object's runtime animation progress only."""
        self.animation_progress = int(progress)

    def set_gameobject_type(self, gameobject_type: int) -> None:
        """Set this object's runtime GameObject type only."""
        self.gameobject_type = int(gameobject_type)
