#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Common identity for persistent spawned world entities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, TypeVar

from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)
from server.modules.handlers.world.runtime.runtime_store import RuntimeStore
from server.modules.handlers.world.runtime.world_object import WorldObject


SpawnedObjectT = TypeVar("SpawnedObjectT", bound="SpawnedWorldObject")


class _SnapshotCompatibility(Protocol[SpawnedObjectT]):
    def __call__(
        self,
        runtime_object: SpawnedObjectT,
        mapping: Mapping[str, Any],
        *,
        runtime_guid: int,
    ) -> bool:
        ...


class _SpawnedObjectFactory(Protocol[SpawnedObjectT]):
    def __call__(
        self,
        mapping: Mapping[str, Any],
        *,
        runtime_guid: int,
    ) -> SpawnedObjectT:
        ...


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


def resolve_spawned_world_object(
    mapping: Mapping[str, Any],
    *,
    runtime_guid: int,
    store: RuntimeStore[SpawnedObjectT],
    snapshot_compatible: _SnapshotCompatibility[SpawnedObjectT],
    fallback_factory: _SpawnedObjectFactory[SpawnedObjectT],
) -> SpawnedObjectT:
    """Resolve a compatible stored snapshot or construct its fallback.

    Object-specific snapshot rules and construction remain supplied by the
    concrete runtime type. This helper knows nothing about packets, visibility,
    persistence, editor behavior, collision, lifecycle, or gameplay.
    """
    stored = store.get_by_spawn_id(_mapping_int(mapping, "guid"))
    if stored is not None and snapshot_compatible(
        stored,
        mapping,
        runtime_guid=runtime_guid,
    ):
        return stored
    return fallback_factory(mapping, runtime_guid=runtime_guid)
