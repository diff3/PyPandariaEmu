#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive lifetime store for persistent runtime Creatures."""

from __future__ import annotations

from typing import Any, Mapping

from server.modules.handlers.world.runtime.creature import (
    Creature,
    _mapping_creature_display_id,
    _mapping_creature_npc_flags,
    _normalized_creature_orientation,
)
from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)
from server.modules.handlers.world.runtime.runtime_store import RuntimeStore
from server.modules.handlers.world.runtime.spawned_world_object import (
    resolve_spawned_world_object,
)


class CreatureRuntimeStore(RuntimeStore[Creature]):
    """Own long-lived snapshots of authoritative persistent Creature data.

    The store provides identity-based retention and lookup only. It does not
    own persistence, visibility, packets, lifecycle, updates, world
    membership, movement, combat, AI, or gameplay behavior.
    """

    def snapshot_matches(
        self,
        creature: Creature,
        mapping: Mapping[str, Any],
        *,
        runtime_guid: int,
    ) -> bool:
        """Validate the snapshot according to existing Creature rules."""
        return creature_matches_mapping(
            creature,
            mapping,
            runtime_guid=runtime_guid,
        )

    def resolve(
        self,
        mapping: Mapping[str, Any],
        *,
        runtime_guid: int,
    ) -> Creature:
        """Reuse a matching Creature or construct the existing fallback."""
        return resolve_spawned_world_object(
            mapping,
            runtime_guid=runtime_guid,
            store=self,
            snapshot_compatible=self.snapshot_matches,
            fallback_factory=Creature.from_mapping,
        )


_CREATURE_RUNTIME_STORE = CreatureRuntimeStore()


def get_creature_runtime_store() -> CreatureRuntimeStore:
    """Return the process-wide passive Creature runtime store."""
    return _CREATURE_RUNTIME_STORE


def creature_matches_mapping(
    creature: Creature,
    mapping: Mapping[str, Any],
    *,
    runtime_guid: int,
) -> bool:
    """Return whether a runtime snapshot matches persistent Creature data."""
    return (
        creature_identity_matches_mapping(
            creature,
            mapping,
            runtime_guid=runtime_guid,
        )
        and float(creature.x) == _mapping_float(mapping, "x")
        and float(creature.y) == _mapping_float(mapping, "y")
        and float(creature.z) == _mapping_float(mapping, "z")
        and float(creature.orientation)
        == _normalized_creature_orientation(_mapping_float(mapping, "orientation"))
        and creature.rotation
        == (
            _mapping_float(mapping, "rotation0"),
            _mapping_float(mapping, "rotation1"),
            _mapping_float(mapping, "rotation2"),
            _mapping_float(mapping, "rotation3"),
        )
        and float(creature.scale) == _mapping_float(mapping, "size", 1.0)
        and int(creature.display_id) == _mapping_creature_display_id(mapping)
        and int(creature.npc_flags) == _mapping_creature_npc_flags(mapping)
    )


def creature_identity_matches_mapping(
    creature: Creature,
    mapping: Mapping[str, Any],
    *,
    runtime_guid: int,
) -> bool:
    """Return whether a mapping identifies the same runtime Creature."""
    map_id = _mapping_int(mapping, "map_id", _mapping_int(mapping, "map"))
    return (
        int(creature.runtime_guid) == int(runtime_guid)
        and int(creature.spawn_id) == _mapping_int(mapping, "guid")
        and int(creature.entry) == _mapping_int(mapping, "entry")
        and int(creature.map_id) == map_id
        and int(creature.instance_id) == _mapping_int(mapping, "instance_id")
    )


def resolve_creature_runtime(
    mapping: Mapping[str, Any],
    *,
    runtime_guid: int,
) -> Creature:
    """Reuse a matching stored Creature or construct a temporary fallback."""
    return get_creature_runtime_store().resolve(
        mapping,
        runtime_guid=runtime_guid,
    )
