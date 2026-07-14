#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lifetime store for persistent runtime GameObjects."""

from __future__ import annotations

from typing import Any, Mapping

from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)
from server.modules.handlers.world.runtime.runtime_store import RuntimeStore
from server.modules.handlers.world.runtime.spawned_world_object import (
    resolve_spawned_world_object,
)


class GameObjectRuntimeStore(RuntimeStore[GameObject]):
    """Own long-lived GameObjects initialized from persistent spawn mappings.

    Retained GameObjects own their mutable runtime values while mappings are
    persistence snapshots. The store provides identity-based
    retention and lookup only. It does not own persistence, visibility,
    packets, collision, lifecycle, updates, world membership, or gameplay
    behavior.
    """

    def snapshot_matches(
        self,
        gameobject: GameObject,
        mapping: Mapping[str, Any],
        *,
        runtime_guid: int,
    ) -> bool:
        """Validate the snapshot according to existing GameObject rules."""
        matcher = (
            gameobject_matches_mapping
            if _mapping_int(mapping, "type") in (11, 15)
            else gameobject_identity_matches_mapping
        )
        return matcher(gameobject, mapping, runtime_guid=runtime_guid)

    def resolve(
        self,
        mapping: Mapping[str, Any],
        *,
        runtime_guid: int,
    ) -> GameObject:
        """Reuse matching runtime state or construct the existing fallback."""
        return resolve_spawned_world_object(
            mapping,
            runtime_guid=runtime_guid,
            store=self,
            snapshot_compatible=self.snapshot_matches,
            fallback_factory=GameObject.from_mapping,
        )


_GAMEOBJECT_RUNTIME_STORE = GameObjectRuntimeStore()


def get_gameobject_runtime_store() -> GameObjectRuntimeStore:
    """Return the process-wide passive GameObject runtime store."""
    return _GAMEOBJECT_RUNTIME_STORE


def gameobject_identity_matches_mapping(
    gameobject: GameObject,
    mapping: Mapping[str, Any],
    *,
    runtime_guid: int,
) -> bool:
    """Return whether a mapping describes the same runtime GameObject."""
    map_id = _mapping_int(mapping, "map_id", _mapping_int(mapping, "map"))
    return (
        int(gameobject.runtime_guid) == int(runtime_guid)
        and int(gameobject.spawn_id) == _mapping_int(mapping, "guid")
        and int(gameobject.entry) == _mapping_int(mapping, "entry")
        and int(gameobject.map_id) == map_id
        and int(gameobject.instance_id) == _mapping_int(mapping, "instance_id")
    )


def gameobject_matches_mapping(
    gameobject: GameObject,
    mapping: Mapping[str, Any],
    *,
    runtime_guid: int,
) -> bool:
    """Return whether identity and transform match authoritative data."""
    return (
        gameobject_identity_matches_mapping(
            gameobject,
            mapping,
            runtime_guid=runtime_guid,
        )
        and float(gameobject.x) == _mapping_float(mapping, "x")
        and float(gameobject.y) == _mapping_float(mapping, "y")
        and float(gameobject.z) == _mapping_float(mapping, "z")
        and float(gameobject.orientation) == _mapping_float(mapping, "orientation")
        and gameobject.rotation
        == (
            _mapping_float(mapping, "rotation0"),
            _mapping_float(mapping, "rotation1"),
            _mapping_float(mapping, "rotation2"),
            _mapping_float(mapping, "rotation3"),
        )
        and float(gameobject.scale) == _mapping_float(mapping, "size", 1.0)
        and int(gameobject.display_id) == _mapping_int(mapping, "display_id")
        and int(gameobject.state) == _mapping_int(mapping, "state")
        and int(gameobject.flags) == _mapping_int(mapping, "flags")
        and int(gameobject.faction) == _mapping_int(mapping, "faction")
        and int(gameobject.art_kit) == _mapping_int(mapping, "artkit")
        and int(gameobject.animation_progress)
        == _mapping_int(mapping, "animprogress")
        and int(gameobject.gameobject_type) == _mapping_int(mapping, "type")
    )


def resolve_gameobject_runtime(
    mapping: Mapping[str, Any],
    *,
    runtime_guid: int,
) -> GameObject:
    """Reuse stored runtime state or construct a temporary fallback.

    Ordinary persistent GameObjects use identity-only matching because their
    mutable values are runtime-authoritative. Transport projections retain
    full mapping matching because their runtime state is supplied by the
    existing transport subsystem.
    """
    return get_gameobject_runtime_store().resolve(
        mapping,
        runtime_guid=runtime_guid,
    )
