#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lifetime store for persistent runtime GameObjects."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Mapping

from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.runtime_object import (
    _mapping_float,
    _mapping_int,
)


class GameObjectRuntimeStore:
    """Own long-lived GameObjects initialized from persistent spawn mappings.

    Retained GameObjects own their mutable runtime values while the mappings
    remain persistence-authoritative. The store provides identity-based
    retention and lookup only. It does not own persistence, visibility,
    packets, collision, lifecycle, updates, world membership, or gameplay
    behavior.
    """

    def __init__(self) -> None:
        self._by_runtime_guid: dict[int, GameObject] = {}
        self._runtime_guid_by_spawn_id: dict[int, int] = {}

    def add(self, gameobject: GameObject) -> GameObject:
        """Retain a GameObject under its runtime and persistent identities."""
        runtime_guid = int(gameobject.runtime_guid)
        spawn_id = int(gameobject.spawn_id)

        previous = self._by_runtime_guid.get(runtime_guid)
        if previous is not None:
            previous_spawn_id = int(previous.spawn_id)
            if previous_spawn_id != spawn_id:
                self._runtime_guid_by_spawn_id.pop(previous_spawn_id, None)

        previous_runtime_guid = self._runtime_guid_by_spawn_id.get(spawn_id)
        if previous_runtime_guid is not None and previous_runtime_guid != runtime_guid:
            self._by_runtime_guid.pop(previous_runtime_guid, None)

        self._by_runtime_guid[runtime_guid] = gameobject
        self._runtime_guid_by_spawn_id[spawn_id] = runtime_guid
        return gameobject

    def remove(self, runtime_guid: int) -> GameObject | None:
        """Remove and return the GameObject for a runtime GUID, if present."""
        normalized_guid = int(runtime_guid)
        gameobject = self._by_runtime_guid.pop(normalized_guid, None)
        if gameobject is None:
            return None
        spawn_id = int(gameobject.spawn_id)
        if self._runtime_guid_by_spawn_id.get(spawn_id) == normalized_guid:
            self._runtime_guid_by_spawn_id.pop(spawn_id, None)
        return gameobject

    def get(self, runtime_guid: int) -> GameObject | None:
        """Return the retained GameObject for a runtime GUID."""
        return self._by_runtime_guid.get(int(runtime_guid))

    def get_by_spawn_id(self, spawn_id: int) -> GameObject | None:
        """Return the retained GameObject for a persistent spawn ID."""
        runtime_guid = self._runtime_guid_by_spawn_id.get(int(spawn_id))
        if runtime_guid is None:
            return None
        return self._by_runtime_guid.get(runtime_guid)

    def contains(self, runtime_guid: int) -> bool:
        """Return whether a runtime GUID is retained."""
        return int(runtime_guid) in self._by_runtime_guid

    def clear(self) -> None:
        """Remove all retained runtime mirrors."""
        self._by_runtime_guid.clear()
        self._runtime_guid_by_spawn_id.clear()

    def __iter__(self) -> Iterator[GameObject]:
        """Iterate over retained GameObject instances."""
        return iter(self._by_runtime_guid.values())


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
    stored = get_gameobject_runtime_store().get_by_spawn_id(
        _mapping_int(mapping, "guid")
    )
    if stored is not None:
        mapping_type = _mapping_int(mapping, "type")
        uses_transport_projection = mapping_type in (11, 15)
        matcher = (
            gameobject_matches_mapping
            if uses_transport_projection
            else gameobject_identity_matches_mapping
        )
        if matcher(stored, mapping, runtime_guid=runtime_guid):
            return stored
    return GameObject.from_mapping(mapping, runtime_guid=runtime_guid)
