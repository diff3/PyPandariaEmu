#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive lifetime store for persistent runtime GameObjects."""

from __future__ import annotations

from collections.abc import Iterator

from server.modules.handlers.world.runtime.gameobject import GameObject


class GameObjectRuntimeStore:
    """Own long-lived mirrors of authoritative persistent spawn mappings.

    The store provides identity-based retention and lookup only. It does not
    own persistence, visibility, packets, collision, lifecycle, updates, world
    membership, or gameplay behavior.
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
