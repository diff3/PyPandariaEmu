#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic identity-indexed lifetime storage for spawned runtime objects."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Generic, Protocol, TypeVar


class _RuntimeStoreEntry(Protocol):
    """Structural identity required by ``RuntimeStore``."""

    runtime_guid: int
    spawn_id: int


RuntimeEntryT = TypeVar("RuntimeEntryT", bound=_RuntimeStoreEntry)


class RuntimeStore(Generic[RuntimeEntryT]):
    """Retain runtime objects under runtime and persistent spawn identities.

    The store owns only indexes and object lifetime. It does not know concrete
    runtime-object types, mappings, snapshot validation, fallback construction,
    persistence, visibility, packets, lifecycle, or gameplay behavior.
    """

    def __init__(self) -> None:
        self._by_runtime_guid: dict[int, RuntimeEntryT] = {}
        self._runtime_guid_by_spawn_id: dict[int, int] = {}

    def add(self, runtime_object: RuntimeEntryT) -> RuntimeEntryT:
        """Retain an object under its runtime and persistent identities."""
        runtime_guid = int(runtime_object.runtime_guid)
        spawn_id = int(runtime_object.spawn_id)

        previous = self._by_runtime_guid.get(runtime_guid)
        if previous is not None:
            previous_spawn_id = int(previous.spawn_id)
            if previous_spawn_id != spawn_id:
                self._runtime_guid_by_spawn_id.pop(previous_spawn_id, None)

        previous_runtime_guid = self._runtime_guid_by_spawn_id.get(spawn_id)
        if previous_runtime_guid is not None and previous_runtime_guid != runtime_guid:
            self._by_runtime_guid.pop(previous_runtime_guid, None)

        self._by_runtime_guid[runtime_guid] = runtime_object
        self._runtime_guid_by_spawn_id[spawn_id] = runtime_guid
        return runtime_object

    def remove(self, runtime_guid: int) -> RuntimeEntryT | None:
        """Remove and return the object for a runtime GUID, if present."""
        normalized_guid = int(runtime_guid)
        runtime_object = self._by_runtime_guid.pop(normalized_guid, None)
        if runtime_object is None:
            return None
        spawn_id = int(runtime_object.spawn_id)
        if self._runtime_guid_by_spawn_id.get(spawn_id) == normalized_guid:
            self._runtime_guid_by_spawn_id.pop(spawn_id, None)
        return runtime_object

    def get(self, runtime_guid: int) -> RuntimeEntryT | None:
        """Return the retained object for a runtime GUID."""
        return self._by_runtime_guid.get(int(runtime_guid))

    def get_by_spawn_id(self, spawn_id: int) -> RuntimeEntryT | None:
        """Return the retained object for a persistent spawn ID."""
        runtime_guid = self._runtime_guid_by_spawn_id.get(int(spawn_id))
        if runtime_guid is None:
            return None
        return self._by_runtime_guid.get(runtime_guid)

    def contains(self, runtime_guid: int) -> bool:
        """Return whether a runtime GUID is retained."""
        return int(runtime_guid) in self._by_runtime_guid

    def clear(self) -> None:
        """Remove all retained objects and identity indexes."""
        self._by_runtime_guid.clear()
        self._runtime_guid_by_spawn_id.clear()

    def __iter__(self) -> Iterator[RuntimeEntryT]:
        """Iterate over retained runtime objects."""
        return iter(self._by_runtime_guid.values())
