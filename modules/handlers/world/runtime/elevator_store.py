#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Runtime-GUID lifetime store for elevators."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Mapping

from server.modules.handlers.world.runtime.elevator import Elevator


class ElevatorRuntimeStore:
    """Retain long-lived elevators without owning their simulation."""

    def __init__(self) -> None:
        self._by_runtime_guid: dict[int, Elevator] = {}

    def add(self, elevator: Elevator) -> Elevator:
        """Retain and return an elevator under its runtime GUID."""
        self._by_runtime_guid[int(elevator.runtime_guid)] = elevator
        return elevator

    def remove(self, runtime_guid: int) -> Elevator | None:
        """Remove and return an elevator, if present."""
        return self._by_runtime_guid.pop(int(runtime_guid), None)

    def get(self, runtime_guid: int) -> Elevator | None:
        """Return an elevator by runtime GUID."""
        return self._by_runtime_guid.get(int(runtime_guid))

    def contains(self, runtime_guid: int) -> bool:
        """Return whether an elevator is retained."""
        return int(runtime_guid) in self._by_runtime_guid

    def clear(self) -> None:
        """Remove every retained elevator."""
        self._by_runtime_guid.clear()

    def __iter__(self) -> Iterator[Elevator]:
        """Iterate over retained elevators."""
        return iter(self._by_runtime_guid.values())


_ELEVATOR_RUNTIME_STORE = ElevatorRuntimeStore()


def get_elevator_runtime_store() -> ElevatorRuntimeStore:
    """Return the process-wide elevator runtime store."""
    return _ELEVATOR_RUNTIME_STORE


def resolve_elevator_runtime(
    mapping: Mapping[str, Any],
    *,
    runtime_guid: int,
    state: Any | None = None,
) -> Elevator:
    """Reuse the retained elevator or construct an unregistered fallback."""
    elevator = _ELEVATOR_RUNTIME_STORE.get(int(runtime_guid))
    if elevator is not None:
        return elevator
    if state is not None:
        return Elevator.from_runtime_state(state, mapping)
    return Elevator.from_mapping(mapping, runtime_guid=int(runtime_guid))
