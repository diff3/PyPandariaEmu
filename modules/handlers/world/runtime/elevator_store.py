#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Runtime-GUID lifetime store for elevators."""

from __future__ import annotations

from typing import Any, Mapping

from server.modules.handlers.world.runtime.elevator import Elevator
from server.modules.handlers.world.runtime.runtime_store import RuntimeGuidStore


class ElevatorRuntimeStore(RuntimeGuidStore[Elevator]):
    """Retain long-lived elevators without owning their simulation."""


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
