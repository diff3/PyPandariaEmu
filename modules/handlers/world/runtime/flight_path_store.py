#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Runtime-GUID lifetime store for active taxi FlightPaths."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from server.modules.handlers.world.runtime.flight_path import (
    FlightPath,
    flight_path_runtime_guid,
)


class FlightPathRuntimeStore:
    """Retain FlightPaths without owning flight simulation or lifecycle."""

    def __init__(self) -> None:
        self._by_runtime_guid: dict[int, FlightPath] = {}

    def add(self, flight_path: FlightPath) -> FlightPath:
        """Retain and return a FlightPath under its runtime GUID."""
        self._by_runtime_guid[int(flight_path.runtime_guid)] = flight_path
        return flight_path

    def remove(self, runtime_guid: int) -> FlightPath | None:
        """Remove and return a FlightPath, if present."""
        return self._by_runtime_guid.pop(int(runtime_guid), None)

    def get(self, runtime_guid: int) -> FlightPath | None:
        """Return a FlightPath by runtime GUID."""
        return self._by_runtime_guid.get(int(runtime_guid))

    def contains(self, runtime_guid: int) -> bool:
        """Return whether a FlightPath is retained."""
        return int(runtime_guid) in self._by_runtime_guid

    def clear(self) -> None:
        """Remove every retained FlightPath."""
        self._by_runtime_guid.clear()

    def __iter__(self) -> Iterator[FlightPath]:
        """Iterate over retained FlightPaths."""
        return iter(self._by_runtime_guid.values())


_FLIGHT_PATH_RUNTIME_STORE = FlightPathRuntimeStore()


def get_flight_path_runtime_store() -> FlightPathRuntimeStore:
    """Return the process-wide active FlightPath store."""
    return _FLIGHT_PATH_RUNTIME_STORE


def register_flight_path_runtime(session: Any) -> FlightPath:
    """Create and retain one FlightPath at the existing flight-start boundary."""
    return _FLIGHT_PATH_RUNTIME_STORE.add(FlightPath.from_session(session))


def resolve_flight_path_runtime(session: Any) -> FlightPath:
    """Return the retained FlightPath or an unregistered fallback snapshot."""
    runtime_guid = flight_path_runtime_guid(session)
    flight_path = _FLIGHT_PATH_RUNTIME_STORE.get(runtime_guid)
    if flight_path is not None:
        return flight_path
    return FlightPath.from_session(session)


def sync_flight_path_runtime_from_session(session: Any) -> FlightPath | None:
    """Publish committed session geometry into an existing FlightPath."""
    runtime_guid = flight_path_runtime_guid(session)
    flight_path = _FLIGHT_PATH_RUNTIME_STORE.get(runtime_guid)
    if flight_path is None:
        return None
    flight_path.publish_transform(session)
    return flight_path


def unregister_flight_path_runtime(session: Any) -> FlightPath | None:
    """Release the FlightPath at an existing flight termination boundary."""
    return _FLIGHT_PATH_RUNTIME_STORE.remove(flight_path_runtime_guid(session))
