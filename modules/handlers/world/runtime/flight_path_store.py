#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Runtime-GUID lifetime store for active taxi FlightPaths."""

from __future__ import annotations

from typing import Any

from server.modules.handlers.world.runtime.flight_path import (
    FlightPath,
    flight_path_runtime_guid,
)
from server.modules.handlers.world.runtime.runtime_store import RuntimeGuidStore


class FlightPathRuntimeStore(RuntimeGuidStore[FlightPath]):
    """Retain FlightPaths without owning flight simulation or lifecycle."""


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
