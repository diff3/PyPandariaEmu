#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import inspect
from pathlib import Path

from server.modules.handlers.world import feature_config
from server.modules.handlers.world import transport_debug
from server.modules.handlers.world import transport_runtime
from server.modules.handlers.world.movements.manager import MovementManager


def test_transport_lifecycle_debug_defaults_to_disabled(monkeypatch) -> None:
    monkeypatch.setattr(feature_config.ConfigLoader, "get_config", lambda: {})

    assert feature_config.transport_lifecycle_debug_enabled() is False


def test_transport_lifecycle_debug_reads_existing_transport_config_style(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        feature_config.ConfigLoader,
        "get_config",
        lambda: {"Transport": {"DebugLifecycle": True}},
    )

    assert feature_config.transport_lifecycle_debug_enabled() is True


def test_transport_lifecycle_event_is_silent_when_disabled(monkeypatch) -> None:
    captured = []
    monkeypatch.setattr(
        transport_debug,
        "transport_lifecycle_debug_enabled",
        lambda: False,
    )
    monkeypatch.setattr(
        transport_debug.Logger,
        "info",
        lambda message, *args: captured.append(message % args),
    )

    emitted = transport_debug.log_transport_event(
        transport_debug.TransportDebugEvent.BOUNDARY_REACHED,
        transport_guid=7,
        source="map:1",
        destination="map:0",
    )

    assert emitted is False
    assert captured == []


def test_transport_lifecycle_event_is_structured_when_enabled(monkeypatch) -> None:
    captured = []
    monkeypatch.setattr(
        transport_debug,
        "transport_lifecycle_debug_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        transport_debug.Logger,
        "info",
        lambda message, *args: captured.append(message % args),
    )

    emitted = transport_debug.log_transport_event(
        transport_debug.TransportDebugEvent.WORLDPORT_STARTED,
        transport_guid=7,
        entry=20808,
        transfer_id="boundary-7",
        source="map:1",
        destination="map:0",
        participants=2,
    )

    assert emitted is True
    assert captured == [
        "[TransportLifecycle] event=worldport_started "
        "transport=0x0000000000000007 entry=20808 transfer_id=boundary-7 "
        "from=map:1 to=map:0 participants=2"
    ]


def test_transport_runtime_has_no_tick_logging_facility() -> None:
    runtime_source = inspect.getsource(transport_runtime)
    manager_source = inspect.getsource(MovementManager)
    movement_source = (
        Path(transport_runtime.__file__).parent / "opcodes" / "movement.py"
    ).read_text(encoding="utf-8")

    assert "transport_tick" not in runtime_source
    assert "_maybe_log_transport_tick" not in runtime_source
    assert "[TRANSPORT_DISCOVERY]" not in runtime_source
    assert "[TRANSPORT_DISCOVERY_SUMMARY]" not in runtime_source
    assert "[TransportOffset]" not in movement_source
    assert "def _log_tick" not in manager_source
