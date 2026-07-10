from __future__ import annotations

from collections.abc import Callable
from typing import Any
import time

from shared.Logger import Logger


HANDLERS: dict[str, Callable[[Any, Any], tuple[int, Any]]] = {}


def register(opcode: str):
    """Register a world opcode handler in the shared dispatcher registry."""
    def wrapper(func):
        HANDLERS[str(opcode)] = func
        return func

    return wrapper


def dispatch(session, opcode: str, data):
    """
    Dispatch one world packet to its registered handler.

    Inputs:
    - session: connection-scoped world session
    - opcode: decoded opcode name
    - data: packet context / handler input
    """
    handler = HANDLERS.get(str(opcode))
    if handler is None:
        Logger.warning(f"Unhandled opcode: {opcode}")
        return 0, None

    if (
        (str(opcode).startswith("MSG_MOVE") or str(opcode).startswith("CMSG_MOVE"))
        and str(opcode) != "CMSG_MOVE_SPLINE_DONE"
    ):
        try:
            from server.modules.handlers.world.taxi_runtime import is_taxi_active
        except Exception:
            is_taxi_active = None
        if callable(is_taxi_active) and is_taxi_active(session):
            Logger.debug("[TAXI] ignored movement opcode=%s while controls locked", str(opcode))
            return 0, None

    Logger.debug(f"[DISPATCH] opcode={opcode} handler={handler.__name__}")
    if str(opcode) != "CMSG_LOADING_SCREEN_NOTIFY":
        return handler(session, data)

    started = time.monotonic()
    trace_id = str(getattr(session, "loading_screen_trace_id", "pending") or "pending")
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=dispatcher event=entering handler=%s",
        trace_id,
        handler.__name__,
    )
    try:
        result = handler(session, data)
    except Exception as exc:
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=dispatcher event=exception "
            "elapsed_ms=%.3f error=%s",
            str(getattr(session, "loading_screen_trace_id", trace_id) or trace_id),
            (time.monotonic() - started) * 1000.0,
            str(exc),
        )
        raise
    response = result[1] if isinstance(result, tuple) and len(result) > 1 else None
    packet_count = len(response) if isinstance(response, list) else (1 if response else 0)
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=dispatcher event=leaving "
        "elapsed_ms=%.3f packets=%s empty=%s",
        str(getattr(session, "loading_screen_trace_id", trace_id) or trace_id),
        (time.monotonic() - started) * 1000.0,
        packet_count,
        "true" if not response else "false",
    )
    return result
