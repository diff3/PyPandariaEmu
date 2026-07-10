from __future__ import annotations

import time
from typing import Any


_HISTORY_LIMIT = 20


def _entry_int(entry: dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(entry.get(key, default) or default)
    except Exception:
        return int(default)


def _history(session) -> list[dict[str, Any]]:
    history = getattr(session, "_go_history", None)
    if not isinstance(history, list):
        history = []
        session._go_history = history
    return history


def push(
    session,
    operation: str,
    entry: dict[str, Any] | None = None,
    *,
    undo_type: str | None = None,
    undo_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry = dict(entry or {})
    record = {
        "timestamp": time.strftime("%H:%M:%S", time.localtime()),
        "monotonic": time.monotonic(),
        "operation": str(operation or "").upper(),
        "name": str(entry.get("name", "") or ""),
        "entry": _entry_int(entry, "entry"),
        "spawn_id": _entry_int(entry, "guid"),
        "undo_type": str(undo_type or ""),
        "undo_data": dict(undo_data) if isinstance(undo_data, dict) else None,
    }
    history = _history(session)
    history.append(record)
    del history[:-_HISTORY_LIMIT]
    return record


def pop_latest_undo(session, undo_type: str) -> dict[str, Any] | None:
    history = _history(session)
    expected = str(undo_type or "").upper()
    for index in range(len(history) - 1, -1, -1):
        record = history[index]
        if str(record.get("undo_type", "")).upper() != expected:
            continue
        undo_data = record.get("undo_data")
        if not isinstance(undo_data, dict):
            continue
        record["undo_type"] = ""
        record["undo_data"] = None
        return dict(undo_data)
    return None


def list_history(session) -> list[dict[str, Any]]:
    return list(_history(session))
