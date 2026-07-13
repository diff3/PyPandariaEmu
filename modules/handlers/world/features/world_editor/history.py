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
    history = getattr(session, "_world_editor_history", None)
    if not isinstance(history, list):
        history = []
        session._world_editor_history = history
    return history


def push(
    session,
    operation: str,
    entry: dict[str, Any] | None = None,
    *,
    object_type: str = "GameObject",
    runtime_guid: int | None = None,
    undo_type: str | None = None,
    undo_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry = dict(entry or {})
    record = {
        "timestamp": time.strftime("%H:%M:%S", time.localtime()),
        "monotonic": time.monotonic(),
        "operation": str(operation or "").upper(),
        "object_type": str(object_type or ""),
        "name": str(entry.get("name", "") or ""),
        "entry": _entry_int(entry, "entry"),
        "spawn_id": _entry_int(entry, "guid"),
        "runtime_guid": int(runtime_guid or entry.get("world_guid", 0) or 0),
        "undo_type": str(undo_type or "").upper(),
        "undo_data": dict(undo_data) if isinstance(undo_data, dict) else None,
    }
    history = _history(session)
    history.append(record)
    del history[:-_HISTORY_LIMIT]
    session._go_history = history
    return record


def pop_latest_undo(session, undo_type: str, *, object_type: str | None = None) -> dict[str, Any] | None:
    history = _history(session)
    expected = str(undo_type or "").upper()
    expected_object_type = str(object_type or "") if object_type is not None else ""
    for index in range(len(history) - 1, -1, -1):
        record = history[index]
        if expected_object_type and str(record.get("object_type", "")) != expected_object_type:
            continue
        if str(record.get("undo_type", "")).upper() != expected:
            continue
        undo_data = record.get("undo_data")
        if not isinstance(undo_data, dict):
            continue
        record["undo_type"] = ""
        record["undo_data"] = None
        return dict(undo_data)
    return None


def list_history(session, *, object_type: str | None = None) -> list[dict[str, Any]]:
    records = list(_history(session))
    if object_type is None:
        return records
    expected = str(object_type or "")
    return [record for record in records if str(record.get("object_type", "")) == expected]
