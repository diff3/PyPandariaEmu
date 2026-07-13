from __future__ import annotations

from typing import Any

from server.modules.handlers.world.features.world_editor import gameobject_editor
from server.modules.handlers.world.features.world_editor import history as editor_history


GAMEOBJECT_TYPE = "GameObject"


def _clipboard_store(session) -> dict[str, dict[str, Any]]:
    store = getattr(session, "_world_editor_clipboard", None)
    if not isinstance(store, dict):
        store = {}
        session._world_editor_clipboard = store
    return store


def set_clipboard(session, object_type: str, data: dict[str, Any]) -> dict[str, Any]:
    item = {
        "object_type": str(object_type or ""),
        "data": dict(data),
    }
    _clipboard_store(session)[item["object_type"]] = item
    return item


def get_clipboard(session, object_type: str | None = None) -> dict[str, Any] | None:
    store = getattr(session, "_world_editor_clipboard", None)
    if not isinstance(store, dict):
        return None
    if object_type is not None:
        item = store.get(str(object_type or ""))
        return dict(item) if isinstance(item, dict) else None
    if not store:
        return None
    item = next(reversed(store.values()))
    return dict(item) if isinstance(item, dict) else None


def copy_gameobject(entry: dict[str, Any]) -> dict[str, Any]:
    copied = dict(entry)
    copied.pop("world_guid", None)
    return copied


def copy(session) -> list[tuple[str, bytes]]:
    entry = gameobject_editor.selected_entry(session)
    if entry is None:
        return gameobject_editor.chat_lines(["[GMGo] No GameObject selected."])
    clipboard = copy_gameobject(entry)
    set_clipboard(session, GAMEOBJECT_TYPE, clipboard)
    session._go_clipboard = clipboard
    world_guid = gameobject_editor.world_guid_for_entry(session, entry)
    gameobject_editor.log_action("COPY", session, entry, world_guid)
    editor_history.push(session, "COPY", entry, object_type=GAMEOBJECT_TYPE, runtime_guid=world_guid)
    return gameobject_editor.chat_lines(["[GMGo] Copied GameObject."])


def place_gameobject(session, clipboard: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    return gameobject_editor.create(
        session,
        gameobject_editor.entry_int(clipboard, "entry"),
        clipboard,
        operation="PLACE",
    )


def place(session) -> list[tuple[str, bytes]]:
    item = get_clipboard(session, GAMEOBJECT_TYPE)
    clipboard = item.get("data") if isinstance(item, dict) else None
    if not isinstance(clipboard, dict):
        return gameobject_editor.chat_lines(["[GMGo] Nothing copied."])
    responses, _placed = place_gameobject(session, clipboard)
    return responses
