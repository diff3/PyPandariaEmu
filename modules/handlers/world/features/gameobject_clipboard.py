from __future__ import annotations

from typing import Any

from server.modules.handlers.world.features import gameobject_editor
from server.modules.handlers.world.features import gameobject_history


def copy_gameobject(entry: dict[str, Any]) -> dict[str, Any]:
    copied = dict(entry)
    copied.pop("world_guid", None)
    return copied


def copy(session) -> list[tuple[str, bytes]]:
    found = gameobject_editor.find_nearest_editable_gameobject(session)
    if found is None:
        return gameobject_editor.chat_lines(["[GMGo] No nearby editable GameObject."])
    entry, _distance = found
    clipboard = copy_gameobject(entry)
    session._go_clipboard = clipboard
    gameobject_editor.log_action("COPY", session, entry, gameobject_editor.world_guid_for_entry(session, entry))
    gameobject_history.push(session, "COPY", entry)
    return gameobject_editor.chat_lines(["[GMGo] Copied GameObject."])


def place_gameobject(session, clipboard: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    return gameobject_editor.create(
        session,
        gameobject_editor.entry_int(clipboard, "entry"),
        clipboard,
        operation="PLACE",
    )


def place(session) -> list[tuple[str, bytes]]:
    clipboard = getattr(session, "_go_clipboard", None)
    if not isinstance(clipboard, dict):
        return gameobject_editor.chat_lines(["[GMGo] Nothing copied."])
    responses, _placed = place_gameobject(session, clipboard)
    return responses
