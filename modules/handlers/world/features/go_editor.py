from __future__ import annotations

from server.modules.handlers.world.features.world_editor import clipboard as gameobject_clipboard
from server.modules.handlers.world.features.world_editor import gameobject_editor


find_nearest_editable_gameobject = gameobject_editor.find_nearest_editable_gameobject
find_nearest_editable = gameobject_editor.find_nearest_editable
find_nearby = gameobject_editor.find_nearby
show_info = gameobject_editor.show_info
copy_gameobject = gameobject_clipboard.copy_gameobject
place_gameobject = gameobject_clipboard.place_gameobject
delete_gameobject = gameobject_editor.delete
move_gameobject = gameobject_editor.move
rotate_gameobject = gameobject_editor.rotate
restore_deleted_gameobject = gameobject_editor.restore_deleted_gameobject
add_gameobject = gameobject_editor.create
select_gameobject = gameobject_editor.select_nearest
clear_selection = gameobject_editor.clear


def info(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.info(session)


def list_nearby_command(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) > 1:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go list [radius]"])
    radius = gameobject_editor.DEFAULT_SEARCH_RADIUS
    if args:
        try:
            radius = float(args[0])
        except Exception:
            return gameobject_editor.chat_lines(["[GMGo] Usage: .go list [radius]"])
    return gameobject_editor.list_nearby(session, radius)


def add(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) != 1:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go add <entry>"])
    try:
        go_entry = int(args[0])
    except Exception:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go add <entry>"])
    responses, _created = gameobject_editor.create(session, go_entry, operation="ADD")
    return responses


def search(session, args: list[str]) -> list[tuple[str, bytes]]:
    if not args:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go search <text> [limit]"])
    limit = 20
    text_args = list(args)
    if len(args) >= 2:
        try:
            parsed_limit = int(args[-1])
        except Exception:
            parsed_limit = None
        if parsed_limit is not None:
            limit = max(1, min(int(parsed_limit), 100))
            text_args = list(args[:-1])
    query = " ".join(str(part) for part in text_args).strip()
    if not query:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go search <text> [limit]"])
    return gameobject_editor.search_templates(session, query, limit)


def delete_nearest(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.delete_nearest(session)


def undo(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.undo(session)


def move(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.move_nearest(session)


def rotate(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.rotate_nearest(session)


def scale(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) != 1:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go scale <value>"])
    try:
        value = float(args[0])
    except Exception:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go scale <value>"])
    return gameobject_editor.scale(session, value)


def copy(session) -> list[tuple[str, bytes]]:
    return gameobject_clipboard.copy(session)


def place(session) -> list[tuple[str, bytes]]:
    return gameobject_clipboard.place(session)


def history(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.history(session)


def reload(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.reload(session)


def select(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) > 1:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go select [spawnid]"])
    if not args:
        return gameobject_editor.select_nearest(session)
    try:
        spawn_id = int(args[0])
    except Exception:
        return gameobject_editor.chat_lines(["[GMGo] Usage: .go select [spawnid]"])
    return gameobject_editor.select_spawn(session, spawn_id)


def current(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.current(session)


def clear(session) -> list[tuple[str, bytes]]:
    return gameobject_editor.clear(session)
