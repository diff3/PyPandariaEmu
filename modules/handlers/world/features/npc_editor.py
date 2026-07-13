from __future__ import annotations

from server.modules.handlers.world.features.world_editor import creature_editor


def info(session) -> list[tuple[str, bytes]]:
    return creature_editor.info(session)


def list_nearby_command(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) > 1:
        return creature_editor.chat_lines(["[GMNpc] Usage: .npc list [radius]"])
    radius = creature_editor.DEFAULT_SEARCH_RADIUS
    if args:
        try:
            radius = float(args[0])
        except Exception:
            return creature_editor.chat_lines(["[GMNpc] Usage: .npc list [radius]"])
    return creature_editor.list_nearby(session, radius)


def search(session, args: list[str]) -> list[tuple[str, bytes]]:
    if not args:
        return creature_editor.chat_lines(["[GMNpc] Usage: .npc search <text> [limit]"])
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
        return creature_editor.chat_lines(["[GMNpc] Usage: .npc search <text> [limit]"])
    return creature_editor.search_templates(session, query, limit)


def add(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) != 1:
        return creature_editor.chat_lines(["[GMNpc] Usage: .npc add <entry>"])
    try:
        creature_entry = int(args[0])
    except Exception:
        return creature_editor.chat_lines(["[GMNpc] Usage: .npc add <entry>"])
    responses, _created = creature_editor.create(session, creature_entry, operation="ADD")
    return responses


def select(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) > 1:
        return creature_editor.chat_lines(["[GMNpc] Usage: .npc select [spawnid]"])
    if not args:
        return creature_editor.select_nearest(session)
    try:
        spawn_id = int(args[0])
    except Exception:
        return creature_editor.chat_lines(["[GMNpc] Usage: .npc select [spawnid]"])
    return creature_editor.select_spawn(session, spawn_id)


def current(session) -> list[tuple[str, bytes]]:
    return creature_editor.current(session)


def clear(session) -> list[tuple[str, bytes]]:
    return creature_editor.clear(session)


def delete_selected(session) -> list[tuple[str, bytes]]:
    return creature_editor.delete_selected(session)


def undo(session) -> list[tuple[str, bytes]]:
    return creature_editor.undo(session)


def move(session) -> list[tuple[str, bytes]]:
    return creature_editor.move_selected(session)


def rotate(session) -> list[tuple[str, bytes]]:
    return creature_editor.rotate_selected(session)


def copy(session) -> list[tuple[str, bytes]]:
    return creature_editor.copy(session)


def place(session) -> list[tuple[str, bytes]]:
    return creature_editor.place(session)


def history(session) -> list[tuple[str, bytes]]:
    return creature_editor.history(session)
