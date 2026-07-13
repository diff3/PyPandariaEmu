from __future__ import annotations

from typing import Any

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.features.world_editor import history as editor_history
from server.modules.handlers.world.features.world_editor import selection
from server.modules.handlers.world.runtime import gameobject_spawns as gameobject_runtime


DEFAULT_SEARCH_RADIUS = selection.DEFAULT_SEARCH_RADIUS


def _gm_name(session) -> str:
    return str(
        getattr(session, "player_name", "")
        or getattr(session, "char_name", "")
        or getattr(session, "char_guid", "")
        or getattr(session, "account_id", "")
        or "unknown"
    )


def _chat(message: str) -> tuple[str, bytes]:
    return ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(str(message)))


def chat_lines(lines: list[str]) -> list[tuple[str, bytes]]:
    return [_chat(line) for line in lines]


def entry_int(entry: dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(entry.get(key, default) or default)
    except Exception:
        return int(default)


def entry_float(entry: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(entry.get(key, default) or default)
    except Exception:
        return float(default)


def world_guid_for_entry(session, entry: dict[str, Any]) -> int:
    return selection.gameobject_world_guid(session, entry)


def player_position(session) -> tuple[float, float, float, float]:
    return selection.player_position(session)


def entry_map_id(entry: dict[str, Any]) -> int:
    return entry_int(entry, "map_id", entry_int(entry, "map"))


def distance_3d(session, entry: dict[str, Any]) -> float:
    px, py, pz, _orientation = player_position(session)
    dx = entry_float(entry, "x") - px
    dy = entry_float(entry, "y") - py
    dz = entry_float(entry, "z") - pz
    return ((dx * dx) + (dy * dy) + (dz * dz)) ** 0.5


def front_dot(session, entry: dict[str, Any]) -> float:
    return 1.0


def is_editable_candidate(entry: dict[str, Any]) -> bool:
    return selection.is_editable_gameobject(entry)


def _persistent_spawn(entry: dict[str, Any]) -> dict[str, Any] | None:
    spawn_id = entry_int(entry, "guid")
    if spawn_id <= 0:
        return None
    return DatabaseConnection.get_gameobject_spawn(spawn_id)


def find_nearby(session, radius: float = DEFAULT_SEARCH_RADIUS) -> list[tuple[dict[str, Any], float]]:
    return selection.find_nearby_gameobjects(session, radius)


def find_nearest_editable_gameobject(session, radius: float = DEFAULT_SEARCH_RADIUS) -> tuple[dict[str, Any], float] | None:
    return selection.find_nearest_gameobject(session, radius)


def find_nearest_editable(session, radius: float = DEFAULT_SEARCH_RADIUS) -> tuple[dict[str, Any], float] | None:
    return find_nearest_editable_gameobject(session, radius)


def get_by_spawn_id(session, spawn_id: int) -> dict[str, Any] | None:
    entry = DatabaseConnection.get_gameobject_spawn(int(spawn_id or 0))
    if entry is None or not is_editable_candidate(entry):
        return None
    entry = dict(entry)
    map_id = int(getattr(session, "map_id", 0) or 0)
    if entry_map_id(entry) not in (0, map_id):
        return None
    entry["realm_id"] = int(getattr(session, "realm_id", 1) or 1)
    entry["world_guid"] = world_guid_for_entry(session, entry)
    return entry


def selected_entry(session) -> dict[str, Any] | None:
    selected = selection.get_selection(session, selection.GAMEOBJECT_TYPE)
    if selected is None:
        return None
    entry = get_by_spawn_id(session, entry_int(selected, "spawn_id"))
    if entry is None:
        selection.clear_selection(session, selection.GAMEOBJECT_TYPE)
        return None
    return entry


def _no_selection() -> list[tuple[str, bytes]]:
    return chat_lines(["[GMGo] No GameObject selected."])


def _select_entry(session, entry: dict[str, Any]) -> list[tuple[str, bytes]]:
    selection.selection_from_gameobject(session, entry)
    world_guid = world_guid_for_entry(session, entry)
    log_action("SELECT", session, entry, world_guid)
    return chat_lines(show_info(session, entry) + ["[GMGo] Selected."])


def select_nearest(session) -> list[tuple[str, bytes]]:
    found = find_nearest_editable_gameobject(session)
    if found is None:
        return chat_lines(["[GMGo] No nearby editable GameObject."])
    entry, _distance = found
    return _select_entry(session, entry)


def select_spawn(session, spawn_id: int) -> list[tuple[str, bytes]]:
    entry = get_by_spawn_id(session, int(spawn_id))
    if entry is None:
        return chat_lines(["[GMGo] No editable GameObject with that SpawnID."])
    return _select_entry(session, entry)


def current(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        return _no_selection()
    return chat_lines(show_info(session, entry) + ["[GMGo] Currently selected."])


def clear(session) -> list[tuple[str, bytes]]:
    selection.clear_selection(session, selection.GAMEOBJECT_TYPE)
    return chat_lines(["[GMGo] Selection cleared."])


def log_action(action: str, session, entry: dict[str, Any], world_guid: int) -> None:
    Logger.info(
        "[GMGo] %s GM=%s Entry=%s SpawnID=%s RuntimeGUID=0x%016X",
        str(action).upper(),
        _gm_name(session),
        entry_int(entry, "entry"),
        entry_int(entry, "guid"),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
    )


def show_info(session, entry: dict[str, Any], distance: float | None = None) -> list[str]:
    world_guid = world_guid_for_entry(session, entry)
    phase_id = entry_int(entry, "phaseId")
    phase_group = entry_int(entry, "phaseGroup")
    lines = [
        f"[GMGo] Name: {str(entry.get('name', '') or '<unnamed>')}",
        f"[GMGo] Entry: {entry_int(entry, 'entry')}",
        f"[GMGo] Spawn ID: {entry_int(entry, 'guid')}",
        f"[GMGo] Runtime GUID: 0x{int(world_guid) & 0xFFFFFFFFFFFFFFFF:016X}",
        f"[GMGo] GameObject type: {entry_int(entry, 'type')}",
        f"[GMGo] Map: {entry_map_id(entry)}",
        f"[GMGo] Phase: {phase_id}/{phase_group}",
        (
            "[GMGo] Position: "
            f"({entry_float(entry, 'x'):.3f}, {entry_float(entry, 'y'):.3f}, "
            f"{entry_float(entry, 'z'):.3f})"
        ),
        f"[GMGo] Orientation: {entry_float(entry, 'orientation'):.6f}",
        f"[GMGo] Scale: {entry_float(entry, 'size', 1.0):.3f}",
        f"[GMGo] State: {entry_int(entry, 'state')}",
        f"[GMGo] Script name: {str(entry.get('ScriptName', entry.get('script', '')) or '<none>')}",
        f"[GMGo] Respawn: {entry_int(entry, 'spawntimesecs')}s",
    ]
    if distance is not None:
        lines.append(f"[GMGo] Distance: {float(distance):.3f}")
    return lines


def info(session) -> list[tuple[str, bytes]]:
    found = find_nearest_editable_gameobject(session)
    if found is None:
        return chat_lines(["[GMGo] No nearby editable GameObject."])
    entry, distance = found
    world_guid = world_guid_for_entry(session, entry)
    log_action("INFO", session, entry, world_guid)
    return chat_lines(show_info(session, entry, distance))


def list_nearby(session, radius: float = DEFAULT_SEARCH_RADIUS) -> list[tuple[str, bytes]]:
    nearby = find_nearby(session, radius)
    if not nearby:
        return chat_lines(["[GMGo] No nearby editable GameObjects."])
    lines = [f"[GMGo] Nearby editable GameObjects ({float(radius):.1f} yd):"]
    for entry, distance in nearby[:20]:
        lines.append(
            f"[GMGo] {distance:.2f} | {entry_int(entry, 'entry')} | "
            f"{entry_int(entry, 'guid')} | {str(entry.get('name', '') or '<unnamed>')} | "
            f"type={entry_int(entry, 'type')}"
        )
    first_entry, _distance = nearby[0]
    log_action("LIST", session, first_entry, world_guid_for_entry(session, first_entry))
    return chat_lines(lines)


def search_templates(session, text: str, limit: int = 20) -> list[tuple[str, bytes]]:
    query = str(text or "").strip()
    if not query:
        return chat_lines(["[GMGo] Usage: .go search <text> [limit]"])
    limit = max(1, min(int(limit or 20), 100))
    results = DatabaseConnection.search_gameobject_templates(query, limit=limit)
    if not results:
        return chat_lines([f"[GMGo] No GameObject templates found for: {query}"])

    Logger.info(
        "[GMGo] SEARCH GM=%s text=%r limit=%s results=%s",
        _gm_name(session),
        query,
        int(limit),
        len(results),
    )
    lines = [f"[GMGo] Search results for '{query}' ({len(results)}):"]
    for row in results:
        lines.append(
            f"[GMGo] {str(row.get('name', '') or '<unnamed>')} | "
            f"Entry {entry_int(row, 'entry')} | Type {entry_int(row, 'type')}"
        )
    lines.append("[GMGo] Use .go add <entry> to spawn one of the listed templates.")
    return chat_lines(lines)


def _spawn_from_entry(session, go_entry: int, source: dict[str, Any] | None = None) -> dict[str, Any] | None:
    px, py, pz, orientation = player_position(session)
    source = source or {}
    return DatabaseConnection.create_gameobject_spawn(
        int(go_entry),
        map_id=int(getattr(session, "map_id", 0) or 0),
        x=px,
        y=py,
        z=pz,
        orientation=orientation,
        spawn_mask=entry_int(source, "spawnMask", 1),
        phase_id=entry_int(source, "phaseId", 0),
        phase_group=entry_int(source, "phaseGroup", 0),
        state=entry_int(source, "state", 1),
        animprogress=entry_int(source, "animprogress", 255),
        spawntimesecs=entry_int(source, "spawntimesecs", 300),
        scale=float(source["size"]) if "size" in source else None,
    )


def create(session, go_entry: int, source: dict[str, Any] | None = None, *, operation: str = "ADD") -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    created = _spawn_from_entry(session, int(go_entry), source)
    if created is None:
        return chat_lines([f"[GMGo] Unknown GameObject template: {int(go_entry)}"]), None
    result = gameobject_runtime.spawn_persistent_gameobject(session, entry_int(created, "guid"))
    created = dict(result.entry or created)
    world_guid = int(result.runtime_guid or world_guid_for_entry(session, created))
    log_action(operation, session, created, world_guid)
    editor_history.push(session, operation, created, object_type="GameObject", runtime_guid=world_guid)
    verb = "Placed copied GameObject." if str(operation).upper() == "PLACE" else "Created GameObject"
    return list(result.responses) + chat_lines([
        f"[GMGo] {verb}",
        f"[GMGo] Entry {entry_int(created, 'entry')}",
        f"[GMGo] SpawnID {entry_int(created, 'guid')}",
    ]), created


def delete(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    world_guid = world_guid_for_entry(session, entry)
    despawn = gameobject_runtime.despawn_persistent_gameobject(
        session,
        entry_int(entry, "guid"),
        existing_spawn=entry,
    )
    deleted = DatabaseConnection.delete_gameobject_spawn(entry_int(entry, "guid"))
    if deleted is None:
        return chat_lines(["[GMGo] Delete failed."]), None
    selected = selection.get_selection(session, selection.GAMEOBJECT_TYPE)
    if selected is not None and entry_int(selected, "spawn_id") == entry_int(deleted, "guid"):
        selection.clear_selection(session, selection.GAMEOBJECT_TYPE)
    log_action("DELETE", session, deleted, world_guid)
    editor_history.push(
        session,
        "DELETE",
        deleted,
        object_type="GameObject",
        runtime_guid=world_guid,
        undo_type="DELETE",
        undo_data=dict(deleted),
    )
    return list(despawn.responses) + chat_lines([
        f"[GMGo] Deleting {str(deleted.get('name', '') or '<unnamed>')}",
        f"[GMGo] Entry {entry_int(deleted, 'entry')}",
        f"[GMGo] SpawnID {entry_int(deleted, 'guid')}",
        "[GMGo] Deleted.",
    ]), dict(deleted)


def delete_nearest(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        found = find_nearest_editable_gameobject(session)
        if found is None:
            return chat_lines(["[GMGo] No editable GameObject found."])
        entry, _distance = found
    responses, _deleted = delete(session, entry)
    return responses


def restore_deleted_gameobject(session, undo_entry: dict[str, Any]) -> list[tuple[str, bytes]]:
    if not DatabaseConnection.restore_gameobject_spawn(undo_entry):
        return chat_lines(["[GMGo] Undo failed."])
    result = gameobject_runtime.spawn_persistent_gameobject(session, entry_int(undo_entry, "guid"))
    restored = dict(result.entry or undo_entry)
    world_guid = int(result.runtime_guid or world_guid_for_entry(session, restored))
    log_action("UNDO", session, restored, world_guid)
    editor_history.push(session, "UNDO", restored, object_type="GameObject", runtime_guid=world_guid)
    return list(result.responses) + chat_lines([
        "[GMGo] Restored deleted GameObject.",
        f"[GMGo] Entry {entry_int(restored, 'entry')}",
        f"[GMGo] SpawnID {entry_int(restored, 'guid')}",
    ])


def undo(session) -> list[tuple[str, bytes]]:
    undo_entry = editor_history.pop_latest_undo(session, "DELETE", object_type="GameObject")
    if undo_entry is None:
        return chat_lines(["[GMGo] Nothing to restore."])
    return restore_deleted_gameobject(session, undo_entry)


def move(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    px, py, pz, _orientation = player_position(session)
    previous = dict(entry)
    world_guid = world_guid_for_entry(session, entry)
    updated = DatabaseConnection.update_gameobject_spawn_transform(
        entry_int(entry, "guid"),
        x=px,
        y=py,
        z=pz,
    )
    if updated is None:
        return chat_lines(["[GMGo] Move failed."]), None
    result = gameobject_runtime.replace_persistent_gameobject(
        session,
        entry_int(entry, "guid"),
        old_spawn=entry,
    )
    updated = dict(result.entry or updated)
    world_guid = int(result.runtime_guid or world_guid)
    live_responses = list(result.responses)
    log_action("MOVE", session, updated, world_guid)
    editor_history.push(
        session,
        "MOVE",
        updated,
        object_type="GameObject",
        runtime_guid=world_guid,
        undo_type="MOVE",
        undo_data=previous,
    )
    return live_responses + chat_lines(["[GMGo] Moved."]), updated


def move_nearest(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        return _no_selection()
    responses, _updated = move(session, entry)
    return responses


def rotate(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    _px, _py, _pz, orientation = player_position(session)
    previous = dict(entry)
    world_guid = world_guid_for_entry(session, entry)
    updated = DatabaseConnection.update_gameobject_spawn_transform(
        entry_int(entry, "guid"),
        orientation=orientation,
    )
    if updated is None:
        return chat_lines(["[GMGo] Rotate failed."]), None
    result = gameobject_runtime.replace_persistent_gameobject(
        session,
        entry_int(entry, "guid"),
        old_spawn=entry,
    )
    updated = dict(result.entry or updated)
    world_guid = int(result.runtime_guid or world_guid)
    live_responses = list(result.responses)
    log_action("ROTATE", session, updated, world_guid)
    editor_history.push(
        session,
        "ROTATE",
        updated,
        object_type="GameObject",
        runtime_guid=world_guid,
        undo_type="ROTATE",
        undo_data=previous,
    )
    return live_responses + chat_lines(["[GMGo] Rotated."]), updated


def rotate_nearest(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        return _no_selection()
    responses, _updated = rotate(session, entry)
    return responses


def scale(session, value: float) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        return _no_selection()
    previous = dict(entry)
    new_scale = max(0.01, float(value or 0.0))
    updated = DatabaseConnection.update_gameobject_spawn_scale(entry_int(entry, "guid"), new_scale)
    if updated is None:
        return chat_lines(["[GMGo] Scale failed."])
    world_guid = world_guid_for_entry(session, updated)
    result = gameobject_runtime.replace_persistent_gameobject(
        session,
        entry_int(entry, "guid"),
        old_spawn=entry,
    )
    updated = dict(result.entry or updated)
    world_guid = int(result.runtime_guid or world_guid)
    live_responses = list(result.responses)
    log_action("SCALE", session, updated, world_guid)
    editor_history.push(
        session,
        "SCALE",
        updated,
        object_type="GameObject",
        runtime_guid=world_guid,
        undo_type="SCALE",
        undo_data=previous,
    )
    return live_responses + chat_lines([f"[GMGo] Scaled to {new_scale:.3f}."])


def reload(session) -> list[tuple[str, bytes]]:
    selected = selection.get_selection(session, selection.GAMEOBJECT_TYPE)
    if selected is None:
        return _no_selection()
    spawn_id = entry_int(selected, "spawn_id")
    old_entry = get_by_spawn_id(session, spawn_id)
    if old_entry is None:
        selection.clear_selection(session, selection.GAMEOBJECT_TYPE)
        return chat_lines(["[GMGo] Selected GameObject no longer exists."])
    world_guid = world_guid_for_entry(session, old_entry)
    loaded_entries = getattr(session, "loaded_gameobject_entries", None)
    runtime_entry = old_entry
    if isinstance(loaded_entries, dict):
        cached = loaded_entries.get(int(world_guid)) or loaded_entries.get(int(spawn_id))
        if isinstance(cached, dict):
            runtime_entry = dict(cached)
    reloaded = DatabaseConnection.get_gameobject_spawn(spawn_id)
    if reloaded is None or not is_editable_candidate(reloaded):
        selection.clear_selection(session, selection.GAMEOBJECT_TYPE)
        return chat_lines(["[GMGo] Reload failed: DB spawn not found."])
    reloaded = dict(reloaded)
    reloaded["realm_id"] = int(getattr(session, "realm_id", 1) or 1)
    reloaded["world_guid"] = int(world_guid)
    result = gameobject_runtime.replace_persistent_gameobject(
        session,
        spawn_id,
        old_spawn=runtime_entry,
    )
    reloaded = dict(result.entry or reloaded)
    world_guid = int(result.runtime_guid or world_guid)
    live_responses = list(result.responses)
    selection.selection_from_gameobject(session, reloaded)
    log_action("RELOAD", session, reloaded, world_guid)
    return live_responses + chat_lines([
        "[GMGo] Reloaded GameObject.",
        f"[GMGo] Entry {entry_int(reloaded, 'entry')}",
        f"[GMGo] SpawnID {entry_int(reloaded, 'guid')}",
    ])


def history(session) -> list[tuple[str, bytes]]:
    records = editor_history.list_history(session, object_type="GameObject")
    if not records:
        return chat_lines(["[GMGo] No editor history."])
    lines = ["[GMGo] History:"]
    for record in reversed(records[-10:]):
        lines.append(
            f"[GMGo] {record.get('timestamp', '')} {record.get('operation', '')} "
            f"{record.get('name', '') or '<unnamed>'} entry={record.get('entry', 0)} "
            f"spawn={record.get('spawn_id', 0)}"
        )
    return chat_lines(lines)
