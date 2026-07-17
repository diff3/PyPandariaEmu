from __future__ import annotations

from typing import Any

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.bootstrap.creatures import _build_creature_update_payload
from server.modules.handlers.world.bootstrap.playerobjects import make_update_object_response
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.features.world_editor import clipboard as editor_clipboard
from server.modules.handlers.world.features.world_editor import history as editor_history
from server.modules.handlers.world.features.world_editor import selection
from server.modules.handlers.world.runtime.creature import Creature
from server.modules.handlers.world.runtime.creature_persistence import (
    creature_persistence_snapshot,
)
from server.modules.handlers.world.runtime.creature_store import (
    get_creature_runtime_store,
    resolve_creature_runtime,
)


DEFAULT_SEARCH_RADIUS = selection.DEFAULT_SEARCH_RADIUS
CREATURE_TYPE = selection.CREATURE_TYPE


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
    return selection.entry_int(entry, key, default)


def entry_float(entry: dict[str, Any], key: str, default: float = 0.0) -> float:
    return selection.entry_float(entry, key, default)


def player_position(session) -> tuple[float, float, float, float]:
    return selection.player_position(session)


def world_guid_for_entry(session, entry: dict[str, Any]) -> int:
    return selection.creature_world_guid(session, entry)


def find_nearby(session, radius: float = DEFAULT_SEARCH_RADIUS) -> list[tuple[dict[str, Any], float]]:
    return selection.find_nearby_creatures(session, radius)


def find_nearest_editable_creature(session, radius: float = DEFAULT_SEARCH_RADIUS) -> tuple[dict[str, Any], float] | None:
    return selection.find_nearest_creature(session, radius)


def get_by_spawn_id(session, spawn_id: int) -> dict[str, Any] | None:
    getter = getattr(DatabaseConnection, "get_creature_spawn", None)
    if not callable(getter):
        return None
    entry = getter(int(spawn_id or 0))
    if entry is None:
        return None
    entry = dict(entry)
    map_id = int(getattr(session, "map_id", 0) or 0)
    entry_map = entry_int(entry, "map_id", entry_int(entry, "map"))
    if entry_map not in (0, map_id):
        return None
    entry["realm_id"] = int(getattr(session, "realm_id", 1) or 1)
    entry["world_guid"] = world_guid_for_entry(session, entry)
    return entry


def selected_entry(session) -> dict[str, Any] | None:
    selected = selection.get_selection(session, CREATURE_TYPE)
    if selected is None:
        return None
    entry = get_by_spawn_id(session, entry_int(selected, "spawn_id"))
    if entry is None:
        selection.clear_selection(session, CREATURE_TYPE)
        return None
    return entry


def _no_selection() -> list[tuple[str, bytes]]:
    return chat_lines(["[GMNpc] No Creature selected."])


def log_action(action: str, session, entry: dict[str, Any], world_guid: int) -> None:
    Logger.info(
        "[GMNpc] %s GM=%s Entry=%s SpawnID=%s RuntimeGUID=0x%016X",
        str(action).upper(),
        _gm_name(session),
        entry_int(entry, "entry"),
        entry_int(entry, "guid"),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
    )


def same_map_sessions(session) -> list[Any]:
    state = getattr(session, "global_state", None)
    if state is None:
        return [session]
    map_id = int(getattr(session, "map_id", 0) or 0)
    sessions = []
    for target in list(getattr(state, "sessions", set()) or ()):
        if int(getattr(target, "map_id", 0) or 0) == map_id:
            sessions.append(target)
    if session not in sessions:
        sessions.append(session)
    return sessions


def destroy_payload(session, world_guid: int) -> tuple[str, bytes]:
    from server.modules.handlers.world.opcodes.movement import _build_out_of_range_update_object_payload

    return (
        "SMSG_UPDATE_OBJECT",
        _build_out_of_range_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=int(world_guid),
        ),
    )


def _runtime_object_for_entry(
    session,
    entry: dict[str, Any],
    *,
    template: dict[str, Any] | None = None,
) -> Creature:
    """Return and retain the live Creature for a persistent spawn."""
    world_guid = int(world_guid_for_entry(session, entry))
    store = get_creature_runtime_store()
    runtime_mapping = dict(entry)
    if isinstance(template, dict):
        runtime_mapping["template"] = template
    elif not isinstance(runtime_mapping.get("template"), dict):
        runtime_mapping["template"] = (
            DatabaseConnection.get_creature_template(
                entry_int(runtime_mapping, "entry")
            )
            or {}
        )
    runtime_object = resolve_creature_runtime(
        runtime_mapping,
        runtime_guid=world_guid,
    )
    return store.add(runtime_object)


def create_payload(
    session,
    entry: dict[str, Any],
    creature: Creature | None = None,
) -> tuple[str, bytes]:
    world_guid = world_guid_for_entry(session, entry)
    created = dict(entry)
    created["world_guid"] = int(world_guid)
    template = DatabaseConnection.get_creature_template(entry_int(created, "entry")) or {}
    created["template"] = template
    runtime_object = creature or _runtime_object_for_entry(
        session,
        created,
        template=template,
    )
    return make_update_object_response(
        _build_creature_update_payload(
            map_id=int(created.get("map_id", created.get("map", getattr(session, "map_id", 0))) or 0),
            entry=created,
            realm_id=int(getattr(session, "realm_id", 1) or 1),
            creature=runtime_object,
        )
    )


def dispatch_to_peers(session, response: tuple[str, bytes], world_guid: int | None = None) -> None:
    for target in same_map_sessions(session):
        if target is session:
            continue
        if world_guid is not None:
            loaded = getattr(target, "loaded_npcs", None)
            if isinstance(loaded, set) and int(world_guid) not in loaded:
                continue
        sender = getattr(target, "send_response", None)
        if callable(sender):
            sender([response])


def remove_runtime_references(session, entry: dict[str, Any], world_guid: int) -> None:
    spawn_id = entry_int(entry, "guid")
    for target in same_map_sessions(session):
        loaded = getattr(target, "loaded_npcs", None)
        if isinstance(loaded, set):
            loaded.discard(int(world_guid))
        for attr in (
            "npc_flags_by_guid",
            "npc_entries_by_guid",
            "npc_positions_by_guid",
            "npc_names_by_guid",
        ):
            values = getattr(target, attr, None)
            if isinstance(values, dict):
                values.pop(int(world_guid), None)
                values.pop(int(spawn_id), None)


def add_runtime_references(
    session,
    entry: dict[str, Any],
    world_guid: int,
) -> Creature:
    runtime_object = _runtime_object_for_entry(session, entry)
    loaded = getattr(session, "loaded_npcs", None)
    if not isinstance(loaded, set):
        loaded = set()
        session.loaded_npcs = loaded
    loaded.add(int(world_guid))
    return runtime_object


def show_info(session, entry: dict[str, Any], distance: float | None = None) -> list[str]:
    world_guid = world_guid_for_entry(session, entry)
    template = DatabaseConnection.get_creature_template(entry_int(entry, "entry")) or {}
    lines = [
        f"[GMNpc] Name: {str(template.get('name', entry.get('name', '')) or '<unnamed>')}",
        f"[GMNpc] Entry: {entry_int(entry, 'entry')}",
        f"[GMNpc] Spawn ID: {entry_int(entry, 'guid')}",
        f"[GMNpc] Runtime GUID: 0x{int(world_guid) & 0xFFFFFFFFFFFFFFFF:016X}",
        f"[GMNpc] Creature type: {entry_int(template, 'type')}",
        f"[GMNpc] Map: {entry_int(entry, 'map_id', entry_int(entry, 'map'))}",
        (
            "[GMNpc] Position: "
            f"({entry_float(entry, 'x'):.3f}, {entry_float(entry, 'y'):.3f}, "
            f"{entry_float(entry, 'z'):.3f})"
        ),
        f"[GMNpc] Orientation: {entry_float(entry, 'orientation'):.6f}",
        f"[GMNpc] Respawn: {entry_int(entry, 'spawntimesecs')}s",
    ]
    if distance is not None:
        lines.append(f"[GMNpc] Distance: {float(distance):.3f}")
    return lines


def info(session) -> list[tuple[str, bytes]]:
    found = find_nearest_editable_creature(session)
    if found is None:
        return chat_lines(["[GMNpc] No nearby editable Creature."])
    entry, distance = found
    log_action("INFO", session, entry, world_guid_for_entry(session, entry))
    return chat_lines(show_info(session, entry, distance))


def list_nearby(session, radius: float = DEFAULT_SEARCH_RADIUS) -> list[tuple[str, bytes]]:
    nearby = find_nearby(session, radius)
    if not nearby:
        return chat_lines(["[GMNpc] No nearby editable Creatures."])
    lines = [f"[GMNpc] Nearby editable Creatures ({float(radius):.1f} yd):"]
    for entry, distance in nearby[:20]:
        template = DatabaseConnection.get_creature_template(entry_int(entry, "entry")) or {}
        lines.append(
            f"[GMNpc] {distance:.2f} | {entry_int(entry, 'entry')} | "
            f"{entry_int(entry, 'guid')} | {str(template.get('name', '') or '<unnamed>')} | "
            f"type={entry_int(template, 'type')}"
        )
    first_entry, _distance = nearby[0]
    log_action("LIST", session, first_entry, world_guid_for_entry(session, first_entry))
    return chat_lines(lines)


def search_templates(session, text: str, limit: int = 20) -> list[tuple[str, bytes]]:
    query = str(text or "").strip()
    if not query:
        return chat_lines(["[GMNpc] Usage: .npc search <text> [limit]"])
    limit = max(1, min(int(limit or 20), 100))
    results = DatabaseConnection.search_creature_templates(query, limit=limit)
    if not results:
        return chat_lines([f"[GMNpc] No Creature templates found for: {query}"])

    Logger.info("[GMNpc] SEARCH GM=%s text=%r limit=%s results=%s", _gm_name(session), query, int(limit), len(results))
    lines = [f"[GMNpc] Search results for '{query}' ({len(results)}):"]
    for row in results:
        lines.append(
            f"[GMNpc] {str(row.get('name', '') or '<unnamed>')} | "
            f"Entry {entry_int(row, 'entry')} | Type {entry_int(row, 'type')}"
        )
    lines.append("[GMNpc] Use .npc add <entry> to spawn one of the listed templates.")
    return chat_lines(lines)


def _select_entry(session, entry: dict[str, Any]) -> list[tuple[str, bytes]]:
    selection.selection_from_creature(session, entry)
    world_guid = world_guid_for_entry(session, entry)
    log_action("SELECT", session, entry, world_guid)
    return chat_lines(show_info(session, entry) + ["[GMNpc] Selected."])


def select_nearest(session) -> list[tuple[str, bytes]]:
    found = find_nearest_editable_creature(session)
    if found is None:
        return chat_lines(["[GMNpc] No nearby editable Creature."])
    entry, _distance = found
    return _select_entry(session, entry)


def select_spawn(session, spawn_id: int) -> list[tuple[str, bytes]]:
    entry = get_by_spawn_id(session, int(spawn_id))
    if entry is None:
        return chat_lines(["[GMNpc] No editable Creature with that SpawnID."])
    return _select_entry(session, entry)


def current(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        return _no_selection()
    return chat_lines(show_info(session, entry) + ["[GMNpc] Currently selected."])


def clear(session) -> list[tuple[str, bytes]]:
    selection.clear_selection(session, CREATURE_TYPE)
    return chat_lines(["[GMNpc] Selection cleared."])


def _spawn_from_entry(session, creature_entry: int, source: dict[str, Any] | None = None) -> dict[str, Any] | None:
    px, py, pz, orientation = player_position(session)
    source = source or {}
    return DatabaseConnection.create_creature_spawn(
        int(creature_entry),
        map_id=int(getattr(session, "map_id", 0) or 0),
        x=px,
        y=py,
        z=pz,
        orientation=orientation,
        spawn_mask=entry_int(source, "spawnMask", 1),
        phase_id=entry_int(source, "phaseId", 0),
        phase_group=entry_int(source, "phaseGroup", 0),
        spawntimesecs=entry_int(source, "spawntimesecs", 300),
        spawndist=entry_float(source, "spawndist", 0.0),
        movement_type=entry_int(source, "movement_type", 0),
    )


def create(session, creature_entry: int, source: dict[str, Any] | None = None, *, operation: str = "ADD") -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    created = _spawn_from_entry(session, int(creature_entry), source)
    if created is None:
        return chat_lines([f"[GMNpc] Unknown Creature template: {int(creature_entry)}"]), None
    world_guid = world_guid_for_entry(session, created)
    runtime_object = add_runtime_references(session, created, world_guid)
    create_response = create_payload(session, created, runtime_object)
    dispatch_to_peers(session, create_response, None)
    log_action(operation, session, created, world_guid)
    editor_history.push(session, operation, created, object_type=CREATURE_TYPE, runtime_guid=world_guid)
    verb = "Placed copied Creature." if str(operation).upper() == "PLACE" else "Created Creature"
    return [create_response] + chat_lines([
        f"[GMNpc] {verb}",
        f"[GMNpc] Entry {entry_int(created, 'entry')}",
        f"[GMNpc] SpawnID {entry_int(created, 'guid')}",
    ]), created


def delete(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    world_guid = world_guid_for_entry(session, entry)
    deleted = DatabaseConnection.delete_creature_spawn(entry_int(entry, "guid"))
    if deleted is None:
        return chat_lines(["[GMNpc] Delete failed."]), None
    get_creature_runtime_store().remove(int(world_guid))
    destroy = destroy_payload(session, world_guid)
    dispatch_to_peers(session, destroy, world_guid)
    remove_runtime_references(session, deleted, world_guid)
    selected = selection.get_selection(session, CREATURE_TYPE)
    if selected is not None and entry_int(selected, "spawn_id") == entry_int(deleted, "guid"):
        selection.clear_selection(session, CREATURE_TYPE)
    log_action("DELETE", session, deleted, world_guid)
    editor_history.push(
        session,
        "DELETE",
        deleted,
        object_type=CREATURE_TYPE,
        runtime_guid=world_guid,
        undo_type="DELETE",
        undo_data=dict(deleted),
    )
    template = DatabaseConnection.get_creature_template(entry_int(deleted, "entry")) or {}
    return [destroy] + chat_lines([
        f"[GMNpc] Deleting {str(template.get('name', deleted.get('name', '')) or '<unnamed>')}",
        f"[GMNpc] Entry {entry_int(deleted, 'entry')}",
        f"[GMNpc] SpawnID {entry_int(deleted, 'guid')}",
        "[GMNpc] Deleted.",
    ]), dict(deleted)


def delete_selected(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        found = find_nearest_editable_creature(session)
        if found is None:
            return chat_lines(["[GMNpc] No editable Creature found."])
        entry, _distance = found
    responses, _deleted = delete(session, entry)
    return responses


def restore_deleted_creature(session, undo_entry: dict[str, Any]) -> list[tuple[str, bytes]]:
    if not DatabaseConnection.restore_creature_spawn(undo_entry):
        return chat_lines(["[GMNpc] Undo failed."])
    world_guid = world_guid_for_entry(session, undo_entry)
    runtime_object = add_runtime_references(session, undo_entry, world_guid)
    create_response = create_payload(session, undo_entry, runtime_object)
    dispatch_to_peers(session, create_response, None)
    log_action("UNDO", session, undo_entry, world_guid)
    editor_history.push(session, "UNDO", undo_entry, object_type=CREATURE_TYPE, runtime_guid=world_guid)
    return [create_response] + chat_lines([
        "[GMNpc] Restored deleted Creature.",
        f"[GMNpc] Entry {entry_int(undo_entry, 'entry')}",
        f"[GMNpc] SpawnID {entry_int(undo_entry, 'guid')}",
    ])


def undo(session) -> list[tuple[str, bytes]]:
    undo_entry = editor_history.pop_latest_undo(session, "DELETE", object_type=CREATURE_TYPE)
    if undo_entry is None:
        return chat_lines(["[GMNpc] Nothing to restore."])
    return restore_deleted_creature(session, undo_entry)


def move(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    px, py, pz, _orientation = player_position(session)
    previous = dict(entry)
    runtime_object = _runtime_object_for_entry(session, entry)
    world_guid = int(runtime_object.runtime_guid)
    destroy = destroy_payload(session, world_guid)
    previous_position = runtime_object.world_position
    runtime_object.set_position(px, py, pz)
    persistence_snapshot = creature_persistence_snapshot(
        runtime_object,
        entry,
    )
    updated = DatabaseConnection.update_creature_spawn_transform(
        entry_int(entry, "guid"),
        x=float(persistence_snapshot["x"]),
        y=float(persistence_snapshot["y"]),
        z=float(persistence_snapshot["z"]),
    )
    if updated is None:
        runtime_object.set_position(*previous_position)
        return chat_lines(["[GMNpc] Move failed."]), None
    updated["world_guid"] = int(world_guid)
    remove_runtime_references(session, entry, world_guid)
    add_runtime_references(session, updated, world_guid)
    create_response = create_payload(session, updated, runtime_object)
    dispatch_to_peers(session, destroy, world_guid)
    dispatch_to_peers(session, create_response, None)
    log_action("MOVE", session, updated, world_guid)
    editor_history.push(
        session,
        "MOVE",
        updated,
        object_type=CREATURE_TYPE,
        runtime_guid=world_guid,
        undo_type="MOVE",
        undo_data=previous,
    )
    return [destroy, create_response] + chat_lines(["[GMNpc] Moved."]), updated


def move_selected(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        return _no_selection()
    responses, _updated = move(session, entry)
    return responses


def rotate(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    _px, _py, _pz, orientation = player_position(session)
    previous = dict(entry)
    runtime_object = _runtime_object_for_entry(session, entry)
    world_guid = int(runtime_object.runtime_guid)
    destroy = destroy_payload(session, world_guid)
    previous_orientation = float(runtime_object.orientation)
    runtime_object.set_orientation(orientation)
    persistence_snapshot = creature_persistence_snapshot(
        runtime_object,
        entry,
    )
    updated = DatabaseConnection.update_creature_spawn_transform(
        entry_int(entry, "guid"),
        orientation=float(persistence_snapshot["orientation"]),
    )
    if updated is None:
        runtime_object.set_orientation(previous_orientation)
        return chat_lines(["[GMNpc] Rotate failed."]), None
    updated["world_guid"] = int(world_guid)
    remove_runtime_references(session, entry, world_guid)
    add_runtime_references(session, updated, world_guid)
    create_response = create_payload(session, updated, runtime_object)
    dispatch_to_peers(session, destroy, world_guid)
    dispatch_to_peers(session, create_response, None)
    log_action("ROTATE", session, updated, world_guid)
    editor_history.push(
        session,
        "ROTATE",
        updated,
        object_type=CREATURE_TYPE,
        runtime_guid=world_guid,
        undo_type="ROTATE",
        undo_data=previous,
    )
    return [destroy, create_response] + chat_lines(["[GMNpc] Rotated."]), updated


def rotate_selected(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        return _no_selection()
    responses, _updated = rotate(session, entry)
    return responses


def copy_creature(entry: dict[str, Any]) -> dict[str, Any]:
    copied = dict(entry)
    copied.pop("world_guid", None)
    return copied


def copy(session) -> list[tuple[str, bytes]]:
    entry = selected_entry(session)
    if entry is None:
        return _no_selection()
    clipboard = copy_creature(entry)
    editor_clipboard.set_clipboard(session, CREATURE_TYPE, clipboard)
    world_guid = world_guid_for_entry(session, entry)
    log_action("COPY", session, entry, world_guid)
    editor_history.push(session, "COPY", entry, object_type=CREATURE_TYPE, runtime_guid=world_guid)
    return chat_lines(["[GMNpc] Copied Creature."])


def place(session) -> list[tuple[str, bytes]]:
    item = editor_clipboard.get_clipboard(session, CREATURE_TYPE)
    clipboard = item.get("data") if isinstance(item, dict) else None
    if not isinstance(clipboard, dict):
        return chat_lines(["[GMNpc] Nothing copied."])
    responses, _placed = create(session, entry_int(clipboard, "entry"), clipboard, operation="PLACE")
    return responses


def history(session) -> list[tuple[str, bytes]]:
    records = editor_history.list_history(session, object_type=CREATURE_TYPE)
    if not records:
        return chat_lines(["[GMNpc] No editor history."])
    lines = ["[GMNpc] History:"]
    for record in reversed(records[-10:]):
        lines.append(
            f"[GMNpc] {record.get('timestamp', '')} {record.get('operation', '')} "
            f"{record.get('name', '') or '<unnamed>'} entry={record.get('entry', 0)} "
            f"spawn={record.get('spawn_id', 0)}"
        )
    return chat_lines(lines)
