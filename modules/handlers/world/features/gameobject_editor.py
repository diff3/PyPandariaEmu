from __future__ import annotations

import math
from typing import Any

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import GameObjectGuid, MoTransportGuid
from server.modules.handlers.world.bootstrap.gameobjects import _build_gameobject_update_payload
from server.modules.handlers.world.bootstrap.playerobjects import make_update_object_response
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.features import gameobject_history
from server.modules.handlers.world.transport_runtime import (
    GAMEOBJECT_TYPE_MO_TRANSPORT,
    GAMEOBJECT_TYPE_TRANSPORT,
)


DEFAULT_SEARCH_RADIUS = 10.0
_FRONT_DOT_EPSILON = 0.05
_RUNTIME_ONLY_KEYS = ("synthetic_transport", "_transport_create_source_path")


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
    world_guid = int(entry.get("world_guid", 0) or 0)
    if world_guid > 0:
        return world_guid
    spawn_id = entry_int(entry, "guid")
    go_type = entry_int(entry, "type", -1)
    if go_type == GAMEOBJECT_TYPE_MO_TRANSPORT or bool(entry.get("use_transport_guid")):
        return int(MoTransportGuid.from_spawn_guid(spawn_id))
    return int(GameObjectGuid.from_spawn_guid(spawn_id, int(getattr(session, "realm_id", 1) or 1)))


def player_position(session) -> tuple[float, float, float, float]:
    return (
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )


def entry_map_id(entry: dict[str, Any]) -> int:
    return entry_int(entry, "map_id", entry_int(entry, "map"))


def distance_3d(session, entry: dict[str, Any]) -> float:
    px, py, pz, _orientation = player_position(session)
    dx = entry_float(entry, "x") - px
    dy = entry_float(entry, "y") - py
    dz = entry_float(entry, "z") - pz
    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz))


def front_dot(session, entry: dict[str, Any]) -> float:
    px, py, _pz, orientation = player_position(session)
    dx = entry_float(entry, "x") - px
    dy = entry_float(entry, "y") - py
    horizontal = math.sqrt((dx * dx) + (dy * dy))
    if horizontal <= 0.000001:
        return 1.0
    return ((dx / horizontal) * math.cos(orientation)) + ((dy / horizontal) * math.sin(orientation))


def is_editable_candidate(entry: dict[str, Any]) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry_int(entry, "guid") <= 0:
        return False
    go_type = entry_int(entry, "type", -1)
    if go_type in (GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT):
        return False
    if any(bool(entry.get(key)) for key in _RUNTIME_ONLY_KEYS):
        return False
    return True


def _persistent_spawn(entry: dict[str, Any]) -> dict[str, Any] | None:
    spawn_id = entry_int(entry, "guid")
    if spawn_id <= 0:
        return None
    return DatabaseConnection.get_gameobject_spawn(spawn_id)


def find_nearby(session, radius: float = DEFAULT_SEARCH_RADIUS) -> list[tuple[dict[str, Any], float]]:
    radius = max(0.0, float(radius or DEFAULT_SEARCH_RADIUS))
    px, py, _pz, _orientation = player_position(session)
    map_id = int(getattr(session, "map_id", 0) or 0)
    raw_entries = DatabaseConnection.get_gameobjects_near(
        map_id,
        px,
        py,
        radius=radius,
        limit=120,
    )

    candidates: list[tuple[int, float, float, int, dict[str, Any]]] = []
    for raw in raw_entries or ():
        entry = dict(raw)
        if entry_map_id(entry) not in (0, map_id):
            continue
        if not is_editable_candidate(entry):
            continue
        if _persistent_spawn(entry) is None:
            continue
        distance = distance_3d(session, entry)
        if distance > radius:
            continue
        dot = front_dot(session, entry)
        entry["realm_id"] = int(getattr(session, "realm_id", 1) or 1)
        entry["world_guid"] = world_guid_for_entry(session, entry)
        candidates.append((0 if dot >= _FRONT_DOT_EPSILON else 1, distance, -dot, entry_int(entry, "guid"), entry))

    if not candidates:
        return []

    has_front = any(rank == 0 for rank, _distance, _dot, _guid, _entry in candidates)
    if has_front:
        candidates = [candidate for candidate in candidates if candidate[0] == 0]
    candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
    return [(entry, float(distance)) for _rank, distance, _dot, _guid, entry in candidates]


def find_nearest_editable_gameobject(session, radius: float = DEFAULT_SEARCH_RADIUS) -> tuple[dict[str, Any], float] | None:
    nearby = find_nearby(session, radius)
    if not nearby:
        return None
    return nearby[0]


def find_nearest_editable(session, radius: float = DEFAULT_SEARCH_RADIUS) -> tuple[dict[str, Any], float] | None:
    return find_nearest_editable_gameobject(session, radius)


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


def create_payload(session, entry: dict[str, Any]) -> tuple[str, bytes]:
    world_guid = world_guid_for_entry(session, entry)
    created = dict(entry)
    created["world_guid"] = int(world_guid)
    return make_update_object_response(
        _build_gameobject_update_payload(
            map_id=int(created.get("map_id", created.get("map", getattr(session, "map_id", 0))) or 0),
            entry=created,
            realm_id=int(getattr(session, "realm_id", 1) or 1),
        )
    )


def invalidate_geometry_caches() -> None:
    try:
        from server.modules.handlers.world.collision import geometry_shadow

        geometry_shadow._world_cache = None
        geometry_shadow._world_cache_signature = None
    except Exception:
        pass


def remove_runtime_references(session, entry: dict[str, Any], world_guid: int) -> None:
    spawn_id = entry_int(entry, "guid")
    map_id = entry_map_id(entry)
    for target in same_map_sessions(session):
        loaded = getattr(target, "loaded_gameobjects", None)
        if isinstance(loaded, set):
            loaded.discard(int(world_guid))
        entries = getattr(target, "loaded_gameobject_entries", None)
        if isinstance(entries, dict):
            entries.pop(int(world_guid), None)
            entries.pop(int(spawn_id), None)
        transports = getattr(target, "loaded_transport_entries", None)
        if isinstance(transports, dict):
            transports.pop(int(world_guid), None)
    try:
        from server.modules.handlers.world.collision import gameobject_collision_index

        gameobject_collision_index.remove(int(map_id), int(spawn_id))
        gameobject_collision_index.remove(int(map_id), int(world_guid))
    except Exception as exc:
        Logger.warning("[GMGo] collision index remove failed guid=%s err=%s", int(world_guid), exc)
    invalidate_geometry_caches()


def add_runtime_references(session, entry: dict[str, Any], world_guid: int) -> None:
    loaded = getattr(session, "loaded_gameobjects", None)
    if not isinstance(loaded, set):
        loaded = set()
        session.loaded_gameobjects = loaded
    loaded.add(int(world_guid))
    entries = getattr(session, "loaded_gameobject_entries", None)
    if not isinstance(entries, dict):
        entries = {}
        session.loaded_gameobject_entries = entries
    restored = dict(entry)
    restored["world_guid"] = int(world_guid)
    entries[int(world_guid)] = restored
    try:
        from server.modules.handlers.world.collision.gameobject_collision import (
            build_gameobject_collision,
            load_display_bounds,
        )
        from server.modules.handlers.world.collision import gameobject_collision_index

        bounds = load_display_bounds().get(entry_int(restored, "display_id"))
        collision = build_gameobject_collision(restored, bounds)
        if collision is not None:
            gameobject_collision_index.register(collision)
    except Exception as exc:
        Logger.warning("[GMGo] collision index restore failed guid=%s err=%s", int(world_guid), exc)
    invalidate_geometry_caches()


def dispatch_to_peers(session, response: tuple[str, bytes], world_guid: int | None = None) -> None:
    for target in same_map_sessions(session):
        if target is session:
            continue
        if world_guid is not None:
            loaded = getattr(target, "loaded_gameobjects", None)
            if isinstance(loaded, set) and int(world_guid) not in loaded:
                continue
        sender = getattr(target, "send_response", None)
        if callable(sender):
            sender([response])


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
    )


def create(session, go_entry: int, source: dict[str, Any] | None = None, *, operation: str = "ADD") -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    created = _spawn_from_entry(session, int(go_entry), source)
    if created is None:
        return chat_lines([f"[GMGo] Unknown GameObject template: {int(go_entry)}"]), None
    world_guid = world_guid_for_entry(session, created)
    add_runtime_references(session, created, world_guid)
    create_response = create_payload(session, created)
    dispatch_to_peers(session, create_response, None)
    log_action(operation, session, created, world_guid)
    gameobject_history.push(session, operation, created)
    verb = "Placed copied GameObject." if str(operation).upper() == "PLACE" else "Created GameObject"
    return [create_response] + chat_lines([
        f"[GMGo] {verb}",
        f"[GMGo] Entry {entry_int(created, 'entry')}",
        f"[GMGo] SpawnID {entry_int(created, 'guid')}",
    ]), created


def delete(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    world_guid = world_guid_for_entry(session, entry)
    deleted = DatabaseConnection.delete_gameobject_spawn(entry_int(entry, "guid"))
    if deleted is None:
        return chat_lines(["[GMGo] Delete failed."]), None
    destroy = destroy_payload(session, world_guid)
    dispatch_to_peers(session, destroy, world_guid)
    remove_runtime_references(session, deleted, world_guid)
    log_action("DELETE", session, deleted, world_guid)
    gameobject_history.push(session, "DELETE", deleted, undo_type="DELETE", undo_data=dict(deleted))
    return [destroy] + chat_lines([
        "[GMGo] Deleted:",
        f"[GMGo] Entry {entry_int(deleted, 'entry')}",
        f"[GMGo] SpawnID {entry_int(deleted, 'guid')}",
    ]), dict(deleted)


def delete_nearest(session) -> list[tuple[str, bytes]]:
    found = find_nearest_editable_gameobject(session)
    if found is None:
        return chat_lines(["[GMGo] No nearby editable GameObject."])
    entry, _distance = found
    responses, _deleted = delete(session, entry)
    return responses


def restore_deleted_gameobject(session, undo_entry: dict[str, Any]) -> list[tuple[str, bytes]]:
    if not DatabaseConnection.restore_gameobject_spawn(undo_entry):
        return chat_lines(["[GMGo] Undo failed."])
    world_guid = world_guid_for_entry(session, undo_entry)
    add_runtime_references(session, undo_entry, world_guid)
    create_response = create_payload(session, undo_entry)
    dispatch_to_peers(session, create_response, None)
    log_action("UNDO", session, undo_entry, world_guid)
    gameobject_history.push(session, "UNDO", undo_entry)
    return [create_response] + chat_lines([
        "[GMGo] Restored deleted GameObject.",
        f"[GMGo] Entry {entry_int(undo_entry, 'entry')}",
        f"[GMGo] SpawnID {entry_int(undo_entry, 'guid')}",
    ])


def undo(session) -> list[tuple[str, bytes]]:
    undo_entry = gameobject_history.pop_latest_undo(session, "DELETE")
    if undo_entry is None:
        return chat_lines(["[GMGo] Nothing to restore."])
    return restore_deleted_gameobject(session, undo_entry)


def move(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    px, py, pz, _orientation = player_position(session)
    previous = dict(entry)
    world_guid = world_guid_for_entry(session, entry)
    destroy = destroy_payload(session, world_guid)
    updated = DatabaseConnection.update_gameobject_spawn_transform(
        entry_int(entry, "guid"),
        x=px,
        y=py,
        z=pz,
    )
    if updated is None:
        return chat_lines(["[GMGo] Move failed."]), None
    updated["world_guid"] = int(world_guid)
    remove_runtime_references(session, entry, world_guid)
    add_runtime_references(session, updated, world_guid)
    create_response = create_payload(session, updated)
    dispatch_to_peers(session, destroy, world_guid)
    dispatch_to_peers(session, create_response, None)
    log_action("MOVE", session, updated, world_guid)
    gameobject_history.push(session, "MOVE", updated, undo_type="MOVE", undo_data=previous)
    return [destroy, create_response] + chat_lines(["[GMGo] Moved."]), updated


def move_nearest(session) -> list[tuple[str, bytes]]:
    found = find_nearest_editable_gameobject(session)
    if found is None:
        return chat_lines(["[GMGo] No nearby editable GameObject."])
    entry, _distance = found
    responses, _updated = move(session, entry)
    return responses


def rotate(session, entry: dict[str, Any]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    _px, _py, _pz, orientation = player_position(session)
    previous = dict(entry)
    world_guid = world_guid_for_entry(session, entry)
    destroy = destroy_payload(session, world_guid)
    updated = DatabaseConnection.update_gameobject_spawn_transform(
        entry_int(entry, "guid"),
        orientation=orientation,
    )
    if updated is None:
        return chat_lines(["[GMGo] Rotate failed."]), None
    updated["world_guid"] = int(world_guid)
    remove_runtime_references(session, entry, world_guid)
    add_runtime_references(session, updated, world_guid)
    create_response = create_payload(session, updated)
    dispatch_to_peers(session, destroy, world_guid)
    dispatch_to_peers(session, create_response, None)
    log_action("ROTATE", session, updated, world_guid)
    gameobject_history.push(session, "ROTATE", updated, undo_type="ROTATE", undo_data=previous)
    return [destroy, create_response] + chat_lines(["[GMGo] Rotated."]), updated


def rotate_nearest(session) -> list[tuple[str, bytes]]:
    found = find_nearest_editable_gameobject(session)
    if found is None:
        return chat_lines(["[GMGo] No nearby editable GameObject."])
    entry, _distance = found
    responses, _updated = rotate(session, entry)
    return responses


def history(session) -> list[tuple[str, bytes]]:
    records = gameobject_history.list_history(session)
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
