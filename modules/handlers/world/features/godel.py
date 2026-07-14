from __future__ import annotations

import math
from typing import Any

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import GameObjectGuid, MoTransportGuid
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.bootstrap.gameobjects import _build_gameobject_update_payload
from server.modules.handlers.world.bootstrap.playerobjects import make_update_object_response
from server.modules.handlers.world.transport_runtime import (
    GAMEOBJECT_TYPE_MO_TRANSPORT,
    GAMEOBJECT_TYPE_TRANSPORT,
)
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_store import (
    gameobject_identity_matches_mapping,
    get_gameobject_runtime_store,
)


_RUNTIME_ONLY_KEYS = ("synthetic_transport", "_transport_create_source_path")
_CLOSE_SEARCH_RADIUS = 5.0
_FRONT_DOT_EPSILON = 0.05


def _gm_guid(session) -> int:
    return int(
        getattr(session, "char_guid", 0)
        or getattr(session, "player_guid", 0)
        or getattr(session, "world_guid", 0)
        or 0
    )


def _chat(message: str) -> tuple[str, bytes]:
    return ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(str(message)))


def _chat_lines(lines: list[str]) -> list[tuple[str, bytes]]:
    return [_chat(line) for line in lines]


def _entry_int(entry: dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(entry.get(key, default) or default)
    except Exception:
        return int(default)


def _entry_float(entry: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(entry.get(key, default) or default)
    except Exception:
        return float(default)


def _world_guid_for_entry(session, entry: dict[str, Any]) -> int:
    if int(entry.get("world_guid", 0) or 0) > 0:
        return int(entry.get("world_guid", 0) or 0)
    spawn_id = _entry_int(entry, "guid")
    go_type = _entry_int(entry, "type", -1)
    if go_type == GAMEOBJECT_TYPE_MO_TRANSPORT or bool(entry.get("use_transport_guid")):
        return int(MoTransportGuid.from_spawn_guid(spawn_id))
    return int(GameObjectGuid.from_spawn_guid(spawn_id, int(getattr(session, "realm_id", 1) or 1)))


def _selection_key(entry: dict[str, Any]) -> tuple[int, int]:
    return (_entry_int(entry, "guid"), _entry_int(entry, "entry"))


def _delete_mode_enabled(session) -> bool:
    return bool(getattr(session, "_godel_enabled", False))


def enable(session) -> list[tuple[str, bytes]]:
    session._godel_enabled = True
    session._godel_selected = None
    Logger.info("[GoDel] enabled GM=%s", _gm_guid(session))
    return _chat_lines([
        "[GoDel] delete mode enabled.",
        "Use .godel close to inspect the nearest GameObject.",
    ])


def disable(session) -> list[tuple[str, bytes]]:
    session._godel_enabled = False
    session._godel_selected = None
    Logger.info("[GoDel] disabled GM=%s", _gm_guid(session))
    return _chat_lines(["[GoDel] delete mode disabled."])


def _format_entry_lines(entry: dict[str, Any], runtime_guid: int) -> list[str]:
    spawn_id = _entry_int(entry, "guid")
    phase_id = _entry_int(entry, "phaseId")
    phase_group = _entry_int(entry, "phaseGroup")
    return [
        f"[GoDel] Entry: {_entry_int(entry, 'entry')}",
        f"[GoDel] Spawn ID: {spawn_id}",
        f"[GoDel] Runtime GUID: 0x{int(runtime_guid) & 0xFFFFFFFFFFFFFFFF:016X}",
        f"[GoDel] Name: {str(entry.get('name', '') or '<unnamed>')}",
        f"[GoDel] Map: {_entry_int(entry, 'map_id', _entry_int(entry, 'map'))}",
        f"[GoDel] Phase: {phase_id}/{phase_group}",
        (
            "[GoDel] Position: "
            f"({_entry_float(entry, 'x'):.3f}, {_entry_float(entry, 'y'):.3f}, "
            f"{_entry_float(entry, 'z'):.3f}, {_entry_float(entry, 'orientation'):.6f})"
        ),
        f"[GoDel] Current state: {_entry_int(entry, 'state')}",
        f"[GoDel] Respawn time: {_entry_int(entry, 'spawntimesecs')}s",
        "[GoDel] Run .godel close again to delete.",
        "[GoDel] Use .godel undo to restore the last deleted object.",
    ]


def _format_close_entry_lines(entry: dict[str, Any], runtime_guid: int, distance: float) -> list[str]:
    return [
        f"[GoDel] Entry: {_entry_int(entry, 'entry')}",
        f"[GoDel] Spawn ID: {_entry_int(entry, 'guid')}",
        f"[GoDel] Runtime GUID: 0x{int(runtime_guid) & 0xFFFFFFFFFFFFFFFF:016X}",
        f"[GoDel] Name: {str(entry.get('name', '') or '<unnamed>')}",
        f"[GoDel] Map: {_entry_int(entry, 'map_id', _entry_int(entry, 'map'))}",
        (
            "[GoDel] Position: "
            f"({_entry_float(entry, 'x'):.3f}, {_entry_float(entry, 'y'):.3f}, "
            f"{_entry_float(entry, 'z'):.3f})"
        ),
        f"[GoDel] Orientation: {_entry_float(entry, 'orientation'):.6f}",
        f"[GoDel] Distance: {float(distance):.3f}",
        "[GoDel] Selected.",
        "[GoDel] Run .godel close again to delete.",
        "[GoDel] Use .godel undo to restore the last deleted object.",
    ]


def _cannot_delete_reason(entry: dict[str, Any]) -> str | None:
    spawn_id = _entry_int(entry, "guid")
    if spawn_id <= 0:
        return "target has no persistent DB spawn id"
    go_type = _entry_int(entry, "type", -1)
    if go_type in (GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT):
        return "transports cannot be deleted with .godel"
    if any(bool(entry.get(key)) for key in _RUNTIME_ONLY_KEYS):
        return "runtime-only objects cannot be deleted"
    if DatabaseConnection.get_gameobject_spawn(spawn_id) is None:
        return "target is not a persistent DB spawn"
    return None


def _cannot_select_reason(entry: dict[str, Any]) -> str | None:
    spawn_id = _entry_int(entry, "guid")
    if spawn_id <= 0:
        return "target has no persistent DB spawn id"
    go_type = _entry_int(entry, "type", -1)
    if go_type in (GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT):
        return "transports cannot be selected with .godel"
    if any(bool(entry.get(key)) for key in _RUNTIME_ONLY_KEYS):
        return "runtime-only objects cannot be selected"
    if DatabaseConnection.get_gameobject_spawn(spawn_id) is None:
        return "target is not a persistent DB spawn"
    return None


def _entry_map_id(entry: dict[str, Any]) -> int:
    return _entry_int(entry, "map_id", _entry_int(entry, "map"))


def _player_position(session) -> tuple[float, float, float, float]:
    return (
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )


def _distance_3d(session, entry: dict[str, Any]) -> float:
    px, py, pz, _orientation = _player_position(session)
    dx = _entry_float(entry, "x") - px
    dy = _entry_float(entry, "y") - py
    dz = _entry_float(entry, "z") - pz
    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz))


def _front_dot(session, entry: dict[str, Any]) -> float:
    px, py, _pz, orientation = _player_position(session)
    dx = _entry_float(entry, "x") - px
    dy = _entry_float(entry, "y") - py
    horizontal = math.sqrt((dx * dx) + (dy * dy))
    if horizontal <= 0.000001:
        return 1.0
    facing_x = math.cos(orientation)
    facing_y = math.sin(orientation)
    return ((dx / horizontal) * facing_x) + ((dy / horizontal) * facing_y)


def _is_selectable_candidate(entry: dict[str, Any]) -> bool:
    if not isinstance(entry, dict):
        return False
    if _entry_int(entry, "guid") <= 0:
        return False
    go_type = _entry_int(entry, "type", -1)
    if go_type in (GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT):
        return False
    if any(bool(entry.get(key)) for key in _RUNTIME_ONLY_KEYS):
        return False
    return True


def _find_nearest_close_gameobject(session) -> tuple[dict[str, Any], float] | None:
    px, py, _pz, _orientation = _player_position(session)
    map_id = int(getattr(session, "map_id", 0) or 0)
    entries = DatabaseConnection.get_gameobjects_near(
        map_id,
        px,
        py,
        radius=_CLOSE_SEARCH_RADIUS,
        limit=80,
    )
    candidates: list[tuple[int, float, float, dict[str, Any]]] = []
    for raw in entries or ():
        entry = dict(raw)
        if _entry_map_id(entry) not in (0, map_id):
            continue
        if not _is_selectable_candidate(entry):
            continue
        distance = _distance_3d(session, entry)
        if distance > _CLOSE_SEARCH_RADIUS:
            continue
        front_dot = _front_dot(session, entry)
        in_front = front_dot >= _FRONT_DOT_EPSILON
        candidates.append((0 if in_front else 1, distance, -front_dot, entry))

    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1], item[2], _entry_int(item[3], "guid")))
    _front_rank, distance, _front_dot_value, entry = candidates[0]
    entry["realm_id"] = int(getattr(session, "realm_id", 1) or 1)
    entry["world_guid"] = _world_guid_for_entry(session, entry)
    return entry, float(distance)


def _destroy_payload(session, world_guid: int) -> tuple[str, bytes]:
    from server.modules.handlers.world.opcodes.movement import _build_out_of_range_update_object_payload

    return (
        "SMSG_UPDATE_OBJECT",
        _build_out_of_range_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=int(world_guid),
        ),
    )


def _create_payload(session, entry: dict[str, Any]) -> tuple[str, bytes]:
    world_guid = _world_guid_for_entry(session, entry)
    restored = dict(entry)
    restored["world_guid"] = int(world_guid)
    return make_update_object_response(
        _build_gameobject_update_payload(
            map_id=int(restored.get("map_id", restored.get("map", getattr(session, "map_id", 0))) or 0),
            entry=restored,
            realm_id=int(getattr(session, "realm_id", 1) or 1),
        )
    )


def _same_map_sessions(session) -> list[Any]:
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


def _remove_runtime_references(session, world_guid: int, spawn_id: int, map_id: int) -> None:
    for target in _same_map_sessions(session):
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
        Logger.warning("[GoDel] collision index remove failed guid=%s err=%s", int(world_guid), exc)
    try:
        from server.modules.handlers.world.collision import geometry_shadow

        geometry_shadow._world_cache = None
        geometry_shadow._world_cache_signature = None
    except Exception:
        pass
    get_gameobject_runtime_store().remove(int(world_guid))


def _add_runtime_references(session, entry: dict[str, Any], world_guid: int) -> None:
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
    store = get_gameobject_runtime_store()
    runtime_object = store.get_by_spawn_id(_entry_int(restored, "guid"))
    if runtime_object is None or not gameobject_identity_matches_mapping(
        runtime_object,
        restored,
        runtime_guid=int(world_guid),
    ):
        runtime_object = store.add(
            GameObject.from_mapping(
                restored,
                runtime_guid=int(world_guid),
            )
        )
    try:
        from server.modules.handlers.world.collision.gameobject_collision import (
            build_gameobject_collision,
            load_display_bounds,
        )
        from server.modules.handlers.world.collision import gameobject_collision_index

        bounds = load_display_bounds().get(_entry_int(restored, "display_id"))
        collision = build_gameobject_collision(
            restored,
            bounds,
            runtime_object,
        )
        if collision is not None:
            gameobject_collision_index.register(collision)
    except Exception as exc:
        Logger.warning("[GoDel] collision index restore failed guid=%s err=%s", int(world_guid), exc)
    try:
        from server.modules.handlers.world.collision import geometry_shadow

        geometry_shadow._world_cache = None
        geometry_shadow._world_cache_signature = None
    except Exception:
        pass


def _dispatch_destroy(session, response: tuple[str, bytes], world_guid: int) -> None:
    for target in _same_map_sessions(session):
        if target is session:
            continue
        loaded = getattr(target, "loaded_gameobjects", None)
        if isinstance(loaded, set) and int(world_guid) not in loaded:
            continue
        sender = getattr(target, "send_response", None)
        if callable(sender):
            sender([response])


def handle_gameobject_click(session, entry: dict[str, Any]) -> list[tuple[str, bytes]] | None:
    if not _delete_mode_enabled(session):
        return None
    if not isinstance(entry, dict):
        return _chat_lines(["[GoDel] No GameObject selected."])

    world_guid = _world_guid_for_entry(session, entry)
    spawn_id = _entry_int(entry, "guid")
    previous = getattr(session, "_godel_selected", None)
    selected_key = _selection_key(entry)
    if not isinstance(previous, dict) or tuple(previous.get("key", ())) != selected_key:
        session._godel_selected = {"key": selected_key, "entry": dict(entry), "world_guid": int(world_guid)}
        Logger.info(
            "[GoDel] selected GM=%s entry=%s spawn_id=%s runtime_guid=0x%016X",
            _gm_guid(session),
            _entry_int(entry, "entry"),
            int(spawn_id),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        )
        return _chat_lines(_format_entry_lines(entry, world_guid))

    reason = _cannot_delete_reason(entry)
    if reason is not None:
        session._godel_selected = None
        return _chat_lines([f"[GoDel] Cannot delete: {reason}."])

    deleted = DatabaseConnection.delete_gameobject_spawn(spawn_id)
    if deleted is None:
        session._godel_selected = None
        return _chat_lines(["[GoDel] Delete failed: DB spawn was not removed."])

    map_id = _entry_int(deleted, "map_id", _entry_int(deleted, "map"))
    destroy = _destroy_payload(session, world_guid)
    _dispatch_destroy(session, destroy, world_guid)
    _remove_runtime_references(session, world_guid, spawn_id, map_id)
    session._godel_selected = None
    session._godel_undo = dict(deleted)
    Logger.info(
        "[GoDel] deleted GM=%s entry=%s spawn_id=%s runtime_guid=0x%016X",
        _gm_guid(session),
        _entry_int(deleted, "entry"),
        int(spawn_id),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
    )
    return [destroy] + _chat_lines([
        f"[GoDel] Deleted spawn {spawn_id} entry {_entry_int(deleted, 'entry')}.",
        "[GoDel] Use .godel undo to restore it.",
    ])


def close(session) -> list[tuple[str, bytes]]:
    if not _delete_mode_enabled(session):
        return _chat_lines(["[GoDel] Delete mode is not enabled. Use .godel on first."])

    found = _find_nearest_close_gameobject(session)
    if found is None:
        session._godel_selected = None
        return _chat_lines(["[GoDel] No GameObject found nearby."])

    entry, distance = found
    world_guid = _world_guid_for_entry(session, entry)
    spawn_id = _entry_int(entry, "guid")
    selected_key = _selection_key(entry)
    previous = getattr(session, "_godel_selected", None)
    if not isinstance(previous, dict) or tuple(previous.get("key", ())) != selected_key:
        reason = _cannot_select_reason(entry)
        if reason is not None:
            session._godel_selected = None
            return _chat_lines([f"[GoDel] Cannot select: {reason}."])
        session._godel_selected = {
            "key": selected_key,
            "entry": dict(entry),
            "world_guid": int(world_guid),
        }
        Logger.info(
            "[GoDel] selected GM=%s entry=%s spawn_id=%s runtime_guid=0x%016X",
            _gm_guid(session),
            _entry_int(entry, "entry"),
            int(spawn_id),
            int(world_guid) & 0xFFFFFFFFFFFFFFFF,
        )
        return _chat_lines(_format_close_entry_lines(entry, world_guid, distance))

    reason = _cannot_delete_reason(entry)
    if reason is not None:
        session._godel_selected = None
        return _chat_lines([f"[GoDel] Cannot delete: {reason}."])

    deleted = DatabaseConnection.delete_gameobject_spawn(spawn_id)
    if deleted is None:
        session._godel_selected = None
        return _chat_lines(["[GoDel] Delete failed: DB spawn was not removed."])

    map_id = _entry_int(deleted, "map_id", _entry_int(deleted, "map"))
    destroy = _destroy_payload(session, world_guid)
    _dispatch_destroy(session, destroy, world_guid)
    _remove_runtime_references(session, world_guid, spawn_id, map_id)
    session._godel_selected = None
    session._godel_undo = dict(deleted)
    Logger.info(
        "[GoDel] deleted GM=%s entry=%s spawn_id=%s runtime_guid=0x%016X",
        _gm_guid(session),
        _entry_int(deleted, "entry"),
        int(spawn_id),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
    )
    return [destroy] + _chat_lines([
        "[GoDel] Deleted GameObject:",
        f"[GoDel] Entry {_entry_int(deleted, 'entry')}",
        f"[GoDel] SpawnID {spawn_id}",
        "[GoDel] Use .godel undo to restore it.",
    ])


def undo(session) -> list[tuple[str, bytes]]:
    entry = getattr(session, "_godel_undo", None)
    if not isinstance(entry, dict):
        return _chat_lines(["[GoDel] Nothing to undo."])
    if not DatabaseConnection.restore_gameobject_spawn(entry):
        return _chat_lines(["[GoDel] Undo failed: could not recreate DB spawn."])

    world_guid = _world_guid_for_entry(session, entry)
    _add_runtime_references(session, entry, world_guid)
    session._godel_undo = None
    session._godel_selected = None
    Logger.info(
        "[GoDel] undo GM=%s entry=%s spawn_id=%s runtime_guid=0x%016X",
        _gm_guid(session),
        _entry_int(entry, "entry"),
        _entry_int(entry, "guid"),
        int(world_guid) & 0xFFFFFFFFFFFFFFFF,
    )
    return [_create_payload(session, entry)] + _chat_lines([
        f"[GoDel] Restored spawn {_entry_int(entry, 'guid')} entry {_entry_int(entry, 'entry')}.",
    ])
