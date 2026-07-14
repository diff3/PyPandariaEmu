#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import GameObjectGuid, MoTransportGuid
from server.modules.handlers.world.bootstrap.gameobjects import (
    build_database_gameobject_responses,
    build_gameobject_destroy_response,
)
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_store import (
    gameobject_identity_matches_mapping,
    gameobject_matches_mapping,
    get_gameobject_runtime_store,
)


GAMEOBJECT_TYPE_MO_TRANSPORT = 15


@dataclass
class GameObjectSpawnRuntimeResult:
    operation: str
    spawn_id: int
    entry: dict[str, Any] | None
    runtime_guid: int
    responses: list[tuple[str, bytes]] = field(default_factory=list)
    affected_sessions: int = 0
    destroy_sent: int = 0
    create_sent: int = 0
    collision_removed: bool = False
    collision_created: bool = False


def _entry_int(entry: dict[str, Any] | None, key: str, default: int = 0) -> int:
    if not isinstance(entry, dict):
        return int(default)
    try:
        return int(entry.get(key, default) or default)
    except Exception:
        return int(default)


def _runtime_guid(session, entry: dict[str, Any] | None) -> int:
    if not isinstance(entry, dict):
        return 0
    world_guid = _entry_int(entry, "world_guid")
    if world_guid > 0:
        return world_guid
    spawn_id = _entry_int(entry, "guid")
    go_type = _entry_int(entry, "type", -1)
    if go_type == GAMEOBJECT_TYPE_MO_TRANSPORT or bool(
        entry.get("use_transport_guid")
    ):
        return int(MoTransportGuid.from_spawn_guid(spawn_id))
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    return int(GameObjectGuid.from_spawn_guid(spawn_id, realm_id))


def _runtime_object(
    session,
    entry: dict[str, Any] | None,
    *,
    runtime_guid: int | None = None,
    require_mapping_transform: bool = True,
) -> GameObject | None:
    """Resolve lifecycle state with an unchanged temporary fallback.

    New persistent representations require the cached transform to match.
    Existing live representations may use identity-only matching because their
    inherited GameObject transform is runtime-authoritative.
    """
    if not isinstance(entry, dict):
        return None
    resolved_runtime_guid = (
        _runtime_guid(session, entry)
        if runtime_guid is None
        else int(runtime_guid)
    )
    stored = get_gameobject_runtime_store().get_by_spawn_id(
        _entry_int(entry, "guid")
    )
    if stored is not None:
        matcher = (
            gameobject_matches_mapping
            if require_mapping_transform
            else gameobject_identity_matches_mapping
        )
        if matcher(
            stored,
            entry,
            runtime_guid=resolved_runtime_guid,
        ):
            return stored
    return GameObject.from_mapping(
        entry,
        runtime_guid=resolved_runtime_guid,
    )


def _same_map_sessions(
    session,
    *runtime_objects: GameObject,
) -> list[Any]:
    wanted = {
        int(runtime_object.map_id)
        for runtime_object in runtime_objects
        if int(runtime_object.map_id) >= 0
    }
    if not wanted:
        wanted.add(int(getattr(session, "map_id", 0) or 0))
    state = getattr(session, "global_state", None)
    sessions: list[Any] = []
    if state is not None:
        for target in list(getattr(state, "sessions", set()) or ()):
            if int(getattr(target, "map_id", 0) or 0) in wanted:
                sessions.append(target)
    if session not in sessions:
        sessions.append(session)
    return sessions


def _send_or_return(
    session,
    target,
    responses: list[tuple[str, bytes]],
) -> list[tuple[str, bytes]]:
    if not responses:
        return []
    if target is session:
        return list(responses)
    sender = getattr(target, "send_response", None)
    if callable(sender):
        sender(list(responses))
    return []


def _remove_session_visibility(target, runtime_object: GameObject) -> None:
    runtime_guid = int(runtime_object.runtime_guid)
    spawn_id = int(runtime_object.spawn_id)
    loaded = getattr(target, "loaded_gameobjects", None)
    if isinstance(loaded, set):
        loaded.discard(int(runtime_guid))
    entries = getattr(target, "loaded_gameobject_entries", None)
    if isinstance(entries, dict):
        entries.pop(int(runtime_guid), None)
        entries.pop(int(spawn_id), None)
    transports = getattr(target, "loaded_transport_entries", None)
    if isinstance(transports, dict):
        transports.pop(int(runtime_guid), None)


def _invalidate_geometry_caches() -> None:
    try:
        from server.modules.handlers.world.collision import geometry_shadow

        geometry_shadow._world_cache = None
        geometry_shadow._world_cache_signature = None
    except Exception:
        pass


def _remove_collision(runtime_object: GameObject) -> bool:
    try:
        from server.modules.handlers.world.collision import gameobject_collision_index

        gameobject_collision_index.remove(
            int(runtime_object.map_id),
            int(runtime_object.spawn_id),
        )
        gameobject_collision_index.remove(
            int(runtime_object.map_id),
            int(runtime_object.runtime_guid),
        )
        return True
    except Exception as exc:
        Logger.warning(
            "[PersistentGameObject] collision remove failed guid=%s err=%s",
            int(runtime_object.runtime_guid),
            exc,
        )
        return False


def _create_collision(
    runtime_object: GameObject,
    entry: dict[str, Any],
) -> bool:
    restored = dict(entry)
    restored["world_guid"] = int(runtime_object.runtime_guid)
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
        if collision is None:
            return False
        gameobject_collision_index.register(collision)
        return True
    except Exception as exc:
        Logger.warning(
            "[PersistentGameObject] collision create failed guid=%s err=%s",
            int(runtime_object.runtime_guid),
            exc,
        )
        return False


def _visibility_refresh_for_session(target) -> list[tuple[str, bytes]]:
    loaded = getattr(target, "loaded_gameobjects", None)
    if not isinstance(loaded, set):
        loaded = set()
        target.loaded_gameobjects = loaded
    return list(build_database_gameobject_responses(target, loaded_guids=loaded))


def _loaded_targets(
    sessions: list[Any],
    runtime_object: GameObject,
) -> list[Any]:
    runtime_guid = int(runtime_object.runtime_guid)
    return [
        target
        for target in sessions
        if isinstance(getattr(target, "loaded_gameobjects", None), set)
        and int(runtime_guid) in getattr(target, "loaded_gameobjects")
    ]


def _log_result(
    *,
    operation: str,
    runtime_object: GameObject | None,
    affected_sessions: int,
    old_runtime_object: GameObject | None = None,
    new_runtime_object: GameObject | None = None,
    destroy_sent: int = 0,
    create_sent: int = 0,
    collision_removed: bool = False,
    collision_created: bool = False,
) -> None:
    old_transform = old_runtime_object.transform if old_runtime_object else (
        (0.0, 0.0, 0.0),
        0.0,
        1.0,
    )
    new_transform = new_runtime_object.transform if new_runtime_object else (
        (0.0, 0.0, 0.0),
        0.0,
        1.0,
    )
    old_position, old_orientation, old_scale = old_transform
    new_position, new_orientation, new_scale = new_transform
    Logger.info(
        "[PersistentGameObject] operation=%s spawn_id=%s entry=%s runtime_guid=0x%016X "
        "affected_sessions=%s old_position=(%.3f,%.3f,%.3f) new_position=(%.3f,%.3f,%.3f) "
        "old_orientation=%.6f new_orientation=%.6f old_scale=%.3f new_scale=%.3f "
        "destroy_sent=%s create_sent=%s collision_removed=%s collision_created=%s",
        str(operation),
        int(runtime_object.spawn_id) if runtime_object else 0,
        int(runtime_object.entry) if runtime_object else 0,
        int(runtime_object.runtime_guid) & 0xFFFFFFFFFFFFFFFF
        if runtime_object
        else 0,
        int(affected_sessions),
        old_position[0],
        old_position[1],
        old_position[2],
        new_position[0],
        new_position[1],
        new_position[2],
        old_orientation,
        new_orientation,
        old_scale,
        new_scale,
        int(destroy_sent),
        int(create_sent),
        str(bool(collision_removed)).lower(),
        str(bool(collision_created)).lower(),
    )


def spawn_persistent_gameobject(session, spawn_id: int) -> GameObjectSpawnRuntimeResult:
    entry = DatabaseConnection.get_gameobject_spawn(int(spawn_id))
    if entry is None:
        return GameObjectSpawnRuntimeResult("spawn", int(spawn_id), None, 0)
    entry = dict(entry)
    runtime_object = _runtime_object(session, entry)
    if runtime_object is None:
        return GameObjectSpawnRuntimeResult("spawn", int(spawn_id), None, 0)
    runtime_guid = int(runtime_object.runtime_guid)
    entry["world_guid"] = runtime_guid
    get_gameobject_runtime_store().add(runtime_object)
    sessions = _same_map_sessions(session, runtime_object)
    collision_created = _create_collision(runtime_object, entry)
    _invalidate_geometry_caches()

    responses: list[tuple[str, bytes]] = []
    create_sent = 0
    for target in sessions:
        refresh = _visibility_refresh_for_session(target)
        create_sent += len(refresh)
        responses.extend(_send_or_return(session, target, refresh))
    _log_result(
        operation="spawn",
        runtime_object=runtime_object,
        affected_sessions=len(set(id(target) for target in sessions)),
        new_runtime_object=runtime_object,
        create_sent=create_sent,
        collision_created=collision_created,
    )
    return GameObjectSpawnRuntimeResult(
        "spawn",
        int(spawn_id),
        entry,
        runtime_guid,
        responses=responses,
        affected_sessions=len(set(id(target) for target in sessions)),
        create_sent=create_sent,
        collision_created=collision_created,
    )


def despawn_persistent_gameobject(
    session,
    spawn_id: int,
    *,
    existing_spawn: dict[str, Any] | None = None,
) -> GameObjectSpawnRuntimeResult:
    entry = (
        dict(existing_spawn)
        if isinstance(existing_spawn, dict)
        else DatabaseConnection.get_gameobject_spawn(int(spawn_id))
    )
    if entry is None:
        return GameObjectSpawnRuntimeResult("despawn", int(spawn_id), None, 0)
    runtime_object = _runtime_object(
        session,
        entry,
        require_mapping_transform=False,
    )
    if runtime_object is None:
        return GameObjectSpawnRuntimeResult("despawn", int(spawn_id), None, 0)
    runtime_guid = int(runtime_object.runtime_guid)
    sessions = _same_map_sessions(session, runtime_object)
    loaded = _loaded_targets(sessions, runtime_object)
    destroy = build_gameobject_destroy_response(
        session,
        runtime_guid,
        gameobject=runtime_object,
    )
    responses: list[tuple[str, bytes]] = []
    destroy_sent = 0
    for target in loaded:
        destroy_sent += 1
        responses.extend(_send_or_return(session, target, [destroy]))
    for target in sessions:
        _remove_session_visibility(target, runtime_object)
    collision_removed = _remove_collision(runtime_object)
    _invalidate_geometry_caches()
    _log_result(
        operation="despawn",
        runtime_object=runtime_object,
        affected_sessions=len(set(id(target) for target in sessions)),
        old_runtime_object=runtime_object,
        destroy_sent=destroy_sent,
        collision_removed=collision_removed,
    )
    return GameObjectSpawnRuntimeResult(
        "despawn",
        int(spawn_id),
        entry,
        runtime_guid,
        responses=responses,
        affected_sessions=len(set(id(target) for target in sessions)),
        destroy_sent=destroy_sent,
        collision_removed=collision_removed,
    )


def replace_persistent_gameobject(
    session,
    spawn_id: int,
    *,
    old_spawn: dict[str, Any] | None = None,
) -> GameObjectSpawnRuntimeResult:
    new_entry = DatabaseConnection.get_gameobject_spawn(int(spawn_id))
    if new_entry is None:
        return GameObjectSpawnRuntimeResult("replace", int(spawn_id), None, 0)
    new_entry = dict(new_entry)
    old_entry = dict(old_spawn) if isinstance(old_spawn, dict) else dict(new_entry)
    new_runtime_object = _runtime_object(session, new_entry)
    if new_runtime_object is None:
        return GameObjectSpawnRuntimeResult("replace", int(spawn_id), None, 0)
    runtime_guid = int(new_runtime_object.runtime_guid)
    old_runtime_object = _runtime_object(
        session,
        old_entry,
        runtime_guid=runtime_guid,
        require_mapping_transform=False,
    )
    if old_runtime_object is None:
        return GameObjectSpawnRuntimeResult("replace", int(spawn_id), None, 0)
    new_entry["world_guid"] = runtime_guid
    sessions = _same_map_sessions(
        session,
        old_runtime_object,
        new_runtime_object,
    )
    loaded = _loaded_targets(sessions, old_runtime_object)
    destroy = build_gameobject_destroy_response(
        session,
        runtime_guid,
        gameobject=old_runtime_object,
    )
    responses: list[tuple[str, bytes]] = []
    destroy_sent = 0
    for target in loaded:
        destroy_sent += 1
        responses.extend(_send_or_return(session, target, [destroy]))
    for target in sessions:
        _remove_session_visibility(target, old_runtime_object)
    collision_removed = _remove_collision(old_runtime_object)
    _invalidate_geometry_caches()
    get_gameobject_runtime_store().add(new_runtime_object)
    collision_created = _create_collision(new_runtime_object, new_entry)
    _invalidate_geometry_caches()

    create_sent = 0
    for target in sessions:
        refresh = _visibility_refresh_for_session(target)
        create_sent += len(refresh)
        responses.extend(_send_or_return(session, target, refresh))
    _log_result(
        operation="replace",
        runtime_object=new_runtime_object,
        affected_sessions=len(set(id(target) for target in sessions)),
        old_runtime_object=old_runtime_object,
        new_runtime_object=new_runtime_object,
        destroy_sent=destroy_sent,
        create_sent=create_sent,
        collision_removed=collision_removed,
        collision_created=collision_created,
    )
    return GameObjectSpawnRuntimeResult(
        "replace",
        int(spawn_id),
        new_entry,
        runtime_guid,
        responses=responses,
        affected_sessions=len(set(id(target) for target in sessions)),
        destroy_sent=destroy_sent,
        create_sent=create_sent,
        collision_removed=collision_removed,
        collision_created=collision_created,
    )
