#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import time
from typing import Iterable

from shared.Logger import Logger
from server.modules.handlers.world.position.position_service import position_delta, position_from_session
from server.modules.handlers.world.state.global_state import global_state
from server.modules.handlers.world.state.region_manager import region_manager

PLAYER_VISIBILITY_DISTANCE = 120.0


WEATHER_TYPES: dict[str, int] = {
    "clear": 0,
    "fine": 0,
    "sun": 0,
    "fog": 1,
    "rain": 4,
    "snow": 7,
    "sand": 41,
    "sandstorm": 41,
    "storm": 86,
    "thunder": 86,
}


def resolve_weather_type(weather_key: str, density: float) -> int:
    key = str(weather_key or "").strip().lower()
    if key in ("clear", "fine", "sun", "sunny"):
        return 0
    if key == "fog":
        return 1
    if key in ("rain", "rainy"):
        if density >= 0.66:
            return 5
        if density >= 0.33:
            return 4
        return 3
    if key in ("snow", "snowy"):
        if density >= 0.66:
            return 8
        if density >= 0.33:
            return 7
        return 6
    if key in ("sand", "sandstorm"):
        if density >= 0.66:
            return 42
        if density >= 0.33:
            return 41
        return 22
    if key in ("storm", "thunder"):
        return 86
    return WEATHER_TYPES.get(key, -1)


def pack_wow_game_time(epoch_seconds: int) -> int:
    lt = time.localtime(int(epoch_seconds))
    year = max(0, int(lt.tm_year) - 2000)
    month = max(0, int(lt.tm_mon) - 1)
    day = max(0, int(lt.tm_mday) - 1)
    weekday = (int(lt.tm_wday) + 1) % 7
    hour = int(lt.tm_hour)
    minute = int(lt.tm_min)
    return (
        ((year & 0xFF) << 24)
        | ((month & 0x0F) << 20)
        | ((day & 0x3F) << 14)
        | ((weekday & 0x07) << 11)
        | ((hour & 0x1F) << 6)
        | (minute & 0x3F)
    )


def compute_weather(global_time, map_id, seed):
    states = ("sunny", "rainy", "snowy")
    index = hash((int(global_time) // 300, int(map_id), int(seed))) % len(states)
    return states[int(index)]


def _weather_state_from_key(weather_key: str, density: float = 0.5, abrupt: int = 0) -> dict[str, float | int]:
    normalized_density = 0.0 if str(weather_key).strip().lower() in ("clear", "fine", "sun", "sunny") else float(density)
    return {
        "weather_type": int(resolve_weather_type(weather_key, normalized_density)),
        "density": float(normalized_density),
        "abrupt": int(abrupt),
    }


def refresh_region_weather(target_session) -> None:
    state = getattr(target_session, "global_state", None)
    region = getattr(target_session, "region", None)
    if state is None or region is None:
        return
    if bool(getattr(region, "weather_manual", False)) and isinstance(getattr(region, "weather", None), dict):
        target_session.weather = dict(region.weather)
        return
    weather_key = compute_weather(state.time, region.map_id, state.weather_seed)
    region.weather = _weather_state_from_key(weather_key, 0.5, 0)
    target_session.weather = dict(region.weather)


def advance_global_time(delta: int = 1) -> None:
    global_state.time = int(getattr(global_state, "time", 0) or 0) + int(delta)


def iter_world_sessions(state=None) -> list:
    scoped_state = state or global_state
    return list(scoped_state.chat_channels.setdefault("world", set()) or ())


def iter_active_sessions(state=None) -> list:
    scoped_state = state or global_state
    return list(getattr(scoped_state, "sessions", set()) or ())


def _is_session_in_world(session) -> bool:
    login_state = getattr(session, "login_state", None)
    login_state_value = getattr(login_state, "value", login_state)
    return (
        session is not None
        and callable(getattr(session, "send_response", None))
        and str(login_state_value or "") == "IN_WORLD"
        and int(getattr(session, "char_guid", 0) or 0) > 0
    )


def iter_in_world_sessions(*, state=None, map_id: int | None = None, region=None) -> list:
    sessions = iter_active_sessions(state)
    if region is not None:
        sessions = [session for session in sessions if getattr(session, "region", None) is region]
    if map_id is not None:
        sessions = [session for session in sessions if int(getattr(session, "map_id", 0) or 0) == int(map_id)]
    return [session for session in sessions if _is_session_in_world(session)]


def iter_region_sessions(target_session=None, *, region=None, map_id: int | None = None) -> list:
    target_region = region
    if target_region is None and target_session is not None:
        target_region = getattr(target_session, "region", None)
    if target_region is None and map_id is not None:
        target_region = region_manager.get_region(int(map_id))
    if target_region is None:
        return []
    return list(getattr(target_region, "players", ()) or ())


def _session_guid(session) -> int:
    return int(getattr(session, "char_guid", 0) or 0)


def _visible_guid_set(session) -> set[int]:
    visible = getattr(session, "visible_guids", None)
    if isinstance(visible, set):
        return visible
    normalized = set(int(guid) for guid in (visible or ()) if int(guid or 0) > 0)
    session.visible_guids = normalized
    return normalized


def _clear_session_visibility(session) -> None:
    visible_guids = _visible_guid_set(session)
    if not visible_guids:
        return

    session_guid = _session_guid(session)
    for peer in iter_in_world_sessions():
        if peer is session:
            continue
        if session_guid > 0:
            _visible_guid_set(peer).discard(session_guid)
    visible_guids.clear()


def _sessions_share_phase(left, right) -> bool:
    left_phase = int(getattr(left, "phase_mask", 0) or 0)
    right_phase = int(getattr(right, "phase_mask", 0) or 0)
    return left_phase == 0 or right_phase == 0 or left_phase == right_phase


def _sessions_in_visibility_range(left, right) -> bool:
    if int(getattr(left, "map_id", 0) or 0) != int(getattr(right, "map_id", 0) or 0):
        return False
    if int(getattr(left, "instance_id", 0) or 0) != int(getattr(right, "instance_id", 0) or 0):
        return False
    if not _sessions_share_phase(left, right):
        return False

    delta = position_delta(position_from_session(left), position_from_session(right))
    return math.isfinite(float(delta.distance_3d)) and float(delta.distance_3d) <= float(PLAYER_VISIBILITY_DISTANCE)


def attach_session_to_world_state(target_session, *, map_id: int) -> None:
    _clear_session_visibility(target_session)
    region = getattr(target_session, "region", None)
    if region is not None:
        region.players.discard(target_session)
    state = getattr(target_session, "global_state", None)
    if state is not None:
        state.chat_channels.setdefault("world", set()).discard(target_session)
        getattr(state, "sessions", set()).discard(target_session)
    target_session.region = None
    target_session.global_state = global_state
    target_session.region = region_manager.get_region(int(map_id))
    target_session.region.players.add(target_session)
    target_session.global_state.chat_channels.setdefault("world", set()).add(target_session)
    target_session.global_state.sessions.add(target_session)
    target_session._multiplayer_removed = False
    target_session._multiplayer_last_broadcast_at = 0.0
    target_session._multiplayer_last_broadcast_key = None
    target_session._multiplayer_last_resync_at = 0.0
    target_session._multiplayer_last_resync_key = None
    target_session.visible_guids.clear()
    target_session.time_offset = int(getattr(target_session.global_state, "time_offset", 0) or 0)
    target_session.time_speed = float(getattr(target_session.global_state, "time_speed", 0.01666667) or 0.01666667)
    target_session.server_time = int(time.time())
    target_session.game_time = pack_wow_game_time(
        int(target_session.server_time) + int(getattr(target_session, "time_offset", 0) or 0)
    )
    refresh_region_weather(target_session)


def dispatch_responses_to_sessions(targets, responses) -> None:
    normalized_targets = list(targets or [])
    if not normalized_targets or not responses:
        return
    for target in normalized_targets:
        sender = getattr(target, "send_response", None)
        if callable(sender):
            try:
                sender(responses)
            except Exception as exc:
                Logger.warning(
                    f"[MULTI] send failed player={int(getattr(target, 'char_guid', 0) or 0)} "
                    f"guid=0x{int(getattr(target, 'world_guid', 0) or 0):016X} err={exc}"
                )
                region = getattr(target, "region", None)
                if region is not None:
                    region.players.discard(target)
                state = getattr(target, "global_state", None)
                if state is not None:
                    state.chat_channels.setdefault("world", set()).discard(target)
                    getattr(state, "sessions", set()).discard(target)
                target.send_response = None


def _filtered_targets(targets: Iterable, *, exclude=None) -> list:
    excluded = set(exclude or ())
    return [target for target in list(targets or ()) if target not in excluded]


def broadcast_world_responses(responses, *, exclude=None, state=None) -> None:
    dispatch_responses_to_sessions(_filtered_targets(iter_world_sessions(state), exclude=exclude), responses)


def broadcast_region_responses(responses, *, target_session=None, region=None, map_id: int | None = None, exclude=None) -> None:
    dispatch_responses_to_sessions(
        _filtered_targets(iter_region_sessions(target_session, region=region, map_id=map_id), exclude=exclude),
        responses,
    )


def build_system_message_responses(message: str) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload

    # Fallback if we need to restore center-screen notifications:
    # from server.modules.handlers.world.chat.codec import build_motd_notification_payload
    # return [
    #     ("SMSG_NOTIFICATION", build_motd_notification_payload(message)),
    #     ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message)),
    # ]
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def broadcast_system_message(
    message: str,
    *,
    scope: str = "world",
    target_session=None,
    region=None,
    map_id: int | None = None,
    exclude=None,
) -> None:
    responses = build_system_message_responses(str(message or ""))
    if str(scope) == "region":
        broadcast_region_responses(responses, target_session=target_session, region=region, map_id=map_id, exclude=exclude)
        return
    broadcast_world_responses(responses, exclude=exclude)


def broadcast_region_weather(target_session, weather_type: int, density: float, abrupt: int = 0, *, announce: str | None = None) -> None:
    from server.modules.handlers.world.login.packets import build_login_packet

    weather_state = {
        "weather_type": int(weather_type),
        "density": float(density),
        "abrupt": int(abrupt),
    }
    setattr(target_session, "weather", dict(weather_state))

    payload = build_login_packet(
        "SMSG_WEATHER",
        type("Ctx", (), weather_state)(),
    )
    if payload is not None:
        dispatch_responses_to_sessions([target_session], [("SMSG_WEATHER", payload)])

    region = getattr(target_session, "region", None)
    if region is None:
        if announce:
            broadcast_system_message(str(announce), scope="world")
        return

    region.weather = dict(weather_state)
    region.weather_manual = True

    if payload is not None:
        for player in iter_region_sessions(region=region):
            player.weather = dict(weather_state)
        broadcast_region_responses([("SMSG_WEATHER", payload)], region=region, exclude=[target_session])

    if announce:
        broadcast_system_message(str(announce), scope="region", region=region)


def broadcast_world_time(hour: int, minute: int, *, announce: str | None = None) -> None:
    from server.modules.handlers.world.login.packets import build_login_packet
    from server.modules.handlers.world.opcodes import login as login_handlers

    now = int(time.time())
    lt = time.localtime(now)
    current_seconds = int(lt.tm_hour) * 3600 + int(lt.tm_min) * 60 + int(lt.tm_sec)
    target_seconds = int(hour) * 3600 + int(minute) * 60 + int(lt.tm_sec)
    offset = int(target_seconds - current_seconds)

    global_state.time_offset = int(offset)
    global_state.time_speed = 0.01666667

    for player in iter_world_sessions():
        player.server_time = now
        player.time_offset = int(offset)
        player.time_speed = float(global_state.time_speed)
        player.game_time = pack_wow_game_time(int(player.server_time) + int(player.time_offset))
        payload = build_login_packet("SMSG_LOGIN_SET_TIME_SPEED", login_handlers._build_world_login_context(player))
        if payload is not None:
            dispatch_responses_to_sessions([player], [("SMSG_LOGIN_SET_TIME_SPEED", payload)])

    if announce:
        broadcast_system_message(str(announce), scope="world")


def _build_player_create_update_response(source_session) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    if int(getattr(source_session, "char_guid", 0) or 0) <= 0:
        return None

    ctx = WorldLoginContext.from_session(source_session)
    ctx.exact_0002_mode = "barncastle"
    ctx.exact_0002_remote_player = True
    ctx.exact_0002_map_id = int(getattr(source_session, "map_id", 0) or 0)
    ctx.exact_0002_low_guid = int(getattr(source_session, "char_guid", 0) or 0)
    payload = build_login_packet("SMSG_UPDATE_OBJECT_1773613176_0002", ctx)
    if payload is None:
        return None
    return ("SMSG_UPDATE_OBJECT", payload)


def _build_player_name_response(source_session) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.opcodes.entities import build_query_player_name_response

    char_guid = int(getattr(source_session, "char_guid", 0) or 0)
    if char_guid <= 0:
        return None

    return ("SMSG_QUERY_PLAYER_NAME_RESPONSE", build_query_player_name_response(source_session, char_guid))


def _build_player_value_update_responses(source_session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    guid = int(getattr(source_session, "char_guid", 0) or 0)
    if guid <= 0:
        return []

    ctx = WorldLoginContext.from_session(source_session)
    ctx.exact_0004_map_id = int(getattr(source_session, "map_id", 0) or 0)
    ctx.exact_0004_guid = guid
    ctx.exact_0006_map_id = int(getattr(source_session, "map_id", 0) or 0)
    ctx.exact_0006_guid = guid

    responses: list[tuple[str, bytes]] = []
    payload_0004 = build_login_packet("SMSG_UPDATE_OBJECT_1773613176_0004", ctx)
    if payload_0004 is not None:
        responses.append(("SMSG_UPDATE_OBJECT", payload_0004))
    payload_0006 = build_login_packet("SMSG_UPDATE_OBJECT_1773613185_0006", ctx)
    if payload_0006 is not None:
        responses.append(("SMSG_UPDATE_OBJECT", payload_0006))
    return responses


def _build_player_remove_update_response(source_session) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    low_guid = int(getattr(source_session, "char_guid", 0) or 0)
    if low_guid <= 0:
        return None

    ctx = WorldLoginContext.from_session(source_session)
    ctx.exact_0007_map_id = int(getattr(source_session, "map_id", 0) or 0)
    ctx.exact_0007_out_of_range_guids = [low_guid]
    payload = build_login_packet("SMSG_UPDATE_OBJECT_1773613205_0007", ctx)
    if payload is None:
        return None
    return ("SMSG_UPDATE_OBJECT", payload)


def _build_player_create_responses(source_session) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    name_response = _build_player_name_response(source_session)
    create_response = _build_player_create_update_response(source_session)
    if name_response is not None:
        responses.append(name_response)
    if create_response is not None:
        responses.append(create_response)
    return responses


def _send_player_create(observer_session, source_session) -> bool:
    source_guid = _session_guid(source_session)
    if source_guid <= 0:
        return False

    visible_guids = _visible_guid_set(observer_session)
    if source_guid in visible_guids:
        return False

    responses = _build_player_create_responses(source_session)
    if not responses:
        return False

    dispatch_responses_to_sessions([observer_session], responses)
    visible_guids.add(source_guid)
    return True


def _send_player_remove(observer_session, source_session) -> bool:
    source_guid = _session_guid(source_session)
    if source_guid <= 0:
        return False

    visible_guids = _visible_guid_set(observer_session)
    if source_guid not in visible_guids:
        return False

    remove_response = _build_player_remove_update_response(source_session)
    visible_guids.discard(source_guid)
    if remove_response is None:
        return False

    dispatch_responses_to_sessions([observer_session], [remove_response])
    return True


def _reconcile_session_visibility_pair(source_session, other_session, *, source_value_responses=None) -> tuple[bool, bool, bool]:
    if other_session is source_session or not _is_session_in_world(other_session):
        return False, False, False

    source_guid = _session_guid(source_session)
    other_guid = _session_guid(other_session)
    if source_guid <= 0 or other_guid <= 0:
        return False, False, False

    if _sessions_in_visibility_range(source_session, other_session):
        created_for_source = _send_player_create(source_session, other_session)
        created_for_other = _send_player_create(other_session, source_session)
        updated_for_other = False
        if not created_for_other and source_value_responses and source_guid in _visible_guid_set(other_session):
            responses: list[tuple[str, bytes]] = []
            remove_response = _build_player_remove_update_response(source_session)
            create_response = _build_player_create_update_response(source_session)
            if remove_response is not None:
                responses.append(remove_response)
            if create_response is not None:
                responses.append(create_response)
            if responses:
                dispatch_responses_to_sessions([other_session], responses)
                updated_for_other = True
        return created_for_source, created_for_other, updated_for_other

    removed_from_source = _send_player_remove(source_session, other_session)
    removed_from_other = _send_player_remove(other_session, source_session)
    return removed_from_source, removed_from_other, False


def sync_player_visibility(target_session) -> None:
    if not _is_session_in_world(target_session):
        return

    same_map_sessions = iter_in_world_sessions(map_id=int(getattr(target_session, "map_id", 0) or 0))
    other_sessions = [session for session in same_map_sessions if session is not target_session]
    if not other_sessions:
        return

    created_links = 0
    removed_links = 0
    for other in other_sessions:
        had_other_before = _session_guid(other) in _visible_guid_set(target_session)
        had_target_before = _session_guid(target_session) in _visible_guid_set(other)
        changed_for_target, changed_for_other, _ = _reconcile_session_visibility_pair(target_session, other)
        now_has_other = _session_guid(other) in _visible_guid_set(target_session)
        now_has_target = _session_guid(target_session) in _visible_guid_set(other)
        if changed_for_target and now_has_other:
            created_links += 1
        elif had_other_before and not now_has_other:
            removed_links += 1
        if changed_for_other and now_has_target:
            created_links += 1
        elif had_target_before and not now_has_target:
            removed_links += 1

    Logger.info(
        f"[MULTI] synced visibility player={int(getattr(target_session, 'char_guid', 0) or 0)} "
        f"map={int(getattr(target_session, 'map_id', 0) or 0)} peers={len(other_sessions)} "
        f"created={created_links} removed={removed_links} visible={len(_visible_guid_set(target_session))}"
    )


def sync_all_players_on_map(map_id: int) -> None:
    sessions = iter_in_world_sessions(map_id=int(map_id))
    if len(sessions) < 2:
        return

    pair_count = 0
    for index, target in enumerate(sessions):
        for other in sessions[index + 1:]:
            _reconcile_session_visibility_pair(target, other)
            pair_count += 1

    Logger.info(
        f"[MULTI] resynced map={int(map_id)} players={len(sessions)} pairs={pair_count}"
    )


def broadcast_player_state_update(source_session, *, force: bool = False) -> None:
    if not _is_session_in_world(source_session):
        return

    now = float(time.time())
    key = (
        int(getattr(source_session, "map_id", 0) or 0),
        int(getattr(source_session, "char_guid", 0) or 0),
        round(float(getattr(source_session, "x", 0.0) or 0.0), 3),
        round(float(getattr(source_session, "y", 0.0) or 0.0), 3),
        round(float(getattr(source_session, "z", 0.0) or 0.0), 3),
        round(float(getattr(source_session, "orientation", 0.0) or 0.0), 3),
    )
    last_key = getattr(source_session, "_multiplayer_last_broadcast_key", None)
    last_at = float(getattr(source_session, "_multiplayer_last_broadcast_at", 0.0) or 0.0)
    if not force and key == last_key and (now - last_at) < 0.10:
        return

    value_responses = _build_player_value_update_responses(source_session)
    create_responses = _build_player_create_responses(source_session)
    if not value_responses and not create_responses:
        return

    peers = [
        session
        for session in iter_in_world_sessions(map_id=int(getattr(source_session, "map_id", 0) or 0))
        if session is not source_session
    ]
    if not peers:
        return

    created = 0
    updated = 0
    removed = 0
    for peer in peers:
        had_source_before = _session_guid(source_session) in _visible_guid_set(peer)
        had_peer_before = _session_guid(peer) in _visible_guid_set(source_session)
        changed_for_source, changed_for_peer, updated_for_peer = _reconcile_session_visibility_pair(
            source_session,
            peer,
            source_value_responses=value_responses,
        )
        has_source_now = _session_guid(source_session) in _visible_guid_set(peer)
        has_peer_now = _session_guid(peer) in _visible_guid_set(source_session)
        if changed_for_source and has_peer_now:
            created += 1
        elif had_peer_before and not has_peer_now:
            removed += 1
        if changed_for_peer and has_source_now:
            created += 1
        elif had_source_before and not has_source_now:
            removed += 1
        updated += int(updated_for_peer)

    source_session._multiplayer_last_broadcast_at = now
    source_session._multiplayer_last_broadcast_key = key
    source_session._multiplayer_removed = False
    if force or created or updated or removed:
        Logger.debug(
            f"[MULTI] update player={int(getattr(source_session, 'char_guid', 0) or 0)} "
            f"map={int(getattr(source_session, 'map_id', 0) or 0)} peers={len(peers)} "
            f"created={created} updated={updated} removed={removed} "
            f"visible={len(_visible_guid_set(source_session))}"
        )


def broadcast_player_remove(source_session) -> None:
    if bool(getattr(source_session, "_multiplayer_removed", False)):
        return

    response = _build_player_remove_update_response(source_session)
    source_guid = _session_guid(source_session)
    peers = [
        session
        for session in iter_in_world_sessions(map_id=int(getattr(source_session, "map_id", 0) or 0))
        if session is not source_session
    ]
    removed_from = 0
    for peer in peers:
        peer_visible = _visible_guid_set(peer)
        if source_guid > 0 and source_guid in peer_visible:
            peer_visible.discard(source_guid)
            if response is not None:
                dispatch_responses_to_sessions([peer], [response])
            removed_from += 1
        _visible_guid_set(source_session).discard(_session_guid(peer))
    _visible_guid_set(source_session).clear()
    if removed_from:
        Logger.info(
            f"[MULTI] removed player={int(getattr(source_session, 'char_guid', 0) or 0)} "
            f"map={int(getattr(source_session, 'map_id', 0) or 0)} peers={removed_from}"
        )
    source_session._multiplayer_removed = True
