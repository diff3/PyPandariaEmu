#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import time
from typing import Iterable

from server.modules.handlers.world.state.global_state import global_state
from server.modules.handlers.world.state.region_manager import region_manager


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


def iter_region_sessions(target_session=None, *, region=None, map_id: int | None = None) -> list:
    target_region = region
    if target_region is None and target_session is not None:
        target_region = getattr(target_session, "region", None)
    if target_region is None and map_id is not None:
        target_region = region_manager.get_region(int(map_id))
    if target_region is None:
        return []
    return list(getattr(target_region, "players", ()) or ())


def attach_session_to_world_state(target_session, *, map_id: int) -> None:
    region = getattr(target_session, "region", None)
    if region is not None:
        region.players.discard(target_session)
    state = getattr(target_session, "global_state", None)
    if state is not None:
        state.chat_channels.setdefault("world", set()).discard(target_session)
    target_session.region = None
    target_session.global_state = global_state
    target_session.region = region_manager.get_region(int(map_id))
    target_session.region.players.add(target_session)
    target_session.global_state.chat_channels.setdefault("world", set()).add(target_session)
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
            sender(responses)


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
    from server.modules.handlers.world.chat.codec import (
        build_motd_notification_payload,
        encode_skyfire_messagechat_system_payload,
    )

    return [
        ("SMSG_NOTIFICATION", build_motd_notification_payload(message)),
        ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message)),
    ]


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
