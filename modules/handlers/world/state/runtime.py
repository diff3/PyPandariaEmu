#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import time

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
    if key in ("clear", "fine", "sun"):
        return 0
    if key == "fog":
        return 1
    if key == "rain":
        if density >= 0.66:
            return 5
        if density >= 0.33:
            return 4
        return 3
    if key == "snow":
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


def refresh_region_weather(target_session) -> None:
    state = getattr(target_session, "global_state", None)
    region = getattr(target_session, "region", None)
    if state is None or region is None:
        return
    region.weather = compute_weather(state.time, region.map_id, state.weather_seed)


def advance_global_time(delta: int = 1) -> None:
    global_state.time = int(getattr(global_state, "time", 0) or 0) + int(delta)


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
    refresh_region_weather(target_session)


def dispatch_responses_to_sessions(targets, responses) -> None:
    normalized_targets = list(targets or [])
    if not normalized_targets or not responses:
        return
    for target in normalized_targets:
        sender = getattr(target, "send_response", None)
        if callable(sender):
            sender(responses)
