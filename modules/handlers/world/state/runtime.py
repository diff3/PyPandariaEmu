#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import re
import time
from typing import Iterable

from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader
from server.modules.handlers.world.position.area_service import resolve_zone_from_position
from server.modules.handlers.world.position.position_service import position_delta, position_from_session
from server.modules.handlers.world.state.global_state import global_state
from server.modules.handlers.world.state.player_visible_snapshot import build_player_visible_snapshot
from server.modules.handlers.world.state.region_manager import region_manager

PLAYER_VISIBILITY_DISTANCE = 120.0
_PLAYER_FIELD_EXPLORED_ZONES = (0x8 + 0x98) + 0x5BB
_PLAYER_EXPLORED_ZONES_SIZE = 200
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

_DEFAULT_WEATHER_CYCLE_SECONDS = 600
_SNOW_ZONE_IDS = frozenset({
    1,      # Dun Morogh
    36,     # Alterac Mountains
    2597,   # Alterac Valley
    618,    # Winterspring
    394,    # Grizzly Hills
    495,    # Howling Fjord
    3537,   # Borean Tundra
    65,     # Dragonblight
    67,     # The Storm Peaks
    210,    # Icecrown
    4197,   # Wintergrasp
})


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


def _weather_config() -> dict:
    return dict(ConfigLoader.load_config().get("worldserver", {}) or {})


def _weather_cycle_seconds() -> int:
    configured = int(_weather_config().get("weather_cycle_seconds", _DEFAULT_WEATHER_CYCLE_SECONDS) or 0)
    return max(60, configured)


def _weather_cycle_slot(*, now: float | None = None) -> int:
    epoch = float(time.time() if now is None else now)
    return int(epoch // _weather_cycle_seconds())


def _resolve_weather_zone_id(target_session) -> int:
    zone_id = int(
        getattr(target_session, "zone", 0)
        or getattr(target_session, "persist_zone", 0)
        or 0
    )
    if zone_id > 0:
        return zone_id

    map_id = int(getattr(target_session, "map_id", 0) or 0)
    x = float(getattr(target_session, "x", 0.0) or 0.0)
    y = float(getattr(target_session, "y", 0.0) or 0.0)
    resolved = int(resolve_zone_from_position(map_id, x, y) or 0)
    if resolved > 0:
        target_session.zone = resolved
    return resolved


def _weather_profile_key(zone_id: int) -> str:
    if int(zone_id) in _SNOW_ZONE_IDS:
        return "snow"
    return "rain"


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


def compute_weather(global_time, map_id, seed, *, zone_id: int = 0, now: float | None = None):
    slot = _weather_cycle_slot(now=now)
    offset = (int(map_id) * 31 + int(zone_id) * 17 + int(seed)) % 4
    phase = int((slot + offset) % 4)

    if _weather_profile_key(int(zone_id)) == "snow":
        states = (
            ("clear", 0.0),
            ("snow", 0.35),
            ("snow", 0.75),
            ("clear", 0.0),
        )
    else:
        states = (
            ("clear", 0.0),
            ("rain", 0.35),
            ("rain", 0.75),
            ("clear", 0.0),
        )

    return states[phase]


def _weather_state_from_key(weather_key: str, density: float = 0.5, abrupt: int = 0) -> dict[str, float | int]:
    normalized_density = 0.0 if str(weather_key).strip().lower() in ("clear", "fine", "sun", "sunny") else float(density)
    return {
        "weather_type": int(resolve_weather_type(weather_key, normalized_density)),
        "density": float(normalized_density),
        "abrupt": int(abrupt),
    }


def refresh_region_weather(target_session) -> bool:
    state = getattr(target_session, "global_state", None)
    region = getattr(target_session, "region", None)
    if state is None or region is None:
        return False
    previous_weather = dict(getattr(target_session, "weather", {}) or {})
    manual_region_weather = getattr(state, "manual_region_weather", None)
    if isinstance(manual_region_weather, dict):
        manual_weather = manual_region_weather.get(int(getattr(region, "map_id", 0) or 0))
        if isinstance(manual_weather, dict):
            region.weather = dict(manual_weather)
            region.weather_manual = True
            target_session.weather = dict(manual_weather)
            return dict(target_session.weather) != previous_weather
    if bool(getattr(region, "weather_manual", False)) and isinstance(getattr(region, "weather", None), dict):
        target_session.weather = dict(region.weather)
        return dict(target_session.weather) != previous_weather

    zone_id = _resolve_weather_zone_id(target_session)
    weather_key, density = compute_weather(
        state.time,
        region.map_id,
        state.weather_seed,
        zone_id=zone_id,
    )
    target_session.weather = _weather_state_from_key(weather_key, density, 0)
    return dict(target_session.weather) != previous_weather


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


def _normalized_explored_zones(raw: str | None, *, size: int = _PLAYER_EXPLORED_ZONES_SIZE) -> list[int]:
    values = [
        max(0, min(0xFFFFFFFF, int(token)))
        for token in re.findall(r"-?\d+", str(raw or ""))
    ]
    if len(values) < int(size):
        values.extend([0] * (int(size) - len(values)))
    return values[: int(size)]


def set_session_explored_zones_state(session, reveal_all: bool, *, size: int = _PLAYER_EXPLORED_ZONES_SIZE) -> str:
    field_value = 0xFFFFFFFF if bool(reveal_all) else 0
    raw = " ".join(str(field_value) for _ in range(int(size)))
    session.explored_zones_raw = raw
    return raw


def build_explored_zones_update_response(session) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.bootstrap.replay import build_multi_u32_update_object_payload

    guid = int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or 0)
    if guid <= 0:
        return None

    values = _normalized_explored_zones(getattr(session, "explored_zones_raw", ""))
    return (
        "SMSG_UPDATE_OBJECT",
        build_multi_u32_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=guid,
            field_updates=[
                (_PLAYER_FIELD_EXPLORED_ZONES + offset, int(value))
                for offset, value in enumerate(values)
            ],
        ),
    )


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

    state = getattr(target_session, "global_state", None)
    region.weather = dict(weather_state)
    region.weather_manual = True
    if state is not None and isinstance(getattr(state, "manual_region_weather", None), dict):
        state.manual_region_weather[int(getattr(region, "map_id", 0) or 0)] = dict(weather_state)

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
    Logger.info("[CREATE PATH] remote=replay")
    payload = build_login_packet("SMSG_UPDATE_OBJECT_1773613176_0002", ctx)
    if payload is None:
        return None
    return ("SMSG_UPDATE_OBJECT", payload)


def build_self_player_appearance_responses(source_session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.inventory_sync import build_self_visible_item_update_responses
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    if int(getattr(source_session, "char_guid", 0) or 0) <= 0:
        return []

    responses: list[tuple[str, bytes]] = []
    ctx = WorldLoginContext.from_session(source_session)
    ctx.exact_0002_mode = "barncastle"
    ctx.exact_0002_map_id = int(getattr(source_session, "map_id", 0) or 0)
    ctx.exact_0002_low_guid = int(getattr(source_session, "char_guid", 0) or 0)
    Logger.info("[CREATE PATH] self=server-built")
    payload = build_login_packet("SMSG_UPDATE_OBJECT_1773613176_0002", ctx)
    if payload is not None:
        responses.append(("SMSG_UPDATE_OBJECT", payload))
    responses.extend(build_self_visible_item_update_responses(source_session))
    return responses


def build_same_map_teleport_self_resync_responses(source_session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.inventory_sync import build_self_visible_item_update_responses
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    guid = int(getattr(source_session, "char_guid", 0) or 0)
    if guid <= 0:
        return []

    responses: list[tuple[str, bytes]] = []

    ctx = WorldLoginContext.from_session(source_session)
    ctx.exact_0006_map_id = int(getattr(source_session, "map_id", 0) or 0)
    ctx.exact_0006_guid = guid
    payload_0006 = build_login_packet("SMSG_UPDATE_OBJECT_1773613185_0006", ctx)
    if payload_0006 is not None:
        responses.append(("SMSG_UPDATE_OBJECT", payload_0006))
    responses.extend(build_self_visible_item_update_responses(source_session))

    source_session.player_object_sent = True
    return responses


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
    explored_response = build_explored_zones_update_response(source_session)
    if explored_response is not None:
        responses.append(explored_response)
    return responses


def _build_player_move_response(source_session) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.opcodes.movement import build_smsg_player_move_payload

    payload = build_smsg_player_move_payload(source_session)
    if not payload:
        return None
    return ("SMSG_PLAYER_MOVE", payload)


def _build_player_remove_update_response(
    source_session,
    *,
    map_id: int | None = None,
) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    low_guid = int(getattr(source_session, "char_guid", 0) or 0)
    if low_guid <= 0:
        return None

    ctx = WorldLoginContext.from_session(source_session)
    ctx.exact_0007_map_id = (
        int(getattr(source_session, "map_id", 0) or 0)
        if map_id is None
        else int(map_id)
    )
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

    from server.modules.handlers.world.inventory_sync import build_self_visible_item_update_responses

    responses = _build_player_create_responses(source_session)
    if responses:
        responses.extend(build_self_visible_item_update_responses(source_session))
    if not responses:
        return False

    observer_guid = int(getattr(observer_session, "char_guid", 0) or 0)
    visible_snapshot = build_player_visible_snapshot(source_session)
    tag = "SELF" if observer_guid == int(visible_snapshot.guid) else "OTHER"

    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue

        try:
            from server.modules.handlers.world.bootstrap.playerobjects import (
                extract_first_update_object_guid_info,
                locate_mask_region,
                extract_field_indices,
            )

            guid_info = extract_first_update_object_guid_info(payload)
            create_guid = guid_info[0] if guid_info else 0

            mask_start, mask_end, mask_blocks = locate_mask_region(payload)
            mask_bytes = payload[mask_start:mask_end]
            field_indices = extract_field_indices(mask_bytes, mask_blocks)

            Logger.info(
                f"[CREATE SEND {tag}] "
                f"observer={observer_guid} "
                f"source={int(visible_snapshot.guid)} "
                f"map={int(visible_snapshot.map_id)} "
                f"pos=({float(visible_snapshot.x):.3f},"
                f"{float(visible_snapshot.y):.3f},"
                f"{float(visible_snapshot.z):.3f},"
                f"{float(visible_snapshot.orientation):.3f}) "
                f"mount={int(visible_snapshot.mount_display_id)} "
                f"create_guid={create_guid} "
                f"mask_words={mask_blocks} "
                f"fields={len(field_indices)} "
                f"size={len(payload)}"
            )

        except Exception as exc:
            Logger.warning(f"[CREATE LOG ERROR] {exc}")

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


def force_player_visibility_destroy(
    target_session,
    *,
    reason: str = "manual",
    map_id: int | None = None,
) -> None:
    """Destroy one player from every observer cache before moving/recreating it."""
    target_guid = _session_guid(target_session)
    if target_guid <= 0:
        return

    remove_response = _build_player_remove_update_response(target_session, map_id=map_id)
    removed_for_observers = 0
    cleared_for_target = 0
    target_visible = _visible_guid_set(target_session)
    source_map_id = (
        int(getattr(target_session, "map_id", 0) or 0)
        if map_id is None
        else int(map_id)
    )

    for observer in iter_in_world_sessions():
        if observer is target_session:
            continue

        observer_guid = _session_guid(observer)
        if observer_guid in target_visible:
            target_visible.discard(observer_guid)
            cleared_for_target += 1

        observer_visible = _visible_guid_set(observer)
        if target_guid not in observer_visible:
            continue

        observer_visible.discard(target_guid)
        if remove_response is None:
            continue

        Logger.info(
            "[DESTROY SEND] observer=%s source=%s map=%s reason=%s",
            int(getattr(observer, "char_guid", 0) or 0),
            int(target_guid),
            int(source_map_id),
            str(reason),
        )
        dispatch_responses_to_sessions([observer], [remove_response])
        removed_for_observers += 1

    target_visible.clear()
    Logger.info(
        "[MULTI] forced visibility destroy player=%s map=%s reason=%s "
        "destroyed=%s cleared_for_player=%s",
        int(target_guid),
        int(source_map_id),
        str(reason),
        int(removed_for_observers),
        int(cleared_for_target),
    )


def _reconcile_session_visibility_pair(
    source_session,
    other_session,
    *,
    source_move_response=None,
    source_value_responses=None,
    source_resync_responses=None,
) -> tuple[bool, bool, bool]:
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
        if not created_for_other and source_guid in _visible_guid_set(other_session):
            responses = []
            if source_move_response is not None:
                responses.append(source_move_response)
            else:
                responses.extend(list(source_value_responses or []))
            if not responses and source_resync_responses:
                # Keep the old resync fallback only when no live movement packet
                # is available. The newer normal-walk SMSG_PLAYER_MOVE path is
                # good enough now that layering remove+create on top mostly adds
                # teleport-like jitter.
                responses.extend(list(source_resync_responses))
            if responses:
                updated_for_other = True
                dispatch_responses_to_sessions([other_session], responses)
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


def force_bilateral_visibility_resync(target_session, *, reason: str = "manual") -> None:
    """Rebuild both visibility directions for one player using normal paths."""
    if not _is_session_in_world(target_session):
        return

    target_guid = _session_guid(target_session)
    if target_guid <= 0:
        return

    same_map_sessions = iter_in_world_sessions(
        map_id=int(getattr(target_session, "map_id", 0) or 0)
    )
    other_sessions = [
        session for session in same_map_sessions if session is not target_session
    ]
    if not other_sessions:
        return

    created_for_target = 0
    created_for_peers = 0
    removed_links = 0

    for other in other_sessions:
        other_guid = _session_guid(other)
        if other_guid <= 0:
            continue

        if _sessions_in_visibility_range(target_session, other):
            if _send_player_remove(target_session, other):
                removed_links += 1
            if _send_player_remove(other, target_session):
                removed_links += 1
            _visible_guid_set(target_session).discard(other_guid)
            _visible_guid_set(other).discard(target_guid)
            if _send_player_create(target_session, other):
                created_for_target += 1
            if _send_player_create(other, target_session):
                created_for_peers += 1
            continue

        if _send_player_remove(target_session, other):
            removed_links += 1
        if _send_player_remove(other, target_session):
            removed_links += 1

    Logger.info(
        "[MULTI] forced bilateral visibility player=%s map=%s reason=%s "
        "peers=%s created_for_player=%s created_for_peers=%s removed=%s visible=%s",
        int(target_guid),
        int(getattr(target_session, "map_id", 0) or 0),
        str(reason),
        len(other_sessions),
        int(created_for_target),
        int(created_for_peers),
        int(removed_links),
        len(_visible_guid_set(target_session)),
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


def resync_player_appearance(source_session) -> None:
    from server.modules.handlers.world.inventory_sync import build_self_visible_item_update_responses

    if not _is_session_in_world(source_session):
        return

    remove_response = _build_player_remove_update_response(source_session)
    create_response = _build_player_create_update_response(source_session)
    if remove_response is None and create_response is None:
        return

    peers = [
        session
        for session in iter_in_world_sessions(map_id=int(getattr(source_session, "map_id", 0) or 0))
        if session is not source_session
    ]
    if not peers:
        return

    source_guid = _session_guid(source_session)
    for peer in peers:
        if source_guid not in _visible_guid_set(peer):
            continue
        responses: list[tuple[str, bytes]] = []
        if remove_response is not None:
            responses.append(remove_response)
        if create_response is not None:
            responses.append(create_response)
            responses.extend(build_self_visible_item_update_responses(source_session))
        if responses:
            dispatch_responses_to_sessions([peer], responses)

    Logger.info(
        f"[MULTI] appearance resync player={int(getattr(source_session, 'char_guid', 0) or 0)} "
        f"map={int(getattr(source_session, 'map_id', 0) or 0)} peers={len(peers)}"
    )


def broadcast_visible_equipment_update(source_session) -> None:
    """Send current visible equipment fields to peers already seeing source."""
    from server.modules.handlers.world.inventory_sync import build_self_visible_item_update_responses

    if not _is_session_in_world(source_session):
        return

    source_guid = _session_guid(source_session)
    if source_guid <= 0:
        return

    responses = build_self_visible_item_update_responses(source_session)
    if not responses:
        return

    peers = [
        session
        for session in iter_in_world_sessions(
            map_id=int(getattr(source_session, "map_id", 0) or 0)
        )
        if session is not source_session and source_guid in _visible_guid_set(session)
    ]
    if not peers:
        return

    dispatch_responses_to_sessions(peers, responses)
    Logger.info(
        "[MULTI] visible equipment update player=%s map=%s peers=%s",
        int(source_guid),
        int(getattr(source_session, "map_id", 0) or 0),
        len(peers),
    )


def broadcast_player_state_update(source_session, *, force: bool = False) -> None:
    if not _is_session_in_world(source_session):
        return

    now = float(time.time())
    key = (
        int(getattr(source_session, "map_id", 0) or 0),
        int(getattr(source_session, "char_guid", 0) or 0),
        round(float(getattr(source_session, "x", 0.0) or 0.0), 5),
        round(float(getattr(source_session, "y", 0.0) or 0.0), 5),
        round(float(getattr(source_session, "z", 0.0) or 0.0), 5),
        round(float(getattr(source_session, "orientation", 0.0) or 0.0), 5),
    )
    last_key = getattr(source_session, "_multiplayer_last_broadcast_key", None)
    last_at = float(getattr(source_session, "_multiplayer_last_broadcast_at", 0.0) or 0.0)
    if not force and key == last_key and (now - last_at) < 0.02:
        return

    move_response = _build_player_move_response(source_session)
    value_responses = []
    if move_response is None:
        value_responses = _build_player_value_update_responses(source_session)
    if move_response is None and not value_responses:
        return

    resync_responses: list[tuple[str, bytes]] = []
    last_resync_key = getattr(source_session, "_multiplayer_last_resync_key", None)
    last_resync_at = float(getattr(source_session, "_multiplayer_last_resync_at", 0.0) or 0.0)
    if move_response is None and key != last_resync_key and (force or (now - last_resync_at) >= 0.75):
        remove_response = _build_player_remove_update_response(source_session)
        create_response = _build_player_create_update_response(source_session)
        if remove_response is not None:
            resync_responses.append(remove_response)
        if create_response is not None:
            resync_responses.append(create_response)

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
            source_move_response=move_response,
            source_value_responses=value_responses,
            source_resync_responses=resync_responses,
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
    if resync_responses:
        source_session._multiplayer_last_resync_at = now
        source_session._multiplayer_last_resync_key = key
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
