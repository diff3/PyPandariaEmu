#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import math
import re
import time
from typing import Iterable

from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader
from shared.PathUtils import get_data_root
from server.modules.handlers.world.position.area_service import resolve_zone_from_position
from server.modules.handlers.world.position.position_service import (
    Position,
    position_delta,
)
from server.modules.handlers.world.runtime.player import Player
from server.modules.handlers.world.runtime.player_store import (
    resolve_player_runtime,
)
from server.modules.handlers.world.state.global_state import global_state
from server.modules.handlers.world.state.player_visible_snapshot import (
    build_player_visible_snapshot,
)
from server.modules.handlers.world.state.region_manager import region_manager
from server.modules.handlers.world.state.weather_zone_registry import canonical_weather_zone_registry

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


def weather_runtime_snapshot_rows() -> list[dict]:
    _process_weather_runtime_commands()
    configured_rows = {
        int(row.get("zone", 0) or 0): dict(row)
        for row in _configured_weather_rows()
        if int(row.get("zone", 0) or 0) > 0
    }
    registry = canonical_weather_zone_registry(set(configured_rows))
    if not registry:
        registry = {
            zone_id: type("WeatherZoneFallback", (), {
                "zone_id": zone_id,
                "parent_zone_id": 0,
                "map_id": 0,
                "name": f"Zone {zone_id}",
                "normalized_name": f"zone {zone_id}",
                "aliases": (),
                "child_zone_ids": (),
                "explicit_weather": True,
            })()
            for zone_id in configured_rows
        }
    season = _current_weather_season()
    result: list[dict] = []
    manual_weather = getattr(global_state, "manual_region_weather", None)
    if not isinstance(manual_weather, dict):
        manual_weather = {}

    for zone in registry.values():
        zone_id = int(zone.zone_id)
        if zone_id <= 0:
            continue
        manual = manual_weather.get(zone_id)
        if isinstance(manual, dict):
            weather_state = dict(manual)
            manual_active = True
        else:
            weather_key, density = compute_weather(
                global_state.time,
                0,
                global_state.weather_seed,
                zone_id=zone_id,
            )
            weather_state = _weather_state_from_key(weather_key, density, 0)
            manual_active = False
        row = configured_rows.get(zone_id, {})
        result.append({
            "zone": zone_id,
            "parent_zone": int(zone.parent_zone_id),
            "map_id": int(zone.map_id),
            "canonical_name": str(zone.name),
            "normalized_name": str(zone.normalized_name),
            "search_aliases": list(zone.aliases),
            "child_zones": list(zone.child_zone_ids),
            "explicit_weather": bool(zone.explicit_weather),
            "season": season,
            "weather_type": int(weather_state.get("weather_type", 0) or 0),
            "density": float(weather_state.get("density", 0.0) or 0.0),
            "abrupt": int(weather_state.get("abrupt", 0) or 0),
            "cycle_slot": int(_weather_cycle_slot()),
            "cycle_seconds": int(_weather_cycle_seconds()),
            "seed": int(global_state.weather_seed),
            "manual": bool(manual_active),
            "rain_chance": int(row.get(f"{season}_rain_chance", 0) or 0),
            "snow_chance": int(row.get(f"{season}_snow_chance", 0) or 0),
            "storm_chance": int(row.get(f"{season}_storm_chance", 0) or 0),
        })

    result.sort(key=lambda item: str(item.get("canonical_name", "")).lower())
    return result


def _process_weather_runtime_commands() -> None:
    root = get_data_root() / "runtime" / "weather_commands"
    if not root.exists():
        return

    for path in sorted(root.glob("*.json")):
        try:
            command = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(command, dict):
                _apply_weather_runtime_command(command)
            path.unlink(missing_ok=True)
        except Exception as exc:
            Logger.warning("[WeatherRuntime] command failed path=%s err=%s", path, exc)


def _apply_weather_runtime_command(command: dict) -> None:
    action = str(command.get("action") or "").strip().lower()
    zone_id = int(command.get("zone", 0) or 0)
    if zone_id <= 0:
        return

    if action == "override":
        weather_key = str(command.get("weather") or "").strip().lower()
        if weather_key == "heavy_rain":
            weather_key = "rain"
        density = float(command.get("density", 0.5) or 0.5)
        weather_type = int(resolve_weather_type(weather_key, density))
        if weather_type < 0:
            return
        _set_manual_weather_for_zone(zone_id, {
            "weather_type": weather_type,
            "density": 0.0 if weather_type == 0 else density,
            "abrupt": 1,
        })
        return

    if action == "reset":
        manual_weather = getattr(global_state, "manual_region_weather", None)
        if isinstance(manual_weather, dict):
            manual_weather.pop(zone_id, None)
        return

    if action == "chance":
        _apply_weather_chance_command(command, zone_id)


def _set_manual_weather_for_zone(zone_id: int, weather_state: dict) -> None:
    manual_weather = getattr(global_state, "manual_region_weather", None)
    if not isinstance(manual_weather, dict):
        global_state.manual_region_weather = {}
        manual_weather = global_state.manual_region_weather
    manual_weather[int(zone_id)] = dict(weather_state)

    for session in iter_active_sessions(global_state):
        if int(_resolve_weather_zone_id(session)) == int(zone_id):
            setattr(session, "weather", dict(weather_state))


def _apply_weather_chance_command(command: dict, zone_id: int) -> None:
    kind = str(command.get("kind") or "").strip().lower()
    season = str(command.get("season") or "").strip().lower()
    if kind not in {"rain", "snow", "storm"} or season not in {"spring", "summer", "fall", "winter"}:
        return

    value = max(0, min(100, int(command.get("value", 0) or 0)))
    column = f"{season}_{kind}_chance"
    cached = getattr(_configured_weather_rows, "_rows", None)
    if not isinstance(cached, list):
        return
    target = None
    for row in cached:
        if int(row.get("zone", 0) or 0) == int(zone_id):
            target = row
            break
    if target is None:
        target = {"zone": int(zone_id)}
        for season_name in ("spring", "summer", "fall", "winter"):
            for chance_kind in ("rain", "snow", "storm"):
                target[f"{season_name}_{chance_kind}_chance"] = 0
        cached.append(target)
    target[column] = value


def _configured_weather_rows() -> list[dict]:
    cached = getattr(_configured_weather_rows, "_rows", None)
    if isinstance(cached, list):
        return [dict(row) for row in cached]

    try:
        from server.modules.database.DatabaseConnection import DatabaseConnection
        from sqlalchemy import text

        session = DatabaseConnection.world()
        rows = list(session.execute(text(
            """
            SELECT
                zone,
                spring_rain_chance,
                spring_snow_chance,
                spring_storm_chance,
                summer_rain_chance,
                summer_snow_chance,
                summer_storm_chance,
                fall_rain_chance,
                fall_snow_chance,
                fall_storm_chance,
                winter_rain_chance,
                winter_snow_chance,
                winter_storm_chance
            FROM game_weather
            ORDER BY zone
            """
        )).mappings())
    except Exception as exc:
        Logger.warning("[WeatherRuntime] game_weather snapshot lookup failed err=%s", exc)
        rows = []

    normalized = [dict(row) for row in rows]
    setattr(_configured_weather_rows, "_rows", normalized)
    return [dict(row) for row in normalized]


def _current_weather_season() -> str:
    month = int(time.localtime().tm_mon)
    if month in (3, 4, 5):
        return "spring"
    if month in (6, 7, 8):
        return "summer"
    if month in (9, 10, 11):
        return "fall"
    return "winter"


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
    zone_id = _resolve_weather_zone_id(target_session)
    manual_region_weather = getattr(state, "manual_region_weather", None)
    if isinstance(manual_region_weather, dict):
        manual_weather = manual_region_weather.get(int(zone_id))
        if isinstance(manual_weather, dict):
            region.weather = dict(manual_weather)
            region.weather_manual = True
            region.weather_zone_id = int(zone_id)
            target_session.weather = dict(manual_weather)
            return dict(target_session.weather) != previous_weather
    if (
        bool(getattr(region, "weather_manual", False))
        and int(getattr(region, "weather_zone_id", 0) or 0) == int(zone_id)
        and isinstance(getattr(region, "weather", None), dict)
    ):
        target_session.weather = dict(region.weather)
        return dict(target_session.weather) != previous_weather

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


def is_player_world_active(session) -> bool:
    """Return whether normal world gameplay may consume this session.

    World-transition ownership is retired only after successful destination
    bootstrap.  A committed destination transform or region membership does
    not make normal gameplay active while that ownership remains live.
    """
    if session is None:
        return False

    transition_owner = str(
        getattr(session, "world_transition_owner", "") or ""
    )
    loading_generation = int(
        getattr(session, "world_transition_loading_generation", 0) or 0
    )
    if transition_owner or loading_generation > 0:
        return False

    login_state = getattr(session, "login_state", None)
    if login_state is None:
        return True
    login_state_value = getattr(login_state, "value", login_state)
    return str(login_state_value or "") == "IN_WORLD"


def _is_session_in_world(session) -> bool:
    login_state = getattr(session, "login_state", None)
    login_state_value = getattr(login_state, "value", login_state)
    return (
        session is not None
        and callable(getattr(session, "send_response", None))
        and str(login_state_value or "") == "IN_WORLD"
        and _session_guid(session) > 0
        and is_player_world_active(session)
    )


def iter_in_world_sessions(*, state=None, map_id: int | None = None, region=None) -> list:
    sessions = iter_active_sessions(state)
    if region is not None:
        sessions = [session for session in sessions if getattr(session, "region", None) is region]
    if map_id is not None:
        sessions = [
            session
            for session in sessions
            if int(resolve_player_runtime(session).map_id) == int(map_id)
        ]
    return [session for session in sessions if _is_session_in_world(session)]


def iter_region_sessions(target_session=None, *, region=None, map_id: int | None = None) -> list:
    target_region = region
    if target_region is None and target_session is not None:
        target_region = getattr(target_session, "region", None)
    if target_region is None and map_id is not None:
        target_region = region_manager.get_region(int(map_id))
    if target_region is None:
        return []
    return [
        session
        for session in list(getattr(target_region, "players", ()) or ())
        if is_player_world_active(session)
    ]


def _session_guid(session) -> int:
    return int(resolve_player_runtime(session).character_guid)


def _normalized_explored_zones(raw: str | None, *, size: int = _PLAYER_EXPLORED_ZONES_SIZE) -> list[int]:
    values = [
        max(0, min(0xFFFFFFFF, int(token)))
        for token in re.findall(r"-?\d+", str(raw or ""))
    ]
    if len(values) < int(size):
        values.extend([0] * (int(size) - len(values)))
    return values[: int(size)]


def effective_explored_zones_for_client(session) -> list[int]:
    if bool(getattr(session, "map_cheat_enabled", False)):
        return [0xFFFFFFFF] * _PLAYER_EXPLORED_ZONES_SIZE

    return _normalized_explored_zones(getattr(session, "explored_zones_raw", ""))


def build_explored_zones_update_response(
    session,
    player: Player | None = None,
) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.bootstrap.playerobjects import build_multi_u32_update_object_payload

    if player is None:
        player = resolve_player_runtime(session)
    guid = int(player.character_guid)
    if guid <= 0:
        return None

    values = effective_explored_zones_for_client(session)
    return (
        "SMSG_UPDATE_OBJECT",
        build_multi_u32_update_object_payload(
            map_id=int(player.map_id),
            guid=guid,
            field_updates=[
                (_PLAYER_FIELD_EXPLORED_ZONES + offset, int(value))
                for offset, value in enumerate(values)
            ],
        ),
    )


def _visible_guid_set(session) -> set[int]:
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    return get_player_visibility_service().known_guids(session)


def _clear_session_visibility(session) -> None:
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    get_player_visibility_service().clear_player_links(
        session,
        iter_in_world_sessions(),
    )


def _sessions_share_phase(left, right) -> bool:
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    return get_player_visibility_service().sessions_share_phase(left, right)


def _sessions_in_visibility_range(left, right) -> bool:
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    return get_player_visibility_service().should_observe(left, right)


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
    target_session.time_offset = int(getattr(target_session.global_state, "time_offset", 0) or 0)
    target_session.time_speed = float(getattr(target_session.global_state, "time_speed", 0.01666667) or 0.01666667)
    target_session.server_time = int(time.time())
    target_session.game_time = pack_wow_game_time(
        int(target_session.server_time) + int(getattr(target_session, "time_offset", 0) or 0)
    )
    refresh_region_weather(target_session)


def dispatch_responses_to_sessions(targets, responses) -> None:
    normalized_targets = list(targets or [])
    normalized_responses = responses if isinstance(responses, list) else list(responses or ())
    if not normalized_targets or not normalized_responses:
        return
    for target in normalized_targets:
        sender = getattr(target, "send_response", None)
        if callable(sender):
            packet_count = len(normalized_responses)
            target._packet_queue_depth = int(getattr(target, "_packet_queue_depth", 0) or 0) + packet_count
            try:
                from server.modules.handlers.world.player_diagnostics import log_player_event

                log_player_event(
                    "packet_queued",
                    target,
                    packets=[str(item[0]) for item in normalized_responses],
                    packet_count=packet_count,
                )
                sender(normalized_responses)
                log_player_event(
                    "packet_sent",
                    target,
                    packets=[str(item[0]) for item in normalized_responses],
                    packet_count=packet_count,
                )
            except Exception as exc:
                Logger.warning(
                    f"[MULTI] send failed player={int(getattr(target, 'char_guid', 0) or 0)} "
                    f"guid=0x{int(getattr(target, 'world_guid', 0) or 0):016X} err={exc}"
                )
                try:
                    log_player_event(
                        "packet_send_failed",
                        target,
                        packets=[str(item[0]) for item in normalized_responses],
                        packet_count=packet_count,
                        error=str(exc),
                    )
                except Exception:
                    pass

                # A failed socket publication is a disconnect lifecycle event.
                # Removing only the membership entries here used to leave the
                # player's bilateral known-object links behind and bypassed all
                # other canonical logout cleanup.
                from server.modules.handlers.world.runtime.lifecycle import (
                    handle_disconnect_session,
                )

                handle_disconnect_session(target)
            finally:
                target._packet_queue_depth = max(
                    0,
                    int(getattr(target, "_packet_queue_depth", 0) or 0) - packet_count,
                )


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

    if not is_player_world_active(target_session):
        return

    zone_id = _resolve_weather_zone_id(target_session)
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
    region.weather_zone_id = int(zone_id)
    if state is not None and isinstance(getattr(state, "manual_region_weather", None), dict):
        state.manual_region_weather[int(zone_id)] = dict(weather_state)

    if payload is not None:
        for player in iter_region_sessions(region=region):
            if int(_resolve_weather_zone_id(player)) == int(zone_id):
                player.weather = dict(weather_state)
                if player is not target_session:
                    dispatch_responses_to_sessions([player], [("SMSG_WEATHER", payload)])

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

    player = resolve_player_runtime(source_session)
    if int(player.character_guid) <= 0:
        return None

    ctx = WorldLoginContext.from_session(source_session)
    ctx.player_runtime = player
    ctx.exact_0002_remote_player = True
    ctx.exact_0002_map_id = int(player.map_id)
    ctx.exact_0002_low_guid = int(player.character_guid)
    Logger.info("[CREATE PATH] remote=server-built")
    payload = build_login_packet("SMSG_UPDATE_OBJECT_1773613176_0002", ctx)
    if payload is None:
        return None
    return ("SMSG_UPDATE_OBJECT", payload)


def build_self_player_appearance_responses(source_session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.inventory_sync import build_self_visible_item_update_responses
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    player = resolve_player_runtime(source_session)
    if int(player.character_guid) <= 0:
        return []

    responses: list[tuple[str, bytes]] = []
    ctx = WorldLoginContext.from_session(source_session)
    ctx.player_runtime = player
    ctx.exact_0002_map_id = int(player.map_id)
    ctx.exact_0002_low_guid = int(player.character_guid)
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

    player = resolve_player_runtime(source_session)
    guid = int(player.character_guid)
    if guid <= 0:
        return []

    responses: list[tuple[str, bytes]] = []

    ctx = WorldLoginContext.from_session(source_session)
    ctx.player_runtime = player
    ctx.exact_0006_map_id = int(player.map_id)
    ctx.exact_0006_guid = guid
    payload_0006 = build_login_packet("SMSG_UPDATE_OBJECT_1773613185_0006", ctx)
    if payload_0006 is not None:
        responses.append(("SMSG_UPDATE_OBJECT", payload_0006))
    responses.extend(build_self_visible_item_update_responses(source_session))
    responses.extend(build_same_map_teleport_world_object_resync_responses(source_session))

    source_session.player_object_sent = True
    return responses


def build_same_map_teleport_world_object_resync_responses(source_session) -> list[tuple[str, bytes]]:
    if not (
        bool(getattr(source_session, "gameobjects_visible", False))
        or bool(getattr(source_session, "npc_auto_stream", False))
    ):
        return []

    source_session.last_gameobject_stream_at = 0.0
    source_session.last_npc_stream_at = 0.0

    try:
        from server.modules.handlers.world.opcodes import movement as movement_handlers
    except Exception as exc:
        Logger.warning("[Teleport] same-map object stream unavailable err=%s", exc)
        return []

    streamer = getattr(movement_handlers, "_maybe_stream_world_objects", None)
    if not callable(streamer):
        return []

    responses = list(streamer(source_session) or [])
    if responses:
        Logger.info(
            "[Teleport] same-map object stream responses=%s player=%s map=%s",
            len(responses),
            int(getattr(source_session, "char_guid", 0) or 0),
            int(getattr(source_session, "map_id", 0) or 0),
        )
    return responses


def _build_player_name_response(source_session) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.opcodes.entities import build_query_player_name_response

    char_guid = int(resolve_player_runtime(source_session).character_guid)
    if char_guid <= 0:
        return None

    return ("SMSG_QUERY_PLAYER_NAME_RESPONSE", build_query_player_name_response(source_session, char_guid))


def _build_player_value_update_responses(source_session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    player = resolve_player_runtime(source_session)
    guid = int(player.character_guid)
    if guid <= 0:
        return []

    ctx = WorldLoginContext.from_session(source_session)
    ctx.player_runtime = player
    ctx.exact_0004_map_id = int(player.map_id)
    ctx.exact_0004_guid = guid
    ctx.exact_0006_map_id = int(player.map_id)
    ctx.exact_0006_guid = guid

    responses: list[tuple[str, bytes]] = []
    payload_0004 = build_login_packet("SMSG_UPDATE_OBJECT_1773613176_0004", ctx)
    if payload_0004 is not None:
        responses.append(("SMSG_UPDATE_OBJECT", payload_0004))
    payload_0006 = build_login_packet("SMSG_UPDATE_OBJECT_1773613185_0006", ctx)
    if payload_0006 is not None:
        responses.append(("SMSG_UPDATE_OBJECT", payload_0006))
    explored_response = build_explored_zones_update_response(
        source_session,
        player=player,
    )
    if explored_response is not None:
        responses.append(explored_response)
    return responses


def _build_player_move_response(source_session) -> tuple[str, bytes] | None:
    cached = getattr(source_session, "_cached_player_move_response", None)
    if cached is not None:
        return cached

    from server.modules.handlers.world.opcodes.movement import build_smsg_player_move_payload

    payload = build_smsg_player_move_payload(
        source_session,
        player=resolve_player_runtime(source_session),
    )
    if not payload:
        return None
    return ("SMSG_PLAYER_MOVE", payload)


def _player_movement_debug_enabled() -> bool:
    try:
        from server.modules.handlers.world.feature_config import player_movement_debug_enabled

        return bool(player_movement_debug_enabled())
    except Exception:
        return False


def _movement_debug_log(message: str, *args) -> None:
    if not _player_movement_debug_enabled():
        return
    Logger.info(message, *args)


def _build_player_remove_update_response(
    source_session,
    *,
    map_id: int | None = None,
) -> tuple[str, bytes] | None:
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    player = resolve_player_runtime(source_session)
    low_guid = int(player.character_guid)
    if low_guid <= 0:
        return None

    ctx = WorldLoginContext.from_session(source_session)
    ctx.exact_0007_map_id = (
        int(player.map_id)
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


def _publish_player_create(observer_session, source_session) -> bool:
    source_player = resolve_player_runtime(source_session)
    source_guid = int(source_player.character_guid)
    if source_guid <= 0:
        return False

    from server.modules.handlers.world.inventory_sync import build_self_visible_item_update_responses

    responses = _build_player_create_responses(source_session)
    if responses:
        responses.extend(build_self_visible_item_update_responses(source_session))
    if not responses:
        return False

    observer_guid = _session_guid(observer_session)
    visible_snapshot = build_player_visible_snapshot(
        source_session,
        player=source_player,
    )
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
    return True


def _publish_player_remove(observer_session, source_session) -> bool:
    source_guid = int(resolve_player_runtime(source_session).character_guid)
    if source_guid <= 0:
        return False

    remove_response = _build_player_remove_update_response(source_session)
    if remove_response is None:
        return False

    dispatch_responses_to_sessions([observer_session], [remove_response])
    return True


def _send_player_create(observer_session, source_session) -> bool:
    """Compatibility entry point; known-link ownership lives in the service."""
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    return get_player_visibility_service().ensure_observer(
        observer_session,
        source_session,
        create=_publish_player_create,
    )


def _send_player_remove(observer_session, source_session) -> bool:
    """Compatibility entry point; known-link ownership lives in the service."""
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    return get_player_visibility_service().remove_observer(
        observer_session,
        source_session,
        remove=_publish_player_remove,
    )


def force_player_visibility_destroy(
    target_session,
    *,
    reason: str = "manual",
    map_id: int | None = None,
) -> None:
    """Destroy one player from every observer cache before moving/recreating it."""
    target_player = resolve_player_runtime(target_session)
    target_guid = int(target_player.character_guid)
    if target_guid <= 0:
        return

    remove_response = _build_player_remove_update_response(target_session, map_id=map_id)
    source_map_id = (
        int(target_player.map_id)
        if map_id is None
        else int(map_id)
    )

    def publish_remove(observer, _source) -> bool:
        if remove_response is None:
            return False
        Logger.info(
            "[DESTROY SEND] observer=%s source=%s map=%s reason=%s",
            _session_guid(observer),
            int(target_guid),
            int(source_map_id),
            str(reason),
        )
        dispatch_responses_to_sessions([observer], [remove_response])
        return True

    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    removed_for_observers, cleared_for_target = (
        get_player_visibility_service().clear_player_links(
            target_session,
            iter_in_world_sessions(),
            remove=publish_remove,
        )
    )
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

    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    result = get_player_visibility_service().reconcile_pair(
        source_session,
        other_session,
        # Keep the compatibility publication entry points here for callers
        # that still invoke this legacy reconciliation wrapper. The canonical
        # MovementPublisher uses the pure packet publishers directly.
        create=_send_player_create,
        remove=_send_player_remove,
        should_observe=_sessions_in_visibility_range,
    )
    if result.other_observes_source:
        updated_for_other = False
        if not result.created_for_other:
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
        return result.created_for_source, result.created_for_other, updated_for_other

    return result.removed_from_source, result.removed_from_other, False


def sync_player_visibility(target_session) -> None:
    if not _is_session_in_world(target_session):
        return

    target_player = resolve_player_runtime(target_session)
    same_map_sessions = iter_in_world_sessions(map_id=int(target_player.map_id))
    other_sessions = [session for session in same_map_sessions if session is not target_session]
    if not other_sessions:
        return

    created_links = 0
    removed_links = 0
    for other in other_sessions:
        had_other_before = _session_guid(other) in _visible_guid_set(target_session)
        had_target_before = _session_guid(target_session) in _visible_guid_set(other)
        changed_for_target, changed_for_other, _ = (
            _reconcile_session_visibility_pair(target_session, other)
        )
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
        f"[MULTI] synced visibility player={int(target_player.character_guid)} "
        f"map={int(target_player.map_id)} peers={len(other_sessions)} "
        f"created={created_links} removed={removed_links} "
        f"visible={len(_visible_guid_set(target_session))}"
    )


def force_bilateral_visibility_resync(target_session, *, reason: str = "manual") -> None:
    """Rebuild both visibility directions for one player using normal paths."""
    if not _is_session_in_world(target_session):
        return

    target_player = resolve_player_runtime(target_session)
    target_guid = int(target_player.character_guid)
    if target_guid <= 0:
        return

    same_map_sessions = iter_in_world_sessions(
        map_id=int(target_player.map_id)
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
        int(target_player.map_id),
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

    source_player = resolve_player_runtime(source_session)
    peers = [
        session
        for session in iter_in_world_sessions(map_id=int(source_player.map_id))
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
        f"[MULTI] appearance resync player={int(source_player.character_guid)} "
        f"map={int(source_player.map_id)} peers={len(peers)}"
    )


def broadcast_visible_equipment_update(source_session) -> None:
    """Send current visible equipment fields to peers already seeing source."""
    from server.modules.handlers.world.inventory_sync import build_self_visible_item_update_responses

    if not _is_session_in_world(source_session):
        return

    source_player = resolve_player_runtime(source_session)
    source_guid = int(source_player.character_guid)
    if source_guid <= 0:
        return

    responses = build_self_visible_item_update_responses(source_session)
    if not responses:
        return

    peers = [
        session
        for session in iter_in_world_sessions(
            map_id=int(source_player.map_id)
        )
        if session is not source_session and source_guid in _visible_guid_set(session)
    ]
    if not peers:
        return

    dispatch_responses_to_sessions(peers, responses)
    Logger.info(
        "[MULTI] visible equipment update player=%s map=%s peers=%s",
        int(source_guid),
        int(source_player.map_id),
        len(peers),
    )


def broadcast_player_state_update(source_session, *, force: bool = False) -> None:
    from server.modules.handlers.world.movement_publisher import (
        get_movement_publisher,
    )

    get_movement_publisher().publish(source_session, force=force)


def broadcast_player_remove(source_session) -> None:
    if bool(getattr(source_session, "_multiplayer_removed", False)):
        return

    source_player = resolve_player_runtime(source_session)
    peers = [
        session
        for session in iter_in_world_sessions(map_id=int(source_player.map_id))
        if session is not source_session
    ]
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    removed_from, _cleared = get_player_visibility_service().clear_player_links(
        source_session,
        peers,
        remove=_publish_player_remove,
    )
    if removed_from:
        Logger.info(
            f"[MULTI] removed player={int(source_player.character_guid)} "
            f"map={int(source_player.map_id)} peers={removed_from}"
        )
    source_session._multiplayer_removed = True
