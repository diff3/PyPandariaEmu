#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WorldHandlers.py

Thin-ish router for worldserver.

Responsibilities:
- Decode incoming CMSG packets
- Maintain session/login state transitions
- Build/encode a few pre-login responses (ENUM_CHARACTERS, PING/PONG, etc)
- Request packet bundles from handlers.worldLogin
- Provide bootstrap hooks: get_auth_challenge/reset_state/preload_cache

Notes:
- Returned responses MUST be "raw world packets" (packed header + payload),
  because worldserver will optionally encrypt headers and log via parse_server_packets().
"""

from __future__ import annotations

from http.client import responses
import json
import math
import random
import struct
import time
import random
from turtle import speed
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from server.modules.PacketContext import PacketContext
from server.modules.handlers.worldLogin.context import WorldLoginContext

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitWriter
from server.modules.handlers.worldLogin.packets import (
    build_ENUM_CHARACTERS_RESULT,
    build_login_packet,
    handle_CMSG_REQUEST_HOTFIX as _handle_CMSG_REQUEST_HOTFIX,
    _load_payload_packet,
)
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.session.world_session import LoginState
from server.session.runtime import session
from server.modules.handlers.characters.characters import (
    handle_CMSG_CHAR_DELETE,
    handle_CMSG_CHAR_CREATE,
    handle_CMSG_REORDER_CHARACTERS,
)

from shared.PathUtils import get_captures_root, get_dbc_root, get_json_root

_LOGIN_UPDATE_OBJECT_CAPTURE_DIR = get_captures_root(focus=True) / "debug"

from server.modules.dbc import read_dbc
from server.modules.interpretation.utils import dsl_decode, to_safe_json
# from red.utils.OpcodeLoader import load_world_opcodes
from shared.Logger import Logger
from server.modules.ServerOutput import log_decoded_packet
from server.modules.guid import GuidHelper, HighGuid

from server.modules.handlers.worldLogin import (
    build_char_screen_packets,
    build_player_login_packets,
    build_pre_update_object_packets,
    build_post_update_object_packets,
    build_world_bootstrap_packets,
)

from server.modules.opcodes.WorldOpcodes import (
    WORLD_CLIENT_OPCODES,
    WORLD_SERVER_OPCODES,
    lookup as world_lookup,  # om du använder den
)
from world.mount.mount_service import (
    ALL_MOUNT_SPELLS,
    get_mount_display_id,
    granted_mount_spells,
    is_mount_spell,
)
from world.chat.router import chat_router
from world.position.position_service import (
    POSITION_AUTOSAVE_DISTANCE_THRESHOLD,
    POSITION_DEBUG_ENABLED,
    Position,
    correct_z_if_invalid,
    format_position,
    normalize_position,
    position_from_row,
    position_from_session,
    position_moved_enough,
    save_player_position,
)
from world.state.global_state import global_state
from world.state.region_manager import region_manager
from world.teleport.teleport_service import (
    add_teleport as add_named_teleport,
    find_teleport,
    nearest_teleport,
    remove_teleport as remove_named_teleport,
    search_teleports,
)
from world.handlers import movement as movement_handlers

# _LOGIN_UPDATE_OBJECT_CAPTURE_DIR = Path(__file__).resolve().parents[2] / "captures" / "focus" / "debug"
# _ACCOUNT_DATA_CAPTURE_DIR = Path(__file__).resolve().parents[2] / "captures" / "focus" / "debug"
# _ACCOUNT_DATA_CAPTURE_DIR = Path(__file__).resolve().parents[2] / "captures" / "focus" / "debug"

CAPTURE_DIR = get_captures_root()

_LOGIN_UPDATE_OBJECT_CAPTURE_DIR = get_captures_root(focus=True) / "debug"
_ACCOUNT_DATA_CAPTURE_DIR = get_captures_root(focus=True) / "debug"

_ACCOUNT_DATA_BINDINGS_CAPTURE = _ACCOUNT_DATA_CAPTURE_DIR / "SMSG_UPDATE_ACCOUNT_DATA_1773657568_0001.json"
_ACCOUNT_DATA_CAPTURE_GLOB = "SMSG_UPDATE_ACCOUNT_DATA_*.json"
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
_LANGUAGE_SPELL_IDS = (668, 669, 108127)
_DEFAULT_WALK_SPEED = 2.5
_DEFAULT_RUN_SPEED = 7.0
_DEFAULT_RUN_BACK_SPEED = 4.5
_DEFAULT_SWIM_SPEED = 4.7
_DEFAULT_SWIM_BACK_SPEED = 2.5
_DEFAULT_FLY_SPEED = 7.0
_DEFAULT_FLY_BACK_SPEED = 4.5
_DEFAULT_TURN_SPEED = 3.1415926
_DEFAULT_PITCH_SPEED = 3.1415926
_UNIT_FIELD_MOUNTDISPLAYID = 0x6A
_MOUNT_SPEED_MULTIPLIER = 2.0
_POSITION_SAVE_INTERVAL_SECONDS = 30.0
_RACE_LANGUAGE_SPELL_BY_RACE = {
    3: 672,       # Dwarf -> Dwarvish
    4: 671,       # Night Elf -> Darnassian
    5: 17737,     # Undead -> Gutterspeak
    6: 670,       # Tauren -> Taurahe
    7: 7340,      # Gnome -> Gnomish
    8: 7341,      # Troll -> Troll
    10: 813,      # Blood Elf -> Thalassian
    11: 29932,    # Draenei -> Draenei
    22: 69269,    # Goblin -> Goblin
    24: 108127,   # Pandaren Neutral
    25: 108130,   # Pandaren Alliance
    26: 108131,   # Pandaren Horde
}
RAW_REPLAY_SAY_CHAT_PROFILE = None
USE_SYSTEM_CHAT_FALLBACK = True
SEND_ACCOUNT_DATA_TO_CLIENT = True
RAW_REPLAY_ACCOUNT_DATA_PROFILE = None
TEXT_EMOTE_TO_ANIM_EMOTE: dict[int, int] = {
    5: 5,      # gasp
    34: 10,    # dance
    41: 0,     # talkq
    72: 25,    # point
    77: 14,    # rude
    84: 24,    # shy
    86: 12,    # sleep
    87: 13,    # sit
    93: 1,     # talk
    97: 0,     # thank
    100: 4,    # victory
    101: 3,    # wave
    102: 3,    # welcome
    141: 26,   # stand
}


def _resolve_weather_type(weather_key: str, density: float) -> int:
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


def _pack_wow_game_time(epoch_seconds: int) -> int:
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
TELEPORT_DESTINATIONS: dict[str, dict[str, float | int]] = {
    "dustquillravine": {"map_id": 530, "x": -758.534, "y": 4401.98, "z": 79.563, "orientation": 2.88658},
    "dustfirevalley": {"map_id": 0, "x": -6440.73, "y": -1987.77, "z": 244.718, "orientation": 0.464476},
    "duskwood": {"map_id": 0, "x": -10898.3, "y": -364.784, "z": 39.2681, "orientation": 3.04614},
    "duskwitherspire": {"map_id": 530, "x": 9317.38, "y": -7856.4, "z": 63.2953, "orientation": 5.35693},
    "duskwithergrounds": {"map_id": 530, "x": 9496.84, "y": -7862.65, "z": 16.1435, "orientation": 5.20221},
    "dunemaulcompound": {"map_id": 1, "x": -7068.01, "y": -3775.59, "z": 8.75309, "orientation": 2.4421},
    "dunmorogh": {"map_id": 0, "x": -5602.77, "y": -482.704, "z": 396.98, "orientation": 5.2341},
    "durnholdekeep": {"map_id": 0, "x": -489.74, "y": -148.42, "z": 58.12, "orientation": 2.128},
    "dustwallowmarsh": {"map_id": 1, "x": -3821.03, "y": -4525.71, "z": 10.52, "orientation": 1.102},
    "eastvale": {"map_id": 0, "x": -9445.11, "y": -2231.34, "z": 69.43, "orientation": 3.48},
    "eastplaguelands": {"map_id": 0, "x": 2280.12, "y": -5290.11, "z": 82.91, "orientation": 4.15},
    "evergrove": {"map_id": 530, "x": 2987.12, "y": 5536.77, "z": 146.8, "orientation": 1.32},
    "everlook": {"map_id": 1, "x": 6723.06, "y": -4659.92, "z": 720.70, "orientation": 4.72},
    "felwood": {"map_id": 1, "x": 5483.9, "y": -749.88, "z": 335.62, "orientation": 0.98},
    "feralas": {"map_id": 1, "x": -4841.19, "y": 1030.43, "z": 103.42, "orientation": 2.14},
    "fireplumeridge": {"map_id": 1, "x": -7500.44, "y": -1045.33, "z": -273.11, "orientation": 5.12},
    "gadgetzan": {"map_id": 1, "x": -7146.45, "y": -3745.91, "z": 8.75, "orientation": 0.45},
    "gilneas": {"map_id": 0, "x": -1460.1, "y": 1665.34, "z": 20.21, "orientation": 1.73},
    "gmisland": {"map_id": 1, "zone": 876, "x": 16226.2, "y": 16257.0, "z": 13.2022, "orientation": 1.65007},
    "gm_island": {"map_id": 1, "zone": 876, "x": 16226.2, "y": 16257.0, "z": 13.2022, "orientation": 1.65007},
    "gmisle": {"map_id": 1, "zone": 876, "x": 16226.2, "y": 16257.0, "z": 13.2022, "orientation": 1.65007},
    "goldshire": {"map_id": 0, "x": -9464.0, "y": 62.32, "z": 56.77, "orientation": 2.89},
    "grimtotempost": {"map_id": 1, "x": -4695.2, "y": -1725.11, "z": 86.33, "orientation": 0.45},
    "hammerfall": {"map_id": 0, "x": -918.22, "y": -3538.45, "z": 72.21, "orientation": 1.93},
    "hellfire": {"map_id": 530, "x": -247.51, "y": 946.12, "z": 84.38, "orientation": 3.12},
    "hellfirecitadel": {"map_id": 530, "x": -360.42, "y": 3073.11, "z": -15.0, "orientation": 1.77},
    "hillsbrad": {"map_id": 0, "x": -437.12, "y": -583.19, "z": 53.1, "orientation": 0.92},
    "honorshold": {"map_id": 530, "x": -676.98, "y": 2713.52, "z": 94.3, "orientation": 2.02},
    "hyjal": {"map_id": 1, "x": 4673.33, "y": -3845.92, "z": 944.21, "orientation": 3.14},
    "icecrown": {"map_id": 571, "x": 6153.77, "y": -2077.5, "z": 569.23, "orientation": 3.88},
    "ironforge": {"map_id": 0, "x": -4981.25, "y": -881.54, "z": 502.66, "orientation": 5.40},
    "isleofquel": {"map_id": 530, "x": 12806.5, "y": -6911.11, "z": 41.11, "orientation": 0.77},
    "karazhan": {"map_id": 0, "x": -11118.9, "y": -2010.33, "z": 47.08, "orientation": 0.64},
    "lakeshire": {"map_id": 0, "x": -9256.33, "y": -2211.66, "z": 64.89, "orientation": 2.13},
    "menethilharbor": {"map_id": 0, "x": -3749.2, "y": -734.41, "z": 10.92, "orientation": 3.71},
    "moonglade": {"map_id": 1, "x": 7996.11, "y": -2670.34, "z": 512.15, "orientation": 5.44},
    "mulgore": {"map_id": 1, "x": -2473.87, "y": -501.22, "z": -9.42, "orientation": 4.55},
    "nagrand": {"map_id": 530, "x": -1500.32, "y": 7090.11, "z": 36.44, "orientation": 1.77},
    "netherstorm": {"map_id": 530, "x": 3083.77, "y": 3681.32, "z": 142.11, "orientation": 5.11},
    "orgrimmar": {"map_id": 1, "x": 1502.78, "y": -4415.66, "z": 22.55, "orientation": 0.12},
    "ratchet": {"map_id": 1, "x": -956.66, "y": -3754.71, "z": 5.33, "orientation": 0.60},
    "redridge": {"map_id": 0, "x": -9205.11, "y": -2211.66, "z": 65.3, "orientation": 1.72},
    "senjin": {"map_id": 1, "x": -1004.11, "y": -4701.44, "z": 4.92, "orientation": 0.94},
    "shattrath": {"map_id": 530, "x": -1887.62, "y": 5359.09, "z": -12.43, "orientation": 2.13},
    "silvermooncity": {"map_id": 530, "x": 9485.25, "y": -7279.06, "z": 14.29, "orientation": 6.16},
    "stonetalon": {"map_id": 1, "x": 899.12, "y": 901.44, "z": 126.3, "orientation": 0.32},
    "stormwind": {"map_id": 0, "x": -8833.07, "y": 622.778, "z": 93.9317, "orientation": 0.6771},
    "stranglethorn": {"map_id": 0, "x": -11916.2, "y": -1215.72, "z": 92.28, "orientation": 4.31},
    "tanaris": {"map_id": 1, "x": -6941.23, "y": -3725.88, "z": 8.83, "orientation": 2.88},
    "teldrassil": {"map_id": 1, "x": 9945.12, "y": 2285.34, "z": 1341.11, "orientation": 1.55},
    "thunderbluff": {"map_id": 1, "x": -1277.37, "y": 124.80, "z": 131.29, "orientation": 5.22},
    "undercity": {"map_id": 0, "x": 1831.36, "y": 238.54, "z": 60.52, "orientation": 3.61},
    "westfall": {"map_id": 0, "x": -10684.2, "y": 1033.63, "z": 34.12, "orientation": 1.77},
}
LOGIN_UPDATE_SEQUENCE = (
    "SMSG_UPDATE_OBJECT_1773586161_0001.json",
    "SMSG_UPDATE_OBJECT_1773586161_0002.json",
    "SMSG_UPDATE_OBJECT_1773586161_0003.json",
    "SMSG_UPDATE_OBJECT_1773586165_0004.json",
)

_MAX_MOVEMENT_POSITION_DELTA = 200.0
_MAX_MOVEMENT_Z_DELTA = 100.0
CHAT_MSG_SAY = 1
CHAT_MSG_SYSTEM = 0
CHAT_MSG_YELL = 6
CHAT_MSG_WHISPER = 7
_CHAT_TYPE_BY_OPCODE = {
    "CMSG_MESSAGECHAT_SAY": CHAT_MSG_SAY,
    "CMSG_MESSAGECHAT_YELL": CHAT_MSG_YELL,
    "CMSG_MESSAGECHAT_WHISPER": CHAT_MSG_WHISPER,
}


def _notification_response(message: str) -> list[tuple[str, bytes]]:
    return [("SMSG_NOTIFICATION", _build_motd_notification_payload(message))]


def compute_weather(global_time, map_id, seed):
    states = ("sunny", "rainy", "snowy")
    index = hash((int(global_time) // 300, int(map_id), int(seed))) % len(states)
    return states[int(index)]


def _refresh_region_weather(target_session) -> None:
    state = getattr(target_session, "global_state", None)
    region = getattr(target_session, "region", None)
    if state is None or region is None:
        return
    region.weather = compute_weather(state.time, region.map_id, state.weather_seed)


def _advance_global_time(delta: int = 1) -> None:
    global_state.time = int(getattr(global_state, "time", 0) or 0) + int(delta)


def _detach_session_from_world_state(target_session) -> None:
    region = getattr(target_session, "region", None)
    if region is not None:
        region.players.discard(target_session)
    state = getattr(target_session, "global_state", None)
    if state is not None:
        state.chat_channels.setdefault("world", set()).discard(target_session)
    target_session.region = None


def _attach_session_to_world_state(target_session, *, map_id: int) -> None:
    _detach_session_from_world_state(target_session)
    target_session.global_state = global_state
    target_session.region = region_manager.get_region(int(map_id))
    target_session.region.players.add(target_session)
    target_session.global_state.chat_channels.setdefault("world", set()).add(target_session)
    _refresh_region_weather(target_session)


def _transition_session_region(target_session, *, new_map_id: int) -> None:
    _attach_session_to_world_state(target_session, map_id=int(new_map_id))


def _dispatch_responses_to_sessions(targets, responses) -> None:
    normalized_targets = list(targets or [])
    if not normalized_targets or not responses:
        return
    for target in normalized_targets:
        sender = getattr(target, "send_response", None)
        if callable(sender):
            sender(responses)


def teleport_player(player, map_id: int, x: float, y: float, z: float, orientation: float, *, destination_name: str) -> list[tuple[str, bytes]]:
    player.x = float(x)
    player.y = float(y)
    player.z = float(z)
    player.orientation = float(orientation)
    player.map_id = int(map_id)
    player.zone = _resolve_zone_from_position(int(map_id), float(x), float(y)) or int(getattr(player, "zone", 0) or 0)
    player.instance_id = 0
    player.teleport_pending = True
    player.teleport_destination = str(destination_name or "").strip() or None
    _capture_persist_position_from_session()
    _mark_position_dirty()

    return [
        (
            "SMSG_TRANSFER_PENDING",
            build_login_packet("SMSG_TRANSFER_PENDING", type("Ctx", (), {"map_id": int(map_id)})()),
        ),
        (
            "SMSG_NEW_WORLD",
            build_login_packet(
                "SMSG_NEW_WORLD",
                type(
                    "Ctx",
                    (),
                    {
                        "map_id": int(map_id),
                        "x": float(x),
                        "y": float(y),
                        "z": float(z),
                        "orientation": float(orientation),
                    },
                )(),
            ),
        ),
    ]
MOVEMENT_FOCUS_SEQUENCE = (
    ("SMSG_MOVE_SET_ACTIVE_MOVER", "SMSG_MOVE_SET_ACTIVE_MOVER_1773613176_0001.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613176_0002.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613176_0003.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613176_0004.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613181_0005.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613185_0006.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613205_0007.json"),
)
USE_RAW_ACTIVE_MOVER = False
USE_EXACT_UPDATE_OBJECT_REPLAY = True
USE_RAW_UPDATE_OBJECT_FALLBACK = False
USE_MINIMAL_UPDATE_OBJECT_REPLAY = True
USE_MINIMAL_PLAYER_VALUE_UPDATE_REPLAY = True
USE_AIO_SIMPLE_SAY_CHAT = False
UPDATE_OBJECT_1773613176_0002_MODE = "barncastle"
STATIC_UPDATE_OBJECT_CAPTURE_NAMES = {
    "SMSG_UPDATE_OBJECT_1773613176_0003.json",
    "SMSG_UPDATE_OBJECT_1773613181_0005.json",
    "SMSG_UPDATE_OBJECT_1773613205_0007.json",
}
MINIMAL_PLAYER_VALUE_UPDATE_CAPTURE_NAMES = {
    "SMSG_UPDATE_OBJECT_1773613176_0004.json",
    "SMSG_UPDATE_OBJECT_1773613185_0006.json",
}
EXACT_UPDATE_OBJECT_BUILDERS = {
    "SMSG_UPDATE_OBJECT_1773613176_0002.json": "SMSG_UPDATE_OBJECT_1773613176_0002",
    "SMSG_UPDATE_OBJECT_1773613176_0003.json": "SMSG_UPDATE_OBJECT_1773613176_0003",
    "SMSG_UPDATE_OBJECT_1773613176_0004.json": "SMSG_UPDATE_OBJECT_1773613176_0004",
    "SMSG_UPDATE_OBJECT_1773613181_0005.json": "SMSG_UPDATE_OBJECT_1773613181_0005",
    "SMSG_UPDATE_OBJECT_1773613185_0006.json": "SMSG_UPDATE_OBJECT_1773613185_0006",
    "SMSG_UPDATE_OBJECT_1773613205_0007.json": "SMSG_UPDATE_OBJECT_1773613205_0007",
}


def _assert_player_object_sent() -> None:
    assert getattr(session, "player_object_sent", False) is True, \
        "player object must be sent before UI bootstrap packets"


def _set_login_state(state: Optional[LoginState]) -> None:
    previous = getattr(session, "login_state", None)
    if previous == state:
        return
    session.login_state = state
    Logger.info(
        f"[WorldHandlers] login_state {previous.value if previous else 'None'} -> "
        f"{state.value if state else 'None'}"
    )


def _reset_login_flow_state(*, preserve_loading_screen_done: bool = False) -> None:
    _set_login_state(None)
    session.loading_screen_visible = False
    if not preserve_loading_screen_done:
        session.loading_screen_done = False
    session.chat_motd_sent = False
    session.post_loading_sent = False
    session.player_object_sent = False
    session.pending_account_data_requests = []
    session.account_data_times_sent = False
    session.account_data_captures_sent = False
    session.skyfire_login_stage = 0
    session.teleport_pending = False
    session.teleport_destination = None


def _is_skyfire_gmisland_session() -> bool:
    return (
        int(getattr(session, "char_guid", 0) or 0) == 2
        and int(getattr(session, "map_id", 0) or 0) == 1
        and int(getattr(session, "zone", 0) or 0) == 876
    )


def _build_world_login_context() -> WorldLoginContext:
    ctx = WorldLoginContext.from_session(session)
    ctx.exact_0002_mode = str(UPDATE_OBJECT_1773613176_0002_MODE or "barncastle")
    return ctx


def _ensure_language_spells_known() -> None:
    spells = [int(spell) for spell in (getattr(session, "known_spells", []) or [])]
    changed = False
    for spell_id in _LANGUAGE_SPELL_IDS:
        if int(spell_id) not in spells:
            spells.append(int(spell_id))
            changed = True
    race_spell = int(_RACE_LANGUAGE_SPELL_BY_RACE.get(int(getattr(session, "race", 0) or 0), 0) or 0)
    if race_spell and race_spell not in spells:
        spells.append(race_spell)
        changed = True
    if changed:
        session.known_spells = spells
        Logger.info(
            f"[Language] ensured known spells: "
            f"{', '.join(str(spell) for spell in spells if spell in set(_LANGUAGE_SPELL_IDS) | ({race_spell} if race_spell else set()))}"
        )


def _ensure_mount_spells_known() -> None:
    mount_related_spells = granted_mount_spells()
    if not mount_related_spells:
        return

    spells = [int(spell) for spell in (getattr(session, "known_spells", []) or [])]
    spell_set = set(spells)
    changed = False

    for spell_id in mount_related_spells:
        spell_id = int(spell_id)
        if spell_id not in spell_set:
            spells.append(spell_id)
            spell_set.add(spell_id)
            changed = True

    if changed:
        session.known_spells = spells
        Logger.info("[Mount] ensured %s mount-related spells in known-spells", len(mount_related_spells))


def _restore_default_movement_speeds(player) -> None:
    player.walk_speed = _DEFAULT_WALK_SPEED
    player.run_speed = _DEFAULT_RUN_SPEED
    player.run_back_speed = _DEFAULT_RUN_BACK_SPEED
    player.swim_speed = _DEFAULT_SWIM_SPEED
    player.swim_back_speed = _DEFAULT_SWIM_BACK_SPEED
    player.fly_speed = _DEFAULT_FLY_SPEED
    player.fly_back_speed = _DEFAULT_FLY_BACK_SPEED
    player.turn_speed = _DEFAULT_TURN_SPEED
    player.pitch_speed = _DEFAULT_PITCH_SPEED


def _apply_mount_movement_speeds(player) -> None:
    player.walk_speed = _DEFAULT_WALK_SPEED
    player.run_speed = _DEFAULT_RUN_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.run_back_speed = _DEFAULT_RUN_BACK_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.swim_speed = _DEFAULT_SWIM_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.swim_back_speed = _DEFAULT_SWIM_BACK_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.fly_speed = _DEFAULT_FLY_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.fly_back_speed = _DEFAULT_FLY_BACK_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.turn_speed = _DEFAULT_TURN_SPEED
    player.pitch_speed = _DEFAULT_PITCH_SPEED


def _iter_decoded_ints(value: Any):
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_decoded_ints(item)
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_decoded_ints(item)
        return
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        yield int(value)


def _extract_mount_spell_id_from_decoded(decoded: dict[str, Any] | None) -> Optional[int]:
    if not decoded:
        return None

    direct_keys = (
        "spell_id",
        "spell",
        "cast_spell_id",
        "cast_spell",
        "aura_spell_id",
        "aura",
    )
    for key in direct_keys:
        value = decoded.get(key)
        if isinstance(value, int) and is_mount_spell(value):
            return int(value)

    for value in _iter_decoded_ints(decoded):
        if is_mount_spell(value):
            return int(value)
    return None


def _extract_mount_spell_id_from_payload(payload: bytes) -> Optional[int]:
    if not payload or len(payload) < 4 or not ALL_MOUNT_SPELLS:
        return None

    unique_matches: list[int] = []
    seen: set[int] = set()
    scan_limit = min(len(payload) - 3, 64)

    for offset in range(0, scan_limit, 4):
        value = struct.unpack_from("<I", payload, offset)[0]
        if value in ALL_MOUNT_SPELLS and value not in seen:
            unique_matches.append(value)
            seen.add(value)

    if not unique_matches:
        for offset in range(0, scan_limit):
            value = struct.unpack_from("<I", payload, offset)[0]
            if value in ALL_MOUNT_SPELLS and value not in seen:
                unique_matches.append(value)
                seen.add(value)

    if not unique_matches:
        return None
    return int(unique_matches[0])


def _extract_mount_spell_id(ctx: PacketContext) -> Optional[int]:
    spell_id = _extract_mount_spell_id_from_decoded(ctx.decoded)
    if spell_id:
        return spell_id

    spell_id = _extract_mount_spell_id_from_payload(ctx.payload)
    if spell_id:
        return spell_id

    current_mount = int(getattr(ctx.session, "mount_spell", 0) or 0)
    if current_mount and is_mount_spell(current_mount):
        return current_mount
    return None


def _build_live_player_update_response() -> Optional[tuple[str, bytes]]:
    payload = build_login_packet("SMSG_UPDATE_OBJECT_1773613176_0002", _build_world_login_context())
    if payload is None:
        Logger.warning("[Mount] missing live UPDATE_OBJECT builder")
        return None
    return _make_update_object_response(payload)


def _resolve_player_world_guid(player) -> int:
    world_guid = int(getattr(player, "world_guid", 0) or 0)
    if world_guid > 0:
        return world_guid

    player_guid = int(getattr(player, "player_guid", 0) or 0)
    if player_guid > 0xFFFFFFFF:
        return player_guid

    realm_id = int(getattr(player, "realm_id", 0) or 0)
    char_guid = int(getattr(player, "char_guid", 0) or 0)
    if char_guid > 0:
        return int(
            GuidHelper.make(
                high=HighGuid.PLAYER,
                realm=realm_id,
                low=char_guid,
            )
        )

    return player_guid


def _build_mount_display_update_response(player, display_id: int) -> Optional[tuple[str, bytes]]:
    player_guid = _resolve_player_world_guid(player)
    map_id = int(getattr(player, "map_id", 0) or 0)
    if player_guid <= 0 or map_id < 0:
        Logger.warning(
            "[Mount] skipping mount display update guid=%s map_id=%s display_id=%s",
            int(player_guid),
            int(map_id),
            int(display_id),
        )
        return None
    payload = _build_single_u32_update_object_payload(
        map_id=map_id,
        guid=player_guid,
        field_index=_UNIT_FIELD_MOUNTDISPLAYID,
        value=int(display_id) & 0xFFFFFFFF,
    )
    return _make_update_object_response(payload)


def send_mount_update(player, spell_id: int) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    display_id = get_mount_display_id(spell_id)
    if display_id > 0:
        display_packet = _build_mount_display_update_response(player, display_id)
        if display_packet is not None:
            responses.append(display_packet)
            Logger.info("[Mount] mount display spell=%s display_id=%s", int(spell_id), int(display_id))
    responses.extend(_notification_response(f"Mounted spell={int(spell_id)} speed={float(player.run_speed):.2f}"))
    return responses


def send_dismount_update(player) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    display_packet = _build_mount_display_update_response(player, 0)
    if display_packet is not None:
        responses.append(display_packet)
    responses.extend(_notification_response(f"Dismounted speed={float(player.run_speed):.2f}"))
    return responses


def handle_mount(player, spell_id: int) -> list[tuple[str, bytes]]:
    player.is_mounted = True
    player.mount_spell = int(spell_id)
    _apply_mount_movement_speeds(player)
    Logger.info("[Mount] mounted spell=%s", int(spell_id))
    return send_mount_update(player, int(spell_id))


def dismount(player) -> list[tuple[str, bytes]]:
    player.is_mounted = False
    player.mount_spell = None
    _restore_default_movement_speeds(player)
    Logger.info("[Mount] dismounted")
    return send_dismount_update(player)


def unpack_guid(mask: int, data: bytes) -> int:
    guid_bytes = [0] * 8
    offset = 0

    for bit in range(8):
        if mask & (1 << bit):
            if offset >= len(data):
                raise ValueError("packed guid data shorter than mask indicates")
            guid_bytes[bit] = data[offset]
            offset += 1

    return int.from_bytes(bytes(guid_bytes), "little", signed=False)


def _extract_first_update_object_guid_info(payload: bytes) -> Optional[tuple[int, int, bytes]]:
    if len(payload) < 8:
        return None

    update_count = struct.unpack_from("<I", payload, 2)[0]
    if update_count <= 0:
        return None

    offset = 6
    update_type = payload[offset]
    offset += 1

    if update_type == 3:
        if offset + 4 > len(payload):
            return None
        out_of_range_count = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        if out_of_range_count <= 0:
            return None

    if offset >= len(payload):
        return None

    mask = payload[offset]
    offset += 1
    packed_len = int(mask).bit_count()
    if offset + packed_len > len(payload):
        return None

    packed_guid_bytes = payload[offset : offset + packed_len]
    return unpack_guid(mask, packed_guid_bytes), int(mask), packed_guid_bytes


def _extract_first_update_object_guid(payload: bytes) -> Optional[int]:
    guid_info = _extract_first_update_object_guid_info(payload)
    if guid_info is None:
        return None
    guid, _mask, _packed_guid_bytes = guid_info
    return guid


def _debug_log_replayed_update_object_guid(payload: bytes, update_index: int | None = None) -> None:
    session_player_guid = int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )
    if session_player_guid <= 0:
        return

    try:
        guid_info = _extract_first_update_object_guid_info(payload)
    except Exception as exc:
        Logger.warning(f"[GUID DEBUG] failed to decode packed guid: {exc}")
        return

    if guid_info is None:
        Logger.warning("[GUID DEBUG] no packed guid found in SMSG_UPDATE_OBJECT")
        return

    packet_guid, guid_mask, packed_guid_bytes = guid_info
    packed_guid_bytes_display = "[" + " ".join(f"{byte:02X}" for byte in packed_guid_bytes) + "]"
    Logger.info(
        "[GUID DEBUG]\n"
        f"update_index = {update_index if update_index is not None else -1}\n"
        f"mask = 0x{guid_mask:02X}\n"
        f"raw_sniffed_guid_bytes = {packed_guid_bytes_display}\n"
        f"reconstructed = 0x{packet_guid:016X}\n"
        f"session_player_guid = 0x{session_player_guid:016X}"
    )
    if packet_guid != session_player_guid:
        Logger.warning("[GUID MISMATCH] UPDATE_OBJECT GUID does not match session player GUID.")


def _debug_verify_update_object_guid(payload: bytes) -> None:
    expected = int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )
    if expected <= 0:
        return

    try:
        guid_info = _extract_first_update_object_guid_info(payload)
    except Exception as exc:
        Logger.warning(f"[GUID CHECK] failed to decode packed guid: {exc}")
        return

    if guid_info is None:
        Logger.warning("[GUID CHECK] no packed guid found in SMSG_UPDATE_OBJECT")
        return
    received, _guid_mask, _packed_guid_bytes = guid_info

    Logger.info(
        "[GUID CHECK]\n"
        f"expected: 0x{expected:X}\n"
        f"received: 0x{received:X}"
    )
    if received != expected:
        Logger.warning("WARNING: Player UPDATE_OBJECT GUID mismatch")


def _extract_movement_from_decoded(decoded: dict[str, Any]) -> Optional[tuple[float, float, float, float]]:
    return movement_handlers._extract_movement_from_decoded(session, decoded)


def _score_movement_candidate(
    x: float,
    y: float,
    z: float,
    orientation: float,
) -> float:
    return movement_handlers._score_movement_candidate(session, x, y, z, orientation)


def _normalize_orientation(value: float | None) -> float | None:
    return movement_handlers._normalize_orientation(value)


def _extract_movement_from_payload(payload: bytes) -> Optional[tuple[float, float, float, float]]:
    return movement_handlers._extract_movement_from_payload(session, payload)


def _accept_movement_update(
    opcode_name: str,
    x: float,
    y: float,
    z: float,
    orientation: float,
) -> bool:
    return movement_handlers._accept_movement_update(session, opcode_name, x, y, z, orientation)


def _find_player_living_movement_block(payload: bytes) -> Optional[dict[str, float]]:
    block_size = 13 * 4
    if len(payload) < block_size:
        return None

    for offset in range(0, len(payload) - block_size + 1):
        try:
            (
                fly_speed,
                turn_speed,
                swim_speed,
                pitch_speed,
                x,
                orientation,
                walk_speed,
                y,
                fly_back_speed,
                run_back_speed,
                run_speed,
                swim_back_speed,
                z,
            ) = struct.unpack_from("<13f", payload, offset)
        except struct.error:
            continue

        values = (
            fly_speed,
            turn_speed,
            swim_speed,
            pitch_speed,
            x,
            orientation,
            walk_speed,
            y,
            fly_back_speed,
            run_back_speed,
            run_speed,
            swim_back_speed,
            z,
        )
        if not all(math.isfinite(value) for value in values):
            continue
        if not (6.5 <= run_speed <= 7.5):
            continue
        if not (3.0 <= turn_speed <= 3.3):
            continue
        if not (3.0 <= pitch_speed <= 3.3):
            continue
        if not (2.0 <= walk_speed <= 3.0):
            continue
        if not (4.0 <= run_back_speed <= 5.0):
            continue
        if not (4.0 <= fly_back_speed <= 5.0):
            continue
        if not (-math.pi * 4 <= orientation <= math.pi * 4):
            continue
        if abs(x) > 100000 or abs(y) > 100000 or abs(z) > 100000:
            continue

        return {
            "offset": float(offset),
            "fly_speed": float(fly_speed),
            "turn_speed": float(turn_speed),
            "swim_speed": float(swim_speed),
            "pitch_speed": float(pitch_speed),
            "x": float(x),
            "orientation": float(orientation),
            "walk_speed": float(walk_speed),
            "y": float(y),
            "fly_back_speed": float(fly_back_speed),
            "run_back_speed": float(run_back_speed),
            "run_speed": float(run_speed),
            "swim_back_speed": float(swim_back_speed),
            "z": float(z),
        }

    return None


def _debug_log_player_movement_flags(payload: bytes, *, update_index: int | None = None) -> None:
    if update_index != 1:
        return

    movement = _find_player_living_movement_block(payload)
    if movement is None:
        Logger.warning("[PLAYER MOVEMENT FLAGS] no living player movement block found in UPDATE_OBJECT")
        return

    Logger.info(
        f"[PLAYER MOVEMENT FLAGS] run={movement['run_speed']:.6f} "
        f"turn={movement['turn_speed']:.6f} pitch={movement['pitch_speed']:.6f}"
    )
    Logger.info(
        f"[PLAYER MOVEMENT CREATE] is_living=1 orientation={movement['orientation']:.6f} "
        f"walk={movement['walk_speed']:.6f} swim={movement['swim_speed']:.6f} "
        f"offset={int(movement['offset'])}"
    )


def parse_movement_info(
    opcode_name: str,
    payload: bytes,
    decoded: dict[str, Any] | None = None,
) -> Optional[tuple[float, float, float, float]]:
    return movement_handlers.parse_movement_info(session, opcode_name, payload, decoded)


def _make_update_object_response(payload: bytes, *, update_index: int | None = None) -> tuple[str, bytes]:
    _debug_log_replayed_update_object_guid(payload, update_index=update_index)
    _debug_verify_update_object_guid(payload)
    _debug_log_player_movement_flags(payload, update_index=update_index)
    return "SMSG_UPDATE_OBJECT", payload


def load_sniff_payload(filepath: str | Path) -> bytes:
    path = Path(filepath)
    data = json.loads(path.read_text(encoding="utf-8"))

    payload_hex = data.get("hex_compact") or data.get("hex_spaced")
    if payload_hex:
        return bytes.fromhex(payload_hex.replace(" ", ""))

    raw_hex = data.get("raw_data_hex")
    header_hex = data.get("raw_header_hex")
    if not raw_hex or not header_hex:
        raise RuntimeError(f"Missing payload data in {path}")
    raw_bytes = bytes.fromhex(raw_hex.replace(" ", ""))
    header_len = len(bytes.fromhex(header_hex.replace(" ", "")))
    return raw_bytes[header_len:]


def send_raw_packet(
    _session: WorldSession,
    opcode_name: str,
    filepath: str | Path,
    *,
    update_index: int | None = None,
) -> tuple[str, bytes]:
    path = Path(filepath)
    payload = load_sniff_payload(path)
    Logger.info(
        f"[WorldHandlers] raw replay {opcode_name} source={path.name} payload_len={len(payload)}"
    )
    if opcode_name == "SMSG_UPDATE_OBJECT":
        return _make_update_object_response(payload, update_index=update_index)
    return opcode_name, payload


def send_raw_sniff_packet(
    _session: WorldSession,
    opcode_name: str,
    filepath: str | Path,
    *,
    update_index: int | None = None,
) -> tuple[str, bytes]:
    path = Path(filepath)
    payload = load_sniff_payload(path)
    Logger.info(
        f"[RAW REPLAY] {opcode_name} payload={len(payload)} bytes source={path.name}"
    )
    if opcode_name == "SMSG_UPDATE_OBJECT":
        return _make_update_object_response(payload, update_index=update_index)
    return opcode_name, payload


def _build_raw_replay_messagechat_packet(*, profile: str | None) -> Optional[tuple[str, bytes]]:
    profile_name = str(profile or "").strip()
    if not profile_name:
        return None

    path = get_captures_root(profile=profile_name) / "debug" / "SMSG_MESSAGECHAT.json"
    if not path.exists():
        Logger.info(
            f"[CHAT][RAW] missing capture profile={profile_name!r} path={path}"
        )
        return None

    payload = load_sniff_payload(path)
    Logger.info(
        f"[CHAT][RAW] replaying SMSG_MESSAGECHAT profile={profile_name!r} "
        f"payload={len(payload)} source={path.name}"
    )
    return "SMSG_MESSAGECHAT", payload


def _build_dynamic_active_mover_packet() -> tuple[str, bytes]:
    Logger.info("[ACTIVE_MOVER MODE] dynamic")
    payload = build_login_packet("SMSG_MOVE_SET_ACTIVE_MOVER", _build_world_login_context())
    if payload is None:
        raise RuntimeError("Missing dynamic builder for SMSG_MOVE_SET_ACTIVE_MOVER")
    return "SMSG_MOVE_SET_ACTIVE_MOVER", payload


def _build_exact_update_object_packet(path: Path, *, update_index: int) -> tuple[str, bytes]:
    builder_name = EXACT_UPDATE_OBJECT_BUILDERS.get(path.name)
    if not builder_name:
        raise RuntimeError(f"No exact UPDATE_OBJECT builder registered for {path.name}")
    payload = build_login_packet(builder_name, _build_world_login_context())
    if payload is None:
        raise RuntimeError(f"Missing exact UPDATE_OBJECT builder for {builder_name}")
    Logger.info(
        f"[UPDATE_OBJECT MODE] exact source={path.name} payload={len(payload)} bytes"
    )
    return _make_update_object_response(payload, update_index=update_index)


def _should_skip_static_update_object_capture(path: Path) -> bool:
    if not USE_MINIMAL_UPDATE_OBJECT_REPLAY:
        return False
    if path.name in STATIC_UPDATE_OBJECT_CAPTURE_NAMES:
        return True
    if (
        USE_MINIMAL_PLAYER_VALUE_UPDATE_REPLAY
        and path.name in MINIMAL_PLAYER_VALUE_UPDATE_CAPTURE_NAMES
    ):
        return True
    return False


def _build_replayed_update_object_packet(
    session: WorldSession,
    opcode_name: str,
    path: Path,
    *,
    update_index: int,
) -> tuple[str, bytes]:
    if path.name in EXACT_UPDATE_OBJECT_BUILDERS:
        return _build_exact_update_object_packet(path, update_index=update_index)
    if not USE_RAW_UPDATE_OBJECT_FALLBACK:
        raise RuntimeError(
            f"Missing exact UPDATE_OBJECT builder for {path.name} while "
            "USE_RAW_UPDATE_OBJECT_FALLBACK is disabled"
        )
    return send_raw_sniff_packet(
        session,
        opcode_name,
        path,
        update_index=update_index,
    )


def replay_movement_focus_sequence_old(session: WorldSession) -> list[tuple[str, bytes]]:
    entries = [
        (opcode_name, _LOGIN_UPDATE_OBJECT_CAPTURE_DIR / filename)
        for opcode_name, filename in MOVEMENT_FOCUS_SEQUENCE
    ]
    required_entries: list[tuple[str, Path]] = []
    if USE_RAW_ACTIVE_MOVER:
        required_entries.append(entries[0])
    required_entries.extend(entries[1:])

    missing_paths = [path for _opcode_name, path in required_entries if not path.exists()]
    if missing_paths:
        missing = ", ".join(path.name for path in missing_paths)
        raise RuntimeError(
            f"Missing movement focus captures in {_LOGIN_UPDATE_OBJECT_CAPTURE_DIR}: {missing}"
        )

    session.player_object_sent = True
    responses: list[tuple[str, bytes]] = []
    if USE_RAW_ACTIVE_MOVER:
        opcode_name, path = entries[0]
        Logger.info("[ACTIVE_MOVER MODE] raw")
        Logger.info("[WorldLoginReplay] sending movement focus packet 1/? opcode=SMSG_MOVE_SET_ACTIVE_MOVER")
        responses.append(send_raw_sniff_packet(session, opcode_name, path))
    else:
        responses.append(_build_dynamic_active_mover_packet())

    Logger.info("[UPDATE_OBJECT MODE] raw")
    update_entries = entries[1:]
    total_packets = len(update_entries)
    for index, (opcode_name, path) in enumerate(update_entries, start=1):
        Logger.info(
            f"[WorldLoginReplay] sending movement focus packet {index}/{total_packets} "
            f"opcode={opcode_name}"
        )
        if path.name in EXACT_UPDATE_OBJECT_BUILDERS:
            responses.append(
                _build_exact_update_object_packet(
                    path,
                    update_index=index,
                )
            )
            continue
        responses.append(
            send_raw_sniff_packet(
                session,
                opcode_name,
                path,
                update_index=index,
            )
        )
    return responses


def replay_update_object_sequence_old(session: WorldSession) -> list[tuple[str, bytes]]:
    paths = [
        _LOGIN_UPDATE_OBJECT_CAPTURE_DIR / filename
        for filename in LOGIN_UPDATE_SEQUENCE
    ]
    missing_paths = [path for path in paths if not path.exists()]
    if missing_paths:
        missing = ", ".join(path.name for path in missing_paths)
        raise RuntimeError(
            f"Missing login UPDATE_OBJECT captures in {_LOGIN_UPDATE_OBJECT_CAPTURE_DIR}: {missing}"
        )

    session.player_object_sent = True
    responses: list[tuple[str, bytes]] = []
    total_packets = len(paths)
    for index, path in enumerate(paths, start=1):
        Logger.info(
            f"[WorldLoginReplay] sending UPDATE_OBJECT packet {index}/{total_packets}"
        )
        responses.append(
            send_raw_packet(
                session,
                "SMSG_UPDATE_OBJECT",
                path,
                update_index=index,
            )
        )
    return responses

_CAPTURE_DIR = get_captures_root(focus=True) / "debug"


def replay_movement_focus_sequence(session: WorldSession) -> list[tuple[str, bytes]]:
    entries = [
        (opcode_name, _CAPTURE_DIR / filename)
        for opcode_name, filename in MOVEMENT_FOCUS_SEQUENCE
    ]

    # ---- Validate only captures that are actually read from disk ----
    required_paths: list[Path] = []
    if USE_RAW_ACTIVE_MOVER:
        required_paths.append(entries[0][1])

    for _opcode_name, path in entries[1:]:
        if _should_skip_static_update_object_capture(path):
            continue
        if path.name in EXACT_UPDATE_OBJECT_BUILDERS:
            continue
        if USE_RAW_UPDATE_OBJECT_FALLBACK:
            required_paths.append(path)
            continue
        raise RuntimeError(
            f"Missing exact UPDATE_OBJECT builder for {path.name} while "
            "USE_RAW_UPDATE_OBJECT_FALLBACK is disabled"
        )

    missing = [path for path in required_paths if not path.exists()]
    if missing:
        raise RuntimeError(
            f"Missing movement focus captures in {_CAPTURE_DIR}: "
            + ", ".join(p.name for p in missing)
        )

    session.player_object_sent = True
    responses: list[tuple[str, bytes]] = []

    # ---- Active mover ----
    if USE_RAW_ACTIVE_MOVER:
        opcode_name, path = entries[0]
        Logger.info("[ACTIVE_MOVER MODE] raw")
        responses.append(send_raw_sniff_packet(session, opcode_name, path))
    else:
        responses.append(_build_dynamic_active_mover_packet())

    # ---- UPDATE_OBJECT sequence ----
    update_entries = entries[1:]
    total = len(update_entries)

    if USE_RAW_UPDATE_OBJECT_FALLBACK:
        Logger.info("[UPDATE_OBJECT MODE] exact-with-raw-fallback")
    else:
        Logger.info("[UPDATE_OBJECT MODE] exact-only")

    for index, (opcode_name, path) in enumerate(update_entries, start=1):
        Logger.info(
            f"[WorldLoginReplay] packet {index}/{total} opcode={opcode_name}"
        )
        if _should_skip_static_update_object_capture(path):
            Logger.info(
                f"[UPDATE_OBJECT MODE] minimal-skip source={path.name}"
            )
            continue
        responses.append(
            _build_replayed_update_object_packet(
                session,
                opcode_name,
                path,
                update_index=index,
            )
        )

    return responses


def replay_update_object_sequence(session: WorldSession) -> list[tuple[str, bytes]]:
    paths = [_CAPTURE_DIR / filename for filename in LOGIN_UPDATE_SEQUENCE]

    # ---- Validate ----
    missing = [p for p in paths if not p.exists()]
    if missing:
        raise RuntimeError(
            f"Missing login UPDATE_OBJECT captures in {_CAPTURE_DIR}: "
            + ", ".join(p.name for p in missing)
        )

    session.player_object_sent = True
    responses: list[tuple[str, bytes]] = []

    total = len(paths)
    if USE_RAW_UPDATE_OBJECT_FALLBACK:
        Logger.info("[UPDATE_OBJECT MODE] exact-with-raw-fallback")
    else:
        Logger.info("[UPDATE_OBJECT MODE] exact-only")

    for index, path in enumerate(paths, start=1):
        Logger.info(
            f"[WorldLoginReplay] UPDATE_OBJECT {index}/{total}"
        )
        if _should_skip_static_update_object_capture(path):
            Logger.info(
                f"[UPDATE_OBJECT MODE] minimal-skip source={path.name}"
            )
            continue

        responses.append(
            _build_replayed_update_object_packet(
                session,
                "SMSG_UPDATE_OBJECT",
                path,
                update_index=index,
            )
        )

    return responses

def _is_pre_player_login_state(state: Optional[LoginState]) -> bool:
    return state in {None, LoginState.AUTHED, LoginState.CHAR_SCREEN}


def _queue_world_bootstrap_transition(ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    if getattr(session, "post_loading_sent", False):
        Logger.info("[WorldHandlers] WORLD_BOOTSTRAP already queued; skipping duplicate")
        return []

    _set_login_state(LoginState.WORLD_BOOTSTRAP)

    responses: list[tuple[str, bytes]] = []
    pre_update_packets = build_pre_update_object_packets(ctx)
    update_packets: list[tuple[str, bytes]] = []
    if not getattr(session, "player_object_sent", False):
        update_packets = replay_movement_focus_sequence(session)
    post_update_packets = build_post_update_object_packets(ctx)
    bootstrap_packets = [
        (opcode_name, payload)
        for opcode_name, payload in build_world_bootstrap_packets(ctx)
        if opcode_name != "SMSG_MOVE_SET_ACTIVE_MOVER"
    ]

    for opcode_name, payload in pre_update_packets:
        if not SEND_ACCOUNT_DATA_TO_CLIENT and opcode_name == "SMSG_ACCOUNT_DATA_TIMES":
            Logger.info("[WorldLogin] suppressing SMSG_ACCOUNT_DATA_TIMES")
            continue
        Logger.info(f"[WorldLogin] sending {opcode_name}")
        if opcode_name == "SMSG_LOGIN_SET_TIME_SPEED":
            Logger.info("[WorldLogin] sending SMSG_LOGIN_SETTIMESPEED")
        if opcode_name == "SMSG_ACCOUNT_DATA_TIMES":
            session.account_data_times_sent = True
        responses.append((opcode_name, payload))
    responses.extend(update_packets)
    for opcode_name, payload in post_update_packets:
        Logger.info(f"[WorldLogin] sending {opcode_name}")
        responses.append((opcode_name, payload))
    for opcode_name, payload in bootstrap_packets:
        if opcode_name == "SMSG_MOVE_SET_ACTIVE_MOVER":
            Logger.info("[WorldLoginExperiment] sending ACTIVE_MOVER")
        elif opcode_name == "SMSG_TIME_SYNC_REQUEST":
            Logger.info("[WorldLoginExperiment] sending TIME_SYNC_REQUEST")
        responses.append((opcode_name, payload))

    session.loading_screen_done = True
    session.post_loading_sent = True
    Logger.info("[WorldHandlers] WORLD_BOOTSTRAP queued replayed UPDATE_OBJECT sequence + minimal bootstrap bundle")
    return responses


def _queue_teleport_world_transition(ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    _set_login_state(LoginState.WORLD_BOOTSTRAP)

    responses: list[tuple[str, bytes]] = []

    for opcode_name in (
        "SMSG_FEATURE_SYSTEM_STATUS",
        "SMSG_LOGIN_VERIFY_WORLD",
        "SMSG_LOGIN_SET_TIME_SPEED",
        "SMSG_BIND_POINT_UPDATE",
    ):
        payload = build_login_packet(opcode_name, ctx)
        if payload is None:
            continue
        Logger.info(f"[Teleport] sending {opcode_name}")
        responses.append((opcode_name, payload))

    Logger.info("[Teleport] replaying sniffed movement focus sequence")
    responses.extend(replay_movement_focus_sequence(session))

    time_sync = build_login_packet("SMSG_TIME_SYNC_REQUEST", ctx)
    if time_sync is not None:
        Logger.info("[Teleport] sending SMSG_TIME_SYNC_REQUEST")
        responses.append(("SMSG_TIME_SYNC_REQUEST", time_sync))

    for opcode_name in (
        "SMSG_PHASE_SHIFT_CHANGE",
        "SMSG_INIT_WORLD_STATES",
        "SMSG_WEATHER",
        "SMSG_QUERY_TIME_RESPONSE",
        "SMSG_UI_TIME",
    ):
        payload = build_login_packet(opcode_name, ctx)
        if payload is None:
            continue
        Logger.info(f"[Teleport] sending {opcode_name}")
        responses.append((opcode_name, payload))

    session.player_object_sent = True
    session.loading_screen_done = True
    session.post_loading_sent = True
    session.teleport_pending = False
    session.teleport_destination = None
    _transition_session_region(session, new_map_id=int(getattr(session, "map_id", 0) or 0))
    _capture_persist_position_from_session()
    _mark_position_dirty()
    _save_session_position(reason="teleport", online=1, force=True)
    Logger.info("[WorldHandlers] TELEPORT_BOOTSTRAP queued player create + active mover + time sync")
    return responses


def _decode_loading_screen_showing(decoded: dict[str, Any], payload: bytes) -> int:
    for key in ("showing", "is_loading", "show"):
        if key in decoded:
            return int(decoded.get(key) or 0)
    if len(payload) >= 4:
        packed = int.from_bytes(payload[:4], "little", signed=False)
        return (packed >> 31) & 0x01
    return 0


def _decode_chat_message(
    opcode_name: str,
    payload: bytes,
    decoded: dict[str, Any] | None = None,
) -> dict[str, Any]:
    decoded = decoded or {}

    message = str(decoded.get("msg") or "").strip()
    language = int(decoded.get("language") or 0)
    channel = str(decoded.get("channel") or "").strip()
    target = str(decoded.get("target") or "").strip()

    if not message and len(payload) > 5:
        try:
            message = payload[5:].decode("utf-8", errors="ignore").strip("\x00").strip()
        except Exception:
            message = ""

    return {
        "message": message,
        "language": language,
        "channel": channel,
        "target": target,
    }


def _pack_sized_cstring(value: str) -> bytes:
    text = str(value or "").encode("utf-8", errors="strict") + b"\x00"
    return struct.pack("<I", len(text)) + text


def _chat_guid_bytes_for_messagechat(guid: int) -> bytes:
    """Return the chat GUID bytes used by SkyFire's messagechat packet.

    SkyFire uses the full ObjectGuid bytes for sender and receiver in
    ChatHandler::BuildChatPacket. For player say packets it passes `this, this`,
    so both senderGUID and receiverGUID are the player's full world guid.
    """
    return struct.pack("<Q", int(guid or 0) & 0xFFFFFFFFFFFFFFFF)



def _write_guid_mask_bits(bits: BitWriter, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        bits.write_bits(1 if raw_guid[index] else 0, 1)



def _append_guid_byte_seq(payload: bytearray, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        value = raw_guid[index]
        if value:
            payload.append((value ^ 1) & 0xFF)


def _encode_text_emote_payload(*, player_guid: int, target_guid: int, text_emote: int, emote_num: int) -> bytes:
    player_raw = struct.pack("<Q", int(player_guid or 0) & 0xFFFFFFFFFFFFFFFF)
    target_raw = struct.pack("<Q", int(target_guid or 0) & 0xFFFFFFFFFFFFFFFF)

    bits = BitWriter()
    for raw, index in (
        (player_raw, 1),
        (target_raw, 7),
        (player_raw, 6),
        (target_raw, 5),
        (player_raw, 3),
        (target_raw, 6),
        (target_raw, 2),
        (player_raw, 7),
        (target_raw, 0),
        (target_raw, 1),
        (player_raw, 4),
        (player_raw, 2),
        (target_raw, 3),
        (target_raw, 4),
        (player_raw, 0),
        (player_raw, 5),
    ):
        bits.write_bits(1 if raw[index] else 0, 1)

    payload = bytearray(bits.getvalue())
    _append_guid_byte_seq(payload, target_raw, (2, 1))
    _append_guid_byte_seq(payload, player_raw, (7, 4))
    _append_guid_byte_seq(payload, target_raw, (7,))
    _append_guid_byte_seq(payload, player_raw, (5, 2))
    payload += struct.pack("<I", int(text_emote) & 0xFFFFFFFF)
    _append_guid_byte_seq(payload, player_raw, (6,))
    _append_guid_byte_seq(payload, target_raw, (0,))
    _append_guid_byte_seq(payload, player_raw, (3, 1))
    _append_guid_byte_seq(payload, target_raw, (6,))
    _append_guid_byte_seq(payload, player_raw, (0,))
    _append_guid_byte_seq(payload, target_raw, (3, 5, 4))
    payload += struct.pack("<I", int(emote_num) & 0xFFFFFFFF)
    return bytes(payload)


def _build_single_u32_update_object_payload(*, map_id: int, guid: int, field_index: int, value: int) -> bytes:
    mask_words = (int(field_index) // 32) + 1
    mask = bytearray(mask_words * 4)
    mask_word = int(field_index) // 32
    mask_bit = int(field_index) % 32
    struct.pack_into("<I", mask, mask_word * 4, 1 << mask_bit)

    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
    payload += struct.pack("<B", 0)
    payload += GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)
    payload += struct.pack("<B", mask_words)
    payload += bytes(mask)
    payload += struct.pack("<I", int(value) & 0xFFFFFFFF)
    payload += struct.pack("<B", 0)
    return bytes(payload)


def _encode_skyfire_messagechat_payload(
    message: str,
    *,
    chat_type: int,
    sender_guid: int = 0,
    receiver_guid: int = 0,
    language: int = 0,
) -> bytes:
    """Build SMSG_MESSAGECHAT using the SkyFire BuildChatPacket bit/byte order."""
    message_bytes = str(message or '').encode('utf-8', errors='strict')
    sender_raw = _chat_guid_bytes_for_messagechat(sender_guid)
    receiver_raw = _chat_guid_bytes_for_messagechat(receiver_guid)
    group_raw = b'\x00' * 8
    guild_raw = b'\x00' * 8
    has_language = int(language or 0) > 0

    bits = BitWriter()
    bits.write_bits(1, 1)  # !hasSenderName
    bits.write_bits(0, 1)  # HideInChatLog
    bits.write_bits(0, 1)  # Fake Bit
    bits.write_bits(1, 1)  # !hasChannelName
    bits.write_bits(0, 1)  # Unk
    bits.write_bits(1, 1)  # SendFakeTime
    bits.write_bits(1, 1)  # !chatTag
    bits.write_bits(1, 1)  # RealmID?

    _write_guid_mask_bits(bits, group_raw, (0, 1, 5, 4, 3, 2, 6, 7))

    bits.write_bits(0, 1)  # Fake Bit
    _write_guid_mask_bits(bits, receiver_raw, (7, 6, 1, 4, 0, 2, 3, 5))

    bits.write_bits(0, 1)  # Fake Bit
    bits.write_bits(0 if has_language else 1, 1)  # !hasLanguage
    bits.write_bits(1, 1)  # !hasPrefix

    _write_guid_mask_bits(bits, sender_raw, (0, 3, 7, 2, 1, 5, 4, 6))

    bits.write_bits(1, 1)  # !hasAchievementId
    bits.write_bits(0 if message_bytes else 1, 1)  # !message.length()

    if message_bytes:
        bits.write_bits(len(message_bytes), 12)

    bits.write_bits(1, 1)  # !hasReceiverName
    bits.write_bits(1, 1)  # RealmID?
    bits.write_bits(0, 1)  # Fake Bit

    _write_guid_mask_bits(bits, guild_raw, (2, 5, 7, 4, 0, 1, 3, 6))

    payload = bytearray(bits.getvalue())

    _append_guid_byte_seq(payload, guild_raw, (4, 5, 7, 3, 2, 6, 0, 1))
    _append_guid_byte_seq(payload, sender_raw, (4, 7, 1, 5, 0, 6, 2, 3))

    payload.append(int(chat_type) & 0xFF)

    _append_guid_byte_seq(payload, group_raw, (1, 3, 4, 6, 0, 2, 5, 7))
    _append_guid_byte_seq(payload, receiver_raw, (2, 5, 3, 6, 7, 4, 1, 0))

    if has_language:
        payload.append(int(language) & 0xFF)

    if message_bytes:
        payload.extend(message_bytes)

    return bytes(payload)


def _encode_skyfire_messagechat_say_payload(message: str, sender_guid: int = 0, language: int = 0) -> bytes:
    return _encode_skyfire_messagechat_payload(
        message,
        chat_type=CHAT_MSG_SAY,
        sender_guid=sender_guid,
        receiver_guid=sender_guid,
        language=language,
    )


def _encode_skyfire_messagechat_system_payload(message: str) -> bytes:
    return _encode_skyfire_messagechat_payload(
        message,
        chat_type=CHAT_MSG_SYSTEM,
        sender_guid=0,
        receiver_guid=0,
        language=0,
    )


def _encode_aio_simple_messagechat_say_payload(message: str, sender_guid: int = 0) -> bytes:
    """Use the smallest tolerated MoP SAY form for AIO-style chat experiments."""
    payload = _encode_skyfire_messagechat_say_payload(
        message,
        sender_guid=int(sender_guid or 0),
        language=0,
    )
    Logger.info(
        f"[CHAT][SEND] guid=0x{int(sender_guid or 0):016X} "
        f"bytes={len(payload)} message={message!r} mode=aio-simple-say"
    )
    return payload


def _encode_messagechat_payload(
    *,
    chat_type: int,
    language: int,
    sender_guid: int,
    sender_name: str,
    target_guid: int,
    target_name: str,
    message: str,
) -> bytes:
    if int(chat_type) == CHAT_MSG_SAY and int(target_guid) == 0 and not str(target_name or ""):
        payload = _encode_skyfire_messagechat_say_payload(message, sender_guid=int(sender_guid or 0), language=int(language or 0))
        Logger.info(
            f"[CHAT][SEND] type={int(chat_type)} sender={sender_name or ''} "
            f"target={target_name or ''} guid=0x{int(sender_guid or 0):016X} "
            f"bytes={len(payload)} message={message!r} mode=skyfire-say"
        )
        return payload

    sender_name_bytes = str(sender_name or "").encode("utf-8", errors="strict") + b"\x00"
    target_name_bytes = str(target_name or "").encode("utf-8", errors="strict") + b"\x00"
    message_bytes = str(message or "").encode("utf-8", errors="strict") + b"\x00"
    payload = EncoderHandler.encode_packet(
        "SMSG_MESSAGECHAT",
        {
            "type": int(chat_type),
            "language": int(language),
            "sender_guid": int(sender_guid),
            "flags": 0,
            "sender_name_len": len(sender_name_bytes),
            "sender_name": sender_name_bytes,
            "target_guid": int(target_guid),
            "target_name_len": len(target_name_bytes),
            "target_name": target_name_bytes,
            "message_len": len(message_bytes),
            "message": message_bytes,
            "chat_tag": 0,
        },
    )
    Logger.info(
        f"[CHAT][SEND] type={int(chat_type)} sender={sender_name or ''} "
        f"target={target_name or ''} bytes={len(payload)} message={message!r}"
    )
    return payload


def _build_motd_notification_payload(message: str) -> bytes:
    message_bytes = str(message or "").encode("utf-8", errors="strict")
    bits = BitWriter()
    bits.write_bits(len(message_bytes) & 0xFFF, 12)
    return bits.getvalue() + message_bytes

# Simple AreaTable cache (map_id + bounding box)
_AREA_TABLE = None

def _load_area_table():
    global _AREA_TABLE
    if _AREA_TABLE is not None:
        return _AREA_TABLE

    _AREA_TABLE = []
    dbc_root = get_dbc_root()
    if not dbc_root:
        return _AREA_TABLE

    path = dbc_root / "AreaTable.dbc"
    if not path.exists():
        Logger.warning("[AreaTable] missing")
        return _AREA_TABLE

    try:
        rows = read_dbc(path, "iIIffff")  # minimal fields (id, map, x1,x2,y1,y2)
    except Exception as e:
        Logger.warning(f"[AreaTable] failed: {e}")
        return _AREA_TABLE

    for r in rows:
        area_id = int(r[0])
        map_id = int(r[1])
        x1, x2, y1, y2 = float(r[2]), float(r[3]), float(r[4]), float(r[5])

        _AREA_TABLE.append((map_id, area_id, x1, x2, y1, y2))

    return _AREA_TABLE


def _resolve_zone_from_position(map_id: int, x: float, y: float) -> int:
    for m, area_id, x1, x2, y1, y2 in _load_area_table():
        if m != map_id:
            continue
        if min(x1, x2) <= x <= max(x1, x2) and min(y1, y2) <= y <= max(y1, y2):
            return area_id
    return 0


def _handle_chat_command(message: str) -> Optional[list[tuple[str, bytes]]]:
    command = str(message or "").strip()

    if command.lower().startswith(".roll"):
        roll = random.randint(1, 100)

        msg = f"{session.player_name} rolls {roll} (1-100)"

        payload = _encode_messagechat_payload(
            chat_type=CHAT_MSG_SAY,
            language=0,
            sender_guid=session.player_guid,
            sender_name=session.player_name,
            target_guid=0,
            target_name="",
            message=msg,
        )

        return [("SMSG_MESSAGECHAT", payload)]
    
    # -----------------------------
    # DEBUG POSITION
    # -----------------------------
    if command.lower() == ".getxy":
        Logger.info(
            "[GETXY] "
            f"map={int(getattr(session, 'map_id', 0) or 0)} "
            f"x={float(getattr(session, 'x', 0.0) or 0.0):.2f} "
            f"y={float(getattr(session, 'y', 0.0) or 0.0):.2f} "
            f"z={float(getattr(session, 'z', 0.0) or 0.0):.2f} "
            f"o={float(getattr(session, 'orientation', 0.0) or 0.0):.2f}"
        )
        return []

    # -----------------------------
    # WEATHER COMMAND
    # -----------------------------
    if command.lower().startswith(".weather"):
        parts = command.split()

        if len(parts) not in (2, 3):
            Logger.info("[Weather] Usage: .weather <clear|rain|snow|storm|sand|id> [0.0-1.0]")
            return []

        weather_key = parts[1].strip().lower()
        density = 0.0 if weather_key in ("clear", "fine", "sun") else 0.5
        if len(parts) == 3:
            try:
                density = max(0.0, min(1.0, float(parts[2])))
            except ValueError:
                Logger.info(f"[Weather] Invalid density command={command!r}")
                return []

        try:
            weather_type = int(weather_key)
        except ValueError:
            weather_type = _resolve_weather_type(weather_key, density)

        if weather_type < 0:
            Logger.info(f"[Weather] Unknown weather command={command!r}")
            return []

        session.weather = {
            "weather_type": int(weather_type),
            "density": float(density),
            "abrupt": 0,
        }
        Logger.info(
            f"[Weather] type={int(weather_type)} density={float(density):.2f} abrupt=0"
        )
        return [
            (
                "SMSG_WEATHER",
                build_login_packet(
                    "SMSG_WEATHER",
                    type(
                        "Ctx",
                        (),
                        {
                            "weather_type": int(weather_type),
                            "density": float(density),
                            "abrupt": 0,
                        },
                    )(),
                ),
            )
        ]

    # -----------------------------
    # TIME COMMAND
    # -----------------------------
    if command.lower().startswith(".time"):
        parts = command.split(maxsplit=1)

        if len(parts) != 2:
            Logger.info("[Time] Usage: .time <HH:MM|day|night|dawn|dusk|noon|midnight>")
            return []

        arg = parts[1].strip().lower()
        presets = {
            "day": (12, 0),
            "noon": (12, 0),
            "night": (0, 0),
            "midnight": (0, 0),
            "dawn": (6, 0),
            "dusk": (18, 0),
            "sunrise": (6, 0),
            "sunset": (18, 0),
        }

        if arg in presets:
            hour, minute = presets[arg]
        else:
            time_parts = arg.split(":", 1)
            if len(time_parts) != 2:
                Logger.info(f"[Time] Invalid time command={command!r}")
                return []
            try:
                hour = int(time_parts[0])
                minute = int(time_parts[1])
            except ValueError:
                Logger.info(f"[Time] Invalid time command={command!r}")
                return []

            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                Logger.info(f"[Time] Out-of-range time command={command!r}")
                return []

        now = int(time.time())
        lt = time.localtime(now)
        current_seconds = int(lt.tm_hour) * 3600 + int(lt.tm_min) * 60 + int(lt.tm_sec)
        target_seconds = int(hour) * 3600 + int(minute) * 60 + int(lt.tm_sec)

        session.server_time = now
        session.time_offset = target_seconds - current_seconds
        session.time_speed = 0.01666667
        session.game_time = _pack_wow_game_time(session.server_time + session.time_offset)

        Logger.info(
            f"[Time] hour={hour:02d} minute={minute:02d} "
            f"offset={int(session.time_offset)} packed=0x{int(session.game_time):08X}"
        )

        return [
            ("SMSG_LOGIN_SET_TIME_SPEED", build_login_packet("SMSG_LOGIN_SET_TIME_SPEED", _build_world_login_context())),
        ]

    # -----------------------------
    # SAVE COMMAND
    # -----------------------------
    if command.lower() == ".save":
        _capture_persist_position_from_session()
        _mark_position_dirty()
        ok = _save_session_position(reason="command", online=1, force=True)

        map_id = int(getattr(session, "persist_map_id", 0) or 0)
        zone = int(getattr(session, "persist_zone", 0) or 0)
        x = float(getattr(session, "persist_x", 0.0) or 0.0)
        y = float(getattr(session, "persist_y", 0.0) or 0.0)
        z = float(getattr(session, "persist_z", 0.0) or 0.0)
        orientation = float(getattr(session, "persist_orientation", 0.0) or 0.0)
        player_name = (
            str(getattr(session, "player_name", "") or "").strip()
            or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
        )

        if ok:
            message = (
                f"[Save] {player_name} map={map_id} zone={zone} "
                f"x={x:.2f} y={y:.2f} z={z:.2f} o={orientation:.2f}"
            )
            Logger.info(message)
        else:
            message = f"[Save] failed for {player_name}"
            Logger.warning(message)

        return [
            ("SMSG_NOTIFICATION", _build_motd_notification_payload(message)),
        ]

    # -----------------------------
    # TELEPORT XYZ
    # -----------------------------
    if command.lower().startswith(".telxyz"):
        parts = command.split()

        player_name = (
            str(getattr(session, "player_name", "") or "").strip()
            or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
        )

        if len(parts) != 6:
            Logger.info(f"[Teleport] Invalid .telxyz syntax command={command!r}")
            payload_out = _encode_messagechat_payload(
                chat_type=CHAT_MSG_SAY,
                language=0,
                sender_guid=int(getattr(session, "player_guid", 0) or getattr(session, "world_guid", 0) or 0),
                sender_name=player_name,
                target_guid=0,
                target_name="",
                message="Usage: .telxyz <map> <x> <y> <z> <orientation>",
            )
            return [("SMSG_MESSAGECHAT", payload_out)]

        try:
            map_id = int(parts[1])
            x = float(parts[2])
            y = float(parts[3])
            z = float(parts[4])
            orientation = float(parts[5])
        except (TypeError, ValueError):
            Logger.info(f"[Teleport] Invalid .telxyz args command={command!r}")
            return []

        Logger.info(
            f"[Teleport] {player_name} -> manual ({map_id} {x:.2f} {y:.2f} {z:.2f} {orientation:.2f})"
        )
        return teleport_player(
            session,
            map_id,
            x,
            y,
            z,
            orientation,
            destination_name=f"manual:{map_id}:{x:.2f}:{y:.2f}:{z:.2f}:{orientation:.2f}",
        )

    # -----------------------------
    # TELEPORT COMMANDS
    # -----------------------------
    if not command.startswith(".tel"):
        return None

    parts = command.split()
    if len(parts) == 1:
        return _notification_response("Usage: .tel <name> | .tel search <name> | .tel add <name> | .tel rm <name> | .tel nearest")

    action = parts[1].strip().lower()

    if action == "search":
        query = command.split(None, 2)[2] if len(parts) >= 3 else ""
        matches = search_teleports(query)
        if not matches:
            return _notification_response("Matches: none")
        return _notification_response(f"Matches: {', '.join(matches)}")

    if action == "add":
        name = command.split(None, 2)[2].strip() if len(parts) >= 3 else ""
        if not name:
            return _notification_response("Usage: .tel add <name>")
        try:
            entry = add_named_teleport(
                DatabaseConnection.world(),
                name,
                int(getattr(session, "map_id", 0) or 0),
                float(getattr(session, "x", 0.0) or 0.0),
                float(getattr(session, "y", 0.0) or 0.0),
                float(getattr(session, "z", 0.0) or 0.0),
                float(getattr(session, "orientation", 0.0) or 0.0),
            )
        except Exception as exc:
            Logger.warning(f"[Teleport] add failed name={name!r}: {exc}")
            return _notification_response("Teleport add failed")
        return _notification_response(f"Teleport added: {entry['name']}")

    if action == "rm":
        name = command.split(None, 2)[2].strip() if len(parts) >= 3 else ""
        if not name:
            return _notification_response("Usage: .tel rm <name>")
        try:
            removed = remove_named_teleport(DatabaseConnection.world(), name)
        except Exception as exc:
            Logger.warning(f"[Teleport] rm failed name={name!r}: {exc}")
            return _notification_response("Teleport remove failed")
        if not removed:
            return _notification_response("Teleport not found")
        return _notification_response("Teleport removed")

    if action == "nearest":
        nearest = nearest_teleport(
            int(getattr(session, "map_id", 0) or 0),
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
        )
        if nearest is None:
            return _notification_response("Nearest: none")
        return _notification_response(f"Nearest: {nearest['name']}")

    destination_name = command.split(None, 1)[1].strip() if len(parts) >= 2 else ""
    destination = find_teleport(destination_name)
    if destination is None:
        Logger.info(f"[Teleport] Unknown destination command={command!r}")
        return _notification_response("Teleport not found")

    map_id = int(destination["map"])
    x = float(destination["x"])
    y = float(destination["y"])
    z = float(destination["z"])
    orientation = float(destination["o"])
    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )

    Logger.info(
        f"[Teleport] {player_name} -> {destination['name']} ({x:.2f} {y:.2f} {z:.2f})"
    )

    return teleport_player(
        session,
        map_id,
        x,
        y,
        z,
        orientation,
        destination_name=str(destination["name"]),
    )


def _handle_chat_message(ctx: PacketContext):
    chat = _decode_chat_message(ctx.name, ctx.payload, ctx.decoded)
    message = chat["message"]
    if not message:
        return 0, None

    command_responses = _handle_chat_command(message)
    if command_responses is not None:
        return 0, command_responses if command_responses else None

    player_name = session.player_name
    sender_guid = int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or 0)
    language = int(chat.get("language") or 0)

    Logger.info(f"[CHAT] {player_name}: {message}")

    common_name_kwargs = {
        "name": player_name,
        "realm_name": _get_realm_name(),
        "race": int(getattr(session, "race", 0) or 0),
        "gender": int(getattr(session, "gender", 0) or 0),
        "class_id": int(getattr(session, "class_id", 0) or 0),
    }

    if USE_SYSTEM_CHAT_FALLBACK:
        payload_out = _encode_skyfire_messagechat_system_payload(f"[{player_name}] {message}")
        Logger.info(
            f"[CHAT][FALLBACK] mode=system player={player_name!r} bytes={len(payload_out)} message={message!r}"
        )
    else:
        payload_out = _encode_messagechat_payload(
            chat_type=CHAT_MSG_SAY,
            language=language,
            sender_guid=sender_guid,
            sender_name=player_name,
            target_guid=0,
            target_name="",
            message=message,
        )
    notification_payload = _build_motd_notification_payload(message)
    chat_response = ("SMSG_MESSAGECHAT", payload_out)
    targets = chat_router.get_targets(session, "say")
    dispatched = False
    if targets:
        _dispatch_responses_to_sessions(targets, [chat_response])
        dispatched = True

    responses: list[tuple[str, bytes]] = [("SMSG_NOTIFICATION", notification_payload)]

    raw_replay_messagechat = _build_raw_replay_messagechat_packet(profile=RAW_REPLAY_SAY_CHAT_PROFILE)
    if raw_replay_messagechat is not None:
        responses.append(raw_replay_messagechat)

    if not dispatched:
        responses.insert(0, chat_response)

    return 0, responses

# WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, _ = load_world_opcodes()
SERVER_OPCODE_BY_NAME = {name: code for code, name in WORLD_SERVER_OPCODES.items()}

MAX_CREATURE_QUEST_ITEMS = 6

# -----------------------------------------------------------------------------
# Templates / file helpers
# -----------------------------------------------------------------------------

def load_expected(case_name: str) -> dict:
    path = get_json_root() / f"{case_name}.json"

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
def _load_template(case_name: str) -> dict:
    try:
        return load_expected(case_name)
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Missing template {case_name}: {exc}")
        return {}

# -----------------------------------------------------------------------------
# World packet wrapper
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Decode helpers
# -----------------------------------------------------------------------------

def _log_cmsg(ctx: PacketContext) -> dict:
    decoded = ctx.decoded or {}
    log_decoded_packet("worldserver", ctx.name, to_safe_json(decoded), label=f"[CMSG] {ctx.name}")
    return decoded

def _parse_guid(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, "little", signed=False)
    if isinstance(value, str):
        s = value.strip()
        try:
            return int(s, 16) if s.startswith(("0x", "0X")) else int(s)
        except Exception:
            return None
    return None


def _pack_cstring(value: str, *, required: bool = False) -> bytes:
    text = (value or "").rstrip("\x00")
    encoded = text.encode("utf-8")
    if encoded or required:
        return encoded + b"\x00"
    return b""


def _build_creature_query_response_payload(entry: int, info: dict | None) -> bytes:
    payload = bytearray(struct.pack("<I", int(entry)))
    bits = BitWriter()
    bits.write_bits(1 if info else 0, 1)

    if not info:
        payload.extend(bits.getvalue())
        return bytes(payload)

    name = str(info.get("name") or "").strip()
    subname = str(info.get("subname") or "").strip()
    icon_name = str(info.get("IconName") or "").strip()

    name_bytes = _pack_cstring(name, required=True)
    subname_bytes = _pack_cstring(subname)
    icon_bytes = _pack_cstring(icon_name)

    bits.write_bits(len(subname_bytes), 11)
    bits.write_bits(MAX_CREATURE_QUEST_ITEMS, 22)
    bits.write_bits(0, 11)
    bits.write_bits(len(name_bytes), 11)
    for _ in range(7):
        bits.write_bits(0, 11)
    bits.write_bits(1 if int(info.get("RacialLeader") or 0) else 0, 1)
    bits.write_bits(len(icon_bytes), 6)

    payload.extend(bits.getvalue())

    quest_items = [
        int(info.get(f"questItem{i}", 0) or 0)
        for i in range(1, MAX_CREATURE_QUEST_ITEMS + 1)
    ]

    def append_u32(value: int) -> None:
        payload.extend(struct.pack("<I", int(value or 0)))

    def append_f32(value: float) -> None:
        payload.extend(struct.pack("<f", float(value or 0.0)))

    append_u32(info.get("KillCredit1", 0))
    append_u32(info.get("modelid4", 0))
    append_u32(info.get("modelid2", 0))
    append_u32(info.get("exp", 0))
    append_u32(info.get("type", 0))
    append_f32(info.get("Health_mod", 0.0))
    append_u32(info.get("type_flags", 0))
    append_u32(info.get("type_flags2", 0))
    append_u32(info.get("npc_rank", 0))
    append_u32(info.get("movementId", 0))

    payload.extend(name_bytes)
    payload.extend(subname_bytes)

    append_u32(info.get("modelid1", 0))
    append_u32(info.get("modelid3", 0))

    payload.extend(icon_bytes)

    for item_id in quest_items:
        append_u32(item_id)

    append_u32(info.get("KillCredit2", 0))
    append_f32(info.get("Mana_mod", 0.0))
    append_u32(info.get("family", 0))

    return bytes(payload)


def _guid_mask_bits(raw: bytes, order: tuple[int, ...]) -> bytes:
    bits = BitWriter()
    for index in order:
        bits.write_bits(1 if raw[index] else 0, 1)
    return bits.getvalue()


def _decode_simple_query_type_old(payload: bytes) -> int:
    if not payload:
        return 0
    return (payload[0] >> 5) & 0x07

def _decode_simple_query_type(payload: bytes) -> int:
    # MoP sends a uint32 data_type
    if len(payload) >= 4:
        return struct.unpack_from("<I", payload, 0)[0]

    if payload:
        return payload[0]

    return 0


def _decode_account_data_request_type(payload: bytes) -> int:
    if not payload:
        return 0
    if len(payload) >= 4:
        unpacked = int(struct.unpack_from("<I", payload, 0)[0])
        if 0 <= unpacked < 8:
            return unpacked
    return (int(payload[0]) >> 5) & 0x07


def _decode_account_data_update_payload(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": 0,
        "timestamp": 0,
        "decompressed_size": 0,
        "compressed_size": 0,
        "account_data": "",
    }

    raw = bytes(payload or b"")
    if raw[:1] == b"\x68":
        raw = raw[1:]

    if len(raw) >= 15:
        # MoP 5.4.8 layout from sniff:
        #   uint16 header (type stored in high nibble)
        #   uint8  unknown/reserved
        #   uint32 decompressed_size
        #   uint32 timestamp
        #   uint32 compressed_size
        #   zlib payload
        header = struct.unpack_from("<H", raw, 0)[0]
        data_type = int((header >> 12) & 0x0F)
        decompressed_size = int(struct.unpack_from("<I", raw, 3)[0])
        timestamp = int(struct.unpack_from("<I", raw, 7)[0])
        compressed_size = int(struct.unpack_from("<I", raw, 11)[0])

        if 0 <= data_type < 8 and compressed_size >= 0:
            compressed_offset = 15
            compressed_end = min(len(raw), compressed_offset + compressed_size)
            compressed_blob = raw[compressed_offset:compressed_end]

            result["type"] = data_type
            result["timestamp"] = timestamp
            result["decompressed_size"] = decompressed_size
            result["compressed_size"] = compressed_size

            if decompressed_size == 0:
                return result

            if len(compressed_blob) != compressed_size:
                result["error"] = "truncated_compressed_blob"
                return result

            try:
                inflated = zlib.decompress(compressed_blob)
            except Exception as exc:
                result["error"] = f"decompress_failed:{exc}"
                return result

            if len(inflated) != decompressed_size:
                result["warning"] = "decompressed_size_mismatch"

            result["account_data"] = inflated.decode("utf-8", errors="replace")
            return result

    if len(raw) < 12:
        return result

    # Fallback for older layouts.
    decompressed_size, timestamp, compressed_size = struct.unpack_from("<III", raw, 0)
    result["timestamp"] = int(timestamp)
    result["decompressed_size"] = int(decompressed_size)
    result["compressed_size"] = int(compressed_size)

    compressed_offset = 12
    compressed_end = min(len(raw), compressed_offset + int(compressed_size))
    compressed_blob = raw[compressed_offset:compressed_end]

    type_offset = compressed_offset + int(compressed_size)
    if type_offset < len(raw):
        result["type"] = int(raw[type_offset]) & 0x07

    if int(decompressed_size) == 0:
        return result

    if len(compressed_blob) != int(compressed_size):
        result["error"] = "truncated_compressed_blob"
        return result

    try:
        inflated = zlib.decompress(compressed_blob)
    except Exception as exc:
        result["error"] = f"decompress_failed:{exc}"
        return result

    if len(inflated) != int(decompressed_size):
        result["warning"] = "decompressed_size_mismatch"

    result["account_data"] = inflated.decode("utf-8", errors="replace")
    return result


_ACCOUNT_DATA_TYPE_1_DEFAULT = (
    'SET autoQuestPopUps "v\\x01"\\r\\n'
    'SET trackedQuests "v\\x01"\\r\\n'
    'SET trackedAchievements "v\\x01"\\r\\n'
    'SET cameraSavedDistance "5.550000"\\r\\n'
    'SET cameraSavedPitch "10.000000"\\r\\n'
    'SET minimapTrackedInfov2 "229384"\\r\\n'
    'SET minimapShapeshiftTracking "v\\x01"\\r\\n'
    'SET reputationsCollapsed "v\\x01##$"\\r\\n'
    'SET activeCUFProfile "Primary"\\r\\n'
    'SET EJLootClass "4"\\r\\n'
)

_ACCOUNT_DATA_TYPE_0_DEFAULT = (
    'SET flaggedTutorials "v\\x01"\\r\\n'
    'SET cameraDistanceMaxFactor "1"\\r\\n'
    'SET petJournalTab "2"\\r\\n'
)

_ACCOUNT_DATA_TYPE_2_DEFAULT = """bind W MOVEFORWARD
bind S MOVEBACKWARD
bind A TURNLEFT
bind D TURNRIGHT
bind Q STRAFELEFT
bind E STRAFERIGHT

bind SPACE JUMP
bind X SITORSTAND

bind TAB TARGETNEARESTENEMY
bind SHIFT-TAB TARGETPREVIOUSENEMY

bind ENTER OPENCHAT
bind / OPENCHATSLASH

bind ESCAPE TOGGLEGAMEMENU

bind B TOGGLEBACKPACK
bind SHIFT-B OPENALLBAGS
bind C TOGGLECHARACTER0
bind P TOGGLESPELLBOOK
bind N TOGGLETALENTS
bind M TOGGLEWORLDMAP
bind L TOGGLEQUESTLOG

bind F1 TARGETSELF
bind F2 TARGETPARTYMEMBER1
bind F3 TARGETPARTYMEMBER2
bind F4 TARGETPARTYMEMBER3
bind F5 TARGETPARTYMEMBER4

bind 1 ACTIONBUTTON1
bind 2 ACTIONBUTTON2
bind 3 ACTIONBUTTON3
bind 4 ACTIONBUTTON4
bind 5 ACTIONBUTTON5
bind 6 ACTIONBUTTON6
bind 7 ACTIONBUTTON7
bind 8 ACTIONBUTTON8
bind 9 ACTIONBUTTON9
bind 0 ACTIONBUTTON10
bind - ACTIONBUTTON11
bind = ACTIONBUTTON12

bind SHIFT-1 ACTIONPAGE1
bind SHIFT-2 ACTIONPAGE2
bind SHIFT-3 ACTIONPAGE3
bind SHIFT-4 ACTIONPAGE4
bind SHIFT-5 ACTIONPAGE5
bind SHIFT-6 ACTIONPAGE6
"""

_ACCOUNT_DATA_TYPE_3_DEFAULT = (
    "BINDINGMODE 0\r\n"
    "bind W MOVEFORWARD\r\n"
    "bind S MOVEBACKWARD\r\n"
    "bind A TURNLEFT\r\n"
    "bind D TURNRIGHT\r\n"
    "bind Q STRAFELEFT\r\n"
    "bind E STRAFERIGHT\r\n"
    "bind SPACE JUMP\r\n"
    "bind X SITORSTAND\r\n"
    "bind ENTER OPENCHAT\r\n"
    "bind / OPENCHATSLASH\r\n"
    "bind 1 ACTIONBUTTON1\r\n"
    "bind 2 ACTIONBUTTON2\r\n"
    "bind 3 ACTIONBUTTON3\r\n"
    "bind 4 ACTIONBUTTON4\r\n"
    "bind 5 ACTIONBUTTON5\r\n"
    "bind 6 ACTIONBUTTON6\r\n"
    "bind 7 ACTIONBUTTON7\r\n"
    "bind 8 ACTIONBUTTON8\r\n"
    "bind 9 ACTIONBUTTON9\r\n"
    "bind 0 ACTIONBUTTON10\r\n"
    "bind - ACTIONBUTTON11\r\n"
    "bind = ACTIONBUTTON12\r\n"
    "bind SHIFT-1 ACTIONPAGE1\r\n"
    "bind SHIFT-2 ACTIONPAGE2\r\n"
    "bind SHIFT-3 ACTIONPAGE3\r\n"
    "bind SHIFT-4 ACTIONPAGE4\r\n"
    "bind SHIFT-5 ACTIONPAGE5\r\n"
    "bind SHIFT-6 ACTIONPAGE6\r\n"
    "bind TAB TARGETNEARESTENEMY\r\n"
    "bind SHIFT-TAB TARGETPREVIOUSENEMY\r\n"
    "bind F1 TARGETSELF\r\n"
    "bind F2 TARGETPARTYMEMBER1\r\n"
    "bind F3 TARGETPARTYMEMBER2\r\n"
    "bind F4 TARGETPARTYMEMBER3\r\n"
    "bind F5 TARGETPARTYMEMBER4\r\n"
    "bind C TOGGLECHARACTER0\r\n"
    "bind B TOGGLEBACKPACK\r\n"
    "bind SHIFT-B OPENALLBAGS\r\n"
    "bind P TOGGLESPELLBOOK\r\n"
    "bind N TOGGLETALENTS\r\n"
    "bind L TOGGLEQUESTLOG\r\n"
    "bind ESCAPE TOGGLEGAMEMENU\r\n"
    "bind M TOGGLEWORLDMAP\r\n"
)


_ACCOUNT_DATA_TYPE_7_DEFAULT = """VERSION 5

ADDEDVERSION 19

CHANNELS
END

ZONECHANNELS 35651587

COLORS

SYSTEM 255 255 0 N
SAY 128 0 128 N
PARTY 170 170 255 N
RAID 255 127 0 N
GUILD 64 255 64 N
OFFICER 64 192 64 N
YELL 255 64 64 N
WHISPER 255 128 255 N
WHISPER_FOREIGN 255 128 255 N
WHISPER_INFORM 255 128 255 N
EMOTE 255 128 64 N
TEXT_EMOTE 255 128 64 N
MONSTER_SAY 255 255 159 N
MONSTER_PARTY 170 170 255 N
MONSTER_YELL 255 64 64 N
MONSTER_WHISPER 255 181 235 N
MONSTER_EMOTE 255 128 64 N
CHANNEL 255 192 192 N
CHANNEL_JOIN 192 128 128 N
CHANNEL_LEAVE 192 128 128 N
CHANNEL_LIST 192 128 128 N
CHANNEL_NOTICE 192 192 192 N
CHANNEL_NOTICE_USER 192 192 192 N
AFK 255 128 255 N
DND 255 128 255 N
IGNORED 255 0 0 N
SKILL 85 85 255 N
LOOT 0 170 0 N
MONEY 255 255 0 N
OPENING 128 128 255 N
TRADESKILLS 255 255 255 N
PET_INFO 128 128 255 N
COMBAT_MISC_INFO 128 128 255 N
COMBAT_XP_GAIN 111 111 255 N
COMBAT_HONOR_GAIN 224 202 10 N
COMBAT_FACTION_CHANGE 128 128 255 N
BG_SYSTEM_NEUTRAL 255 120 10 N
BG_SYSTEM_ALLIANCE 0 174 239 N
BG_SYSTEM_HORDE 255 0 0 N
RAID_LEADER 255 72 9 N
RAID_WARNING 255 72 0 N
RAID_BOSS_EMOTE 255 221 0 N
RAID_BOSS_WHISPER 255 221 0 N
FILTERED 255 0 0 N
RESTRICTED 255 0 0 N
BATTLENET 255 255 255 N
ACHIEVEMENT 255 255 0 N
GUILD_ACHIEVEMENT 64 255 64 N
ARENA_POINTS 255 255 255 N
PARTY_LEADER 118 200 255 N
TARGETICONS 255 255 0 N
BN_WHISPER 0 255 246 N
BN_WHISPER_INFORM 0 255 246 N
BN_CONVERSATION 0 177 240 N
BN_CONVERSATION_NOTICE 0 177 240 N
BN_CONVERSATION_LIST 0 177 240 N
BN_INLINE_TOAST_ALERT 130 197 255 N
BN_INLINE_TOAST_BROADCAST 130 197 255 N
BN_INLINE_TOAST_BROADCAST_INFORM 130 197 255 N
BN_INLINE_TOAST_CONVERSATION 130 197 255 N
BN_WHISPER_PLAYER_OFFLINE 255 255 0 N
COMBAT_GUILD_XP_GAIN 111 111 255 N
CURRENCY 0 170 0 N
QUEST_BOSS_EMOTE 255 128 64 N
PET_BATTLE_COMBAT_LOG 231 222 171 N
PET_BATTLE_INFO 225 222 93 N
INSTANCE_CHAT 255 127 0 N
INSTANCE_CHAT_LEADER 255 72 9 N
CHANNEL1 255 192 192 N
CHANNEL2 255 192 192 N
CHANNEL3 255 192 192 N
CHANNEL4 255 192 192 N
CHANNEL5 255 192 192 N
CHANNEL6 255 192 192 N
CHANNEL7 255 192 192 N
CHANNEL8 255 192 192 N
CHANNEL9 255 192 192 N
CHANNEL10 255 192 192 N
END

WINDOW 1
NAME General
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 1
SHOWN 1
MESSAGES
SYSTEM
SYSTEM_NOMENU
SAY
EMOTE
YELL
WHISPER
PARTY
PARTY_LEADER
RAID
RAID_LEADER
RAID_WARNING
GUILD
OFFICER
MONSTER_SAY
MONSTER_YELL
MONSTER_EMOTE
MONSTER_WHISPER
MONSTER_BOSS_EMOTE
MONSTER_BOSS_WHISPER
ERRORS
AFK
DND
IGNORED
BG_HORDE
BG_ALLIANCE
BG_NEUTRAL
COMBAT_FACTION_CHANGE
SKILL
LOOT
MONEY
CHANNEL
ACHIEVEMENT
GUILD_ACHIEVEMENT
BN_WHISPER
BN_WHISPER_INFORM
BN_CONVERSATION
BN_INLINE_TOAST_ALERT
CURRENCY
BN_WHISPER_PLAYER_OFFLINE
PET_BATTLE_INFO
INSTANCE_CHAT
INSTANCE_CHAT_LEADER
END

CHANNELS
END

ZONECHANNELS 2097155

END

WINDOW 2
NAME Combat Log
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 2
SHOWN 0
MESSAGES
OPENING
TRADESKILLS
PET_INFO
COMBAT_XP_GAIN
COMBAT_HONOR_GAIN
COMBAT_MISC_INFO
COMBAT_GUILD_XP_GAIN
END

CHANNELS
END

ZONECHANNELS 0

END

WINDOW 3
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 0
SHOWN 0
MESSAGES
END

CHANNELS
END

ZONECHANNELS 0

END

WINDOW 4
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 0
SHOWN 0
MESSAGES
END

CHANNELS
END

ZONECHANNELS 0

END

WINDOW 5
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 0
SHOWN 0
MESSAGES
END

CHANNELS
END

ZONECHANNELS 0

END

WINDOW 6
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 0
SHOWN 0
MESSAGES
END

CHANNELS
END

ZONECHANNELS 0

END

WINDOW 7
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 0
SHOWN 0
MESSAGES
END

CHANNELS
END

ZONECHANNELS 0

END

WINDOW 8
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 0
SHOWN 0
MESSAGES
END

CHANNELS
END

ZONECHANNELS 0

END

WINDOW 9
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 0
SHOWN 0
MESSAGES
END

CHANNELS
END

ZONECHANNELS 0

END

WINDOW 10
SIZE 0
COLOR 0 0 0 40
LOCKED 1
UNINTERACTABLE 0
DOCKED 0
SHOWN 0
MESSAGES
END

CHANNELS
END

ZONECHANNELS 0

END

"""

_GLOBAL_ACCOUNT_DATA_STORAGE_TYPES = (0, 2, 4)
_GLOBAL_ACCOUNT_DATA_TYPES = _GLOBAL_ACCOUNT_DATA_STORAGE_TYPES
_PER_CHARACTER_ACCOUNT_DATA_TYPES = (1, 3, 5, 6, 7)
_DB_ACCOUNT_DATA_137_TYPES = (1, 2, 3, 7)
_DB_ACCOUNT_DATA_137_RESPONSE_TYPES = (1, 2, 3, 7)


def _build_update_account_data_payload(
    data_type: int,
    account_data: str = "",
    *,
    timestamp: Optional[int] = None,
    guid: int = 0,
) -> bytes:
    raw_guid = struct.pack("<Q", int(guid or 0))
    text = (account_data or "").encode("utf-8", errors="strict")
    compressed = zlib.compress(text)

    bits = BitWriter()
    bits.write_bits(int(data_type) & 0x07, 3)
    _write_guid_mask_bits(bits, raw_guid, (5, 1, 3, 7, 0, 4, 2, 6))

    payload = bytearray(bits.getvalue())
    _append_guid_byte_seq(payload, raw_guid, (3, 1, 5))
    payload.extend(struct.pack("<I", len(text)))
    payload.extend(struct.pack("<I", len(compressed)))
    payload.extend(compressed)
    _append_guid_byte_seq(payload, raw_guid, (7, 4, 0, 6, 2))
    payload.extend(struct.pack("<I", int(timestamp if timestamp is not None else time.time())))
    return bytes(payload)


def _load_sniffed_update_account_data_payloads() -> list[tuple[str, bytes]]:
    if not _ACCOUNT_DATA_CAPTURE_DIR.exists():
        return []

    seen_payloads: set[bytes] = set()
    results: list[tuple[str, bytes]] = []
    for path in sorted(_ACCOUNT_DATA_CAPTURE_DIR.glob(_ACCOUNT_DATA_CAPTURE_GLOB)):
        payload = load_sniff_payload(path)
        if payload in seen_payloads:
            continue
        seen_payloads.add(payload)
        results.append((path.name, payload))
    return results


def _load_raw_account_data_times_payload(profile_name: str | None = None) -> bytes | None:
    if not profile_name:
        return None
    path = get_captures_root(profile=profile_name) / "debug" / "SMSG_ACCOUNT_DATA_TIMES.json"
    if not path.exists():
        Logger.info(
            f"[ACCOUNT_DATA][RAW] missing SMSG_ACCOUNT_DATA_TIMES profile={profile_name!r} path={path}"
        )
        return None
    payload = load_sniff_payload(path)
    Logger.info(
        f"[ACCOUNT_DATA][RAW] loaded SMSG_ACCOUNT_DATA_TIMES profile={profile_name!r} size={len(payload)}"
    )
    return payload


def _load_raw_update_account_data_payload(
    data_type: int,
    profile_name: str | None = None,
) -> bytes | None:
    if not profile_name:
        return None
    json_path = get_captures_root(profile=profile_name) / "json" / "SMSG_UPDATE_ACCOUNT_DATA.json"
    debug_path = get_captures_root(profile=profile_name) / "debug" / "SMSG_UPDATE_ACCOUNT_DATA.json"
    if not json_path.exists() or not debug_path.exists():
        Logger.info(
            f"[ACCOUNT_DATA][RAW] missing SMSG_UPDATE_ACCOUNT_DATA profile={profile_name!r}"
        )
        return None
    try:
        decoded = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        Logger.warning(
            f"[ACCOUNT_DATA][RAW] failed to read {json_path}: {exc}"
        )
        return None
    captured_type = int(decoded.get("type") or 0)
    if captured_type != int(data_type):
        Logger.info(
            f"[ACCOUNT_DATA][RAW] no replay for type={data_type}; "
            f"profile={profile_name!r} only has type={captured_type}"
        )
        return None
    payload = load_sniff_payload(debug_path)
    Logger.info(
        f"[ACCOUNT_DATA][RAW] loaded SMSG_UPDATE_ACCOUNT_DATA type={data_type} "
        f"profile={profile_name!r} size={len(payload)}"
    )
    return payload


def _account_data_text_for_type(data_type: int, account_name: str = "") -> str:
    if int(data_type) == 0:
        return _ACCOUNT_DATA_TYPE_0_DEFAULT
    if int(data_type) == 1:
        return _ACCOUNT_DATA_TYPE_1_DEFAULT
    if int(data_type) == 2:
        return _ACCOUNT_DATA_TYPE_2_DEFAULT
    if int(data_type) == 3:
        return _ACCOUNT_DATA_TYPE_3_DEFAULT
    if int(data_type) == 7:
        return _ACCOUNT_DATA_TYPE_7_DEFAULT
    return ""


def _is_global_account_data_type(data_type: int) -> bool:
    return int(data_type) in _GLOBAL_ACCOUNT_DATA_STORAGE_TYPES


def _normalize_account_data_text(data_type: int, data_text: str) -> str:
    text = str(data_text or "")
    if int(data_type) == 3:
        required_fragments = (
            "BINDINGMODE 0\r\n",
            "bind SHIFT-6 ACTIONPAGE6\r\n",
            "bind M TOGGLEWORLDMAP\r\n",
        )
        if not text.strip():
            return _ACCOUNT_DATA_TYPE_3_DEFAULT
        if all(fragment in text for fragment in required_fragments):
            return text
        Logger.info("[ACCOUNT_DATA] normalizing type=3 payload to canonical bindings layout")
        return _ACCOUNT_DATA_TYPE_3_DEFAULT

    if int(data_type) != 7:
        return text

    if not text.strip():
        return _ACCOUNT_DATA_TYPE_7_DEFAULT

    required_fragments = (
        "WINDOW 2\nNAME Combat Log",
        "INSTANCE_CHAT",
        "INSTANCE_CHAT_LEADER",
        "CHANNELS\nEND\n\nZONECHANNELS 2097155",
    )
    if all(fragment in text for fragment in required_fragments) and "LookingForGroup" not in text:
        if text.rstrip("\n") == _ACCOUNT_DATA_TYPE_7_DEFAULT.rstrip("\n"):
            return _ACCOUNT_DATA_TYPE_7_DEFAULT
        return text

    Logger.info("[ACCOUNT_DATA] normalizing type=7 payload to canonical chat layout")
    return _ACCOUNT_DATA_TYPE_7_DEFAULT


def _account_data_mask_for_types(data_types: tuple[int, ...]) -> int:
    mask = 0
    for data_type in data_types:
        mask |= (1 << int(data_type))
    return mask


def _account_data_times_list_for_types(now: int, data_types: tuple[int, ...]) -> list[int]:
    timestamps = [0] * 8
    for data_type in data_types:
        stored = session.account_data_times.get(int(data_type))
        timestamps[int(data_type)] = int(stored if stored is not None else now)
    return timestamps


def _load_account_data_scope(owner_id: int, *, per_character: bool) -> None:
    if int(owner_id or 0) <= 0:
        return
    loaded = DatabaseConnection.load_account_data(int(owner_id), per_character=per_character)
    data_types = _PER_CHARACTER_ACCOUNT_DATA_TYPES if per_character else _GLOBAL_ACCOUNT_DATA_STORAGE_TYPES
    seeded_types: list[int] = []
    now = int(time.time())
    for data_type in data_types:
        default_text = _account_data_text_for_type(int(data_type), str(session.account_name or ""))
        should_persist = False
        if int(data_type) in loaded:
            timestamp, data_text = loaded[int(data_type)]
            normalized_text = _normalize_account_data_text(int(data_type), str(data_text or ""))
            if normalized_text != str(data_text or ""):
                data_text = normalized_text
                timestamp = int(timestamp or now)
                should_persist = USE_DB_ACCOUNT_DATA_137 and per_character and int(data_type) in _DB_ACCOUNT_DATA_137_TYPES
        elif default_text:
            timestamp, data_text = now, default_text
            should_persist = USE_DB_ACCOUNT_DATA_137 and per_character and int(data_type) in _DB_ACCOUNT_DATA_137_TYPES
        else:
            timestamp, data_text = 0, ""

        if should_persist:
            DatabaseConnection.save_account_data(
                int(owner_id),
                int(data_type),
                int(timestamp),
                str(data_text),
                per_character=per_character,
            )
            seeded_types.append(int(data_type))

        session.account_data[int(data_type)] = str(data_text or "")
        session.account_data_times[int(data_type)] = int(timestamp or 0)
        if data_text:
            session.account_data_mask |= (1 << int(data_type))
        else:
            session.account_data_mask &= ~(1 << int(data_type))

    if seeded_types:
        Logger.info(
            "[ACCOUNT_DATA] seeded defaults scope=%s owner_id=%s types=%s"
            % (
                "character" if per_character else "account",
                int(owner_id),
                ",".join(str(v) for v in seeded_types),
            )
        )


def _load_global_account_data(account_id: int | None = None) -> None:
    owner_id = int(account_id if account_id is not None else getattr(session, "account_id", 0) or 0)
    if owner_id <= 0:
        return
    _load_account_data_scope(owner_id, per_character=False)


def _load_character_account_data(char_guid: int | None = None) -> None:
    owner_id = int(char_guid if char_guid is not None else getattr(session, "char_guid", 0) or 0)
    if owner_id <= 0:
        return
    _load_account_data_scope(owner_id, per_character=True)


def _persist_account_data_entry(
    data_type: int,
    account_text: str,
    timestamp: int,
) -> bool:
    if not 0 <= int(data_type) < 8:
        return False

    if USE_DB_ACCOUNT_DATA_137 and int(data_type) not in _DB_ACCOUNT_DATA_137_TYPES:
        return False

    is_global = _is_global_account_data_type(int(data_type))
    owner_id = int(session.account_id or 0) if is_global else int(session.char_guid or 0)
    if owner_id <= 0:
        return False

    return DatabaseConnection.save_account_data(
        owner_id,
        int(data_type),
        int(timestamp or 0),
        str(account_text or ""),
        per_character=not is_global,
    )


def _flush_account_data_types_to_db(
    data_types: tuple[int, ...],
    *,
    seed_defaults: bool = False,
) -> None:
    now = int(time.time())
    saved_types: list[int] = []

    for data_type in data_types:
        data_type = int(data_type)
        stored_text = session.account_data.get(data_type)
        if stored_text is None:
            if not seed_defaults:
                continue
            stored_text = _account_data_text_for_type(data_type, str(session.account_name or ""))
            session.account_data[data_type] = stored_text

        timestamp = int(session.account_data_times.get(data_type) or now)
        session.account_data_times[data_type] = timestamp
        if stored_text:
            session.account_data_mask |= (1 << data_type)
        else:
            session.account_data_mask &= ~(1 << data_type)

        if _persist_account_data_entry(data_type, str(stored_text or ""), timestamp):
            saved_types.append(data_type)

    if saved_types:
        Logger.info(
            "[ACCOUNT_DATA] flushed types=%s to DB"
            % ",".join(str(v) for v in saved_types)
        )


_ACCOUNT_DATA_PAYLOAD_CACHE: dict[tuple[int, int], bytes] = {}


def _build_update_account_data_payload_target_len(target_len: int, data_type: int = 0) -> bytes:
    cache_key = (int(target_len), int(data_type))
    cached = _ACCOUNT_DATA_PAYLOAD_CACHE.get(cache_key)
    if cached is not None:
        return cached

    seed = 0
    for raw_len in range(1, 4097):
        rnd = random.Random(seed + raw_len)
        filler = bytes(rnd.randrange(256) for _ in range(raw_len)).hex()
        payload = _build_update_account_data_payload(int(data_type), filler)
        if len(payload) == int(target_len):
            _ACCOUNT_DATA_PAYLOAD_CACHE[cache_key] = payload
            Logger.info(
                f"[WorldHandlers] Built account-data payload len={target_len} "
                f"using raw_len={raw_len} data_type={data_type}"
            )
            return payload

    Logger.warning(
        f"[WorldHandlers] Could not build exact account-data payload len={target_len}; "
        "falling back to empty payload"
    )
    fallback = _build_update_account_data_payload(int(data_type), "")
    _ACCOUNT_DATA_PAYLOAD_CACHE[cache_key] = fallback
    return fallback


def _build_minimal_post_timesync_account_packets() -> list[tuple[str, bytes]]:
    # SkyFire does not proactively push account-data blobs after ACTIVE_MOVER.
    return []


def _account_data_payload_types_to_push() -> tuple[int, ...]:
    return _PER_CHARACTER_ACCOUNT_DATA_TYPES


def _account_data_times_mask() -> int:
    return _account_data_mask_for_types(_account_data_payload_types_to_push())


def _account_data_times_list(now: int) -> list[int]:
    return _account_data_times_list_for_types(now, _account_data_payload_types_to_push())


def _build_post_timesync_support_packets() -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    for opcode_name in (
        "SMSG_LOAD_CUF_PROFILES",
        "SMSG_SPELL_GO",
        "SMSG_SPELL_EXECUTE_LOG",
        "SMSG_BATTLE_PET_JOURNAL",
        "SMSG_BATTLE_PET_JOURNAL_LOCK_ACQUIRED",
    ):
        payload = _load_payload_packet(opcode_name)
        if payload is None:
            Logger.warning(f"[WorldHandlers] Missing capture payload for {opcode_name}")
            continue
        responses.append((opcode_name, payload))
    if responses:
        Logger.info(
            "[WorldHandlers] Post-time-sync support packets="
            + ",".join(f"{name}:{len(payload)}" for name, payload in responses)
        )
    return responses


def _get_realm_name() -> str:
    try:
        realm = DatabaseConnection.get_realmlist()
        if realm and getattr(realm, "name", None):
            return str(realm.name)
    except Exception:
        pass
    return ""


def _build_name_query_response(
    guid: int,
    *,
    name: str,
    realm_name: str,
    race: int,
    gender: int,
    class_id: int,
) -> bytes:
    payload = bytearray()
    payload.extend(str(name or "").encode("utf-8", errors="strict") + b"\x00")
    payload.extend(str(realm_name or "").encode("utf-8", errors="strict") + b"\x00")
    payload.extend(struct.pack("<III", int(race), int(gender), int(class_id)))
    payload.append(0)
    return EncoderHandler.encode_packet(
        "SMSG_QUERY_PLAYER_NAME_RESPONSE",
        {
            "guid": int(guid),
            "raw": bytes(payload),
        },
    )


def _build_name_query_response_no_data(guid: int) -> bytes:
    return _build_name_query_response(
        guid,
        name="",
        realm_name="",
        race=0,
        gender=0,
        class_id=0,
    )


def _decode_quest_giver_status_query_guid(payload: bytes) -> Optional[int]:
    if not payload:
        return None

    mask = payload[0]
    guid = [0] * 8
    offset = 1

    for bit_pos, index in enumerate((4, 3, 2, 1, 0, 5, 7, 6)):
        guid[index] = 1 if (mask & (1 << bit_pos)) else 0

    for index in (5, 7, 4, 0, 2, 1, 6, 3):
        if not guid[index]:
            continue
        if offset >= len(payload):
            return None
        guid[index] ^= payload[offset]
        offset += 1

    return int.from_bytes(bytes(guid), "little", signed=False)


def _build_questgiver_status_payload(guid: int, status: int = 0) -> bytes:
    return EncoderHandler.encode_packet(
        "SMSG_QUESTGIVER_STATUS",
        {
            "npcGUID": int(guid or 0),
            "status": int(status),
        },
    )


def _build_request_cemetery_list_response_payload(
    cemetery_ids: list[int] | None = None,
    *,
    is_microdungeon: int = 0,
) -> bytes:
    cemetery_ids = [int(cemetery_id) for cemetery_id in (cemetery_ids or [])]
    return EncoderHandler.encode_packet(
        "SMSG_REQUEST_CEMETERY_LIST_RESPONSE",
        {
            "is_microdungeon": int(is_microdungeon),
            "count": len(cemetery_ids),
            "cemetery_ids": cemetery_ids,
        },
    )


def _resolve_login_character_guid(
    login_guid: Optional[int],
    payload: bytes,
    account_id: Optional[int],
    realm_id: Optional[int],
    account_name: Optional[str] = None,
) -> Optional[int]:
    def _log_match(candidate: int, row: object) -> None:
        player_name = str(getattr(row, "name", "") or f"Player{candidate}")
        account_label = str(account_name or account_id or "?")
        Logger.info(
            f"[WorldHandlers] PLAYER_LOGIN selected player={player_name} "
            f"account={account_label} char_guid={candidate}"
        )

    def _decode_bitpacked_guid(
        body: bytes,
        *,
        mask_order: tuple[int, ...],
        byte_order: tuple[int, ...],
    ) -> Optional[int]:
        if len(body) < 5:
            return None

        offset = 4  # skip the client float seen in MoP PLAYER_LOGIN
        mask = body[offset]
        offset += 1

        raw = [0] * 8
        for bit_pos, byte_index in enumerate(mask_order):
            if mask & (1 << bit_pos):
                raw[byte_index] = 1

        for byte_index in byte_order:
            if not raw[byte_index]:
                continue
            if offset >= len(body):
                return None
            raw[byte_index] ^= body[offset]
            offset += 1

        if offset != len(body):
            return None

        return int.from_bytes(bytes(raw), "little", signed=False)

    candidates: list[int] = []

    if login_guid is not None:
        try:
            low_from_login, _realm_from_login, _high_from_login = GuidHelper.decode_login_guid(login_guid)
            candidates.append(int(low_from_login))
        except Exception:
            pass

    if payload and len(payload) >= 6:
        raw6 = payload[:6]
        candidates.extend(
            [
                int.from_bytes(raw6[:4], "little", signed=False),
                int.from_bytes(raw6[:4], "big", signed=False),
            ]
        )

    deduped: list[int] = []
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)

    for candidate in deduped:
        try:
            row = DatabaseConnection.get_character(candidate, realm_id)
            if row and (account_id is None or int(row.account) == int(account_id)):
                _log_match(int(candidate), row)
                return int(candidate)
        except Exception:
            continue

    if account_id is not None and realm_id is not None:
        try:
            rows = DatabaseConnection.get_characters_for_account(account_id, realm_id)
        except Exception:
            rows = []

        if login_guid is None and rows:
            fallback = rows[0]
            Logger.warning(
                f"[WorldHandlers] PLAYER_LOGIN missing login guid; "
                f"falling back to first character guid={int(fallback.guid)} slot={int(fallback.slot or 0)}"
            )
            return int(fallback.guid)

        row_by_world_guid = {
            int(GuidHelper.make(HighGuid.PLAYER, int(realm_id), int(row.guid))): int(row.guid)
            for row in rows
        }
        row_by_login_guid = {
            int(GuidHelper.make_login_guid(int(row.guid), int(realm_id), HighGuid.PLAYER)): int(row.guid)
            for row in rows
        }

        # Current internal/client-simulator format: 48-bit login guid payload.
        if payload and len(payload) == 6:
            try:
                candidate_login_guid = int.from_bytes(payload, "little", signed=False)
            except Exception:
                candidate_login_guid = None
            if candidate_login_guid in row_by_login_guid:
                candidate = row_by_login_guid[candidate_login_guid]
                row = DatabaseConnection.get_character(candidate, realm_id)
                if row:
                    _log_match(candidate, row)
                return candidate

        # Retail MoP format: float + XOR-bitpacked full player guid.
        packed_variants = (
            ((1, 4, 7, 3, 2, 6, 5, 0), (5, 1, 0, 6, 2, 4, 7, 3), "5.4.8"),
            ((7, 6, 0, 4, 5, 2, 3, 1), (5, 0, 1, 6, 7, 2, 3, 4), "5.4.7"),
        )
        for mask_order, byte_order, label in packed_variants:
            candidate_world_guid = _decode_bitpacked_guid(
                payload,
                mask_order=mask_order,
                byte_order=byte_order,
            )
            if candidate_world_guid in row_by_world_guid:
                candidate = row_by_world_guid[candidate_world_guid]
                row = DatabaseConnection.get_character(candidate, realm_id)
                if row:
                    _log_match(candidate, row)
                return candidate

        # Observed retail client variant in proxy:
        #   float(1000.0) + 3-byte blob, e.g. 05 02 03 for low guid 2.
        # In that format the middle byte tracks the character low guid for
        # normal small DB ids, while the last byte carries the player high guid.
        if len(payload) == 7:
            compact = payload[4:]
            compact_candidates = []
            if len(compact) >= 2:
                compact_candidates.append(int(compact[1]))
                compact_candidates.append(int(compact[1]) ^ 0x01)

            seen_compact = set()
            for candidate in compact_candidates:
                if candidate in seen_compact:
                    continue
                seen_compact.add(candidate)
                if candidate <= 0:
                    continue
                row = DatabaseConnection.get_character(candidate, realm_id)
                if row and int(row.account) == int(account_id):
                    _log_match(candidate, row)
                    return candidate

    if account_id is not None and realm_id is not None:
        try:
            rows = DatabaseConnection.get_characters_for_account(account_id, realm_id)
            for row in rows:
                expected = GuidHelper.make_login_guid(
                    low=int(row.guid),
                    realm=int(realm_id),
                    high=HighGuid.PLAYER,
                )
                if int(expected) == int(login_guid):
                    _log_match(int(row.guid), row)
                    return int(row.guid)
        except Exception:
            pass

    Logger.warning(
        f"[WorldHandlers] PLAYER_LOGIN could not resolve login_guid="
        f"{'None' if login_guid is None else f'0x{int(login_guid):X}'}; "
        f"candidate lows={deduped}"
    )
    return None

def _resolve_session_ids() -> Tuple[Optional[int], Optional[int]]:
    """
    Ensure session.account_id and session.realm_id are populated if possible.
    """
    # account_id from account_name
    if session.account_id is None and session.account_name:
        try:
            acc = DatabaseConnection.get_user_by_username(session.account_name)
            if not acc:
                acc = DatabaseConnection.get_user_by_username(session.account_name.upper())
            if acc:
                session.account_id = acc.id
        except Exception:
            pass

    # realm_id fallback
    if session.realm_id is None:
        try:
            realm = DatabaseConnection.get_realmlist()
            if realm:
                session.realm_id = int(realm.id)
        except Exception:
            pass

    return session.account_id, session.realm_id

# -----------------------------------------------------------------------------
# Equipment/appearance helpers for ENUM_CHARACTERS_RESULT
# -----------------------------------------------------------------------------

_INVTYPE_SLOT_MAP = {
    1: [0],   # head
    2: [1],   # neck
    3: [2],   # shoulders
    4: [3],   # shirt
    5: [4],   # chest
    20: [4],  # robe -> chest slot
    6: [5],   # waist
    7: [6],   # legs
    8: [7],   # feet
    9: [8],   # wrists
    10: [9],  # hands
    11: [10, 11],  # finger
    12: [12, 13],  # trinket
    16: [14],  # cloak
    13: [15],  # weapon
    17: [15],  # 2H weapon
    21: [15],  # weapon main hand
    22: [16],  # weapon off hand
    14: [16],  # shield
    23: [16],  # holdable
    15: [17],  # ranged
    25: [17],  # thrown
    26: [17],  # ranged right
    28: [17],  # relic
    19: [18],  # tabard
    18: [19, 20, 21, 22],  # bag slots
}

_EQUIPMENT_SLOTS = 23

_DBC_CHAR_START_OUTFIT_FMT = (
    "dbbbX"
    "iiiiiiiiiiiiiiiiiiiiiiii"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)
_DBC_CHAR_START_OUTFIT_CACHE: Optional[dict[tuple[int, int, int], list[int]]] = None
_DBC_CHAR_START_OUTFIT_MERGED: Optional[dict[tuple[int, int], list[int]]] = None
_PLAYER_FACTION_TEMPLATE_BY_RACE = {
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 115,
    8: 116,
    9: 2204,
    10: 1610,
    11: 1629,
    12: 1,
    13: 1,
    14: 1,
    15: 1,
    16: 1,
    17: 1,
    18: 1,
    19: 1,
    20: 1,
    21: 1,
    22: 2203,
    23: 1,
    24: 2395,
    25: 2401,
    26: 2402,
}
_PLAYER_DISPLAY_POWER_BY_CLASS = {
    1: 1,   # Warrior -> rage
    2: 0,   # Paladin -> mana
    3: 2,   # Hunter -> focus
    4: 3,   # Rogue -> energy
    5: 0,   # Priest -> mana
    6: 6,   # Death Knight -> runic power
    7: 0,   # Shaman -> mana
    8: 0,   # Mage -> mana
    9: 0,   # Warlock -> mana
    10: 3,  # Monk -> energy on login in common specs
    11: 0,  # Druid -> mana in base form
}
_DEFAULT_MAX_PRIMARY_POWER_BY_DISPLAY = {
    0: 100,
    1: 100,
    2: 100,
    3: 100,
    6: 100,
}

def _default_equipment() -> list[dict]:
    return [{"enchant": 0, "int_type": 0, "display_id": 0} for _ in range(_EQUIPMENT_SLOTS)]

def _equipment_is_empty(entries: list[dict]) -> bool:
    return (not entries) or all((e.get("display_id") or 0) == 0 for e in entries)

def _resolve_dbc_root() -> Optional[Path]:
    return get_dbc_root()

def _load_char_start_outfit() -> dict[tuple[int, int, int], list[int]]:
    global _DBC_CHAR_START_OUTFIT_CACHE, _DBC_CHAR_START_OUTFIT_MERGED
    if _DBC_CHAR_START_OUTFIT_CACHE is not None:
        return _DBC_CHAR_START_OUTFIT_CACHE

    dbc_root = _resolve_dbc_root()
    if not dbc_root:
        Logger.warning("[WorldHandlers] DBC root not configured for CharStartOutfit.")
        _DBC_CHAR_START_OUTFIT_CACHE = {}
        _DBC_CHAR_START_OUTFIT_MERGED = {}
        return _DBC_CHAR_START_OUTFIT_CACHE

    dbc_path = dbc_root / "CharStartOutfit.dbc"
    if not dbc_path.is_file():
        Logger.warning(f"[WorldHandlers] CharStartOutfit.dbc not found at {dbc_path}.")
        _DBC_CHAR_START_OUTFIT_CACHE = {}
        _DBC_CHAR_START_OUTFIT_MERGED = {}
        return _DBC_CHAR_START_OUTFIT_CACHE

    try:
        records = read_dbc(dbc_path, _DBC_CHAR_START_OUTFIT_FMT)
    except Exception as exc:
        Logger.warning(f"[WorldHandlers] Failed to read CharStartOutfit.dbc: {exc}")
        _DBC_CHAR_START_OUTFIT_CACHE = {}
        _DBC_CHAR_START_OUTFIT_MERGED = {}
        return _DBC_CHAR_START_OUTFIT_CACHE

    outfits: dict[tuple[int, int, int], list[int]] = {}
    merged: dict[tuple[int, int], set[int]] = {}
    for row in records:
        if len(row) < 28:
            continue
        race = int(row[1])
        class_ = int(row[2])
        gender = int(row[3])
        items = [int(item_id) for item_id in row[4:4 + 24] if int(item_id) > 0]
        if not items:
            continue
        outfits[(race, class_, gender)] = items
        merged.setdefault((race, class_), set()).update(items)

    _DBC_CHAR_START_OUTFIT_CACHE = outfits
    _DBC_CHAR_START_OUTFIT_MERGED = {k: sorted(v) for k, v in merged.items()}
    Logger.info(f"Loaded CharStartOutfit entries: {len(outfits)}")
    return _DBC_CHAR_START_OUTFIT_CACHE

def _get_outfit_items(race: int, class_: int, gender: int | None = None) -> list[int]:
    outfits = _load_char_start_outfit()
    if not outfits:
        return []
    if gender is not None:
        items = outfits.get((race, class_, gender))
        if items:
            return items
    if _DBC_CHAR_START_OUTFIT_MERGED:
        items = _DBC_CHAR_START_OUTFIT_MERGED.get((race, class_))
        if items:
            return items
    return []



def _build_equipment_from_starting_items(race: int, class_: int, gender: int | None = None) -> Optional[list[dict]]:
    dbc_entries = _get_outfit_items(race, class_, gender)
    db_entries = DatabaseConnection.get_starting_item_entries(race, class_, gender)
    if not dbc_entries and not db_entries:
        return None

    merged_entries = list(dict.fromkeys(dbc_entries + db_entries))
    items = DatabaseConnection.get_item_template_map(merged_entries)
    if not items:
        return None

    equipment = _default_equipment()
    used_slots = set()

    def _apply_entries(entries: list[int], allow_override: bool) -> None:
        for entry in entries:
            mapped = items.get(entry)
            if not mapped:
                continue
            display_id, inv_type = mapped
            if not display_id or inv_type <= 0:
                continue
            slots = _INVTYPE_SLOT_MAP.get(inv_type)
            if not slots:
                continue
            for slot in slots:
                if not allow_override and slot in used_slots:
                    continue
                equipment[slot] = {"enchant": 0, "int_type": inv_type, "display_id": display_id}
                used_slots.add(slot)
                break

    _apply_entries(dbc_entries, allow_override=False)
    _apply_entries(db_entries, allow_override=True)

    if _equipment_is_empty(equipment):
        return None
    return equipment


def _resolve_display_power_for_class(class_id: int) -> int:
    return int(_PLAYER_DISPLAY_POWER_BY_CLASS.get(int(class_id) or 0, 0))


def _resolve_primary_power_for_row(row, class_id: int) -> tuple[int, int, int]:
    display_power = _resolve_display_power_for_class(class_id)
    power_field = {
        0: "power1",
        1: "power2",
        2: "power3",
        3: "power4",
        6: "power5",
    }.get(display_power, "power1")
    current = int(getattr(row, power_field, 0) or 0)
    default_max = int(_DEFAULT_MAX_PRIMARY_POWER_BY_DISPLAY.get(display_power, 100))
    if current <= 0:
        current = default_max
    return display_power, current, max(current, default_max)

def get_auth_challenge() -> Optional[tuple[str, bytes]]:
    """
    Build SMSG_AUTH_CHALLENGE (MoP).
    Payload MUST be exactly 39 bytes:
      uint16
      uint32[8]
      uint8
      uint32 seed
    """

    fields = {
        "uint16_0": 0,

        # MoP expects NON-zero filler here
        "uint32_zeros": [random.getrandbits(32) for _ in range(8)],

        # must be 1, not 0
        "uint8_value": 1,

        # real seed
        "seed": random.getrandbits(32),
    }

    payload = EncoderHandler.encode_packet("SMSG_AUTH_CHALLENGE", fields)

    # HARD sanity check – this catches 99% of bugs
    if len(payload) != 39:
        raise ValueError(
            f"SMSG_AUTH_CHALLENGE payload size is {len(payload)}, expected 39"
        )

    return "SMSG_AUTH_CHALLENGE", payload
    
def reset_state() -> None:
    """
    Called by worldserver on new connections.
    """
    _detach_session_from_world_state(session)
    session.global_state = global_state
    session.account_id = None
    session.account_name = None
    session.realm_id = None
    session.player_guid = None
    session.world_guid = None
    session.char_guid = None
    session.time_sync_seq = 0
    session.last_position_save_at = 0.0
    session.position_dirty = False
    session.persist_map_id = 0
    session.persist_zone = 0
    session.persist_instance_id = 0
    session.persist_x = 0.0
    session.persist_y = 0.0
    session.persist_z = 0.0
    session.persist_orientation = 0.0
    session.last_saved_map_id = 0
    session.last_saved_zone = 0
    session.last_saved_instance_id = 0
    session.last_saved_x = 0.0
    session.last_saved_y = 0.0
    session.last_saved_z = 0.0
    session.last_saved_orientation = 0.0
    _reset_login_flow_state()

def preload_cache() -> None:
    """
    Warm up optional caches (DBC etc).
    """
    try:
        _load_char_start_outfit()
    except Exception as exc:
        Logger.warning(f"[WorldHandlers] preload_cache failed: {exc}")


def _current_position_snapshot() -> tuple[int, int, Position | None]:
    return movement_handlers._current_position_snapshot(session)


def _saved_position_snapshot() -> tuple[int, int, Position | None]:
    return movement_handlers._saved_position_snapshot(session)


def _mark_position_dirty() -> None:
    movement_handlers._mark_position_dirty(session)


def _capture_persist_position_from_session() -> None:
    movement_handlers._capture_persist_position_from_session(session)


def _remember_saved_position(now: float | None = None) -> None:
    movement_handlers._remember_saved_position(session, now)


def _save_session_position(*, reason: str, online: int | None = None, force: bool = False) -> bool:
    return movement_handlers._save_session_position(
        session,
        reason=str(reason),
        online=online,
        force=force,
    )


def _maybe_periodic_position_save() -> bool:
    return movement_handlers._maybe_periodic_position_save(
        session,
        position_save_interval_seconds=_POSITION_SAVE_INTERVAL_SECONDS,
    )

# -----------------------------------------------------------------------------
# CMSG handlers
# -----------------------------------------------------------------------------

def handle_CMSG_PING(ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    decoded = _log_cmsg(ctx)
    ping_val = int(decoded.get("ping_id", 0) or 0)
    try:
        pong_payload = EncoderHandler.encode_packet("SMSG_PONG", {"ping_id": ping_val})
        return 0, ("SMSG_PONG", pong_payload)
    except Exception as exc:
        Logger.error(f"[WorldHandlers] SMSG_PONG encode failed: {exc}")
        return 1, None


def handle_CMSG_LOGOUT_REQUEST(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    _log_cmsg(ctx)
    Logger.info("[WorldHandlers] CMSG_LOGOUT_REQUEST")
    if USE_DB_ACCOUNT_DATA_137:
        _flush_account_data_types_to_db(_DB_ACCOUNT_DATA_137_TYPES, seed_defaults=True)
    _capture_persist_position_from_session()
    _mark_position_dirty()
    _save_session_position(reason="logout", online=0, force=True)

    try:
        logout_response = EncoderHandler.encode_packet(
            "SMSG_LOGOUT_RESPONSE",
            {
                "logout_result": 0,
                "instant_logout": 1,
            },
        )
    except Exception as exc:
        Logger.error(f"[WorldHandlers] SMSG_LOGOUT_RESPONSE encode failed: {exc}")
        return 1, None

    return 0, [
        ("SMSG_LOGOUT_RESPONSE", logout_response),
        ("SMSG_LOGOUT_COMPLETE", b""),
    ]


def handle_CMSG_AUTH_SESSION(ctx: PacketContext):
    decoded = _log_cmsg(ctx)

    # --- resolve account name ---
    session.account_name = (
        decoded.get("account")
        or decoded.get("username")
        or decoded.get("I")
    )
    session.realm_id = decoded.get("VirtualRealmID")

    if not session.account_name:
        Logger.error("[WorldHandlers] AUTH_SESSION missing account name")
        return 1, None

    # --- resolve account_id from auth DB ---
    account_id = DatabaseConnection.get_account_id_by_username(
        session.account_name
    )
    if account_id is None:
        Logger.error(
            f"[WorldHandlers] Unknown account '{session.account_name}'"
        )
        return 1, None

    session.account_id = account_id
    session.player_guid = None
    session.world_guid = None
    session.char_guid = None
    session.player_name = None
    _reset_login_flow_state()
    _set_login_state(LoginState.AUTHED)

    Logger.info(
        f"[WorldHandlers] AUTH_SESSION account={session.account_name} "
        f"account_id={session.account_id} realm_id={session.realm_id}"
    )

    ctx = _build_world_login_context()
    return 0, build_char_screen_packets(ctx)

def handle_CMSG_ENUM_CHARACTERS(ctx: PacketContext):
    account_id = session.account_id
    realm_id = session.realm_id

    if account_id is None or realm_id is None:
        raise RuntimeError(
            "[WorldHandlers] Missing session account_id or realm_id "
            f"(account_id={account_id}, realm_id={realm_id})"
        )

    try:
        payload = build_ENUM_CHARACTERS_RESULT(
            account_id=account_id,
            realm_id=realm_id,
        )
        _set_login_state(LoginState.CHAR_SCREEN)

        return 0, [
            ("SMSG_ENUM_CHARACTERS_RESULT", payload)
        ]

    except Exception as exc:
        Logger.error(
            f"[WorldHandlers] ENUM_CHARACTERS build failed "
            f"(account_id={account_id}, realm_id={realm_id}): {exc}"
        )
        raise
def handle_CMSG_PLAYER_LOGIN(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    payload = ctx.payload
    decoded = _log_cmsg(ctx)

    login_guid = None
    if len(payload) == 6:
        login_guid = int.from_bytes(payload, "little", signed=False)
    elif len(payload) >= 6:
        login_guid = int.from_bytes(payload[:6], "little", signed=False)
    # --------------------------------------------------
    # Account data (MoP: ALWAYS 8 slots)
    # --------------------------------------------------
    session.account_data = {}
    session.account_data_times = {i: 0 for i in range(8)}
    session.account_data_mask = 0
    _load_global_account_data()
    # --------------------------------------------------
    # Decode LOGIN GUID (48-bit)
    # low32 = character DB guid
    # --------------------------------------------------
    char_guid = _resolve_login_character_guid(
        login_guid=login_guid,
        payload=payload,
        account_id=session.account_id,
        realm_id=session.realm_id,
        account_name=getattr(session, "account_name", None),
    )
    if char_guid is None:
        Logger.error("[WorldHandlers] CMSG_PLAYER_LOGIN could not resolve selected character")
        return 1, None

    # IMPORTANT:
    # Realm MUST come from authenticated session
    realm_id = session.realm_id

    # --------------------------------------------------
    # Store identity on session
    # --------------------------------------------------
    selected_world_guid = int(
        GuidHelper.make(
            high=HighGuid.PLAYER,
            realm=int(realm_id or 0),
            low=int(char_guid or 0),
        )
    )
    session.player_guid = selected_world_guid
    session.world_guid = selected_world_guid
    session.char_guid = char_guid
    session.active_mover_guid = selected_world_guid
    _load_character_account_data()
    session.account_data_mask = _account_data_mask_for_types(_PER_CHARACTER_ACCOUNT_DATA_TYPES)
    Logger.info(
        "[GUID MODE]\n"
        f"selected_guid = 0x{selected_world_guid:X}\n"
        f"session_guid = 0x{int(session.world_guid or 0):X}"
    )
    Logger.info(f"[GUID MODE ACTIVE] player_guid=0x{int(session.player_guid or 0):X}")

    # --------------------------------------------------
    # Load character from DB (LIVE DATA)
    # --------------------------------------------------
    row = DatabaseConnection.get_character(char_guid, realm_id)
    if not row:
        Logger.error(
            f"[WorldHandlers] Character not found guid={char_guid} realm={realm_id}"
        )
        return 1, None
    selected_name = str(getattr(row, "name", "") or f"Player{char_guid}")
    Logger.info(
        f"[WorldHandlers] PLAYER_LOGIN selected name={selected_name} "
        f"char_guid={char_guid} realm={realm_id}"
    )

    # --------------------------------------------------
    # Map / zone / instance
    # --------------------------------------------------
    session.map_id = int(row.map or 0)
    session.zone = int(row.zone or 0)
    session.instance_id = int(row.instance_id or 0)

    # --------------------------------------------------
    # Position / orientation
    # --------------------------------------------------
    loaded_position = position_from_row(row)
    normalized_loaded_position = normalize_position(correct_z_if_invalid(loaded_position), safe_z=True)
    if normalized_loaded_position is None:
        Logger.warning(
            "[POS_SAVE] invalid DB position on login player=%s raw=%s; falling back to origin",
            int(char_guid),
            format_position(loaded_position),
        )
        normalized_loaded_position = Position(
            map=int(getattr(row, "map", 0) or 0),
            x=0.0,
            y=0.0,
            z=0.0,
            orientation=0.0,
        )

    session.x = float(normalized_loaded_position.x)
    session.y = float(normalized_loaded_position.y)
    session.z = float(normalized_loaded_position.z)
    session.orientation = float(normalized_loaded_position.orientation)
    Logger.info(
        "[Position] load guid=%s name=%s map=%s zone=%s x=%.3f y=%.3f z=%.3f o=%.3f",
        int(char_guid),
        selected_name,
        int(session.map_id),
        int(session.zone),
        float(session.x),
        float(session.y),
        float(session.z),
        float(session.orientation),
    )
    _capture_persist_position_from_session()
    _remember_saved_position()
    DatabaseConnection.save_character_online_state(
        int(char_guid),
        int(realm_id),
        online=1,
    )

    # --------------------------------------------------
    # Movement speeds (MoP defaults)
    # --------------------------------------------------
    _restore_default_movement_speeds(session)
    session.is_mounted = False
    session.mount_spell = None

    # --------------------------------------------------
    # Gameplay state (LIVE)
    # --------------------------------------------------
    session.level = int(row.level or 1)
    session.class_id = int(row.class_ or 0)
    session.race = int(row.race or 0)
    session.gender = int(row.gender or 0)

    session.money = int(row.money or 0)
    session.health = int(row.health or 1)
    session.display_power, session.power_primary, session.max_power_primary = _resolve_primary_power_for_row(
        row,
        session.class_id,
    )
    session.faction_template = int(_PLAYER_FACTION_TEMPLATE_BY_RACE.get(session.race, 0))
    session.player_bytes = int(row.playerBytes or 0)
    session.player_bytes2 = int(row.playerBytes2 or 0)
    session.player_flags = int(row.playerFlags or 0)
    session.equipment_cache_raw = [
        int(value)
        for value in str(getattr(row, "equipmentCache", "") or "").split()
        if value.strip()
    ]
    session.player_name = selected_name
    _attach_session_to_world_state(session, map_id=int(session.map_id))

    # --------------------------------------------------
    # Spells / actions (create info)
    # --------------------------------------------------
    session.known_spells = DatabaseConnection.get_character_spells(char_guid)
    _ensure_language_spells_known()
    _ensure_mount_spells_known()
    session.action_buttons = DatabaseConnection.get_character_action_buttons(char_guid)

    # --------------------------------------------------
    # World / phase / weather
    # --------------------------------------------------
    session.phase_data = {}
    session.world_states = {}
    session.single_world_state = {}
    session.weather = {}

    # --------------------------------------------------
    # Time sync
    # --------------------------------------------------
    session.server_time = int(time.time())
    session.game_time = _pack_wow_game_time(session.server_time + int(getattr(session, "time_offset", 0) or 0))
    session.time_speed = float(getattr(session, "time_speed", 0.01666667) or 0.01666667)
    session.time_sync_seq = 0
    _reset_login_flow_state(preserve_loading_screen_done=bool(getattr(session, "loading_screen_done", False)))

    _resolve_session_ids()
    _set_login_state(LoginState.PLAYER_LOGIN)

    Logger.success(
        f"[WorldHandlers] PLAYER_LOGIN name={session.player_name} "
        f"char_guid={char_guid} map={session.map_id} zone={session.zone} realm={realm_id}"
    )

    # --------------------------------------------------
    # BUILD CONTEXT *AFTER* SESSION IS COMPLETE
    # --------------------------------------------------
    ctx = _build_world_login_context()
    responses: list[tuple[str, bytes]] = []
    # Disabled for minimal UPDATE_OBJECT debugging:
    # if _is_skyfire_gmisland_session():
    #     responses.extend(_build_skyfire_gmisland_login_prologue())
    responses.extend(build_player_login_packets(ctx))
    if getattr(session, "loading_screen_done", False):
        Logger.info("[WorldHandlers] PLAYER_LOGIN consuming deferred LOADING_SCREEN_NOTIFY show=0")
        responses.extend(_queue_world_bootstrap_transition(ctx))

    Logger.info(f"[DEBUG] char_guid={session.char_guid}")
    Logger.info(f"[DEBUG] account_id={session.account_id}")
    Logger.info(f"[DEBUG] loaded account_data keys={list(session.account_data.keys())}")
    Logger.info("[WorldHandlers] PLAYER_LOGIN queued player login bundle")
    
    return 0, responses

def handle_CMSG_LOADING_SCREEN_NOTIFY(ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    decoded = _log_cmsg(ctx)
    showing = _decode_loading_screen_showing(decoded, ctx.payload)
    _resolve_session_ids()

    session.loading_screen_visible = bool(showing)
    if showing:
        _set_login_state(LoginState.LOADING_SCREEN)
        Logger.info("[WorldHandlers] LOADING_SCREEN_NOTIFY show=1")
        return 0, None

    if (
        _is_pre_player_login_state(session.login_state)
        or not getattr(session, "char_guid", None)
        or not getattr(session, "world_guid", None)
    ):
        session.loading_screen_done = True
        Logger.info(
            f"[WorldHandlers] LOADING_SCREEN_NOTIFY show=0 deferred until PLAYER_LOGIN "
            f"(state={session.login_state.value if session.login_state else 'None'})"
        )
        return 0, None

    if session.login_state not in {
        LoginState.PLAYER_LOGIN,
        LoginState.LOADING_SCREEN,
        LoginState.WORLD_BOOTSTRAP,
        LoginState.IN_WORLD,
    }:
        Logger.info(
            f"[WorldHandlers] LOADING_SCREEN_NOTIFY ignored outside login flow "
            f"(state={session.login_state.value if session.login_state else 'None'})"
        )
        return 0, None
    if getattr(session, "teleport_pending", False):
        Logger.info(
            f"[WorldHandlers] LOADING_SCREEN_NOTIFY show=0 completing teleport "
            f"destination={getattr(session, 'teleport_destination', None)}"
        )
        ctx = _build_world_login_context()
        responses = _queue_teleport_world_transition(ctx)
        return 0, responses
    if getattr(session, "post_loading_sent", False):
        Logger.info("[WorldHandlers] LOADING_SCREEN_NOTIFY show=0 after bootstrap; ignoring duplicate")
        return 0, None

    ctx = _build_world_login_context()
    responses = _queue_world_bootstrap_transition(ctx)
    return 0, responses

def handle_CMSG_TIME_SYNC_RESPONSE(ctx: PacketContext):
    decoded = ctx.decoded or {}

    seq = decoded.get("sequence_id", 0)
    client_ticks = decoded.get("client_ticks", 0)

    session.last_time_sync_seq = seq
    session.time_sync_ok = True
    _advance_global_time(1)
    _refresh_region_weather(session)

    Logger.success(
        f"[TIME_SYNC] OK seq={seq} client_ticks={client_ticks}"
    )

    if (
        int(getattr(session, "char_guid", 0) or 0) == 2
        and int(getattr(session, "map_id", 0) or 0) == 1
        and int(getattr(session, "zone", 0) or 0) == 876
        and int(getattr(session, "skyfire_login_stage", 0) or 0) == 2
    ):
        Logger.info("[WorldHandlers] TIME_SYNC_RESPONSE received after post-time-sync block")
        session.skyfire_login_stage = 3
        Logger.info("[WorldHandlers] TIME_SYNC_RESPONSE advanced SkyFire GMIsland stage 3")
        return 0, None

    return 0, None

def handle_CMSG_DISCARDED_TIME_SYNC_ACKS(ctx: PacketContext):
    Logger.info("[TIME_SYNC] Client discarded pending time sync ACKs")
    return 0, None

def handle_CMSG_OBJECT_UPDATE_FAILED(ctx: PacketContext):
    decoded = _log_cmsg(ctx)
    guid = _parse_guid(decoded.get("guid"))
    if guid in (None, 0):
        guid = 0
        for index in range(8):
            value = _parse_guid(decoded.get(f"guid_{index}"))
            if value is not None:
                guid |= (value & 0xFF) << (index * 8)
    Logger.info(f"[WorldHandlers] OBJECT_UPDATE_FAILED guid=0x{int(guid):X}")
    return 0, None

def handle_CMSG_CREATURE_QUERY(ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    decoded = _log_cmsg(ctx)
    entry = int(decoded.get("entry") or 0)
    if entry <= 0:
        return 0, None

    try:
        info = DatabaseConnection.get_creature_template(entry)
        response = _build_creature_query_response_payload(entry, info)
        if info:
            Logger.info(
                f"[WorldHandlers] CREATURE_QUERY entry={entry} name={info.get('name', '')!r}"
            )
        else:
            Logger.info(f"[WorldHandlers] CREATURE_QUERY entry={entry} missing in creature_template")
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to encode SMSG_CREATURE_QUERY_RESPONSE entry={entry}: {exc}")
        return 1, None

    return 0, [("SMSG_CREATURE_QUERY_RESPONSE", response)]


def handle_CMSG_REQUEST_ACCOUNT_DATA(ctx: PacketContext):
    data_type = _decode_account_data_request_type(ctx.payload)

    Logger.info(f"[ACCOUNT_DATA] request type={data_type} raw={ctx.payload.hex()}")

    if not SEND_ACCOUNT_DATA_TO_CLIENT:
        Logger.info(f"[ACCOUNT_DATA] suppressing SMSG_UPDATE_ACCOUNT_DATA type={data_type}")
        return 0, None

    if _is_global_account_data_type(int(data_type)):
        _load_global_account_data()
    else:
        _load_character_account_data()

    stored_text = session.account_data.get(int(data_type))
    if stored_text is None:
        stored_text = _account_data_text_for_type(int(data_type), str(session.account_name or ""))

    normalized_text = _normalize_account_data_text(int(data_type), str(stored_text or ""))
    if normalized_text != str(stored_text or ""):
        stored_text = normalized_text
        session.account_data[int(data_type)] = stored_text
        stored_timestamp = int(session.account_data_times.get(int(data_type)) or time.time())
        session.account_data_times[int(data_type)] = stored_timestamp
        _persist_account_data_entry(int(data_type), stored_text, stored_timestamp)

    stored_timestamp = session.account_data_times.get(int(data_type))
    response = _build_update_account_data_payload(
        int(data_type),
        str(stored_text or ""),
        timestamp=int(stored_timestamp) if stored_timestamp is not None else None,
    )

    return 0, [("SMSG_UPDATE_ACCOUNT_DATA", response)]

def handle_CMSG_REQUEST_CEMETERY_LIST(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_REQUEST_CEMETERY_LIST")
    response = _build_request_cemetery_list_response_payload([])
    return 0, [("SMSG_REQUEST_CEMETERY_LIST_RESPONSE", response)]


def handle_CMSG_REQUEST_PLAYED_TIME(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    row = None
    if session.char_guid is not None and session.realm_id is not None:
        try:
            row = DatabaseConnection.get_character(int(session.char_guid), int(session.realm_id))
        except Exception as exc:
            Logger.warning(f"[WorldHandlers] REQUEST_PLAYED_TIME row lookup failed: {exc}")

    total_time = int(getattr(row, "totaltime", 0) or 0)
    level_time = int(getattr(row, "leveltime", 0) or 0)
    response = EncoderHandler.encode_packet(
        "SMSG_PLAYED_TIME",
        {
            "total_time": total_time,
            "level_time": level_time,
            "show_in_chat": 0,
        },
    )
    Logger.info(
        f"[WorldHandlers] CMSG_REQUEST_PLAYED_TIME total_time={total_time} "
        f"level_time={level_time}"
    )
    return 0, [("SMSG_PLAYED_TIME", response)]


def handle_CMSG_QUERY_TIME(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_QUERY_TIME")
    response = build_login_packet("SMSG_QUERY_TIME_RESPONSE", _build_world_login_context())
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_QUERY_TIME_RESPONSE")
        return 1, None
    return 0, [("SMSG_QUERY_TIME_RESPONSE", response)]


def handle_CMSG_REQUEST_FORCED_REACTIONS(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_REQUEST_FORCED_REACTIONS")
    response = build_login_packet("SMSG_SET_FORCED_REACTIONS", _build_world_login_context())
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_SET_FORCED_REACTIONS")
        return 1, None
    return 0, [("SMSG_SET_FORCED_REACTIONS", response)]


def handle_CMSG_WORLD_STATE_UI_TIMER_UPDATE(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_WORLD_STATE_UI_TIMER_UPDATE")
    response = build_login_packet("SMSG_UI_TIME", _build_world_login_context())
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_UI_TIME")
        return 1, None
    return 0, [("SMSG_UI_TIME", response)]


def handle_CMSG_NAME_QUERY(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info(f"[WorldHandlers] CMSG_NAME_QUERY payload={ctx.payload.hex(' ')}")
    world_guid = int(session.world_guid or 0)
    low_guid = int(getattr(session, "char_guid", 0) or 0)
    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )
    common_kwargs = {
        "name": player_name,
        "realm_name": _get_realm_name(),
        "race": int(getattr(session, "race", 0) or 0),
        "gender": int(getattr(session, "gender", 0) or 0),
        "class_id": int(getattr(session, "class_id", 0) or 0),
    }
    world_response = _build_name_query_response(world_guid, **common_kwargs)
    Logger.info(
        f"[WorldHandlers] SMSG_QUERY_PLAYER_NAME_RESPONSE guid=0x{world_guid:016X} "
        f"name={player_name!r} size={len(world_response)}"
    )
    return 0, [("SMSG_QUERY_PLAYER_NAME_RESPONSE", world_response)]


def handle_CMSG_QUEST_GIVER_STATUS_QUERY(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    guid = _decode_quest_giver_status_query_guid(ctx.payload)
    Logger.info(
        f"[WorldHandlers] CMSG_QUEST_GIVER_STATUS_QUERY guid="
        f"0x{int(guid or 0):016X}"
    )
    response = _build_questgiver_status_payload(int(guid or 0), 0)
    return 0, [("SMSG_QUESTGIVER_STATUS", response)]

def handle_CMSG_MESSAGECHAT_SAY_old(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return _handle_chat_message(ctx)

def build_query_player_name_response(guid: int) -> bytes:
    """
    Build SMSG_QUERY_PLAYER_NAME_RESPONSE similar to SkyFire.
    """

    name = session.player_name.encode("utf-8") + b"\x00"
    realm = _get_realm_name().encode("utf-8") + b"\x00"

    race = int(getattr(session, "race", 0))
    gender = int(getattr(session, "gender", 0))
    class_id = int(getattr(session, "class_id", 0))

    raw = bytearray()
    raw += name
    raw += realm
    raw += struct.pack("<III", race, gender, class_id)
    raw += b"\x00"  # name_declension / padding (MoP clients expect this)

    payload = EncoderHandler.encode_packet(
        "SMSG_QUERY_PLAYER_NAME_RESPONSE",
        {
            "guid": guid,
            "raw": bytes(raw),
        },
    )

    return payload

def handle_CMSG_MESSAGECHAT_SAY(ctx: PacketContext):
    return _handle_chat_message(ctx)
def handle_CMSG_MESSAGECHAT_YELL(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return _handle_chat_message(ctx)


def handle_CMSG_MESSAGECHAT_WHISPER(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return _handle_chat_message(ctx)


def handle_CMSG_SEND_TEXT_EMOTE(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    decoded = _log_cmsg(ctx)
    emote_id = int((decoded or {}).get("emote_id") or 0)
    emote_num = int((decoded or {}).get("emote_num") or 0)
    target_guid = int((decoded or {}).get("target_guid") or 0)
    player_guid = int(getattr(session, "world_guid", 0) or getattr(session, "player_guid", 0) or 0)
    anim_emote = int(TEXT_EMOTE_TO_ANIM_EMOTE.get(emote_id, 0) or 0)

    Logger.info(
        f"[EMOTE][TEXT] emote_id={emote_id} emote_num={emote_num} anim_emote={anim_emote} "
        f"player_guid=0x{player_guid:016X} target_guid=0x{target_guid:016X}"
    )

    responses: list[tuple[str, bytes]] = [
        (
            "SMSG_TEXT_EMOTE",
            _encode_text_emote_payload(
                player_guid=player_guid,
                target_guid=target_guid,
                text_emote=emote_id,
                emote_num=emote_num,
            ),
        )
    ]

    if anim_emote == 10:
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                _build_single_u32_update_object_payload(
                    map_id=int(getattr(session, "map_id", 0) or 0),
                    guid=player_guid,
                    field_index=0x59,  # UNIT_FIELD_NPC_EMOTESTATE
                    value=10,
                ),
            )
        )
    elif anim_emote > 0:
        emote_payload = EncoderHandler.encode_packet(
            "SMSG_EMOTE",
            {
                "emote_id": anim_emote,
                "guid": player_guid,
            },
        )
        responses.append(("SMSG_EMOTE", emote_payload))

    return 0, responses


def handle_CMSG_EMOTE(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    decoded = _log_cmsg(ctx)
    emote_id = int((decoded or {}).get("emote_id") or 0)
    player_guid = int(getattr(session, "world_guid", 0) or getattr(session, "player_guid", 0) or 0)
    Logger.info(
        f"[EMOTE] emote_id={emote_id} player_guid=0x{player_guid:016X}"
    )
    payload = EncoderHandler.encode_packet(
        "SMSG_EMOTE",
        {
            "emote_id": emote_id,
            "guid": player_guid,
        },
    )
    return 0, [("SMSG_EMOTE", payload)]


def handle_CMSG_CHAT_JOIN_CHANNEL(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    channel_name = "General"
    decoded = ctx.decoded or {}
    if decoded.get("channel_name"):
        channel_name = str(decoded.get("channel_name") or "General").strip() or "General"

    session.chat_joined = True
    Logger.info(f"[WorldHandlers] CHAT_JOIN_CHANNEL accepted channel={channel_name!r}")

    if session.chat_motd_sent:
        return 0, None

    motd_payload = build_login_packet("SMSG_MOTD", _build_world_login_context())
    if motd_payload is None:
        return 0, None

    session.chat_motd_sent = True
    Logger.info("[WorldHandlers] sending MOTD after chat join")
    return 0, [("SMSG_MOTD", motd_payload)]

def handle_disconnect() -> None:
    _capture_persist_position_from_session()
    _mark_position_dirty()
    _save_session_position(reason="disconnect", online=0, force=True)
    _detach_session_from_world_state(session)
    session.send_response = None
    _reset_login_flow_state()


def handle_CMSG_REQUEST_HOTFIX(ctx: PacketContext):
    Logger.info(
        f"[WorldHandlers] CMSG_REQUEST_HOTFIX passthrough "
        f"(state={session.login_state.value if session.login_state else 'None'})"
    )
    return _handle_CMSG_REQUEST_HOTFIX(ctx)

def handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES(ctx: PacketContext):
    Logger.info("[WORLD] Client ready for account data times")

    if not SEND_ACCOUNT_DATA_TO_CLIENT:
        Logger.info("[WORLD] suppressing SMSG_ACCOUNT_DATA_TIMES")
        return 0, None

    _load_global_account_data()
    now = int(time.time())
    global_mask = _account_data_mask_for_types(_GLOBAL_ACCOUNT_DATA_TYPES)

    payload = EncoderHandler.encode_packet(
        "SMSG_ACCOUNT_DATA_TIMES",
        {
            "has_account_data_times": 1,
            "timestamps": _account_data_times_list_for_types(now, _GLOBAL_ACCOUNT_DATA_TYPES),
            "mask": global_mask,
            "server_time": now,
        },
    )

    session.account_data_times_sent = True

    return 0, [("SMSG_ACCOUNT_DATA_TIMES", payload)]

def handle_CMSG_UPDATE_ACCOUNT_DATA(ctx: PacketContext):
    _log_cmsg(ctx)
    parsed = _decode_account_data_update_payload(ctx.payload)

    data_type = int(parsed.get("type") or 0)
    timestamp = int(parsed.get("timestamp") or 0)
    account_text = str(parsed.get("account_data") or "")

    if 0 <= data_type < 8:
        session.account_data[data_type] = account_text
        session.account_data_times[data_type] = timestamp
        if account_text:
            session.account_data_mask |= (1 << data_type)
        else:
            session.account_data_mask &= ~(1 << data_type)
        _persist_account_data_entry(data_type, account_text, timestamp)

    preview = account_text[:120].replace("\r", "\\r").replace("\n", "\\n")
    Logger.info(
        f"[ACCOUNT_DATA] update type={data_type} timestamp={timestamp} "
        f"decompressed_size={int(parsed.get('decompressed_size') or 0)} "
        f"compressed_size={int(parsed.get('compressed_size') or 0)} "
        f"stored_len={len(account_text)} preview={preview!r}"
    )

    error = parsed.get("error")
    if error:
        Logger.warning(f"[ACCOUNT_DATA] update parse warning={error}")
    warning = parsed.get("warning")
    if warning:
        Logger.warning(f"[ACCOUNT_DATA] update parse warning={warning}")

    return 0, None


# -----------------------------------------------------------------------------
# Opcode routing table
# -----------------------------------------------------------------------------
def handle_CMSG_SET_ACTIVE_MOVER(ctx: PacketContext):
    """
    Client tells server which unit is the active mover.
    WorldHandlers owns the final world bootstrap transition.
    """

    Logger.info("[WorldHandlers] CMSG_SET_ACTIVE_MOVER")
    Logger.info(
        f"[WorldHandlers] ACTIVE_MOVER received for session.char_guid={session.char_guid} "
        f"session.world_guid=0x{int(session.world_guid or 0):016X}"
    )
    if session.login_state != LoginState.WORLD_BOOTSTRAP:
        Logger.info(
            f"[WorldHandlers] ACTIVE_MOVER ignored outside WORLD_BOOTSTRAP "
            f"(state={session.login_state.value if session.login_state else 'None'})"
        )
        return 0, None

    # Disabled for minimal UPDATE_OBJECT debugging:
    # if _is_skyfire_gmisland_session():
    #     ...
    _assert_player_object_sent()
    _set_login_state(LoginState.IN_WORLD)
    responses: list[tuple[str, bytes]] = []
    motd = str(getattr(_build_world_login_context(), "motd", "") or "").strip()
    if motd and not session.chat_motd_sent:
        session.chat_motd_sent = True
        notification_payload = _build_motd_notification_payload(motd)
        Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; sending MOTD notification fallback")
        responses.append(("SMSG_NOTIFICATION", notification_payload))

    if not getattr(session, "account_settings_sent", False):
        session.account_settings_sent = True
        if SEND_ACCOUNT_DATA_TO_CLIENT:
            Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; waiting for client account-data requests")
        else:
            Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; suppressing account settings packets")

    _ensure_language_spells_known()
    _ensure_mount_spells_known()
    responses.append(("SMSG_SEND_KNOWN_SPELLS", build_login_packet("SMSG_SEND_KNOWN_SPELLS", _build_world_login_context())))
    Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; resending known spells including language and mounts")

    if responses:
        return 0, responses

    responses.extend(_build_minimal_post_timesync_account_packets(ctx.session))
    Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; no additional bootstrap packets sent")
    return 0, None


def handle_CMSG_CAST_SPELL(ctx: PacketContext):
    spell_id = _extract_mount_spell_id(ctx)
    if not spell_id:
        Logger.debug("[Mount] ignoring CMSG_CAST_SPELL without known mount spell match")
        return 0, None

    Logger.info("[Mount] CMSG_CAST_SPELL spell=%s payload=%s", int(spell_id), len(ctx.payload))
    responses = handle_mount(ctx.session, int(spell_id))
    return 0, responses


def handle_CMSG_CANCEL_AURA(ctx: PacketContext):
    spell_id = _extract_mount_spell_id(ctx)
    active_mount = int(getattr(ctx.session, "mount_spell", 0) or 0)
    if not spell_id and not active_mount:
        Logger.debug("[Mount] ignoring CMSG_CANCEL_AURA without active mount")
        return 0, None
    if spell_id and not is_mount_spell(spell_id):
        Logger.debug("[Mount] ignoring CMSG_CANCEL_AURA spell=%s not mount", int(spell_id))
        return 0, None

    Logger.info("[Mount] CMSG_CANCEL_AURA spell=%s payload=%s", int(spell_id or active_mount), len(ctx.payload))
    responses = dismount(ctx.session)
    return 0, responses


def handle_CMSG_CANCEL_MOUNT_AURA(ctx: PacketContext):
    if not bool(getattr(ctx.session, "is_mounted", False)) and not int(getattr(ctx.session, "mount_spell", 0) or 0):
        Logger.debug("[Mount] ignoring CMSG_CANCEL_MOUNT_AURA without active mount")
        return 0, None

    Logger.info("[Mount] CMSG_CANCEL_MOUNT_AURA payload=%s", len(ctx.payload))
    responses = dismount(ctx.session)
    return 0, responses


def handle_movement_packet(ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    return movement_handlers.handle_movement_packet(ctx.session or session, ctx)


def handle_MSG_MOVE_SET_FACING(ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    return movement_handlers.handle_msg_move_set_facing(ctx.session or session, ctx)


opcode_handlers: Dict[str, Callable[[PacketContext], Tuple[int, Optional[bytes]]]] = {
    "CMSG_PING": handle_CMSG_PING,
    "CMSG_LOGOUT_REQUEST": handle_CMSG_LOGOUT_REQUEST,
    "CMSG_AUTH_SESSION": handle_CMSG_AUTH_SESSION,
    "CMSG_ENUM_CHARACTERS": handle_CMSG_ENUM_CHARACTERS,
    "CMSG_PLAYER_LOGIN": handle_CMSG_PLAYER_LOGIN,
    "CMSG_LOADING_SCREEN_NOTIFY": handle_CMSG_LOADING_SCREEN_NOTIFY,
    "CMSG_TIME_SYNC_RESPONSE": handle_CMSG_TIME_SYNC_RESPONSE,
    "CMSG_CHAT_JOIN_CHANNEL": handle_CMSG_CHAT_JOIN_CHANNEL,
    "CMSG_MESSAGECHAT_SAY": handle_CMSG_MESSAGECHAT_SAY,
    "CMSG_MESSAGECHAT_YELL": handle_CMSG_MESSAGECHAT_YELL,
    "CMSG_MESSAGECHAT_WHISPER": handle_CMSG_MESSAGECHAT_WHISPER,
    "CMSG_SEND_TEXT_EMOTE": handle_CMSG_SEND_TEXT_EMOTE,
    "CMSG_EMOTE": handle_CMSG_EMOTE,
    "CMSG_READY_FOR_ACCOUNT_DATA_TIMES": handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES, 
    "CMSG_UPDATE_ACCOUNT_DATA": handle_CMSG_UPDATE_ACCOUNT_DATA,
    "CMSG_REQUEST_HOTFIX": handle_CMSG_REQUEST_HOTFIX,
    "CMSG_SET_ACTIVE_MOVER": handle_CMSG_SET_ACTIVE_MOVER,
    "CMSG_DISCARDED_TIME_SYNC_ACKS": handle_CMSG_DISCARDED_TIME_SYNC_ACKS,
    "CMSG_OBJECT_UPDATE_FAILED": handle_CMSG_OBJECT_UPDATE_FAILED,
    "CMSG_CREATURE_QUERY": handle_CMSG_CREATURE_QUERY,
    "CMSG_REQUEST_ACCOUNT_DATA": handle_CMSG_REQUEST_ACCOUNT_DATA,
    "CMSG_REQUEST_CEMETERY_LIST": handle_CMSG_REQUEST_CEMETERY_LIST,
    "CMSG_REQUEST_PLAYED_TIME": handle_CMSG_REQUEST_PLAYED_TIME,
    "CMSG_QUERY_TIME": handle_CMSG_QUERY_TIME,
    "CMSG_REQUEST_FORCED_REACTIONS": handle_CMSG_REQUEST_FORCED_REACTIONS,
    "CMSG_WORLD_STATE_UI_TIMER_UPDATE": handle_CMSG_WORLD_STATE_UI_TIMER_UPDATE,
    "CMSG_NAME_QUERY": handle_CMSG_NAME_QUERY,
    "CMSG_CAST_SPELL": handle_CMSG_CAST_SPELL,
    "CMSG_CANCEL_AURA": handle_CMSG_CANCEL_AURA,
    "CMSG_CANCEL_MOUNT_AURA": handle_CMSG_CANCEL_MOUNT_AURA,
    "CMSG_QUEST_GIVER_STATUS_QUERY": handle_CMSG_QUEST_GIVER_STATUS_QUERY,
    "CMSG_CHAR_CREATE": handle_CMSG_CHAR_CREATE,
    "CMSG_CHAR_DELETE": handle_CMSG_CHAR_DELETE,
    "CMSG_REORDER_CHARACTERS": handle_CMSG_REORDER_CHARACTERS,
    "MSG_MOVE_START_FORWARD": handle_movement_packet,
    "MSG_MOVE_START_BACKWARD": handle_movement_packet,
    "MSG_MOVE_STOP": handle_movement_packet,
    "MSG_MOVE_HEARTBEAT": handle_movement_packet,
    "MSG_MOVE_START_TURN_LEFT": handle_movement_packet,
    "MSG_MOVE_START_TURN_RIGHT": handle_movement_packet,
    "MSG_MOVE_STOP_TURN": handle_movement_packet,
    "MSG_MOVE_SET_FACING": handle_MSG_MOVE_SET_FACING,
    "MSG_MOVE_FALL_LAND": handle_movement_packet,
}

USE_DB_ACCOUNT_DATA_137 = True

_ORIG_handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES = handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES
_ORIG_handle_CMSG_REQUEST_ACCOUNT_DATA = handle_CMSG_REQUEST_ACCOUNT_DATA


def _account_data_times_types_for_mode():
    return tuple(_GLOBAL_ACCOUNT_DATA_STORAGE_TYPES)


def handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES(ctx):
    if not USE_DB_ACCOUNT_DATA_137:
        return _ORIG_handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES(ctx)

    session = ctx.session
    account_id = int(getattr(session, "account_id", 0) or 0)
    char_guid = int(getattr(session, "char_guid", 0) or 0)

    if account_id:
        _load_global_account_data(account_id)
    if char_guid:
        _load_character_account_data(char_guid)

    global _GLOBAL_ACCOUNT_DATA_TYPES
    original_types = _GLOBAL_ACCOUNT_DATA_TYPES
    try:
        _GLOBAL_ACCOUNT_DATA_TYPES = _account_data_times_types_for_mode()
        Logger.info(
            "[ACCOUNT_DATA] mode=db times types=%s"
            % ",".join(str(v) for v in _GLOBAL_ACCOUNT_DATA_TYPES)
        )
        return _ORIG_handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES(ctx)
    finally:
        _GLOBAL_ACCOUNT_DATA_TYPES = original_types


def handle_CMSG_REQUEST_ACCOUNT_DATA(ctx):
    if not USE_DB_ACCOUNT_DATA_137:
        return _ORIG_handle_CMSG_REQUEST_ACCOUNT_DATA(ctx)

    session = ctx.session
    account_id = int(getattr(session, "account_id", 0) or 0)
    char_guid = int(getattr(session, "char_guid", 0) or 0)

    if account_id:
        _load_global_account_data(account_id)
    if char_guid:
        _load_character_account_data(char_guid)

    Logger.info("[ACCOUNT_DATA] mode=db request using preloaded global+character data")
    return _ORIG_handle_CMSG_REQUEST_ACCOUNT_DATA(ctx)


##  test things --

def _build_minimal_post_timesync_account_packets(session) -> list[tuple[str, bytes]]:
    if getattr(session, "account_data_captures_sent", False):
        return []

    responses: list[tuple[str, bytes]] = []

    data_types = (1, 3, 7)

    for data_type in data_types:
        stored_text = session.account_data.get(data_type)
        if not stored_text:
            continue

        timestamp = int(session.account_data_times.get(data_type) or time.time())

        payload = _build_update_account_data_payload(
            data_type,
            stored_text,
            timestamp=timestamp,
            guid=int(getattr(session, "world_guid", 0) or 0),
        )

        Logger.info(f"[ACCOUNT_DATA][AUTO] type={data_type} size={len(payload)}")

        responses.append(("SMSG_UPDATE_ACCOUNT_DATA", payload))

    session.account_data_captures_sent = True
    return responses



# Refresh opcode routing so the late-bound wrappers above are actually used.
opcode_handlers["CMSG_READY_FOR_ACCOUNT_DATA_TIMES"] = handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES
opcode_handlers["CMSG_REQUEST_ACCOUNT_DATA"] = handle_CMSG_REQUEST_ACCOUNT_DATA
