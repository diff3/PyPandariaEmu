#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Packet builders for the World Login flow.

These functions:
- build logical packet data (dict)
- hand it to the DSL encoder
- return raw bytes

They do NOT:
- manage sockets
- manage ordering
- contain protocol knowledge beyond field names
"""
from pathlib import Path
from typing import Dict, Any, Optional
import os
import time
import json
import struct
from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitWriter
from server.modules.protocol.PacketContext import PacketContext
from shared.Logger import Logger

from server.modules.handlers.world.constants.login import RACES_MOP, CLASSES_MOP
from server.modules.handlers.world.addons import addon_public_key_bytes
from shared.PathUtils import get_captures_root, get_debug_root
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.equipment import _parse_equipment_cache
from server.modules.game.player import _decode_player_bytes
from server.modules.game.guid import _guid_bytes_and_masks, GuidHelper, HighGuid
from server.modules.handlers.world.position.area_service import resolve_zone_from_position
from server.modules.interpretation.utils import dsl_decode, to_safe_json
from server.modules.handlers.world.mount.mount_service import (
    MOUNT_SUPPORT_SPELLS,
    MOUNT_RIDING_SKILL_ID,
    MOUNT_RIDING_SKILL_VALUE,
    granted_mount_spells,
)
from server.modules.handlers.world.bootstrap.playerobjects import (
    USE_SERVER_BUILT_PLAYER_CREATE,
    build_server_built_player_create,
)

DEBUG_UPDATE_OBJECT_0002 = str(os.getenv("PP_DEBUG_UPDATE_OBJECT_0002", "")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


def _load_raw_from_path(path: Path) -> Optional[bytes]:
    """Load raw (header+payload) bytes from a JSON dump path."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to read {path}: {exc}")
        return None

    raw_hex = data.get("raw_data_hex")
    if raw_hex:
        try:
            return bytes.fromhex(raw_hex.replace(" ", ""))
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid raw_data_hex in {path}")
            return None

    header_hex = data.get("raw_header_hex")
    payload_hex = data.get("hex_compact") or data.get("hex_spaced")
    if header_hex and payload_hex:
        try:
            header_bytes = bytes.fromhex(header_hex.replace(" ", ""))
            payload_bytes = bytes.fromhex(payload_hex.replace(" ", ""))
            return header_bytes + payload_bytes
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid hex fields in {path}")
            return None
    return None


def _load_payload_from_path(path: Path) -> Optional[bytes]:
    """Load payload-only bytes from a JSON dump path."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to read {path}: {exc}")
        return None

    payload_hex = data.get("hex_compact") or data.get("hex_spaced")
    if payload_hex:
        try:
            return bytes.fromhex(payload_hex.replace(" ", ""))
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid payload hex in {path}")
            return None

    raw_hex = data.get("raw_data_hex")
    header_hex = data.get("raw_header_hex")
    if raw_hex and header_hex:
        try:
            raw_bytes = bytes.fromhex(raw_hex.replace(" ", ""))
            header_len = len(bytes.fromhex(header_hex.replace(" ", "")))
            return raw_bytes[header_len:]
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid raw hex fields in {path}")
            return None

    return None


def _load_raw_packet(opcode_name: str) -> Optional[bytes]:
    """
    Load raw (header+payload) bytes for a server opcode from debug or captures.
    Includes focus captures if present.
    """
    paths = [
        get_debug_root() / f"{opcode_name}.json",
        get_captures_root() / "debug" / f"{opcode_name}.json",
        get_captures_root(focus=True) / "debug" / f"{opcode_name}.json",
    ]

    for path in paths:
        if not path.exists():
            continue
        raw = _load_raw_from_path(path)
        if raw:
           return raw, True

    return None

def _load_raw_packet_focus(opcode_name: str) -> Optional[bytes]:
    """
    Load raw (header+payload) bytes for a server opcode from debug or captures.
    Includes focus captures if present.
    """
    paths = [
        get_captures_root(focus=True) / "debug" / f"{opcode_name}.json",
    ]

    for path in paths:
        if not path.exists():
            continue
        raw = _load_raw_from_path(path)
        if raw:
            return raw, True

    return None


def _load_payload_packet_focus(opcode_name: str) -> Optional[bytes]:
    """Load payload-only bytes from a focus capture JSON."""
    paths = [
        get_captures_root(focus=True) / "debug" / f"{opcode_name}.json",
    ]

    for path in paths:
        if not path.exists():
            continue
        payload = _load_payload_from_path(path)
        if payload is not None:
            return payload

    return None


def _load_payload_packet_old(opcode_name: str) -> Optional[bytes]:
    """Load payload-only bytes for a server opcode from debug/captures."""
    paths = [
        get_debug_root() / f"{opcode_name}.json",
        get_captures_root() / "debug" / f"{opcode_name}.json",
        get_captures_root(focus=True) / "debug" / f"{opcode_name}.json",
    ]

    for path in paths:
        if not path.exists():
            continue
        payload = _load_payload_from_path(path)
        if payload is not None:
            return payload

    return None

CAPTURE_DIR = get_captures_root(focus=True) / "debug"

def _load_payload_packet(opcode_name: str) -> Optional[bytes]:
    """Load payload-only bytes for a server opcode from captures."""
    path = CAPTURE_DIR / f"{opcode_name}.json"

    if not path.exists():
        return None

    return _load_payload_from_path(path)


# ---------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------

def _encode(name: str, data: Dict[str, Any]) -> bytes:
    """
    Centralized encoder wrapper so logging / debugging
    can be added in one place.
    """
    try:
        return EncoderHandler.encode_packet(name, data)
    except Exception as exc:
        Logger.error(f"[WorldLogin][ENCODE FAIL] {name}: {exc}")
        raise


# ------------------------------------------------------------
# Opcode → builder dispatch
# ------------------------------------------------------------

def build_login_packet(opcode: str, ctx):
    """
    Dispatch helper used by worldLogin.flow.

    Looks for a function named:
        build_<OPCODE_NAME>
    """
    fn_name = f"build_{opcode}"
    fn = globals().get(fn_name)

    if fn is None:
        return None

    return fn(ctx)

# ---------------------------------------------------------------------
# Core login packets
# ---------------------------------------------------------------------

def build_SMSG_SET_DUNGEON_DIFFICULTY(ctx) -> bytes:
    return _encode("SMSG_SET_DUNGEON_DIFFICULTY", {
        "difficulty": 0,
        "unknown": 0,
    })


# ---------------------------------------------------------------------
# Pre-loading packets
# ---------------------------------------------------------------------

def build_SMSG_ACCOUNT_DATA_TIMES_old(ctx) -> bytes:
    now = int(time.time())
    return _encode("SMSG_ACCOUNT_DATA_TIMES", {
        "has_account_data_times": 1,
        "mask": 0,
        "timestamps": [now] * 8,
        "server_time": now,
    })


def build_SMSG_ACCOUNT_DATA_TIMES(_ctx=None) -> bytes:
    now = int(time.time())
    ctx = _ctx
    timestamps = [now] * 8
    mask = 0
    if ctx is not None:
        ctx_times = list(getattr(ctx, "account_data_times", []) or [])
        if ctx_times:
            timestamps = [int(value or 0) for value in (ctx_times[:8] + ([0] * 8))[:8]]
        mask = int(getattr(ctx, "account_data_mask", 0) or 0)
    Logger.info(f"[ACCOUNT DATA] server_time={now}")
    payload = _encode("SMSG_ACCOUNT_DATA_TIMES", {
        "has_account_data_times": 1,
        "mask": mask,
        "timestamps": timestamps,
        "server_time": now,
    })
    if len(payload) != 41:
        raise AssertionError(f"SMSG_ACCOUNT_DATA_TIMES malformed length: {len(payload)} != 41")
    return payload

def build_SMSG_CLIENTCACHE_VERSION(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"client_cache_version": 5})()
    return _encode("SMSG_CLIENTCACHE_VERSION", {
        "version": int(getattr(ctx, "client_cache_version", 5)),
    })

def build_SMSG_TUTORIAL_FLAGS(ctx) -> bytes:
    fields = {
        "list": [
            19,
            2112,
            0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }
    return EncoderHandler.encode_packet("SMSG_TUTORIAL_FLAGS", fields)


def build_SMSG_FEATURE_SYSTEM_STATUS(ctx) -> bytes:
    info = dict(getattr(ctx, "feature_system_status", {}) or {})
    feedback_system = int(info.get("feedback_system_enabled", 1 if info == {} else 0))
    excessive_warning = int(info.get("excessive_warning", 0))

    payload = bytearray()
    payload.extend(struct.pack(
        "<IIIBI",
        int(info.get("scroll_resurrection_per_day", 0)),
        int(info.get("scroll_resurrection_current", 0)),
        int(info.get("unk_u32_08", 0)),
        int(info.get("mount_preview_mode", 2)),
        int(info.get("unk_u32_0D", 0)),
    ))

    bits = BitWriter()
    bits.write_bits(int(info.get("unk_bit_00", 0)), 1)
    bits.write_bits(int(info.get("in_game_shop_enabled", 1)), 1)
    bits.write_bits(int(info.get("unk_bit_02", 0)), 1)
    bits.write_bits(int(info.get("recruit_a_friend_enabled", 0)), 1)
    bits.write_bits(int(info.get("voice_chat_enabled", 0)), 1)
    bits.write_bits(int(info.get("show_in_game_shop_icon", 1)), 1)
    bits.write_bits(int(info.get("scroll_of_resurrection_enabled", 0)), 1)
    bits.write_bits(excessive_warning, 1)
    bits.write_bits(int(info.get("parental_controls_enabled", 0)), 1)
    bits.write_bits(feedback_system, 1)
    payload.extend(bits.getvalue())

    if excessive_warning:
        payload.extend(struct.pack(
            '<III',
            int(info.get('excessive_warning_after_seconds', 0)),
            int(info.get('excessive_warning_display_seconds', 0)),
            int(info.get('excessive_warning_cooldown_seconds', 0)),
        ))

    if feedback_system:
        payload.extend(struct.pack(
            '<IIII',
            int(info.get('feedback_unk_0', 0)),
            int(info.get('feedback_unk_1', 1)),
            int(info.get('feedback_unk_2', 10)),
            int(info.get('feedback_unk_3', 60000)),
        ))

    return bytes(payload)


def build_SMSG_BATTLE_PAY_GET_PURCHASE_LIST_RESPONSE(_ctx=None) -> bytes:
    payload = _load_payload_packet("SMSG_BATTLE_PAY_GET_PURCHASE_LIST_RESPONSE")
    if payload is not None:
        return payload
    payload = _load_payload_packet_focus("SMSG_BATTLE_PAY_GET_PURCHASE_LIST_RESPONSE")
    if payload is not None:
        return payload
    # Minimal empty response captured from retail-compatible traffic.
    return b"\x00" * 7


def build_SMSG_MOTD_old(ctx) -> bytes:
    return _encode("SMSG_MOTD", {
        "motd": ctx.motd,
    })

def build_SMSG_MOTD(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"motd": "Welcome to PyPandaria"})()
    motd = str(getattr(ctx, "motd", "Welcome to PyPandaria") or "")
    lines = [part for part in motd.split("@") if part] or [""]

    bits = BitWriter()
    bits.write_bits(len(lines) & 0x0F, 4)
    for line in lines:
        encoded = str(line).encode("utf-8", errors="strict")
        bits.write_bits(len(encoded) & 0x7F, 7)

    payload = bytearray(bits.getvalue())
    for line in lines:
        payload.extend(str(line).encode("utf-8", errors="strict"))

    payload = bytes(payload)
    Logger.info(f"[MOP DEBUG] MOTD lines={len(lines)} size={len(payload)} mode=skyfire")
    return payload


def build_SMSG_PVP_SEASON(ctx) -> bytes:
    return _encode("SMSG_PVP_SEASON", {
        "current_season": ctx.pvp_season,
        "previous_season": ctx.pvp_prev_season,
    })


def build_SMSG_SET_TIME_ZONE_INFORMATION(ctx) -> bytes:
    tz = "Etc/UTC"
    fields = {
        "len1": len(tz),
        "len2": len(tz),
        "time_zone1": tz,
        "time_zone2": tz,
    }
    return EncoderHandler.encode_packet(
        "SMSG_SET_TIME_ZONE_INFORMATION",
        fields,
    )

def build_SMSG_HOTFIX_NOTIFY_BLOB(ctx) -> bytes:
    return _encode("SMSG_HOTFIX_NOTIFY_BLOB", {
        "count": 0,
    })


def build_SMSG_CONTACT_LIST(ctx) -> bytes:
    return _encode("SMSG_CONTACT_LIST", {
        "flags": 0,
        "count": 0,
        "contacts": [],
    })


def build_SMSG_BIND_POINT_UPDATE(ctx) -> bytes:
    return _encode("SMSG_BIND_POINT_UPDATE", {
        "map_id": int(getattr(ctx, "bind_map_id", 0) or getattr(ctx, "map_id", 0)),
        "x": float(getattr(ctx, "bind_x", getattr(ctx, "x", 0.0))),
        "y": float(getattr(ctx, "bind_y", getattr(ctx, "y", 0.0))),
        "z": float(getattr(ctx, "bind_z", getattr(ctx, "z", 0.0))),
        "area_id": int(getattr(ctx, "bind_area_id", 0) or getattr(ctx, "zone", 0)),
    })


def build_SMSG_UPDATE_TALENT_DATA(ctx) -> bytes:
    return _encode("SMSG_UPDATE_TALENT_DATA", {
        "active_spec_group": int(getattr(ctx, "activespec", 0) if hasattr(ctx, "activespec") else 0),
        "spec_group_count": 0,
        "spec_groups": [],
    })


def build_SMSG_WORLD_SERVER_INFO_old(ctx) -> bytes:
    return _encode("SMSG_WORLD_SERVER_INFO", ctx.world_server_info)


def build_SMSG_WORLD_SERVER_INFO(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"world_server_info": {}})()
    info = dict(getattr(ctx, "world_server_info", {}) or {})

    has_group_size = int(info.get("has_group_size", 1 if int(info.get("group_size", 0) or 0) > 0 else 0))
    ineligible_for_loot = int(info.get("ineligible_for_loot", 0))
    has_restricted_level = int(info.get("has_restricted_level", 0))
    has_restricted_money = int(info.get("has_restricted_money", 0))

    bits = BitWriter()
    bits.write_bits(has_group_size, 1)
    bits.write_bits(ineligible_for_loot, 1)
    bits.write_bits(has_restricted_level, 1)
    bits.write_bits(has_restricted_money, 1)

    payload = bytearray(bits.getvalue())
    payload.extend(struct.pack(
        '<BII',
        int(info.get('is_tournament_realm', 0)),
        int(info.get('last_weekly_reset', info.get('weekly_reset_time', 0))),
        int(info.get('map_difficulty', info.get('flags', 0))),
    ))

    if has_group_size:
        payload.extend(struct.pack('<I', int(info.get('group_size', 0))))
    if has_restricted_level:
        payload.extend(struct.pack('<I', int(info.get('restricted_level', 0))))
    if ineligible_for_loot:
        payload.extend(struct.pack('<I', int(info.get('encounter_mask', 0))))
    if has_restricted_money:
        payload.extend(struct.pack('<I', int(info.get('restricted_money', 0))))

    return bytes(payload)

_EXPERIMENTAL_JOURNAL_MOUNT_SPELLS = (
    458,   # Brown Horse
    470,   # Black Stallion
    580,   # Timber Wolf
    6648,  # Chestnut Mare
    68978, # White Kodo
    68992, # Green Kodo
    72286, # Invincible
    32235, # Golden Gryphon
    34769, # Thalassian Warhorse
    61425, # Traveler's Tundra Mammoth
    89832, # Drake of the West Wind
)


def _legacy_known_mount_spells() -> list[int]:
    return sorted(int(spell_id) for spell_id in granted_mount_spells())


def _journal_test_mount_spells() -> list[int]:
    spell_set = {int(spell_id) for spell_id in MOUNT_SUPPORT_SPELLS}
    spell_set.update(int(spell_id) for spell_id in _EXPERIMENTAL_JOURNAL_MOUNT_SPELLS)
    return sorted(spell_set)


def build_SMSG_SEND_KNOWN_SPELLS(ctx) -> bytes:
    import struct

    race = int(getattr(ctx, "race", 0) or 0)

    alliance_races = {1, 3, 4, 7, 11, 22, 25}
    horde_races = {2, 5, 6, 8, 9, 10, 26}

    _LANG_COMMON = 7
    _LANG_ORCISH = 1

    spell_set: set[int] = set()

    # ----------------------------------------
    # BASE LANGUAGE (EXACTLY ONE)
    # ----------------------------------------
    if race in alliance_races:
        base_spell = 668  # Common
        base_lang = _LANG_COMMON
    elif race in horde_races:
        base_spell = 669  # Orcish
        base_lang = _LANG_ORCISH
    else:
        base_spell = 0
        base_lang = 0

    if base_spell:
        spell_set.add(base_spell)

    # ----------------------------------------
    # RACIAL LANGUAGE (OPTIONAL)
    # ----------------------------------------
    race_language_spell = {
        3: 672,
        4: 671,
        5: 17737,
        6: 670,
        7: 7340,
        8: 7341,
        10: 813,
        11: 29932,
        22: 69269,
        24: 108127,
        26: 108131,
    }.get(race, 0)

    if race_language_spell:
        spell_set.add(int(race_language_spell))

    # ----------------------------------------
    # MOUNTS
    # ----------------------------------------
    legacy_mount_spells = _legacy_known_mount_spells()
    journal_test_mount_spells = _journal_test_mount_spells()
    for spell_id in journal_test_mount_spells:
        spell_set.add(int(spell_id))

    # ----------------------------------------
    # BUILD LANGUAGE MASK (CRITICAL FIX)
    # ----------------------------------------
    lang_map = {
        668: _LANG_COMMON,
        669: _LANG_ORCISH,
        29932: 35,
        813: 10,
    }

    mask = 0

    for s in spell_set:
        lang = lang_map.get(int(s))
        if lang is not None:
            mask |= (1 << lang)

    # FORCE base language (important for Alliance)
    if base_lang:
        mask |= (1 << base_lang)

    # ----------------------------------------
    # APPLY DIRECTLY TO SESSION (TEST MODE)
    # ----------------------------------------
    setattr(ctx, "language", base_lang)
    setattr(ctx, "known_languages_mask", mask)

    # ----------------------------------------
    # FINAL SPELL LIST
    # ----------------------------------------
    spells = sorted(spell_set)

    Logger.info(
        "[TEST_SPELLS] race=%s spells=%s",
        race,
        spells,
    )
    Logger.info(
        "[TEST_MOUNTS] legacy=%s active=%s",
        legacy_mount_spells,
        journal_test_mount_spells,
    )

    Logger.info(
        "[TEST_LANG] base_lang=%s mask=0x%X",
        base_lang,
        mask,
    )

    # ----------------------------------------
    # BUILD PACKET
    # ----------------------------------------
    payload = bytearray()
    bits = BitWriter()

    bits.write_bits(0, 1)  # has cooldowns
    bits.write_bits(len(spells), 22)

    payload.extend(bits.getvalue())

    for spell_id in spells:
        payload.extend(struct.pack("<I", spell_id))

    return bytes(payload)


def build_SMSG_SEND_UNLEARN_SPELLS(ctx) -> bytes:
    bits = BitWriter()
    bits.write_bits(0, 22)
    return bits.getvalue()


def build_SMSG_UPDATE_ACTION_BUTTONS(ctx) -> bytes:
    button_count = 132
    packet_type = int(getattr(ctx, "action_button_state", 0) or 0) & 0xFF
    source_buttons = list(getattr(ctx, "action_buttons", []) or [])
    button_bytes: list[bytearray] = []

    for index in range(button_count):
        try:
            packed_value = int(source_buttons[index]) & 0xFFFFFFFF
        except Exception:
            packed_value = 0

        action_id = int(packed_value & 0x00FFFFFF)
        action_type_word = int(packed_value & 0xFF000000)
        button_bytes.append(bytearray(struct.pack("<II", action_id, action_type_word)))

    payload = bytearray()
    bits = BitWriter()

    for index in range(button_count):
        bits.write_bits(1 if button_bytes[index][4] else 0, 1)
    for index in range(button_count):
        bits.write_bits(1 if button_bytes[index][5] else 0, 1)
    for index in range(button_count):
        bits.write_bits(1 if button_bytes[index][3] else 0, 1)
    for index in range(button_count):
        bits.write_bits(1 if button_bytes[index][1] else 0, 1)
    for index in range(button_count):
        bits.write_bits(1 if button_bytes[index][6] else 0, 1)
    for index in range(button_count):
        bits.write_bits(1 if button_bytes[index][7] else 0, 1)
    for index in range(button_count):
        bits.write_bits(1 if button_bytes[index][0] else 0, 1)
    for index in range(button_count):
        bits.write_bits(1 if button_bytes[index][2] else 0, 1)

    payload.extend(bits.getvalue())

    for byte_index in (0, 1, 4, 6, 7, 2, 5, 3):
        for index in range(button_count):
            value = button_bytes[index][byte_index]
            payload.append(value ^ 0x01)

    payload.append(packet_type)

    return bytes(payload)


def build_SMSG_ACTION_BUTTONS(session) -> bytes:
    buttons = getattr(session, "action_buttons", [0] * 132)

    payload = bytearray()

    for value in buttons:
        payload += int(value).to_bytes(4, "little")

    return bytes(payload)

def build_SMSG_INITIALIZE_FACTIONS(ctx) -> bytes:
    factions = list(getattr(ctx, "factions", []) or [])
    if not factions:
        factions = [{"flags": 0, "standing": 0} for _ in range(163)]
    return _encode("SMSG_INITIALIZE_FACTIONS", {
        "count": 0,
        "factions": factions[:163],
    })


def build_SMSG_ALL_ACHIEVEMENT_DATA(ctx) -> bytes:
    return _encode("SMSG_ALL_ACHIEVEMENT_DATA", {
        "criteria_count": 0,
        "achievement_count": 0,
    })


def build_SMSG_LOAD_EQUIPMENT_SET(ctx) -> bytes:
    return _encode("SMSG_LOAD_EQUIPMENT_SET", {
        "set_count": 0,
    })


def build_SMSG_LOGIN_SET_TIME_SPEED_old(ctx) -> bytes:
    return _encode("SMSG_LOGIN_SET_TIME_SPEED", {
        "server_time": ctx.server_time,
        "game_time": 0,
        "speed": 1.0,
    })


def build_SMSG_LOGIN_SET_TIME_SPEED(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"server_time": int(time.time())})()
    server_time = int(getattr(ctx, "server_time", int(time.time())))
    game_time = int(getattr(ctx, "game_time", server_time))
    time_speed = float(getattr(ctx, "time_speed", 0.01666667))
    return _encode("SMSG_LOGIN_SET_TIME_SPEED", {
        "unk_1": 0,
        "game_time_1": game_time,
        "unk_2": 0,
        "game_time_2": game_time,
        "time_speed": time_speed,
    })



def build_SMSG_SET_FORCED_REACTIONS(ctx) -> bytes:
    return _encode("SMSG_SET_FORCED_REACTIONS", {
        "faction_count": 0,
        "reactions": [],
    })


def build_SMSG_QUERY_TIME_RESPONSE(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"server_time": int(time.time())})()
    return _encode("SMSG_QUERY_TIME_RESPONSE", {
        "server_time": int(getattr(ctx, "server_time", int(time.time()))),
        "unk": int(getattr(ctx, "query_time_unk", 24024)),
    })


def build_SMSG_UI_TIME(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"server_time": int(time.time())})()
    return _encode("SMSG_UI_TIME", {
        "server_time": int(getattr(ctx, "server_time", int(time.time()))),
    })


def build_SMSG_SETUP_CURRENCY(ctx) -> bytes:
    return _encode("SMSG_SETUP_CURRENCY", {
        "currencies": [],
    })


# ---------------------------------------------------------------------
# Post-loading packets (world entered)
# ---------------------------------------------------------------------

def build_SMSG_LOGIN_VERIFY_WORLD_old(ctx) -> bytes:
    row = DatabaseConnection.get_character(2, 1)
    if not row:
        raise RuntimeError("Character 2 not found in DB")

    return EncoderHandler.encode_packet(
        "SMSG_LOGIN_VERIFY_WORLD",
        {
            "x": float(row.position_x),
            "facing": float(row.orientation),
            "y": float(row.position_y),
            "map": int(row.map),
            "z": float(row.position_z),
        },
    )

def build_SMSG_LOGIN_VERIFY_WORLD(_ctx=None) -> bytes:
    ctx = _ctx or type(
        "Ctx",
        (),
        {"x": 0.0, "y": 0.0, "z": 0.0, "orientation": 0.0, "map_id": 0},
    )()
    return _encode("SMSG_LOGIN_VERIFY_WORLD", {
        "x": float(getattr(ctx, "x", 0.0)),
        "facing": float(getattr(ctx, "orientation", 0.0)),
        "y": float(getattr(ctx, "y", 0.0)),
        "map": int(getattr(ctx, "map_id", 0)),
        "z": float(getattr(ctx, "z", 0.0)),
    })


def build_SMSG_UPDATE_OBJECT_old(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet("SMSG_UPDATE_OBJECT")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT not found")
    return raw


def build_SMSG_UPDATE_OBJECT_1768335962(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT not found")
    return raw

def build_SMSG_UPDATE_OBJECT_1768335964(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT_1768335964")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT_1768335964 not found")
    return raw

def build_SMSG_UPDATE_OBJECT_1768336025(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT_1768336025")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT_1768336025 not found")
    return raw

def build_SMSG_UPDATE_OBJECT_1768336030(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT_1768336030")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT_1768336030 not found")
    return raw

def build_SMSG_UPDATE_OBJECT_1768336134(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT_1768336134")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT_1768336134 not found")
    return raw


_EXACT_UPDATE_OBJECT_1773613181_0005_DEFAULT = bytes.fromhex(
    "01000100000001C104C01F0500000003004035D696C3000000005A62B640A33B71C56C314204000000000000000001F38C0E00040000000000C01F2100000067B002000000D6820000803FC70B0000280000000000803FCB820300010F0000000000FF00"
)
_EXACT_UPDATE_OBJECT_1773613176_0003_DEFAULT_ENTRIES = (
    {
        "guid": 0x1FC0000000000006,
        "object_type": 5,
        "create_flags": bytes.fromhex("000000030040"),
        "stationary_y": -4391.54443359375,
        "stationary_z": 152.76785278320312,
        "stationary_orientation": 0.8706339597702026,
        "stationary_x": 1833.5076904296875,
        "unk472": 71438445,
        "gameobject_rotation": 0,
        "mask_bytes": bytes.fromhex("f38c0e00"),
        "field_bytes": bytes.fromhex("060000000000c01f21000000078402000000f4500000803fd70b0000280000000000803f0ee70300010f0000000000ff"),
        "dynamic_mask_blocks": 0,
    },
    {
        "guid": 0x1FC0000000000007,
        "object_type": 5,
        "create_flags": bytes.fromhex("000000030040"),
        "stationary_y": -3840.890869140625,
        "stationary_z": 0.0,
        "stationary_orientation": 2.0869128704071045,
        "stationary_x": -1006.944580078125,
        "unk472": 71441778,
        "gameobject_rotation": 0,
        "mask_bytes": bytes.fromhex("f38c0e00"),
        "field_bytes": bytes.fromhex("070000000000c01f21000000485100000000ac1e0000803fc70b0000280000000000803fc6860300010f0000000000ff"),
        "dynamic_mask_blocks": 0,
    },
    {
        "guid": 0x1FC0000000000008,
        "object_type": 5,
        "create_flags": bytes.fromhex("000000030040"),
        "stationary_y": 2441.197265625,
        "stationary_z": 0.0,
        "stationary_orientation": 4.662179946899414,
        "stationary_x": -4352.34814453125,
        "unk472": 71408350,
        "gameobject_rotation": 0,
        "mask_bytes": bytes.fromhex("f38c0e00"),
        "field_bytes": bytes.fromhex("080000000000c01f2100000051b402000000ac310000803faf1b0000280000000000803ff7df0300010f0000000000ff"),
        "dynamic_mask_blocks": 0,
    },
    {
        "guid": 0x1FC0000000000014,
        "object_type": 5,
        "create_flags": bytes.fromhex("000000030040"),
        "stationary_y": -738.1724243164062,
        "stationary_z": 210.6576385498047,
        "stationary_orientation": 6.201721668243408,
        "stationary_x": -691.3047485351562,
        "unk472": 71408350,
        "gameobject_rotation": 0,
        "mask_bytes": bytes.fromhex("f38c0e00"),
        "field_bytes": bytes.fromhex("140000000000c01f2100000055e802000000a1fa0000803fd70b0000280000000000803fa5010900010f0000000000ff"),
        "dynamic_mask_blocks": 0,
    },
    {
        "guid": 0x1FC0000000000017,
        "object_type": 5,
        "create_flags": bytes.fromhex("000000030040"),
        "stationary_y": -5189.60791015625,
        "stationary_z": 7.580000400543213,
        "stationary_orientation": 3.7290494441986084,
        "stationary_x": 1200.232177734375,
        "unk472": 71431843,
        "gameobject_rotation": 0,
        "mask_bytes": bytes.fromhex("f38c0e00"),
        "field_bytes": bytes.fromhex("170000000000c01f21000000ca1a0300000018de0000803f3e250000280000000000803f9f060500010f0000000000ff"),
        "dynamic_mask_blocks": 0,
    },
    {
        "guid": 0x1FC0000000000018,
        "object_type": 5,
        "create_flags": bytes.fromhex("000000030040"),
        "stationary_y": -5900.0,
        "stationary_z": 325.0880126953125,
        "stationary_orientation": 1.9386810064315796,
        "stationary_x": 3356.68994140625,
        "unk472": 71423130,
        "gameobject_rotation": 0,
        "mask_bytes": bytes.fromhex("f38c0e00"),
        "field_bytes": bytes.fromhex("180000000000c01f210000006a1b030000000ffc0000803f7a1d0000280000000000803fee310800010f0000000000ff"),
        "dynamic_mask_blocks": 0,
    },
)
_FIRST_LOGIN_UPDATE_OBJECT_CAPTURE_NAME = "SMSG_UPDATE_OBJECT_1773613176_0002.json"
DEFAULT_EXACT_UPDATE_OBJECT_1773613176_0002_MODE = "barncastle"
_MINIMAL_UPDATE_OBJECT_1773613176_0002_ENTRY_OFFSET = 477
_MINIMAL_UPDATE_OBJECT_1773613176_0002_OFFSET_ADJUST = (
    _MINIMAL_UPDATE_OBJECT_1773613176_0002_ENTRY_OFFSET - 6
)
_PLAYER_DISPLAY_IDS = {
    1: {0: 49, 1: 50},
    2: {0: 51, 1: 52},
    3: {0: 53, 1: 54},
    4: {0: 55, 1: 56},
    5: {0: 57, 1: 58},
    6: {0: 59, 1: 60},
    7: {0: 1563, 1: 1564},
    8: {0: 1478, 1: 1479},
    9: {0: 6894, 1: 6895},
    10: {0: 15476, 1: 15475},
    11: {0: 16125, 1: 16126},
}
_PLAYER_FACTION_TEMPLATE_IDS = {
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
_EXACT_UPDATE_OBJECT_1773613176_0002_MOVEMENT_TEMPLATE = bytes.fromhex(
    "200000004009080000080000490000e040e00f494000009040c3f54840ec8f7d46c7c28a4000002040608b7e460000904003000020400000e040711c9740b5b7fd41"
)
_EXACT_UPDATE_OBJECT_1773613176_0002_MASK_BYTES = bytes.fromhex(
    "d10000dc8a028062ff0f1e7c0002008022060004c02900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a200800202601e007800780000000000000000000000000000000080ff010000000000000000000000000000fe010000000000000000000000000000fe0100000000000000000000000000000000000000000000007c7f01000001000010000000000000000000000000000000000000e807fc2f0100000008000000000080003f00000000000000"
)
_EXACT_UPDATE_OBJECT_1773613176_0002_FIELD_TEMPLATE = bytes.fromhex(
    "0200000019000000000000000000803f0000000000000000000000000a0400010300000067000000640000006700000064000000010000004a06000008000000000800006c07000040060000d0070000022bc73e0000c03f733c0000733c000000000000c82df740a88322418e265040587c85400000803f0000803f0000803f0000803f12000000190000001400000018000000130000002100000053000000260000001000000025495240922489400000803f01070300080000010100000085200000020000007ee30000a0510000a2510000f151000089c30000010000000e00000000000040100000000000004012000000000000400c00000000000040140000000000004016000000000000402100000000000040c8000000900100002b002c002d002e0036005f006d0076008900a200ad00e2009e019f01d90199030100010001000100010001002c0101002c0101000100010001000100010005000500050005000500050005002c0105002c01050005000500010001000500050051f896410000a040553e2e41553e2e41553e2e4152491d3b52491d3b52491d3b52491d3b52491d3b52491d3b1e0000000000004108000000004000002c0100000e0000000e0000000e0000000e0000000e0000000e0000000000803f0000803f0000803f0000803f0000803f0000803f0000803f0e0000000000803f0000803f0000803f0000803fffffffff5a00000015000000160000001700000018000000190000001a000000"
)
_EXACT_UPDATE_OBJECT_1773613176_0002_DYNAMIC_MASK_BLOCKS = 0
_EXACT_UPDATE_OBJECT_1773613176_0004_DEFAULT = bytes.fromhex(
    "0100010000000001023F4000001C00000080E00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000733C0000733C00000000000000"
)
_EXACT_UPDATE_OBJECT_1773613185_0006_DEFAULT = bytes.fromhex(
    "0100010000000001023F4000001C00000020E0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000400733C0000733C0000000000000100000000"
)
_EXACT_UPDATE_OBJECT_1773613205_0007_DEFAULT = bytes.fromhex(
    "0100010000000307000000C104C01FC106C01FC107C01FC108C01FC114C01FC117C01FC118C01F"
)
_EXACT_UPDATE_OBJECT_1775665925_0004_DEFAULT = bytes.fromhex(
    "010006000000018F35C0B301400100000000000003F3AF0100000000000600000035C0B30100000040030000009D510000000000000000803F030000"
    "0000000007030000000000000700000007000000070100000037000000370000000100000000018F37C0B301400100000000000003F3AF0100000000"
    "000600000037C0B30100000040030000009E510000000000000000803F03000000000000070300000000000007000000070000000701000000280000"
    "00280000000100000000018F3BC0B301400100000000000003F3AF010000000000060000003BC0B30100000040030000009F51000000000000000080"
    "3F0300000000000007030000000000000700000007000000070100000019000000190000000100000000018F39C0B301400100000000000003F3AF01"
    "00000000000600000039C0B3010000004003000000F2510000000000000000803F030000000000000703000000000000070000000700000007010000"
    "0028000000280000000100000000018F3DC0B301400100000000000003F3AF810000000000000000003DC0B3010000004003000000241B0000000000"
    "000000803F0300000000000007030000000000000700000007000000070100000001000000010000000002810307042000000040090800000800004D"
    "0000E040E00F49400000904006C3F54840F8887D4665A8B63F000020402C057E460000904002000020400000E040711C9740B0B353413FD300004086"
    "258462FF033E7C000200C002060004C00100000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000A200800002601E0018"
    "00180000000000000000000000000000000080FF010000000000000000000000000000FE010000000000000000000000000000FE0100000000000000"
    "00000000000000000000000000000002747F01000001000010000000000000000080000000000000000000E807FC2F0300000008000000000080003F"
    "00000000000000030000000000000719000000000000000000803F0A08000166000000320000006600000032000000210000006DDA0B400000803F01"
    "0000004A0600000800000000080000540B0000D0070000540B0000022BC73E0000C03F733C0000733C0000000000006AF0F5401DD42D410000803F00"
    "00803F0000803F0000803F0000803F1100000016000000130000001B00000015000000210000003200000053000000090000000000803F0000004000"
    "00803F0200090101000001010000009D5100009E5100009F510000F25100000100000035C0B3010000004037C0B301000000403BC0B3010000004039"
    "C0B301000000403DC0B3010000004037000000900100002B005F006D0088008900A200AD00B700E4009F01F40209032A038803A6030000010001002C"
    "0101002C0101000100010005000100010001000100010001000000050005002C0105002C010500050001000500010001000100010001000100000002"
    "0000000FB6E840B7D1A440B7D1A440B7D1A4408A8EAA408A8EAA408A8EAA408A8EAA408A8EAA408A8EAA401E00000000000041082000000040000000"
    "2000002C0100001100000011000000110000001100000011000000110000000000803F0000803F0000803F0000803F0000803F0000803F0000803F11"
    "0000000000803F0000803F0000803F0000803F000020C2FFFFFFFF5A00000016000000150000001700000018000000190000001A0000000100000000"
)
_EXACT_UPDATE_OBJECT_1775665925_0005_DEFAULT = bytes.fromhex(
    "01001500000001C104C01F050000000300406F1188C56D8A18437EBC7C40CAEBE94487873E15464911000000000001F38C0E00040000000000C01F21"
    "0000000784020000001A610000803FD70B0000280000000000803F33E70300010F0000000000FF0001C10AC01F0500000003004072E4BB43A9691643"
    "B762083E645B80C487873E15911001000000000001F38C0E000A0000000000C01F2100000055E8020000008D2A0000803FD70B000028000000000080"
    "3F49230900010F0000000000FF0001C111C01F050000000300409866BFC55B8FF2408A8D9940FD34FA4487873E15152F15000000000001F38C0E0011"
    "0000000000C01F21000000CA1A03000000B7920000803F3E250000280000000000803F28000500010F0000000000FF0001C117C01F05000000030040"
    "B922934400000000B4CC4B40976A024687873E15F00010000000000001F38C0E00170000000000C01F210000008EC50200000053E00000803FAF1B00"
    "00280000000000803FFBA30300010F0000000000FF0001C12BC01F05000000030040AE4F85C5E9880B425F7B7E40F618D544F3590000915F11000000"
    "000001F38C0C002B0000000000C01F21000000102703000000D8B00000803F46250000280000000000803F010B0000000000FF0001C12CC01F050000"
    "00030040CD6489C52664294219AD6F40EC69DB44F3590000FAB810000000000001F38C0C002C0000000000C01F21000000122703000000D8B0000080"
    "3F46250000280000000000803F010B0000000000FF0001C12DC01F050000000300407BECADC520C107424CE0A540337B0D456B060000DAA317000000"
    "000001F38C0C002D0000000000C01F21000000265402000000163F0000803F33060000280000000000803F010B0000000000FF0001C12EC01F050000"
    "000300402980DBC508ACE542BC74B7409ABD8F45F359000061A71B000000000001F38C0C002E0000000000C01F21000000D51D03000000D8B0000080"
    "3FDD250000280000000000803F010B0000000000FF0001C12FC01F0500000003004085E9C0C5DE31C6426DAC843C33032545F35900002A2100000000"
    "000001F38C0C002F0000000000C01F21000000D61D03000000D8B00000803FDD250000280000000000803F010B0000000000FF0001C130C01F050000"
    "00030040BADAE2C1920B8A42488A3A40488180C4074C0000ABE50F000000000001F38C0C00300000000000C01F21000000C0B80000000014A6000080"
    "3F68010000280000000000803F010B0000000000FF0001C131C01F0500000003004027F144C2B87E0C43E1974440A4A881C4BC45000081FD0F000000"
    "000001F38C0C00310000000000C01F21000000C1B8000000002A980000803F68010000280000000000803F010B0000000000FF0001C132C01F050000"
    "0003004052B83D437B140243C3B6A640AEC7A0C4BC450000C0D117000000000001F38C0C00320000000000C01F210000004A10000000002A98000080"
    "3F68010000280000000000803F010B0000000000FF0001C133C01F050000000300403D4A3943152C8942B667C040D78BA3C4074C0000A8D71D000000"
    "000001F38C0C00330000000000C01F210000004B100000000014A60000803F68010000280000000000803F010B0000000000FF0001C134C01F050000"
    "000300408F6AB0C57B14F5C3C6DEE33E520617C66B060000FA8703000000000001F38C0C00340000000000C01F21000000265402000000163F000080"
    "3F33060000280000000000803F010B0000000000FF0001C124C01F05000000030040CD6C9344B4A8A043A6611C3F29080045074C0000B0CF04000000"
    "000001F38C0C00240000000000C01F210000007B2E0000000014A60000803F68010000280000000000803F010B0000000000FF0001C125C01F050000"
    "000300408FD29544FA6EE1430BEF5A3F8593FE44074C000095A206000000000001F38C0C00250000000000C01F210000007A2E0000000014A6000080"
    "3F68010000280000000000803F010B0000000000FF0001C126C01F05000000030040A4B68CC500308543F90FC93F1F254945271D000050500B000000"
    "000001F38C0C00260000000000C01F21000000E50003000000359F0000803FAF230000280000000000803F010B0000000000FF0001C127C01F050000"
    "00030040857396C57FAAF3422540C93F1F455E45F359000071520B000000000001F38C0C00270000000000C01F21000000D31D03000000D8B0000080"
    "3FDD250000280000000000803F010B0000000000FF0001C128C01F05000000030040AE7BB2C53F75D5421EF9574071418C45F3590000C41B10000000"
    "000001F38C0C00280000000000C01F21000000D41D03000000D8B00000803FDD250000280000000000803F010B0000000000FF0001C129C01F050000"
    "00030040E10C9CC54C77FD4283A3C140F6803745F3590000FB251E000000000001F38C0C00290000000000C01F21000000112C03000000D8B0000080"
    "3FDD250000280000000000803F010B0000000000FF0001C12AC01F05000000030040CDA888C5B9FC2F4277A1B6409AC1ED44F3590000A4741B000000"
    "000001F38C0C002A0000000000C01F21000000112703000000D8B00000803F46250000280000000000803F010B0000000000FF00"
)
_EXACT_UPDATE_OBJECT_1775665925_0006_DEFAULT = bytes.fromhex(
    "01002C00000001F7DC5708B1B912F105000000010040CD1E7E46F69767413F914B3F004C7D46F83106000000000001F38C0D00DC570800B1B912F121"
    "000000B1B902000000FFFF0000803FD5140000000000000000803F5E000000010300FF000000000001E7DA5708B912F10500000001004000267E4678"
    "7A5C41AA60B03F9A557D46042C0A000000000001F38C0C00DA57080000B912F12100000000B902000000FFFF0000803F8A140000000000000000803F"
    "010500FF000000000001F7D95708FDB812F10500000001004033297E460D7159410A80ED3F665A7D46E1CD0C000000000001F38C0C00D9570800FDB8"
    "12F121000000FDB802000000FFFF0000803F87140000000000000000803F010500FF000000000001F7D55708FEB812F10500000001004000287E4642"
    "CF574194872B4066607D4676930F000000000001F38C0C00D5570800FEB812F121000000FEB802000000FFFF0000803F88140000000000000000803F"
    "010500FF000000000001F710E40830E632F103200000000029CC0000000000010000013C310000E04009E5E00F494000009040F0C3F5484033CD7D46"
    "AB3EA04000002040004C7E4600009040E733110000204015000041711C97402B18624105F30000C082008022FB008600000000000100000410E40800"
    "30E632F10900000030E60200000000000000003F0001000201000000D5020600D50206005A0000002300000000030000D0070000D00700000AD7233C"
    "CDCCCC3DCD710000CD710000000000000000803F0000803F01000000010000000000803F0001F7D8BB08AA7930F103200000000029CC00000800004F"
    "AB0000E04009BAE00F494000009040F0C3F548409AAD7D46BD18764000002040003C7E46000090407831D9000020400000E040711C974007CE5D4105"
    "F30000C082008062FB0006000000000001000004D8BB0800AA7930F109000000AA790000000000000000803F0001000201000000002EC22C002EC22C"
    "5D000000A70600000000040000080000D0070000D00700000000403F00002040766B0000766B0000000000000000803F0000803F010000000000803F"
    "0001F7DE5708FDB812F10500000001004033BF7E465BC2A6412C7D124000FA7D4654910E000000000001F38C0C00DE570800FDB812F121000000FDB8"
    "02000000FFFF0000803F87140000000000000000803F010500FF000000000001F7DD5708B1B912F10500000001004066387E46E02D53411EDCAE4033"
    "4D7D4686A119000000000001F38C0D00DD570800B1B912F121000000B1B902000000FFFF0000803FD5140000000000000000803F5E000000010300FF"
    "000000000001F7DB5708B1B912F105000000010040333B7E465D6D5141D09B3A4000607D46EAE50F000000000001F38C0D00DB570800B1B912F12100"
    "0000B1B902000000FFFF0000803FD5140000000000000000803F5E000000010300FF000000000001F7D85708FCB812F10500000001004000307E464E"
    "625841ECA3B440CD507D4616FB1A000000000001F38C0C00D8570800FCB812F121000000FCB802000000FFFF0000803F86140000000000000000803F"
    "010500FF000000000001F7D75708FFB812F105000000010040CD2A7E4673685C410C8FBD3C004E7D46622F00000000000001F38C0C00D7570800FFB8"
    "12F121000000FFB802000000FFFF0000803F89140000000000000000803F010500FF000000000001E7D65708B912F10500000001004033317E468BFD"
    "5541FB747C40665A7D46C54511000000000001F38C0C00D657080000B912F12100000000B902000000FFFF0000803F8A140000000000000000803F01"
    "0500FF000000000001F7D45708FDB812F1050000000100409A377E462D43534117829B409A557D46938C15000000000001F38C0C00D4570800FDB812"
    "F121000000FDB802000000FFFF0000803F87140000000000000000803F010500FF000000000001F7D35708FCB812F10500000001004000327E46C976"
    "5441696F524066607D46FB0A10000000000001F38C0C00D3570800FCB812F121000000FCB802000000FFFF0000803F86140000000000000000803F01"
    "0500FF000000000001F7D257087DB912F105000000010040CD2C7E46F1635941CA4FB6409A557D4614611B000000000001F38C0C00D25708007DB912"
    "F1210000007DB902000000FFFF0000803FC3140000000000000000803F010500FF000000000001F7D15708FEB812F10500000001004066BE7E4683C0"
    "A6414148963F00F47D46C5DC08000000000001F38C0C00D1570800FEB812F121000000FEB802000000FFFF0000803F88140000000000000000803F01"
    "0500FF000000000001F7D05708EDB912F105000000010040003E7E465DED9941E8BCBE3F667C7D462ED90A000000000001F38C0C00D0570800EDB912"
    "F121000000EDB902000000FFFF6666663FE7140000000000000000803F010500FF000000000001F7CF570813FC12F105000000010040CD427E46DC68"
    "4F4118268E4033717D46EF4313000000000001F38C0C00CF57080013FC12F12100000013FC02000000FFFF0000803F73070000000000000000803F01"
    "1300FF000000000001F7CE57089CBF12F10500000001004000BC7E46B8AF7D4134BA8B3F00A07D46464E08000000000001F38C0C00CE5708009CBF12"
    "F1210000009CBF02000000FFFF0000803F57180000200000000000803F010500FF000000000001F7CD570801B912F10500000001004033C97E4655C1"
    "A641D0B8A040CDF47D46D59116000000000001F38C0C00CD57080001B912F12100000001B902000000FFFF0000803F8B140000000000000000803F01"
    "0500FF000000000001E7CC5708B912F10500000001004000C87E465BC2A641B6F888409AF97D46378612000000000001F38C0C00CC57080000B912F1"
    "2100000000B902000000FFFF0000803F8A140000000000000000803F010500FF000000000001F7CB5708FDB812F10500000001004033C57E461AC0A6"
    "411D38A04066F47D46EA7716000000000001F38C0C00CB570800FDB812F121000000FDB802000000FFFF0000803F87140000000000000000803F0105"
    "00FF000000000001F7CA5708FCB812F105000000010040CDC47E4630CCA641B9C2BF409AF17D46D0AE1D000000000001F38C0C00CA570800FCB812F1"
    "21000000FCB802000000FFFF0000803F86140000000000000000803F010500FF000000000001F7C9570839DB12F105000000010040CDC27E4683C0A6"
    "41BA66C74000F67D46BB951F000000000001F38C0D00C957080039DB12F12100000039DB02000000FFFF0000004083140000000000000000803F7200"
    "0000010500FF000000000001F7C8570868D812F105000000010040CDBE7E46F1E3AE41BF60434066D67D46F6FB0F000000000001F38C0C00C8570800"
    "68D812F12100000068D802000000FFFF0000803FF21C0000000000000000803F011600FF000000000001F7C7570837F112F10500000001004033C57E"
    "46FF21AF410612424033D17D46E4F90F000000000001F38C0C00C757080037F112F12100000037F102000000FFFF0000803F07000000040000000000"
    "803F010300FF000000000001F7C65708918D11F1050000000100409A8F7E461372B7419C33C64066B27D4601491F000000000001F38C0C00C6570800"
    "918D11F121000000918D01000000FFFF0000803F27000000000000000000803F010700FF000000000001F7C557088C8D11F105000000010040338B7E"
    "460770FB411B47C840667C7D46D2CD1F000000000001F38C0C00C55708008C8D11F1210000008C8D01000000FFFF0000803F27000000000000000000"
    "803F010700FF000000000001F7C457088B8D11F105000000010040337D7E46D870FB4152BA183F66807D46C8B304000000000001F38C0C00C4570800"
    "8B8D11F1210000008B8D01000000FFFF0000803F27000000000000000000803F010700FF000000000001F7C35708898D11F10500000001004033897E"
    "461C6BFB4179AF4240CD9E7D46EBFA0F000000000001F38C0C00C3570800898D11F121000000898D01000000FFFF0000803F27000000000000000000"
    "803F010700FF000000000001F7C25708928D11F105000000010040CD7C7E46006FFB41E9653040669C7D4632B40F000000000001F38C0C00C2570800"
    "928D11F121000000928D01000000FFFF0000803F27000000000000000000803F010700FF000000000001F7C15708878D11F105000000010040CD767E"
    "46696FFB4195600F4066967D460D670E000000000001F38C0C00C1570800878D11F121000000878D01000000FFFF0000803F27000000000000000000"
    "803F010700FF000000000001F7C05708938D11F105000000010040CD747E460080FB410B7BA23F9A8B7D46A27C09000000000001F38C0C00C0570800"
    "938D11F121000000938D01000000FFFF0000803F27000000000000000000803F010700FF000000000001F7BF57088E8D11F10500000001004000C07E"
    "462731A741A37510409ADD7D4601760E000000000001F38C0C00BF5708008E8D11F1210000008E8D01000000FFFF0000803F27000000000000000000"
    "803F010700FF000000000001F7BE57088D8D11F1050000000100409AB97E465B31A7419CF9B93F9AD57D46B1A00A000000000001F38C0C00BE570800"
    "8D8D11F1210000008D8D01000000FFFF0000803F27000000000000000000803F010700FF000000000001F7BD5708908D11F10500000001004066CA7E"
    "46FF32A7410820934033D77D46670E14000000000001F38C0C00BD570800908D11F121000000908D01000000FFFF0000803F27000000000000000000"
    "803F010700FF000000000001F7BC57088F8D11F10500000001004033CB7E46D033A741082093409ACF7D46670E14000000000001F38C0C00BC570800"
    "8F8D11F1210000008F8D01000000FFFF0000803F27000000000000000000803F010700FF000000000001F7BB5708868D11F1050000000100409AC37E"
    "462731A741F9F7C54066C87D461C3A1F000000000001F38C0C00BB570800868D11F121000000868D01000000FFFF0000803F27000000000000000000"
    "803F010700FF000000000001F7BA5708888D11F105000000010040CDBA7E462731A7419CF9B93F9ACD7D46B1A00A000000000001F38C0C00BA570800"
    "888D11F121000000888D01000000FFFF0000803F27000000000000000000803F010700FF000000000001F7B85708090F10F10500000001004033AF7E"
    "46CDCC524177BE474033CB7D46C8FF0F000000000001F38C0C00B8570800090F10F121000000090F00000000FFFF0000803F98010000000000000000"
    "803F010800FF000000640001F7B75708855110F1050000000100409AA17E46E5D05241D578494066EE7D46060010000000000001F38C0C00B7570800"
    "855110F121000000855100000000FFFF0000803FD8000000000000000000803F010800FF000000640001F7B657089B7212F1050000000100409AB37E"
    "46CDCC5241AE47E13D33AB7D462AE100000000000001F38C0C00B65708009B7212F1210000009B7202000000FFFF0000803FA7020000000000000000"
    "803F010800FF000000640001F7B55708090F10F10500000001004033AD7E46CDCC52413D0AD73D00C47D46F0D600000000000001F38C0C00B5570800"
    "090F10F121000000090F00000000FFFF0000803F98010000000000000000803F010800FF000000640001D7B957082510F10500000001004066CC7D46"
    "1283C84160E51840CDC87E4669E10E000000000001F38C0D00B9570800250010F121000000250000000000FFFFC3F5A83F1300000000000000000080"
    "3F0A070000010900FF0000006400"
)
_EXACT_UPDATE_OBJECT_1773613176_0002_OFFSETS = {
    "object_guid_low_u32": 800,
    "last_entry_packed_guid_low": 479,
    "fly_speed": 494,
    "turn_speed": 498,
    "swim_speed": 502,
    "pitch_speed": 506,
    "pos_x": 510,
    "orientation": 514,
    "walk_speed": 518,
    "pos_y": 522,
    "fly_back_speed": 526,
    "run_back_speed": 531,
    "run_speed": 535,
    "swim_back_speed": 539,
    "pos_z": 543,
    "guid1_0": 530,
    "display_power": 832,
    "faction_template": 856,
    "display_id": 888,
    "native_display_id": 892,
    "health": 836,
    "power_primary": 840,
    "max_health": 844,
    "max_power_primary": 848,
    "level": 852,
    "appearance_block": 828,
    "player_bytes": 980,
    "player_bytes2": 984,
    "equipment_slot_8": 1000,
    "equipment_slot_12": 1004,
    "equipment_slot_14": 1008,
    "equipment_slot_30": 1012,
    "equipment_slot_32": 1016,
}


def _build_update_object_packet_prefix(map_id: int, update_count: int) -> bytes:
    return struct.pack("<HI", int(map_id), int(update_count))


def _build_update_object_payload_from_default(default_payload: bytes, *, map_id: int) -> bytes:
    payload = bytearray(bytes(default_payload))
    struct.pack_into("<H", payload, 0, int(map_id) & 0xFFFF)
    return bytes(payload)


def _build_exact_update_object_create_entry(
    *,
    guid: int,
    object_type: int,
    create_flags: bytes,
    body: bytes,
) -> bytes:
    payload = bytearray()
    payload += struct.pack("<B", 1)
    payload += GuidHelper.pack(int(guid))
    payload += struct.pack("<B", int(object_type))
    payload += bytes(create_flags)
    payload += bytes(body)
    return bytes(payload)


def _build_exact_update_object_value_update_entry(
    *,
    guid: int,
    mask_bytes: bytes,
    field_bytes: bytes,
    dynamic_mask_blocks: int,
    dynamic_mask_bytes: bytes = b"",
) -> bytes:
    payload = bytearray()
    payload += struct.pack("<B", 0)
    payload += GuidHelper.pack(int(guid))
    payload += struct.pack("<B", len(mask_bytes) // 4)
    payload += bytes(mask_bytes)
    payload += bytes(field_bytes)
    payload += struct.pack("<B", int(dynamic_mask_blocks))
    if dynamic_mask_blocks > 0:
        expected_len = int(dynamic_mask_blocks) * 4
        normalized_dynamic_mask = bytes(dynamic_mask_bytes[:expected_len]).ljust(expected_len, b"\x00")
        payload += normalized_dynamic_mask
    return bytes(payload)


def _merge_exact_u32_field_updates(mask_bytes: bytes, field_bytes: bytes, extra_fields: dict[int, int] | None) -> tuple[bytes, bytes, list[int]]:
    merged_fields: dict[int, int] = {}

    bit_count = len(mask_bytes) * 8
    byte_offset = 0
    for field_index in range(bit_count):
        mask_byte = mask_bytes[field_index // 8]
        mask_bit = field_index % 8
        if not (mask_byte & (1 << mask_bit)):
            continue
        if byte_offset + 4 > len(field_bytes):
            break
        merged_fields[int(field_index)] = int(struct.unpack_from("<I", field_bytes, byte_offset)[0])
        byte_offset += 4

    for field_index, value in (extra_fields or {}).items():
        merged_fields[int(field_index)] = int(value) & 0xFFFFFFFF

    if not merged_fields:
        return bytes(mask_bytes), bytes(field_bytes), []

    ordered_bits = sorted(merged_fields)
    max_bit = ordered_bits[-1]
    merged_mask = bytearray(((max_bit // 32) + 1) * 4)
    merged_field_bytes = bytearray()
    serialized_pairs: list[tuple[int, int]] = []

    for field_index, field_value in sorted(merged_fields.items()):
        word_index = field_index // 32
        bit_index = field_index % 32
        current_word = struct.unpack_from("<I", merged_mask, word_index * 4)[0]
        struct.pack_into("<I", merged_mask, word_index * 4, current_word | (1 << bit_index))
        value_u32 = int(field_value) & 0xFFFFFFFF
        merged_field_bytes += struct.pack("<I", value_u32)
        serialized_pairs.append((int(field_index), value_u32))

    Logger.info(
        "[UPDATE_OBJECT DEBUG] 0006 merge sorted_bits=%s serialized_pairs=%s",
        ordered_bits,
        serialized_pairs,
    )

    return bytes(merged_mask), bytes(merged_field_bytes), ordered_bits


def _build_exact_fixed_u32_field_block(
    fields: dict[int, int],
    *,
    mask_blocks: int,
) -> tuple[bytes, bytes, list[int]]:
    normalized_fields = {
        int(field_index): int(field_value) & 0xFFFFFFFF
        for field_index, field_value in (fields or {}).items()
    }
    if not normalized_fields:
        return (b"\x00" * (int(mask_blocks) * 4), b"", [])

    mask = bytearray(int(mask_blocks) * 4)
    field_bytes = bytearray()
    ordered_bits = sorted(normalized_fields)

    for field_index in ordered_bits:
        if field_index < 0:
            continue
        word_index = field_index // 32
        bit_index = field_index % 32
        if word_index >= int(mask_blocks):
            raise ValueError(f"field index {field_index} exceeds fixed mask block count {mask_blocks}")
        current_word = struct.unpack_from("<I", mask, word_index * 4)[0]
        struct.pack_into("<I", mask, word_index * 4, current_word | (1 << bit_index))
        field_bytes += struct.pack("<I", normalized_fields[field_index])

    return bytes(mask), bytes(field_bytes), ordered_bits


def _build_exact_update_object_1773613181_0005_body(
    *,
    stationary_y: float,
    stationary_z: float,
    stationary_orientation: float,
    stationary_x: float,
    unk472: int,
    gameobject_rotation: int,
    mask_bytes: bytes,
    field_bytes: bytes,
    dynamic_mask_blocks: int,
) -> bytes:
    payload = bytearray()
    payload += struct.pack("<ffff", float(stationary_y), float(stationary_z), float(stationary_orientation), float(stationary_x))
    payload += struct.pack("<I", int(unk472))
    payload += struct.pack("<Q", int(gameobject_rotation) & 0xFFFFFFFFFFFFFFFF)
    payload += struct.pack("<B", len(mask_bytes) // 4)
    payload += bytes(mask_bytes)
    payload += bytes(field_bytes)
    payload += struct.pack("<B", int(dynamic_mask_blocks))
    return bytes(payload)


def build_SMSG_UPDATE_OBJECT_1773613181_0005(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_0005_map_id", int(getattr(ctx, "map_id", 1)))
    guid = int(getattr(ctx, "exact_0005_guid", 0x1FC0000000000004))
    object_type = int(getattr(ctx, "exact_0005_object_type", 5) or 5)
    create_flags = bytes(
        getattr(ctx, "exact_0005_create_flags", bytes.fromhex("000000030040"))
    )
    stationary_y = float(getattr(ctx, "exact_0005_stationary_y", -301.6734924316406))
    stationary_z = float(getattr(ctx, "exact_0005_stationary_z", 0.0))
    stationary_orientation = float(getattr(ctx, "exact_0005_stationary_orientation", 5.699505805969238))
    stationary_x = float(getattr(ctx, "exact_0005_stationary_x", -3859.727294921875))
    unk472 = int(getattr(ctx, "exact_0005_unk472", 71446892))
    gameobject_rotation = int(getattr(ctx, "exact_0005_gameobject_rotation", 0))
    mask_bytes = bytes(getattr(ctx, "exact_0005_mask_bytes", bytes.fromhex("f38c0e00")))
    field_bytes = bytes(
        getattr(
            ctx,
            "exact_0005_field_bytes",
            bytes.fromhex("040000000000c01f2100000067b002000000d6820000803fc70b0000280000000000803fcb820300010f0000000000ff"),
        )
    )
    dynamic_mask_blocks = int(getattr(ctx, "exact_0005_dynamic_mask_blocks", 0))

    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, 1)
    payload += _build_exact_update_object_create_entry(
        guid=guid,
        object_type=object_type,
        create_flags=create_flags,
        body=_build_exact_update_object_1773613181_0005_body(
            stationary_y=stationary_y,
            stationary_z=stationary_z,
            stationary_orientation=stationary_orientation,
            stationary_x=stationary_x,
            unk472=unk472,
            gameobject_rotation=gameobject_rotation,
            mask_bytes=mask_bytes,
            field_bytes=field_bytes,
            dynamic_mask_blocks=dynamic_mask_blocks,
        ),
    )
    built = bytes(payload)
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0005 map_id={map_id} guid=0x{guid:016X} "
        f"packet_size={len(built)}"
    )
    return built


def build_SMSG_UPDATE_OBJECT_1775665925_0004(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_1775665925_0004_map_id", int(getattr(ctx, "map_id", 1) or 1))
    built = _build_update_object_payload_from_default(
        _EXACT_UPDATE_OBJECT_1775665925_0004_DEFAULT,
        map_id=map_id,
    )
    Logger.info(f"[UPDATE_OBJECT BUILD] 1775665925_0004 map_id={map_id} packet_size={len(built)}")
    return built


def build_SMSG_UPDATE_OBJECT_1775665925_0005(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_1775665925_0005_map_id", int(getattr(ctx, "map_id", 1) or 1))
    built = _build_update_object_payload_from_default(
        _EXACT_UPDATE_OBJECT_1775665925_0005_DEFAULT,
        map_id=map_id,
    )
    Logger.info(f"[UPDATE_OBJECT BUILD] 1775665925_0005 map_id={map_id} packet_size={len(built)}")
    return built


def build_SMSG_UPDATE_OBJECT_1775665925_0006(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_1775665925_0006_map_id", int(getattr(ctx, "map_id", 1) or 1))
    built = _build_update_object_payload_from_default(
        _EXACT_UPDATE_OBJECT_1775665925_0006_DEFAULT,
        map_id=map_id,
    )
    Logger.info(f"[UPDATE_OBJECT BUILD] 1775665925_0006 map_id={map_id} packet_size={len(built)}")
    return built


def build_SMSG_UPDATE_OBJECT_1773613176_0004(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_0004_map_id", int(getattr(ctx, "map_id", 1)))
    guid = _resolve_player_value_update_guid(ctx, "exact_0004_guid")
    display_id = int(
        getattr(
            ctx,
            "display_id",
            _resolve_player_display_id(
                int(getattr(ctx, "race", 0) or 0),
                int(getattr(ctx, "gender", 0) or 0),
                15476,
            ),
        )
        or 15476
    )
    base_fields = {
        6: 0,
        69: display_id,
        70: display_id,
        71: 0,
        162: int(getattr(ctx, "player_flags", 0) or 0),
    }
    extra_fields = getattr(ctx, "exact_0004_extra_u32_fields", None)
    if extra_fields:
        base_fields.update({int(field_index): int(field_value) for field_index, field_value in extra_fields.items()})
    mask_bytes, field_bytes, set_bits = _build_exact_fixed_u32_field_block(base_fields, mask_blocks=63)
    dynamic_mask_blocks = int(getattr(ctx, "exact_0004_dynamic_mask_blocks", 1))
    dynamic_mask_bytes = bytes(getattr(ctx, "exact_0004_dynamic_mask_bytes", b"\x00" * (dynamic_mask_blocks * 4)))

    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, 1)
    payload += _build_exact_update_object_value_update_entry(
        guid=guid,
        mask_bytes=mask_bytes,
        field_bytes=field_bytes,
        dynamic_mask_blocks=dynamic_mask_blocks,
        dynamic_mask_bytes=dynamic_mask_bytes,
    )
    built = bytes(payload)
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0004 map_id={map_id} guid=0x{guid:016X} "
        f"mask_blocks={len(mask_bytes)//4} packet_size={len(built)}"
    )
    Logger.info(
        "[UPDATE_OBJECT DEBUG] 0004 raw=%s update_type=0 guid=0x%016X guid_mask=0x%02X mask_blocks=%s",
        built.hex(),
        int(guid) & 0xFFFFFFFFFFFFFFFF,
        int(GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)[0]),
        len(mask_bytes) // 4,
    )
    Logger.info(
        "[UPDATE_OBJECT DEBUG] 0004 set_fields=%s dynamic_mask_blocks=%s dynamic_mask_bytes=%s",
        set_bits,
        dynamic_mask_blocks,
        dynamic_mask_bytes.hex(),
    )
    return built


def build_SMSG_UPDATE_OBJECT_1773613176_0003(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_0003_map_id", int(getattr(ctx, "map_id", 1)))
    entries = tuple(getattr(ctx, "exact_0003_entries", _EXACT_UPDATE_OBJECT_1773613176_0003_DEFAULT_ENTRIES))

    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, len(entries))
    for entry in entries:
        payload += _build_exact_update_object_create_entry(
            guid=int(entry["guid"]),
            object_type=int(entry.get("object_type", 5)),
            create_flags=bytes(entry.get("create_flags", bytes.fromhex("000000030040"))),
            body=_build_exact_update_object_1773613181_0005_body(
                stationary_y=float(entry["stationary_y"]),
                stationary_z=float(entry["stationary_z"]),
                stationary_orientation=float(entry["stationary_orientation"]),
                stationary_x=float(entry["stationary_x"]),
                unk472=int(entry.get("unk472", 0)),
                gameobject_rotation=int(entry.get("gameobject_rotation", 0)),
                mask_bytes=bytes(entry.get("mask_bytes", bytes.fromhex("f38c0e00"))),
                field_bytes=bytes(entry["field_bytes"]),
                dynamic_mask_blocks=int(entry.get("dynamic_mask_blocks", 0)),
            ),
        )

    built = bytes(payload)
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0003 map_id={map_id} entries={len(entries)} "
        f"packet_size={len(built)}"
    )
    return built


def build_SMSG_UPDATE_OBJECT_1773613176_0002(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    if USE_SERVER_BUILT_PLAYER_CREATE and not hasattr(ctx, "exact_0002_payload"):
        built = build_server_built_player_create(ctx)
        if built is not None:
            if bool(getattr(ctx, "exact_0002_remote_player", False)):
                patched = bytearray(built)
                _patch_update_object_1773613176_0002_remote_flags(patched)
                built = bytes(patched)
            map_id = struct.unpack_from("<H", built, 0)[0]
            Logger.info("[PLAYER CREATE] server-built template path")
            Logger.info(
                f"[UPDATE_OBJECT BUILD] 0002 mode=server-template map_id={map_id} packet_size={len(built)}"
            )
            return built

        Logger.info("[PLAYER CREATE] fallback to replay")

    mode = str(
        getattr(
            ctx,
            "exact_0002_mode",
            DEFAULT_EXACT_UPDATE_OBJECT_1773613176_0002_MODE,
        )
        or DEFAULT_EXACT_UPDATE_OBJECT_1773613176_0002_MODE
    ).strip().lower()
    if hasattr(ctx, "exact_0002_payload"):
        built = bytearray(bytes(getattr(ctx, "exact_0002_payload")))
        default_map_id = int(getattr(ctx, "map_id", struct.unpack_from("<H", built, 0)[0]))
        map_id = _ctx_int_preserve_zero(ctx, "exact_0002_map_id", default_map_id)
        struct.pack_into("<H", built, 0, map_id)
        built = bytes(built)
        active_mode = "custom"
    if mode == "barncastle":
        built = _build_barncastle_update_object_1773613176_0002_payload(ctx)
        map_id = struct.unpack_from("<H", built, 0)[0]
        active_mode = "barncastle"
    else:
        built = _build_live_update_object_1773613176_0002_payload(ctx)
        map_id = struct.unpack_from("<H", built, 0)[0]
        active_mode = "full-capture"
    if bool(getattr(ctx, "exact_0002_remote_player", False)):
        patched = bytearray(built)
        _patch_update_object_1773613176_0002_remote_flags(patched)
        built = bytes(patched)
        active_mode = f"{active_mode}-remote"
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0002 mode={active_mode} map_id={map_id} packet_size={len(built)}"
    )
    _debug_log_update_object_0002(built, mode=active_mode)
    return built


def _decode_packed_guid(mask: int, packed_bytes: bytes) -> int:
    raw = [0] * 8
    offset = 0
    for bit in range(8):
        if mask & (1 << bit):
            raw[bit] = packed_bytes[offset]
            offset += 1
    return int.from_bytes(bytes(raw), "little", signed=False)


def _debug_log_update_object_0002(payload: bytes, *, mode: str) -> None:
    if not DEBUG_UPDATE_OBJECT_0002:
        return

    decoded = to_safe_json(dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {})
    updates = list(decoded.get("updates") or [])
    if not updates:
        Logger.info("[UPDATE_OBJECT DEBUG] 0002 mode=%s size=%s raw=%s", mode, len(payload), payload.hex())
        return

    update = updates[0] or {}
    mask = update.get("mask") or {}
    movement_flags = update.get("movement_flags")
    if movement_flags is None:
        movement_flags = 0
    movement_flags_extra = update.get("movement_flags_extra")
    if movement_flags_extra is None:
        movement_flags_extra = 0
    guid_mask = int(update.get("guid_mask", 0) or 0) & 0xFF
    packed_guid = GuidHelper.pack(int(update.get("guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF)

    Logger.info(
        "[UPDATE_OBJECT DEBUG] 0002 mode=%s size=%s update_type=%s object_type=%s guid=0x%016X guid_mask=0x%02X packed_guid=%s",
        mode,
        len(payload),
        int(update.get("update_type", 0) or 0),
        int(update.get("object_type", 0) or 0),
        int(update.get("guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
        guid_mask,
        packed_guid.hex(),
    )
    Logger.info(
        "[UPDATE_OBJECT DEBUG] 0002 movement flags=0x%X flags_extra=0x%X ts=%s pos=(%s,%s,%s,%s) pitch=%s fall=%s transport=%s",
        int(movement_flags or 0),
        int(movement_flags_extra or 0),
        update.get("timestamp"),
        update.get("pos_x"),
        update.get("pos_y"),
        update.get("pos_z"),
        update.get("orientation"),
        update.get("pitch"),
        "yes" if update.get("has_fall_data") else "no",
        "yes" if update.get("has_transport_data") else "no",
    )
    Logger.info(
        "[UPDATE_OBJECT DEBUG] 0002 mask_blocks=%s dynamic_mask_blocks=%s set_bits=%s raw=%s",
        int(update.get("mask_blocks", 0) or 0),
        int(update.get("dynamic_mask_blocks", 0) or 0),
        list(mask.get("set_bits") or []),
        payload.hex(),
    )


def _patch_u32(payload: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", payload, int(offset), int(value) & 0xFFFFFFFF)


def _patch_f32(payload: bytearray, offset: int, value: float) -> None:
    struct.pack_into("<f", payload, int(offset), float(value))


def _patch_u16(payload: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", payload, int(offset), int(value) & 0xFFFF)


def _ctx_int_preserve_zero(ctx: Any, primary_key: str, fallback: int) -> int:
    value = getattr(ctx, primary_key, None)
    if value is None:
        return int(fallback)
    return int(value)


def _resolve_player_display_id(race: int, gender: int, fallback: int = 15475) -> int:
    gender_map = _PLAYER_DISPLAY_IDS.get(int(race) or 0)
    if not gender_map:
        return int(fallback)
    return int(gender_map.get(int(gender) or 0, fallback))


def _resolve_player_faction_template(race: int, fallback: int = 1610) -> int:
    return int(_PLAYER_FACTION_TEMPLATE_IDS.get(int(race) or 0, fallback))


def _patch_mount_skill_block_1773613176_0002_fields(
    payload: bytearray,
    offsets: dict[str, int],
    ctx: Any,
) -> None:
    """
    Rebuild the entire 16-slot skill block.

    This fixes:
    - missing language selection
    - client not sending chat CMSG
    - inconsistent skill state from template

    Layout (per slot):
        ids   @ base + 288
        value @ base + 320
        max   @ base + 352
    """

    field_base = int(offsets["object_guid_low_u32"])

    # --- constants ---
    LANG_COMMON = 98
    LANG_ORCISH = 109

    race = int(getattr(ctx, "race", 0) or 0)

    # --- clear all slots ---
    for i in range(16):
        _patch_u16(payload, field_base + 288 + (i * 2), 0)
        _patch_u16(payload, field_base + 320 + (i * 2), 0)
        _patch_u16(payload, field_base + 352 + (i * 2), 0)

    # --- slot 0: primary language ---
    if race in (1, 3, 4, 7, 11):  # alliance
        lang = LANG_COMMON
    else:
        lang = LANG_ORCISH

    _patch_u16(payload, field_base + 288 + (0 * 2), lang)
    _patch_u16(payload, field_base + 320 + (0 * 2), 300)
    _patch_u16(payload, field_base + 352 + (0 * 2), 300)

    # --- slot 1: riding (mount usability) ---
    _patch_u16(payload, field_base + 288 + (1 * 2), int(MOUNT_RIDING_SKILL_ID))
    _patch_u16(payload, field_base + 320 + (1 * 2), int(MOUNT_RIDING_SKILL_VALUE))
    _patch_u16(payload, field_base + 352 + (1 * 2), int(MOUNT_RIDING_SKILL_VALUE))

    # --- optional: racial language (slot 2) ---
    # Example mapping (expand later if needed)
    RACIAL_LANG = {
        1: 113,  # Human -> Common (same, harmless)
        3: 111,  # Dwarf -> Dwarven
        4: 113,  # Night Elf -> Darnassian
        7: 115,  # Gnome -> Gnomish
        11: 113, # Draenei -> Draenei
        2: 109,  # Orc -> Orcish
        5: 110,  # Undead -> Gutterspeak
        6: 114,  # Tauren -> Taurahe
        8: 116,  # Troll -> Troll
        10: 139, # Blood Elf -> Thalassian
    }

    racial = RACIAL_LANG.get(race)
    if racial:
        _patch_u16(payload, field_base + 288 + (2 * 2), racial)
        _patch_u16(payload, field_base + 320 + (2 * 2), 300)
        _patch_u16(payload, field_base + 352 + (2 * 2), 300)


def _patch_live_update_object_1773613176_0002_fields(ctx: Any, payload: bytearray, *, offset_adjust: int = 0) -> None:
    offsets = {key: value - offset_adjust for key, value in _EXACT_UPDATE_OBJECT_1773613176_0002_OFFSETS.items()}
    low_guid = int(getattr(ctx, "exact_0002_low_guid", getattr(ctx, "char_guid", 2)) or 2) & 0xFF
    if offsets["object_guid_low_u32"] >= 0:
        _patch_u32(payload, offsets["object_guid_low_u32"], low_guid)
    payload[offsets["last_entry_packed_guid_low"]] = low_guid
    payload[offsets["guid1_0"]] = low_guid ^ 0x01

    dynamic_floats = {
        "fly_speed": float(getattr(ctx, "fly_speed", 7.0) or 7.0),
        "turn_speed": float(getattr(ctx, "turn_speed", 3.1415926) or 3.1415926),
        "swim_speed": float(getattr(ctx, "swim_speed", 4.5) or 4.5),
        "pitch_speed": float(getattr(ctx, "pitch_speed", 3.1415926) or 3.1415926),
        "pos_x": float(getattr(ctx, "x", 0.0) or 0.0),
        "orientation": float(getattr(ctx, "orientation", 0.0) or 0.0),
        "walk_speed": float(getattr(ctx, "walk_speed", 2.5) or 2.5),
        "pos_y": float(getattr(ctx, "y", 0.0) or 0.0),
        "fly_back_speed": float(getattr(ctx, "fly_back_speed", 4.5) or 4.5),
        "run_back_speed": float(getattr(ctx, "run_back_speed", 4.5) or 4.5),
        "run_speed": float(getattr(ctx, "run_speed", 7.0) or 7.0),
        "swim_back_speed": float(getattr(ctx, "swim_back_speed", 2.5) or 2.5),
        "pos_z": float(getattr(ctx, "z", 0.0) or 0.0),
    }
    for key, value in dynamic_floats.items():
        _patch_f32(payload, offsets[key], value)

    display_power = int(getattr(ctx, "display_power", 0) or 0)
    current_health = int(getattr(ctx, "health", 103) or 103)
    max_health = int(getattr(ctx, "max_health", current_health) or current_health)
    primary_power = int(getattr(ctx, "power_primary", 100) or 100)
    max_primary_power = int(getattr(ctx, "max_power_primary", primary_power) or primary_power)
    level = int(getattr(ctx, "level", 1) or 1)
    player_bytes = int(getattr(ctx, "player_bytes", 198401) or 198401)
    player_bytes2 = int(getattr(ctx, "player_bytes2", 16777224) or 16777224)

    _patch_u32(payload, offsets["display_power"], display_power)
    _patch_u32(payload, offsets["health"], current_health)
    _patch_u32(payload, offsets["power_primary"], primary_power)
    _patch_u32(payload, offsets["max_health"], max_health)
    _patch_u32(payload, offsets["max_power_primary"], max_primary_power)
    race = int(getattr(ctx, "race", 0) or 0)
    class_id = int(getattr(ctx, "class_id", 0) or 0)
    gender = int(getattr(ctx, "gender", 0) or 0)
    faction_template = int(
        getattr(
            ctx,
            "faction_template",
            _resolve_player_faction_template(race),
        )
        or _resolve_player_faction_template(race)
    )
    display_id = int(
        getattr(
            ctx,
            "display_id",
            _resolve_player_display_id(race, gender),
        )
        or _resolve_player_display_id(race, gender)
    )
    payload[offsets["appearance_block"]:offsets["appearance_block"]+4] = bytes((race & 0xFF, class_id & 0xFF, 0x00, gender & 0xFF))
    _patch_u32(payload, offsets["faction_template"], faction_template)
    _patch_u32(payload, offsets["display_id"], display_id)
    _patch_u32(payload, offsets["native_display_id"], display_id)

    _patch_u32(payload, offsets["level"], level)
    
    _patch_u32(payload, offsets["player_bytes"], player_bytes)
    _patch_u32(payload, offsets["player_bytes2"], player_bytes2)
    # TEMP TEST: assume next slot
    #known_lang_offset = offsets["player_bytes2"] + 4
    #_patch_u32(payload, known_lang_offset, getattr(ctx, "known_languages_mask", 1))
    

    # These sparse player fields in the Barncastle 0002 template were still
    # carrying Selene's raw equipment cache values. Patch them from the
    # logged-in character's own equipmentCache so visible login gear follows
    # the selected character instead of the template character.
    equipment_cache_raw = list(getattr(ctx, "equipment_cache_raw", []) or [])
    equipment_field_map = {
        "equipment_slot_8": 8,
        "equipment_slot_12": 12,
        "equipment_slot_14": 14,
        "equipment_slot_30": 30,
        "equipment_slot_32": 32,
    }
    for offset_key, raw_index in equipment_field_map.items():
        if raw_index < len(equipment_cache_raw):
            _patch_u32(payload, offsets[offset_key], int(equipment_cache_raw[raw_index]) & 0xFFFFFFFF)

    _patch_mount_skill_block_1773613176_0002_fields(payload, offsets, ctx)


def _build_barncastle_update_object_1773613176_0002_payload(ctx: Any) -> bytes:
    """
    Build a player-create UPDATE_OBJECT from fixed MoP templates plus live data.

    This is the active working login path for 0002.
    """
    map_id = _ctx_int_preserve_zero(
        ctx,
        "exact_0002_map_id",
        int(getattr(ctx, "map_id", 0) or 0),
    )
    low_guid = int(getattr(ctx, "exact_0002_low_guid", getattr(ctx, "char_guid", 2)) or 2) & 0xFF

    entry = bytearray()
    entry.append(2)  # player create/update_type
    entry += GuidHelper.pack(low_guid)
    entry.append(4)  # object_type = Player
    entry += _EXACT_UPDATE_OBJECT_1773613176_0002_MOVEMENT_TEMPLATE
    entry.append(len(_EXACT_UPDATE_OBJECT_1773613176_0002_MASK_BYTES) // 4)
    entry += _EXACT_UPDATE_OBJECT_1773613176_0002_MASK_BYTES
    entry += _EXACT_UPDATE_OBJECT_1773613176_0002_FIELD_TEMPLATE
    entry.append(_EXACT_UPDATE_OBJECT_1773613176_0002_DYNAMIC_MASK_BLOCKS)

    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, 1)
    payload += entry
    _patch_live_update_object_1773613176_0002_fields(
        ctx,
        payload,
        offset_adjust=_MINIMAL_UPDATE_OBJECT_1773613176_0002_OFFSET_ADJUST,
    )
    return bytes(payload)

def _patch_update_object_1773613176_0002_remote_flags(payload: bytearray) -> None:
    """
    Multiplayer reuses the 0002 player-create template for remote characters.
    That template is originally tuned for the locally controlled player, and one
    top-level bit causes the receiving client to treat the other player as
    locally owned/active. Clear that bit for remote players only.
    """
    remote_flag_offset = 14
    remote_self_bit = 0x40
    if len(payload) <= remote_flag_offset:
        return
    payload[remote_flag_offset] &= (~remote_self_bit) & 0xFF


def _build_live_update_object_1773613176_0002_payload(ctx: Any) -> bytes:
    payload = bytearray(load_first_login_update_object_capture())
    offsets = _EXACT_UPDATE_OBJECT_1773613176_0002_OFFSETS

    default_map_id = int(getattr(ctx, "map_id", struct.unpack_from("<H", payload, 0)[0]))
    map_id = _ctx_int_preserve_zero(ctx, "exact_0002_map_id", default_map_id)
    struct.pack_into("<H", payload, 0, map_id)

    _patch_live_update_object_1773613176_0002_fields(ctx, payload)

    return bytes(payload)


def load_first_login_update_object_capture() -> bytes:
    path = get_captures_root(focus=True) / "debug" / _FIRST_LOGIN_UPDATE_OBJECT_CAPTURE_NAME
    payload = _load_payload_from_path(path)
    if payload is None:
        raise RuntimeError(f"Missing capture payload for {_FIRST_LOGIN_UPDATE_OBJECT_CAPTURE_NAME}")
    return payload


def decode_first_login_update_object_capture() -> dict[str, Any]:
    payload = load_first_login_update_object_capture()
    decoded = to_safe_json(dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {})
    entries: list[dict[str, Any]] = []
    updates = list(decoded.get("updates") or [])
    for index, update in enumerate(updates, start=1):
        mask_info = update.get("mask") or {}
        raw_fields = update.get("fields") or {}
        entry: dict[str, Any] = {
            "index": index,
            "update_type": int(update.get("update_type", 0) or 0),
            "object_type": int(update.get("object_type", 0) or 0),
            "packed_guid": f"mask={update.get('guid_mask')} guid={update.get('guid')}",
            "guid": str(update.get("guid") or "0x0"),
            "movement": None,
            "update_mask_bits": list(mask_info.get("set_bits") or []),
            "update_mask_hex": str(mask_info.get("hex") or ""),
            "update_fields_hex": str(raw_fields.get("hex") or ""),
            "update_fields_u32": list(raw_fields.get("u32") or []),
            "dynamic_sources": {},
            "constant_fields": [],
            "notes": [],
        }

        if entry["update_type"] == 1 and entry["object_type"] == 1:
            entry["constant_fields"] = [
                "guid",
                "object_type",
                "mask",
                "fields",
            ]

        if index == len(updates):
            entry["movement"] = {
                "x": float(update.get("pos_x") or 0.0),
                "y": float(update.get("pos_y") or 0.0),
                "z": float(update.get("pos_z") or 0.0),
                "orientation": float(update.get("orientation") or 0.0),
                "walk_speed": float(update.get("walk_speed") or 0.0),
                "run_speed": float(update.get("run_speed") or 0.0),
                "run_back_speed": float(update.get("run_back_speed") or 0.0),
                "fly_speed": float(update.get("fly_speed") or 0.0),
                "fly_back_speed": float(update.get("fly_back_speed") or 0.0),
                "swim_speed": float(update.get("swim_speed") or 0.0),
                "swim_back_speed": float(update.get("swim_back_speed") or 0.0),
                "turn_speed": float(update.get("turn_speed") or 0.0),
                "pitch_speed": float(update.get("pitch_speed") or 0.0),
            }
            entry["dynamic_sources"] = {
                "guid(low)": "session.char_guid (inferred)",
                "x": "session.x",
                "y": "session.y",
                "z": "session.z",
                "orientation": "session.orientation",
                "walk_speed": "session.walk_speed",
                "run_speed": "session.run_speed",
                "run_back_speed": "session.run_back_speed",
                "fly_speed": "session.fly_speed",
                "fly_back_speed": "session.fly_back_speed",
                "swim_speed": "session.swim_speed",
                "swim_back_speed": "session.swim_back_speed",
                "turn_speed": "session.turn_speed",
                "pitch_speed": "session.pitch_speed",
                "race/class/gender/level/health/player_flags": "update_fields (partially unresolved offsets)",
            }
            entry["constant_fields"] = [
                "object_type",
                "movement flag layout",
                "update mask",
                "field ordering",
            ]
            entry["notes"] = [
                "The player-like entry uses guid=0x02, not session.world_guid.",
                "Race/class/gender/level/health are present inside update_fields but not yet offset-mapped individually.",
            ]

        entries.append(entry)

    return {
        "capture_name": _FIRST_LOGIN_UPDATE_OBJECT_CAPTURE_NAME,
        "map_id": int(decoded.get("map_id", 0) or 0),
        "update_count": int(decoded.get("update_count", 0) or 0),
        "entry_count_detected": len(entries),
        "entries": entries,
    }


def format_first_login_update_object_capture() -> str:
    decoded = decode_first_login_update_object_capture()
    lines = [
        "UPDATE_OBJECT",
        f"  capture: {decoded['capture_name']}",
        f"  map_id: {decoded['map_id']}",
        f"  update_count: {decoded['update_count']}",
        f"  entry_count_detected: {decoded['entry_count_detected']}",
    ]
    for entry in decoded["entries"]:
        lines.extend(
            [
                f"  entry {entry['index']}:",
                f"    update_type: {entry['update_type']}",
                f"    object_type: {entry['object_type']}",
                f"    packed_guid: {entry['packed_guid']}",
                f"    guid: {entry['guid']}",
            ]
        )
        movement = entry.get("movement")
        if movement:
            lines.extend(
                [
                    "    movement:",
                    f"      x: {movement['x']}",
                    f"      y: {movement['y']}",
                    f"      z: {movement['z']}",
                    f"      orientation: {movement['orientation']}",
                    f"      fly_speed: {movement['fly_speed']}",
                    f"      walk_speed: {movement['walk_speed']}",
                    f"      run_speed: {movement['run_speed']}",
                    f"      turn_speed: {movement['turn_speed']}",
                    f"      run_back_speed: {movement['run_back_speed']}",
                ]
            )
        if entry.get("update_mask_bits"):
            lines.append(f"    update_mask bits: {entry['update_mask_bits']}")
        if entry.get("update_fields_u32"):
            lines.append(f"    update_fields(u32): {entry['update_fields_u32'][:24]}")
        for field, source in (entry.get("dynamic_sources") or {}).items():
            lines.append(f"    source: {field} -> {source}")
        for field in (entry.get("constant_fields") or []):
            lines.append(f"    constant: {field}")
        notes = entry.get("notes") or []
        for note in notes:
            lines.append(f"    note: {note}")
    return "\n".join(lines)


def build_update_object_player_create(session: Any) -> bytes:
    """
    Migration helper for the first login UPDATE_OBJECT capture.

    The first replayed packet is not a clean player-create packet; it is an
    object-create bundle. The function name is kept for the migration work,
    while the payload currently mirrors the first replay packet structure.
    """
    return build_SMSG_UPDATE_OBJECT_1773613176_0002(session)


def diff_update_object_player_create(session: Any) -> list[dict[str, int]]:
    raw = load_first_login_update_object_capture()
    generated = build_update_object_player_create(session)
    length = max(len(raw), len(generated))
    diffs: list[dict[str, int]] = []
    for offset in range(length):
        raw_byte = raw[offset] if offset < len(raw) else -1
        generated_byte = generated[offset] if offset < len(generated) else -1
        if raw_byte == generated_byte:
            continue
        diffs.append({
            "offset": offset,
            "raw": raw_byte,
            "generated": generated_byte,
        })
    return diffs


def format_update_object_player_create_diff(session: Any, *, limit: int = 64) -> str:
    diffs = diff_update_object_player_create(session)
    if not diffs:
        return "offset | raw | generated\n(no differences)"

    lines = ["offset | raw | generated"]
    for diff in diffs[:limit]:
        raw_byte = "EOF" if diff["raw"] < 0 else f"{diff['raw']:02X}"
        generated_byte = "EOF" if diff["generated"] < 0 else f"{diff['generated']:02X}"
        lines.append(f"{diff['offset']:04d} | {raw_byte} | {generated_byte}")
    if len(diffs) > limit:
        lines.append(f"... {len(diffs) - limit} more differences")
    return "\n".join(lines)


def expected_update_object_player_create_dynamic_offsets() -> list[int]:
    offsets = _EXACT_UPDATE_OBJECT_1773613176_0002_OFFSETS
    expected: list[int] = [0, 1, offsets["last_entry_packed_guid_low"], offsets["guid1_0"]]
    for key in (
        "fly_speed",
        "turn_speed",
        "swim_speed",
        "pitch_speed",
        "pos_x",
        "orientation",
        "walk_speed",
        "pos_y",
        "fly_back_speed",
        "run_back_speed",
        "run_speed",
        "swim_back_speed",
        "pos_z",
        "health",
        "power_primary",
        "max_health",
        "max_power_primary",
        "level",
        "player_bytes",
        "player_bytes2",
    ):
        base = offsets[key]
        expected.extend(range(base, base + 4))
    return sorted(set(expected))


def format_update_object_player_create_diff_with_expected(session: Any, *, limit: int = 96) -> str:
    diffs = diff_update_object_player_create(session)
    expected_offsets = set(expected_update_object_player_create_dynamic_offsets())
    unexpected = [diff for diff in diffs if diff["offset"] not in expected_offsets]

    lines = [
        "offset | raw | generated | expected_dynamic",
    ]
    if not diffs:
        lines.append("(no differences)")
        return "\n".join(lines)

    for diff in diffs[:limit]:
        raw_byte = "EOF" if diff["raw"] < 0 else f"{diff['raw']:02X}"
        generated_byte = "EOF" if diff["generated"] < 0 else f"{diff['generated']:02X}"
        expected = "yes" if diff["offset"] in expected_offsets else "no"
        lines.append(f"{diff['offset']:04d} | {raw_byte} | {generated_byte} | {expected}")
    if len(diffs) > limit:
        lines.append(f"... {len(diffs) - limit} more differences")
    lines.append(f"unexpected_differences={len(unexpected)}")
    return "\n".join(lines)


def build_SMSG_UPDATE_OBJECT_1773613185_0006(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_0006_map_id", int(getattr(ctx, "map_id", 1)))
    guid = _resolve_player_value_update_guid(ctx, "exact_0006_guid")
    display_id = int(
        getattr(
            ctx,
            "display_id",
            _resolve_player_display_id(
                int(getattr(ctx, "race", 0) or 0),
                int(getattr(ctx, "gender", 0) or 0),
                15476,
            ),
        )
        or 15476
    )
    base_fields = {
        6: 0,
        69: display_id,
        70: display_id,
        71: 0,
        162: int(getattr(ctx, "player_flags", 0) or 0),
    }
    extra_fields = getattr(ctx, "exact_0006_extra_u32_fields", None)
    if extra_fields:
        base_fields.update({int(field_index): int(field_value) for field_index, field_value in extra_fields.items()})
    mask_bytes, field_bytes, set_bits = _build_exact_fixed_u32_field_block(base_fields, mask_blocks=63)
    dynamic_mask_blocks = int(getattr(ctx, "exact_0006_dynamic_mask_blocks", 1))
    dynamic_mask_bytes = bytes(getattr(ctx, "exact_0006_dynamic_mask_bytes", b"\x00" * (dynamic_mask_blocks * 4)))

    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, 1)
    payload += _build_exact_update_object_value_update_entry(
        guid=guid,
        mask_bytes=mask_bytes,
        field_bytes=field_bytes,
        dynamic_mask_blocks=dynamic_mask_blocks,
        dynamic_mask_bytes=dynamic_mask_bytes,
    )
    built = bytes(payload)
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0006 map_id={map_id} guid=0x{guid:016X} "
        f"mask_blocks={len(mask_bytes)//4} packet_size={len(built)}"
    )
    Logger.info(
        "[UPDATE_OBJECT DEBUG] 0006 raw=%s update_type=0 guid=0x%016X guid_mask=0x%02X mask_blocks=%s set_fields=%s",
        built.hex(),
        int(guid) & 0xFFFFFFFFFFFFFFFF,
        int(GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)[0]),
        len(mask_bytes) // 4,
        set_bits,
    )
    Logger.info(
        "[UPDATE_OBJECT DEBUG] 0006 dynamic_mask_blocks=%s dynamic_mask_bytes=%s",
        dynamic_mask_blocks,
        dynamic_mask_bytes.hex(),
    )
    return built


def build_SMSG_UPDATE_OBJECT_1775665925_0009(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_1775665925_0009_map_id", int(getattr(ctx, "map_id", 1) or 1))
    guid = _resolve_player_value_update_guid(ctx, "exact_1775665925_0009_guid")
    display_id = int(
        getattr(
            ctx,
            "display_id",
            _resolve_player_display_id(
                int(getattr(ctx, "race", 0) or 0),
                int(getattr(ctx, "gender", 0) or 0),
                15476,
            ),
        )
        or 15476
    )
    player_mask_bytes, player_field_bytes, player_set_bits = _build_exact_fixed_u32_field_block(
        {
            6: 0,
            63: 4194304,
            69: display_id,
            70: display_id,
            71: 0,
        },
        mask_blocks=63,
    )
    creature_display_id = int(getattr(ctx, "exact_1775665925_0009_creature_display_id", 27510) or 27510)
    creature_guid = int(
        getattr(ctx, "exact_1775665925_0009_creature_guid", 0xF13079AA0008BBD8) or 0xF13079AA0008BBD8
    )
    creature_mask_bytes, creature_field_bytes, creature_set_bits = _build_exact_fixed_u32_field_block(
        {
            6: 0,
            63: 4194304,
            69: creature_display_id,
            70: creature_display_id,
            71: 0,
        },
        mask_blocks=5,
    )
    creature2_display_id = int(getattr(ctx, "exact_1775665925_0009_creature2_display_id", 29133) or 29133)
    creature2_guid = int(
        getattr(ctx, "exact_1775665925_0009_creature2_guid", 0xF132E6300008E410) or 0xF132E6300008E410
    )
    creature2_mask_bytes, creature2_field_bytes, creature2_set_bits = _build_exact_fixed_u32_field_block(
        {
            6: 0,
            63: 4194304,
            69: creature2_display_id,
            70: creature2_display_id,
            71: 0,
        },
        mask_blocks=5,
    )

    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, 3)
    payload += _build_exact_update_object_value_update_entry(
        guid=guid,
        mask_bytes=player_mask_bytes,
        field_bytes=player_field_bytes,
        dynamic_mask_blocks=1,
        dynamic_mask_bytes=b"\x00\x00\x00\x00",
    )
    payload += _build_exact_update_object_value_update_entry(
        guid=creature_guid,
        mask_bytes=creature_mask_bytes,
        field_bytes=creature_field_bytes,
        dynamic_mask_blocks=0,
    )
    payload += _build_exact_update_object_value_update_entry(
        guid=creature2_guid,
        mask_bytes=creature2_mask_bytes,
        field_bytes=creature2_field_bytes,
        dynamic_mask_blocks=0,
    )
    built = bytes(payload)
    Logger.info(
        "[UPDATE_OBJECT BUILD] 1775665925_0009 map_id=%s guid=0x%016X player_set_fields=%s creature_set_fields=%s creature2_set_fields=%s packet_size=%s",
        map_id,
        int(guid) & 0xFFFFFFFFFFFFFFFF,
        player_set_bits,
        creature_set_bits,
        creature2_set_bits,
        len(built),
    )
    return built


def _build_exact_update_object_out_of_range_entry(guid_list: list[int]) -> bytes:
    payload = bytearray()
    payload += struct.pack("<BI", 3, len(guid_list))
    for guid in guid_list:
        payload += GuidHelper.pack(int(guid))
    return bytes(payload)


def build_SMSG_UPDATE_OBJECT_1773613205_0007(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = _ctx_int_preserve_zero(ctx, "exact_0007_map_id", int(getattr(ctx, "map_id", 1)))
    guid_list = list(
        getattr(
            ctx,
            "exact_0007_out_of_range_guids",
            [
                0x1FC0000000000004,
                0x1FC0000000000006,
                0x1FC0000000000007,
                0x1FC0000000000008,
                0x1FC0000000000014,
                0x1FC0000000000017,
                0x1FC0000000000018,
            ],
        )
    )
    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, 1)
    payload += _build_exact_update_object_out_of_range_entry([int(guid) for guid in guid_list])
    built = bytes(payload)
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0007 map_id={map_id} out_of_range_count={len(guid_list)} "
        f"packet_size={len(built)}"
    )
    return built


def _resolve_update_world_guid(ctx: Any) -> int:
    world_guid = getattr(ctx, "world_guid", None)
    if world_guid is None:
        world_guid = GuidHelper.make(
            high=HighGuid.PLAYER,
            realm=int(getattr(ctx, "realm_id", 0) or 0),
            low=int(getattr(ctx, "char_guid", 0) or 0),
        )
    return int(world_guid)


def _resolve_player_value_update_guid(ctx: Any, explicit_key: str) -> int:
    guid_value = getattr(ctx, explicit_key, None)
    if guid_value is None:
        guid_value = getattr(ctx, "char_guid", None)
    if guid_value is None:
        guid_value = _resolve_update_world_guid(ctx)

    raw_guid = int(guid_value) & 0xFFFFFFFFFFFFFFFF
    low_guid = raw_guid & 0xFFFFFFFF
    high_byte = (raw_guid >> 56) & 0xFF
    if high_byte == 0:
        high_byte = 0x07
    return ((int(high_byte) & 0xFF) << 56) | int(low_guid)


def _build_manual_active_mover_payload(mover_guid: int) -> bytes:
    raw = int(mover_guid).to_bytes(8, "little", signed=False)
    present = {index for index, value in enumerate(raw) if value}
    bits = BitWriter()
    for index in (5, 1, 4, 2, 3, 7, 0, 6):
        bits.write_bits(1 if raw[index] else 0, 1)

    payload = bytearray(bits.getvalue())
    for index in (4, 6, 2, 0, 3, 7, 5, 1):
        if index not in present:
            continue
        payload.append((raw[index] ^ 0x01) & 0xFF)

    expected_len = 1 + len(present)
    if len(payload) != expected_len:
        raise AssertionError(
            f"SMSG_MOVE_SET_ACTIVE_MOVER manual payload length mismatch: {len(payload)} != {expected_len}"
        )
    return bytes(payload)

def build_SMSG_PHASE_SHIFT_CHANGE_old(ctx) -> bytes:
    return _encode("SMSG_PHASE_SHIFT_CHANGE", {
        "phase_mask": 1,
        "terrain_swap": 0,
        "phase_count": 0,
        "phase_ids": [],
        "visible_map_count": 0,
        "visible_map_ids": [],
        "ui_map_phase_count": 0,
        "ui_map_phase_ids": [],
    })

def build_SMSG_PHASE_SHIFT_CHANGE(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    return _encode("SMSG_PHASE_SHIFT_CHANGE", {
        "phase_mask": int(getattr(ctx, "phase_mask", 1) or 1),
        "terrain_swap": int(getattr(ctx, "terrain_swap", 0) or 0),
        "phase_count": int(getattr(ctx, "phase_count", 0) or 0),
        "phase_ids": list(getattr(ctx, "phase_ids", []) or []),
        "visible_map_count": int(getattr(ctx, "visible_map_count", 0) or 0),
        "visible_map_ids": list(getattr(ctx, "visible_map_ids", []) or []),
        "ui_map_phase_count": int(getattr(ctx, "ui_map_phase_count", 0) or 0),
        "ui_map_phase_ids": list(getattr(ctx, "ui_map_phase_ids", []) or []),
    })


def build_SMSG_TRANSFER_PENDING(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"map_id": 0})()
    return _encode("SMSG_TRANSFER_PENDING", {
        "map_id": int(getattr(ctx, "map_id", 0) or 0),
    })


def build_SMSG_NEW_WORLD(_ctx=None) -> bytes:
    ctx = _ctx or type(
        "Ctx",
        (),
        {"map_id": 0, "x": 0.0, "y": 0.0, "z": 0.0, "orientation": 0.0},
    )()
    return _encode("SMSG_NEW_WORLD", {
        "map_id": int(getattr(ctx, "map_id", 0) or 0),
        "x": float(getattr(ctx, "x", 0.0) or 0.0),
        "y": float(getattr(ctx, "y", 0.0) or 0.0),
        "z": float(getattr(ctx, "z", 0.0) or 0.0),
        "orientation": float(getattr(ctx, "orientation", 0.0) or 0.0),
    })

def build_SMSG_INIT_WORLD_STATES_old(ctx) -> bytes:
    return _encode("SMSG_INIT_WORLD_STATES", {
        "map_id": ctx.map_id,
        "zone_id": ctx.zone,
        "area_id": 0,
        "world_states": [],
    })

def build_SMSG_INIT_WORLD_STATES(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"map_id": 0, "zone": 0})()
    states = list(getattr(ctx, 'states', []) or [])

    bits = BitWriter()
    bits.write_bits(len(states) & 0x1FFFFF, 21)

    payload = bytearray()
    payload.extend(struct.pack('<I', int(getattr(ctx, 'map_id', 0))))
    payload.extend(struct.pack('<I', int(getattr(ctx, 'zone', 0))))
    payload.extend(struct.pack('<I', int(getattr(ctx, 'zone', 0))))
    payload.extend(bits.getvalue())

    for state in states:
        payload.extend(struct.pack('<I', int(state.get('value', 0))))
        payload.extend(struct.pack('<I', int(state.get('state_id', state.get('field', 0)))))

    return bytes(payload)


def handle_CMSG_REQUEST_HOTFIX(ctx: PacketContext):
    captured = _load_payload_packet("SMSG_HOTFIX_NOTIFY_BLOB")
    if captured is not None:
        return 0, ("SMSG_HOTFIX_NOTIFY_BLOB", captured)
    return 0, ("SMSG_HOTFIX_NOTIFY_BLOB", _encode("SMSG_HOTFIX_NOTIFY_BLOB", {
        "count": 0,
    }))

def build_SMSG_UPDATE_WORLD_STATE(ctx) -> bytes:
    return _encode("SMSG_UPDATE_WORLD_STATE", {
        "hidden": 0,
        "value": int(getattr(ctx, "value", 0) or 0),
        "state_id": int(getattr(ctx, "variable_id", 0) or 0),
    })

def build_SMSG_WEATHER(ctx) -> bytes:
    weather = getattr(ctx, "weather", None)
    if not isinstance(weather, dict):
        weather = {}
    weather_type = int(
        getattr(
            ctx,
            "weather_type",
            getattr(ctx, "weather_id", weather.get("weather_type", 0)),
        ) or 0
    )
    if weather_type < 0:
        weather_type = 0
    return _encode("SMSG_WEATHER", {
        "weather_type": weather_type,
        "density": float(
            getattr(
                ctx,
                "density",
                getattr(ctx, "intensity", weather.get("density", 0.0)),
            ) or 0.0
        ),
        "abrupt": int(getattr(ctx, "abrupt", weather.get("abrupt", 0)) or 0),
    })
def build_SMSG_HOTFIX_NOTIFY_BLOB(_ctx=None) -> bytes:
    return _encode("SMSG_HOTFIX_NOTIFY_BLOB", {
        "count": 0,
    })

def build_SMSG_TIME_SYNC_REQUEST_old(ctx) -> bytes:
    return _encode("SMSG_TIME_SYNC_REQUEST", {
        "sequence_id": ctx.time_sync_seq,
    })

def build_SMSG_TIME_SYNC_REQUEST(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"time_sync_seq": 0})()
    return _encode("SMSG_TIME_SYNC_REQUEST", {
        "sequence_id": int(getattr(ctx, "time_sync_seq", 0)),
    })

def build_SMSG_LOAD_CUF_PROFILES(ctx) -> bytes:
    return _encode("SMSG_LOAD_CUF_PROFILES", {
        "profiles": [],
    })
# packets.py

def build_SMSG_AUTH_RESPONSE(ctx) -> bytes:
    realm = DatabaseConnection.get_all_realms()[0]

    races = [{"expansion": 4, "race_id": r} for r in RACES_MOP]
    classes = [{"expansion": 4, "class_id": c} for c in CLASSES_MOP]

    fields = {
        "auth_ok": 1,
        "realm_count": 1,

        "realm_meta_data": [{
            "name_len": len(realm.name),
            "normalized_len": len(realm.name.lower()),
            "is_home": 1,
            "class_count": len(classes),
            "unk21": 0,
            "flag0": realm.flag or 0,
            "flag1": 0,
            "flag2": 0,
            "flag3": 0,
            "race_count": len(races),
            "empty_bit": 0,
            "queued": int(realm.population > 1.5),
        }],

        "realm": [{
            "realm_id": realm.id,
            "realm_name": realm.name,
            "normalized_name": realm.name.lower(),

            "races": races,
            "classes": classes,

            "flag1_int": realm.flag or 0,
            "expansion_active": 4,
            "flag2_int": 0,
            "flag3_int": 0,
            "expansion_server": 4,
            "flag4_int": 0,
            "flag5_int": 0,
            "flag6_int": 0,
            "auth_result": 12,
        }],
    }

    return EncoderHandler.encode_packet("SMSG_AUTH_RESPONSE", fields)


def build_SMSG_ADDON_INFO(ctx) -> bytes:
    addons = list(getattr(ctx, "addons", []) or [])
    banned = list(getattr(ctx, "banned_addons", []) or [])

    payload = bytearray()
    bits = BitWriter()
    bits.write_bits(len(banned) & 0x3FFFF, 18)
    bits.write_bits(len(addons) & 0x7FFFFF, 23)
    for addon in addons:
        enabled = 1 if int(addon.get("enabled", 1) or 0) else 0
        send_public_key = 1 if int(addon.get("send_public_key", 0) or 0) else 0
        bits.write_bits(0, 1)
        bits.write_bits(enabled, 1)
        bits.write_bits(send_public_key, 1)
    payload.extend(bits.getvalue())

    public_key = addon_public_key_bytes()
    for addon in addons:
        enabled = 1 if int(addon.get("enabled", 1) or 0) else 0
        send_public_key = 1 if int(addon.get("send_public_key", 0) or 0) else 0
        if send_public_key:
            payload.extend(public_key)
        if enabled:
            payload.append(enabled)
            payload.extend((0).to_bytes(4, "little", signed=False))
        payload.append(int(addon.get("state", 2) or 2) & 0xFF)

    for addon in banned:
        payload.extend(int(addon.get("id", 0) or 0).to_bytes(4, "little", signed=False))
        payload.extend((1).to_bytes(4, "little", signed=False))
        for _ in range(8):
            payload.extend((0).to_bytes(4, "little", signed=False))
        payload.extend(int(addon.get("timestamp", 0) or 0).to_bytes(4, "little", signed=False))
    return bytes(payload)


def build_SMSG_TUTORIAL_FLAGS(ctx) -> bytes:
    values = list(getattr(ctx, "tutorial_flags", []) or [])
    if len(values) < 16:
        values.extend([0] * (16 - len(values)))
    return _encode("SMSG_TUTORIAL_FLAGS", {
        "list": values[:16],
    })


CHAR_META_MASK_FIELDS = (
    # guid masks
    "guid_0_mask",
    "guid_1_mask",
    "guid_2_mask",
    "guid_3_mask",
    "guid_4_mask",
    "guid_5_mask",
    "guid_6_mask",
    "guid_7_mask",

    # guild guid masks (BÅDA NAMNEN)
    "guildguid_0_mask",
    "guildguid_1_mask",
    "guildguid_2_mask",
    "guildguid_3_mask",
    "guildguid_4_mask",
    "guildguid_5_mask",
    "guildguid_6_mask",
    "guildguid_7_mask",
)

def build_SMSG_MOVE_SET_ACTIVE_MOVER(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"world_guid": None, "realm_id": 0, "char_guid": 0})()
    mover_world_guid = _resolve_update_world_guid(ctx)
    mover_guid = int(getattr(ctx, "char_guid", 0) or 0)
    if mover_guid <= 0:
        mover_guid = int(mover_world_guid) & 0xFFFFFFFF
    mover_guid_mask = GuidHelper.pack(mover_guid)[0]
    Logger.info(
        f"[ACTIVE_MOVER DEBUG] world_guid={hex(int(mover_world_guid))} "
        f"active_mover_guid={hex(int(mover_guid))} mask=0x{mover_guid_mask:02X}"
    )
    return _build_manual_active_mover_payload(mover_guid)

def build_SMSG_MOVE_SET_ACTIVE_MOVER_old(ctx) -> bytes:
    mover_guid = GuidHelper.make(
        high=HighGuid.PLAYER,
        realm=int(getattr(ctx, "realm_id", 0) or 0),
        low=int(getattr(ctx, "char_guid", 0) or 0),
    )

    return _encode("SMSG_MOVE_SET_ACTIVE_MOVER", {
        "moverGUID": mover_guid,
    })

def build_ENUM_CHARACTERS_RESULT(account_id: int, realm_id: int) -> bytes:
    """
    Build SMSG_ENUM_CHARACTERS_RESULT using ONLY live DB data.
    No fallbacks. Invalid characters are skipped.
    """

    rows = DatabaseConnection.get_characters_for_account(account_id, realm_id)

    chars_meta: list[dict] = []
    chars: list[dict] = []

    for idx, row in enumerate(rows):
        try:
            # ---------- NAME ----------
            name = row.name or ""
            name_bytes = name.encode("utf-8")
            if not (1 <= len(name_bytes) <= 63):
                Logger.error(f"[ENUM] Invalid name length guid={row.guid}")
                continue

            # ---------- GUID ----------
            enum_guid = GuidHelper.make(
                high=HighGuid.PLAYER,
                realm=int(realm_id),
                low=int(row.guid),
            )
            guid_bytes, guid_masks = _guid_bytes_and_masks(enum_guid)
            if not guid_masks:
                Logger.error(f"[ENUM] Invalid GUID masks guid={row.guid}")
                continue

            # ---------- META ----------
            # Starta med ALLA maskfält satta till 0 (DSL-krav)
            meta = {
                # guid masks
                "guid_0_mask": 0,
                "guid_1_mask": 0,
                "guid_2_mask": 0,
                "guid_3_mask": 0,
                "guid_4_mask": 0,
                "guid_5_mask": 0,
                "guid_6_mask": 0,
                "guid_7_mask": 0,

                # guild guid masks (båda namnformerna)
                "guildguid_0_mask": 0,
                "guildguid_1_mask": 0,
                "guildguid_2_mask": 0,
                "guildguid_3_mask": 0,
                "guildguid_4_mask": 0,
                "guildguid_5_mask": 0,
                "guildguid_6_mask": 0,
                "guildguid_7_mask": 0,

                # övriga meta-fält
                "boosted": 0,
                "at_login_first": 1 if row.at_login else 0,
                "name_len": len(name_bytes),
            }

            # Applicera GUID-masker (överskriver 0 → 1 där byte != 0)
            meta.update(guid_masks)

            # ---------- APPEARANCE ----------
            appearance = _decode_player_bytes(row.playerBytes, row.playerBytes2)
            if not appearance:
                Logger.error(f"[ENUM] Missing appearance guid={row.guid}")
                continue

            # ---------- EQUIPMENT ----------
            equipment = _parse_equipment_cache(row.equipmentCache or "")
            if not equipment or len(equipment) != 23:
                Logger.warning(f"[ENUM] Invalid equipment guid={row.guid}, using empty fallback")
                equipment = [
                    {"enchant": 0, "int_type": 0, "display_id": 0}
                    for _ in range(23)
                ]

            resolved_zone = int(
                resolve_zone_from_position(
                    int(row.map or 0),
                    float(row.position_x or 0.0),
                    float(row.position_y or 0.0),
                ) or int(row.zone or 0)
            )

            # ---------- CHARACTER ----------
            char = {
                "unk02": 0,
                "slot": row.slot,
                "hair_style": appearance["hair_style"],
                "name": name,
                "x": float(row.position_x),
                "unk00": 0,
                "face": appearance["face"],
                "class": int(row.class_),
                "equipment": equipment,
                "customizationFlag": int(row.at_login),
                "petFamily": 0,
                "mapId": int(row.map),
                "race": int(row.race),
                "skin": appearance["skin"],
                "level": int(row.level),
                "hair_color": appearance["hair_color"],
                "gender": int(row.gender),
                "facial_hair": appearance["facial_hair"],
                "pet_level": 0,
                "y": float(row.position_y),
                "petDisplayID": 0,
                "unk3": 0,
                "char_flags": int(row.playerFlags),
                "zone": resolved_zone,
                "z": float(row.position_z),
                "guid": 0,        # combined by DSL
                "guildguid": 0,   # combined by DSL
            }

            # Inject GUID bytes conditionally
            for i in range(8):
                if meta.get(f"guid_{i}_mask"):
                    char[f"guid_{i}"] = guid_bytes[i]

            chars_meta.append(meta)
            chars.append(char)

        except Exception as exc:
            Logger.error(f"[ENUM] Failed guid={getattr(row, 'guid', None)}: {exc}")
            continue

    fields = {
        "faction_mask_bits": 0,
        "char_count_bits": len(chars),
        "chars_meta": chars_meta,
        "success": 1,
        "chars": chars,
    }

    Logger.info(
        f"[ENUM] Built {len(chars)} characters for account={account_id} realm={realm_id}"
    )

    return EncoderHandler.encode_packet("SMSG_ENUM_CHARACTERS_RESULT", fields)
