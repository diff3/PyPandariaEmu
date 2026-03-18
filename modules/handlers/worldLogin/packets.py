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
import time
import json
import struct
from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitWriter
from server.modules.PacketContext import PacketContext
from shared.Logger import Logger

from .constants import RACES_MOP, CLASSES_MOP
from shared.PathUtils import get_captures_root, get_debug_root
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.equipment import _parse_equipment_cache
from server.modules.player import _decode_player_bytes
from server.modules.guid import _guid_bytes_and_masks, GuidHelper, HighGuid
from server.modules.interpretation.utils import dsl_decode, to_safe_json


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
        "flag": 0x80,
        "mask": 0,
        "timestamps": [now] * 8,
        "server_time": now,
    })


def build_SMSG_ACCOUNT_DATA_TIMES(_ctx=None) -> bytes:
    now = int(time.time())
    Logger.info(f"[ACCOUNT DATA] server_time={now}")
    payload = _encode("SMSG_ACCOUNT_DATA_TIMES", {
        "flag": 0x80,
        "mask": 0,
        "timestamps": [now] * 8,
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
    # Minimal Blizzard-safe MoP payload: keep all feature flags disabled except
    # mount preview. Build this packet raw to avoid any accidental flag
    # derivation from context or stale captures.
    payload = struct.pack(
        "<IIIIIIII3B",
        0,  # voice
        0,  # browser
        0,  # scroll
        1,  # mountpreview
        0,  # complaint1
        0,  # complaint2
        0,  # flags1
        0,  # flags2
        0, 0, 0,  # flags3[3]
    )
    Logger.info(f"[MOP DEBUG] FEATURE_SYSTEM_STATUS size={len(payload)}")
    if len(payload) != 35:
        raise AssertionError(f"SMSG_FEATURE_SYSTEM_STATUS malformed length: {len(payload)} != 35")
    return payload


def build_SMSG_MOTD_old(ctx) -> bytes:
    return _encode("SMSG_MOTD", {
        "motd": ctx.motd,
    })

def build_SMSG_MOTD(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"motd": "Welcome to PyPandaria"})()
    motd = getattr(ctx, "motd", "Welcome to PyPandaria")
    if motd is None:
        motd = ""
    motd = str(motd)
    # MoP-safe MOTD: uint32 line_count followed by null-terminated strings.
    lines = [motd if motd else ""]
    payload = bytearray()
    payload += struct.pack("<I", len(lines))
    for line in lines:
        payload += line.encode("utf-8", errors="strict") + b"\x00"
    payload = bytes(payload)
    Logger.info(f"[MOP DEBUG] MOTD lines={len(lines)} size={len(payload)}")
    if len(payload) < 5:
        raise AssertionError(f"SMSG_MOTD malformed length: {len(payload)} < 5")
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
    return _encode("SMSG_WORLD_SERVER_INFO", {
        "is_tournament_realm": int(info.get("is_tournament_realm", 0)),
        "unk0": int(info.get("unk0", 0)),
        "weekly_reset_time": int(info.get("weekly_reset_time", 0)),
        "flags": int(info.get("flags", 0)),
    })


def build_SMSG_SEND_KNOWN_SPELLS(ctx) -> bytes:
    return _encode("SMSG_SEND_KNOWN_SPELLS", {
        "initial_login": 1,
        "spell_count": len(getattr(ctx, "known_spells", []) or []),
        "spells": [{"spell_id": int(spell)} for spell in (getattr(ctx, "known_spells", []) or [])],
    })


def build_SMSG_SEND_UNLEARN_SPELLS(ctx) -> bytes:
    return _encode("SMSG_SEND_UNLEARN_SPELLS", {
        "count": 0,
        "spells": [],
    })


def build_SMSG_UPDATE_ACTION_BUTTONS(ctx) -> bytes:
    # MoP 5.4.x uses a bitpacked/XOR'd 132-entry action bar payload.
    # We build it manually here until a proper DSL case exists.
    button_count = 132
    packet_type = 1
    source_buttons = list(getattr(ctx, "action_buttons", []) or [])
    button_values = [0] * button_count

    for index, value in enumerate(source_buttons[:button_count]):
        try:
            button_values[index] = int(value) & 0xFFFFFFFF
        except Exception:
            button_values[index] = 0

    button_bytes = [
        list(int(value).to_bytes(8, "little", signed=False))
        for value in button_values
    ]

    bits = BitWriter()
    for byte_index in (4, 5, 3, 1, 6, 7, 0, 2):
        for raw in button_bytes:
            bits.write_bits(1 if raw[byte_index] else 0, 1)

    payload = bytearray(bits.getvalue())

    for byte_index in (0, 1, 4, 6, 7, 2, 5, 3):
        for raw in button_bytes:
            if raw[byte_index]:
                payload.append(raw[byte_index] ^ 0x01)

    payload.append(packet_type & 0xFF)
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
_EXACT_UPDATE_OBJECT_1773613176_0004_DEFAULT = bytes.fromhex(
    "0100010000000001023F4000001C00000080E00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000733C0000733C00000000000000"
)
_EXACT_UPDATE_OBJECT_1773613185_0006_DEFAULT = bytes.fromhex(
    "0100010000000001023F4000001C00000020E0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000400733C0000733C0000000000000100000000"
)
_EXACT_UPDATE_OBJECT_1773613205_0007_DEFAULT = bytes.fromhex(
    "0100010000000307000000C104C01FC106C01FC107C01FC108C01FC114C01FC117C01FC118C01F"
)
_EXACT_UPDATE_OBJECT_1773613176_0002_OFFSETS = {
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
    "guid1_0": 553,
    "health": 836,
    "power_primary": 840,
    "max_health": 844,
    "max_power_primary": 848,
    "level": 852,
    "player_bytes": 980,
    "player_bytes2": 984,
}


def _build_update_object_packet_prefix(map_id: int, update_count: int) -> bytes:
    return struct.pack("<HI", int(map_id), int(update_count))


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
) -> bytes:
    payload = bytearray()
    payload += struct.pack("<B", 0)
    payload += GuidHelper.pack(int(guid))
    payload += struct.pack("<B", len(mask_bytes) // 4)
    payload += bytes(mask_bytes)
    payload += bytes(field_bytes)
    payload += struct.pack("<B", int(dynamic_mask_blocks))
    return bytes(payload)


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
    map_id = int(getattr(ctx, "exact_0005_map_id", getattr(ctx, "map_id", 1)) or 1)
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


def build_SMSG_UPDATE_OBJECT_1773613176_0004(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = int(getattr(ctx, "exact_0004_map_id", getattr(ctx, "map_id", 1)) or 1)
    guid = int(getattr(ctx, "exact_0004_guid", _resolve_update_world_guid(ctx)))
    mask_bytes = bytes(
        getattr(
            ctx,
            "exact_0004_mask_bytes",
            bytes.fromhex(
                "4000001c00000080e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
    )
    field_bytes = bytes(
        getattr(
            ctx,
            "exact_0004_field_bytes",
            bytes.fromhex("04000733c0000733c000000000000000"),
        )
    )
    dynamic_mask_blocks = int(getattr(ctx, "exact_0004_dynamic_mask_blocks", 0))

    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, 1)
    payload += _build_exact_update_object_value_update_entry(
        guid=guid,
        mask_bytes=mask_bytes,
        field_bytes=field_bytes,
        dynamic_mask_blocks=dynamic_mask_blocks,
    )
    built = bytes(payload)
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0004 map_id={map_id} guid=0x{guid:016X} "
        f"mask_blocks={len(mask_bytes)//4} packet_size={len(built)}"
    )
    return built


def build_SMSG_UPDATE_OBJECT_1773613176_0003(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    map_id = int(getattr(ctx, "exact_0003_map_id", getattr(ctx, "map_id", 1)) or 1)
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
    if hasattr(ctx, "exact_0002_payload"):
        built = bytearray(bytes(getattr(ctx, "exact_0002_payload")))
        map_id = int(getattr(ctx, "exact_0002_map_id", getattr(ctx, "map_id", struct.unpack_from("<H", built, 0)[0])) or 1)
        struct.pack_into("<H", built, 0, map_id)
        built = bytes(built)
    else:
        built = _build_live_update_object_1773613176_0002_payload(ctx)
        map_id = struct.unpack_from("<H", built, 0)[0]
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0002 map_id={map_id} packet_size={len(built)}"
    )
    return built


def _decode_packed_guid(mask: int, packed_bytes: bytes) -> int:
    raw = [0] * 8
    offset = 0
    for bit in range(8):
        if mask & (1 << bit):
            raw[bit] = packed_bytes[offset]
            offset += 1
    return int.from_bytes(bytes(raw), "little", signed=False)


def _patch_u32(payload: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", payload, int(offset), int(value) & 0xFFFFFFFF)


def _patch_f32(payload: bytearray, offset: int, value: float) -> None:
    struct.pack_into("<f", payload, int(offset), float(value))


def _build_live_update_object_1773613176_0002_payload(ctx: Any) -> bytes:
    payload = bytearray(load_first_login_update_object_capture())
    offsets = _EXACT_UPDATE_OBJECT_1773613176_0002_OFFSETS

    map_id = int(getattr(ctx, "exact_0002_map_id", getattr(ctx, "map_id", struct.unpack_from("<H", payload, 0)[0])) or 1)
    struct.pack_into("<H", payload, 0, map_id)

    low_guid = int(getattr(ctx, "exact_0002_low_guid", getattr(ctx, "char_guid", 2)) or 2) & 0xFF
    payload[offsets["last_entry_packed_guid_low"]] = low_guid
    payload[offsets["guid1_0"]] = low_guid

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

    current_health = int(getattr(ctx, "health", 103) or 103)
    max_health = int(getattr(ctx, "max_health", current_health) or current_health)
    primary_power = int(getattr(ctx, "power_primary", 100) or 100)
    max_primary_power = int(getattr(ctx, "max_power_primary", primary_power) or primary_power)
    level = int(getattr(ctx, "level", 1) or 1)
    player_bytes = int(getattr(ctx, "player_bytes", 198401) or 198401)
    player_bytes2 = int(getattr(ctx, "player_bytes2", 16777224) or 16777224)

    _patch_u32(payload, offsets["health"], current_health)
    _patch_u32(payload, offsets["power_primary"], primary_power)
    _patch_u32(payload, offsets["max_health"], max_health)
    _patch_u32(payload, offsets["max_power_primary"], max_primary_power)
    _patch_u32(payload, offsets["level"], level)
    _patch_u32(payload, offsets["player_bytes"], player_bytes)
    _patch_u32(payload, offsets["player_bytes2"], player_bytes2)

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
    map_id = int(getattr(ctx, "exact_0006_map_id", getattr(ctx, "map_id", 1)) or 1)
    guid = int(getattr(ctx, "exact_0006_guid", _resolve_update_world_guid(ctx)))
    mask_bytes = bytes(
        getattr(
            ctx,
            "exact_0006_mask_bytes",
            bytes.fromhex(
                "4000001c00000020e0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
    )
    field_bytes = bytes(
        getattr(
            ctx,
            "exact_0006_field_bytes",
            bytes.fromhex("08000400733c0000733c00000000000001000000"),
        )
    )
    dynamic_mask_blocks = int(getattr(ctx, "exact_0006_dynamic_mask_blocks", 0))

    payload = bytearray()
    payload += _build_update_object_packet_prefix(map_id, 1)
    payload += _build_exact_update_object_value_update_entry(
        guid=guid,
        mask_bytes=mask_bytes,
        field_bytes=field_bytes,
        dynamic_mask_blocks=dynamic_mask_blocks,
    )
    built = bytes(payload)
    Logger.info(
        f"[UPDATE_OBJECT BUILD] 0006 map_id={map_id} guid=0x{guid:016X} "
        f"mask_blocks={len(mask_bytes)//4} packet_size={len(built)}"
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
    map_id = int(getattr(ctx, "exact_0007_map_id", getattr(ctx, "map_id", 1)) or 1)
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


def _build_manual_active_mover_payload(mover_guid: int) -> bytes:
    raw = int(mover_guid).to_bytes(8, "little", signed=False)
    payload = bytes([raw[0], raw[6]])
    if len(payload) != 2:
        raise AssertionError(
            f"SMSG_MOVE_SET_ACTIVE_MOVER manual payload length mismatch: {len(payload)} != 2"
        )
    return payload

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
    return _encode("SMSG_INIT_WORLD_STATES", {
        "map_id": int(getattr(ctx, "map_id", 0)),
        "zone_id": int(getattr(ctx, "zone", 0)),
        "area_id": int(getattr(ctx, "zone", 0)),
        "states": [],
        "_": 0,
    })


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
    return _encode("SMSG_WEATHER", {
        "weather_id": 0,   # clear
        "intensity": 0.0,
        "abrupt": 0,
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


def build_SMSG_ADDON_INFO(addons: list[dict]) -> bytes:
    return _encode("SMSG_ADDON_INFO", {
        "addons": addons,
    })


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
    mover_guid = _resolve_update_world_guid(ctx)
    mover_guid_mask = GuidHelper.pack(mover_guid)[0]
    Logger.info(
        f"[ACTIVE_MOVER DEBUG] guid={hex(int(mover_guid))} mask=0x{mover_guid_mask:02X}"
    )
    return _encode("SMSG_MOVE_SET_ACTIVE_MOVER", {
        "raw": _build_manual_active_mover_payload(mover_guid),
    })

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
                "zone": int(row.zone),
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
