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

import json
import math
import random
import struct
import time
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from server.modules.handlers.worldLogin.context import WorldLoginContext

from DSL.modules.dsl.EncoderHandler import EncoderHandler
from DSL.modules.dsl.bitsHandler import BitWriter
from server.modules.handlers.worldLogin.packets import (
    build_ENUM_CHARACTERS_RESULT,
    build_login_packet,
    handle_CMSG_REQUEST_HOTFIX as _handle_CMSG_REQUEST_HOTFIX,
    _load_payload_packet,
)
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.session.world_session import LoginState, WorldSession
from server.modules.handlers.characters.characters import (
    handle_CMSG_CHAR_DELETE,
    handle_CMSG_CHAR_CREATE,
    handle_CMSG_REORDER_CHARACTERS,
)

from server.modules.dbc import read_dbc
from server.modules.interpretation.utils import dsl_decode, to_safe_json
# from red.utils.OpcodeLoader import load_world_opcodes
from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
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

_LOGIN_UPDATE_OBJECT_CAPTURE_DIR = Path(__file__).resolve().parents[2] / "captures" / "focus" / "debug"
_ACCOUNT_DATA_CAPTURE_DIR = Path(__file__).resolve().parents[2] / "captures" / "focus" / "debug"
_ACCOUNT_DATA_BINDINGS_CAPTURE = _ACCOUNT_DATA_CAPTURE_DIR / "SMSG_UPDATE_ACCOUNT_DATA_1773657568_0001.json"
_ACCOUNT_DATA_CAPTURE_GLOB = "SMSG_UPDATE_ACCOUNT_DATA_*.json"
LOGIN_REPLAY_PLAYER_GUID = 0x03000100000002
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
CHAT_MSG_SAY = 1
CHAT_MSG_YELL = 6
CHAT_MSG_WHISPER = 7
_CHAT_TYPE_BY_OPCODE = {
    "CMSG_MESSAGECHAT_SAY": CHAT_MSG_SAY,
    "CMSG_MESSAGECHAT_YELL": CHAT_MSG_YELL,
    "CMSG_MESSAGECHAT_WHISPER": CHAT_MSG_WHISPER,
}
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
    return WorldLoginContext.from_session(session)


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
    if not decoded:
        return None

    def _coerce_float(value: Any) -> Optional[float]:
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)
    current_orientation = float(getattr(session, "orientation", 0.0) or 0.0)

    x = _coerce_float(decoded.get("x"))
    if x is None:
        x = _coerce_float(decoded.get("position_x"))

    y = _coerce_float(decoded.get("y"))
    if y is None:
        y = _coerce_float(decoded.get("position_y"))

    z = _coerce_float(decoded.get("z"))
    if z is None:
        z = _coerce_float(decoded.get("position_z"))

    orientation = _coerce_float(decoded.get("facing"))
    if orientation is None:
        orientation = _coerce_float(decoded.get("orientation"))

    if orientation is None:
        return None

    if x is None:
        x = current_x
    if y is None:
        y = current_y
    if z is None:
        z = current_z

    if None not in (x, y, z):
        return (x, y, z, orientation)
    return None


def _score_movement_candidate(
    x: float,
    y: float,
    z: float,
    orientation: float,
) -> float:
    if not all(math.isfinite(value) for value in (x, y, z, orientation)):
        return float("inf")
    if abs(x) > 100000 or abs(y) > 100000 or abs(z) > 100000:
        return float("inf")
    if abs(orientation) > (math.pi * 8):
        return float("inf")

    current_x = float(getattr(session, "x", 0.0) or 0.0)
    current_y = float(getattr(session, "y", 0.0) or 0.0)
    current_z = float(getattr(session, "z", 0.0) or 0.0)
    current_o = float(getattr(session, "orientation", 0.0) or 0.0)

    score = abs(x - current_x) + abs(y - current_y) + abs(z - current_z)
    score += min(abs(orientation - current_o), math.tau)
    return score


def _extract_movement_from_payload(payload: bytes) -> Optional[tuple[float, float, float, float]]:
    if len(payload) < 16:
        return None

    best: Optional[tuple[float, float, float, float]] = None
    best_score = float("inf")
    for offset in range(0, len(payload) - 15):
        try:
            x, y, z, orientation = struct.unpack_from("<ffff", payload, offset)
        except struct.error:
            continue

        score = _score_movement_candidate(x, y, z, orientation)
        if score < best_score:
            best = (x, y, z, orientation)
            best_score = score

    return best


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


def parse_movement_info(opcode_name: str, payload: bytes) -> Optional[tuple[float, float, float, float]]:
    decoded = dsl_decode(opcode_name, payload, silent=True)
    movement = _extract_movement_from_decoded(decoded)
    if movement is not None:
        return movement

    if opcode_name != "MSG_MOVE_HEARTBEAT":
        decoded = dsl_decode("MSG_MOVE_HEARTBEAT", payload, silent=True)
        movement = _extract_movement_from_decoded(decoded)
        if movement is not None:
            return movement

    return _extract_movement_from_payload(payload)


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


def replay_movement_focus_sequence(session: WorldSession) -> list[tuple[str, bytes]]:
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


def replay_update_object_sequence(session: WorldSession) -> list[tuple[str, bytes]]:
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


def _decode_chat_message(opcode_name: str, payload: bytes) -> dict[str, Any]:
    try:
        decoded = dsl_decode(opcode_name, payload, silent=True) or {}
    except Exception:
        decoded = {}

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
    if int(chat_type) == CHAT_MSG_SAY:
        message_bytes = str(message or "").encode("utf-8", errors="strict")
        # SkyFire MoP self-say uses a compact fixed header plus raw message bytes.
        encoded_len = 0x30 + (len(message_bytes) * 0x40)
        return (
            bytes(
                [
                    0x97,
                    0x00,
                    0x04,
                    0x18,
                    0x08,
                    (encoded_len >> 8) & 0xFF,
                    encoded_len & 0xFF,
                    0x00,
                    0x03,
                    0x01,
                    0x03,
                    0x01,
                ]
            )
            + message_bytes
        )

    sender_name_bytes = str(sender_name or "").encode("utf-8", errors="strict") + b"\x00"
    target_name_bytes = str(target_name or "").encode("utf-8", errors="strict") + b"\x00"
    message_bytes = str(message or "").encode("utf-8", errors="strict") + b"\x00"
    return EncoderHandler.encode_packet(
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


def _handle_chat_command(message: str) -> Optional[list[tuple[str, bytes]]]:
    command = str(message or "").strip()

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
    # SPEED COMMAND
    # -----------------------------
    if command.lower().startswith(".speed"):
        parts = command.split()

        if len(parts) != 2:
            Logger.info("[Speed] Usage: .speed <multiplier>")
            return []

        try:
            speed = float(parts[1])
        except ValueError:
            Logger.info(f"[Speed] Invalid value command={command!r}")
            return []

        if speed <= 0:
            Logger.info(f"[Speed] Non-positive speed command={command!r}")
            return []

        session.walk_speed = 2.5 * speed
        session.run_speed = 7.0 * speed
        session.run_back_speed = 4.5 * speed
        session.swim_speed = 4.7 * speed
        session.swim_back_speed = 2.5 * speed
        session.fly_speed = 7.0 * speed
        session.fly_back_speed = 4.5 * speed

        Logger.info(
            f"[Speed] multiplier={speed:.2f} "
            f"walk={session.walk_speed:.2f} "
            f"run={session.run_speed:.2f} "
            f"fly={session.fly_speed:.2f}"
        )

        return []

    # -----------------------------
    # FLY COMMAND
    # -----------------------------
    if command.lower().startswith(".fly"):
        parts = command.split()

        if len(parts) != 2:
            Logger.info("[Fly] Usage: .fly on|off")
            return []

        state = parts[1].lower()

        if state == "on":
            session.can_fly = True
            session.fly_speed = max(session.fly_speed, 14.0)
            Logger.info("[Fly] enabled")
            return []

        if state == "off":
            session.can_fly = False
            session.fly_speed = 7.0
            Logger.info("[Fly] disabled")
            return []

        Logger.info("[Fly] Usage: .fly on|off")
        return []

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

        session.x = float(x)
        session.y = float(y)
        session.z = float(z)
        session.orientation = float(orientation)
        session.map_id = int(map_id)
        session.instance_id = 0
        session.teleport_pending = True
        session.teleport_destination = f"manual:{map_id}:{x:.2f}:{y:.2f}:{z:.2f}:{orientation:.2f}"

        Logger.info(
            f"[Teleport] {player_name} -> manual ({map_id} {x:.2f} {y:.2f} {z:.2f} {orientation:.2f})"
        )

        return [
            ("SMSG_TRANSFER_PENDING", _build_transfer_pending_payload(map_id)),
            ("SMSG_NEW_WORLD", _build_new_world_payload(map_id, x, y, z, orientation)),
        ]

    # -----------------------------
    # TELEPORT PRESET
    # -----------------------------
    if not command.startswith(".tel"):
        return None

    parts = command.split(maxsplit=1)

    if len(parts) != 2:
        Logger.info(f"[Teleport] Unknown destination command={command!r}")
        return []

    destination_key = parts[1].strip().lower().replace(" ", "_")
    destination = TELEPORT_DESTINATIONS.get(destination_key)

    if destination is None:
        Logger.info(f"[Teleport] Unknown destination command={command!r}")
        return []

    map_id = int(destination["map_id"])
    x = float(destination["x"])
    y = float(destination["y"])
    z = float(destination["z"])
    orientation = float(destination["orientation"])

    session.x = float(x)
    session.y = float(y)
    session.z = float(z)
    session.orientation = float(orientation)
    session.map_id = int(map_id)

    if "zone" in destination:
        session.zone = int(destination["zone"])

    session.instance_id = 0
    session.teleport_pending = True
    session.teleport_destination = destination_key

    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )

    Logger.info(
        f"[Teleport] {player_name} -> {destination_key} ({x:.2f} {y:.2f} {z:.2f})"
    )

    return [
        (
            "SMSG_TRANSFER_PENDING",
            build_login_packet("SMSG_TRANSFER_PENDING", type("Ctx", (), {"map_id": map_id})()),
        ),
        (
            "SMSG_NEW_WORLD",
            build_login_packet(
                "SMSG_NEW_WORLD",
                type(
                    "Ctx",
                    (),
                    {
                        "map_id": map_id,
                        "x": x,
                        "y": y,
                        "z": z,
                        "orientation": orientation,
                    },
                )(),
            ),
        ),
    ]


def _handle_chat_message(opcode_name: str, payload: bytes):

    chat = _decode_chat_message(opcode_name, payload)
    message = chat["message"]
    if not message:
        return 0, None

    player_name = session.player_name
    sender_guid = session.player_guid

    Logger.info(f"[CHAT] {player_name}: {message}")

    payload_out = _encode_messagechat_payload(
        chat_type=CHAT_MSG_SAY,
        language=1,
        sender_guid=sender_guid,
        sender_name=player_name,
        target_guid=0,
        target_name="",
        message=message,
    )

    return 0, [("SMSG_MESSAGECHAT", payload_out)]

# -----------------------------------------------------------------------------
# Config / opcode maps
# -----------------------------------------------------------------------------

cfg = ConfigLoader.load_config()
program = cfg["program"]
expansion = cfg.get("expansion")
version = cfg["version"]

# WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, _ = load_world_opcodes()
SERVER_OPCODE_BY_NAME = {name: code for code, name in WORLD_SERVER_OPCODES.items()}

session = WorldSession()
MAX_CREATURE_QUEST_ITEMS = 6

# -----------------------------------------------------------------------------
# Templates / file helpers
# -----------------------------------------------------------------------------

def load_expected(case_name: str) -> dict:
    path = Path(f"protocols/{program}/{expansion}/{version}/data/json/{case_name}.json")
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

def _log_cmsg(name: str, payload: bytes) -> dict:
    try:
        decoded = dsl_decode(name, payload, silent=True) or {}
        Logger.success(f"[CMSG] {name}\n{json.dumps(to_safe_json(decoded), indent=2)}")
        return decoded
    except Exception as exc:
        Logger.error(f"[CMSG] decode {name} failed: {exc}")
        return {}

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


def _build_update_account_data_payload(data_type: int, account_data: str = "") -> bytes:
    raw_guid = b"\x00" * 8
    text = (account_data or "").encode("utf-8")
    compressed = zlib.compress(text)
    payload = bytearray()
    payload.extend(_guid_mask_bits(raw_guid, (5, 1, 3, 7, 0, 4, 2, 6)))

    payload.extend(struct.pack("<i", len(text)))
    payload.extend(struct.pack("<i", len(compressed)))
    payload.extend(compressed)
    payload.extend(struct.pack("<I", int(time.time())))

    # Overwrite the first 3 bits with the requested account-data type.
    bits = BitWriter()
    bits.write_bits(int(data_type) & 0x07, 3)
    bits.write_bits(0, 8)
    prefix = bits.getvalue()
    payload[0 : len(prefix)] = prefix
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


def _account_data_text_for_type(data_type: int, account_name: str = "") -> str:
    if int(data_type) in (0, 1):
        name = str(account_name or "").strip() or "sandbox"
        safe_name = name.replace("\\", "\\\\").replace('"', '\\"')
        return f'SET accountName "{safe_name}"'
    return ""


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
    responses: list[tuple[str, bytes]] = [
        (
            "SMSG_UPDATE_ACCOUNT_DATA",
            EncoderHandler.encode_packet(
                "SMSG_UPDATE_ACCOUNT_DATA",
                {"raw": _build_update_account_data_payload_target_len(214, 0)},
            ),
        )
    ]
    responses.append((
        "SMSG_UPDATE_ACCOUNT_DATA",
        EncoderHandler.encode_packet(
            "SMSG_UPDATE_ACCOUNT_DATA",
            {"raw": _build_update_account_data_payload_target_len(967, 0)},
        ),
    ))
    Logger.info(
        f"[WorldHandlers] Post-time-sync account-data sizes="
        f"{len(responses[0][1])},{len(responses[1][1])}"
    )
    return responses


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
) -> Optional[int]:
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
                Logger.info(
                    f"[WorldHandlers] PLAYER_LOGIN resolved char_guid={candidate} "
                    f"from login_guid=0x{int(login_guid or 0):X}"
                )
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
                Logger.info(
                    f"[WorldHandlers] PLAYER_LOGIN resolved char_guid={candidate} "
                    f"from raw 48-bit login guid"
                )
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
                Logger.info(
                    f"[WorldHandlers] PLAYER_LOGIN resolved char_guid={candidate} "
                    f"from {label} packed world guid 0x{candidate_world_guid:016X}"
                )
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
                    Logger.info(
                        f"[WorldHandlers] PLAYER_LOGIN resolved char_guid={candidate} "
                        f"from compact retail guid blob {compact.hex(' ')}"
                    )
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
                    Logger.info(
                        f"[WorldHandlers] PLAYER_LOGIN matched login GUID to char_guid={row.guid}"
                    )
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

def _default_equipment() -> list[dict]:
    return [{"enchant": 0, "int_type": 0, "display_id": 0} for _ in range(_EQUIPMENT_SLOTS)]

def _equipment_is_empty(entries: list[dict]) -> bool:
    return (not entries) or all((e.get("display_id") or 0) == 0 for e in entries)

def _resolve_dbc_root() -> Optional[Path]:
    dbc_root = cfg.get("dbc_path")
    if not dbc_root:
        dbc_root = (cfg.get("client") or {}).get("dbc_path")
    if not dbc_root:
        game_root = (cfg.get("client") or {}).get("game_root")
        if game_root:
            dbc_root = Path(game_root) / "Data" / "DBFilesClient"
    return Path(dbc_root) if dbc_root else None

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
    Logger.info(f"[WorldHandlers] Loaded CharStartOutfit entries: {len(outfits)}")
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
    session.account_id = None
    session.account_name = None
    session.realm_id = None
    session.player_guid = None
    session.world_guid = None
    session.char_guid = None
    session.time_sync_seq = 0
    _reset_login_flow_state()

def preload_cache() -> None:
    """
    Warm up optional caches (DBC etc).
    """
    try:
        _load_char_start_outfit()
    except Exception as exc:
        Logger.warning(f"[WorldHandlers] preload_cache failed: {exc}")

# -----------------------------------------------------------------------------
# CMSG handlers
# -----------------------------------------------------------------------------

def handle_CMSG_PING(sock: Any, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    decoded = _log_cmsg("CMSG_PING", payload)
    ping_val = int(decoded.get("ping_id", 0) or 0)
    try:
        pong_payload = EncoderHandler.encode_packet("SMSG_PONG", {"ping_id": ping_val})
        return 0, ("SMSG_PONG", pong_payload)
    except Exception as exc:
        Logger.error(f"[WorldHandlers] SMSG_PONG encode failed: {exc}")
        return 1, None


def handle_CMSG_LOGOUT_REQUEST(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    _log_cmsg("CMSG_LOGOUT_REQUEST", payload)
    Logger.info("[WorldHandlers] CMSG_LOGOUT_REQUEST")

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


def handle_CMSG_AUTH_SESSION(sock, opcode: int, payload: bytes):
    decoded = _log_cmsg("CMSG_AUTH_SESSION", payload)

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

def handle_CMSG_ENUM_CHARACTERS(sock, opcode, payload):
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
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:

    decoded = _log_cmsg("CMSG_PLAYER_LOGIN", payload)

    login_guid = None
    if len(payload) == 6:
        login_guid = int.from_bytes(payload, "little", signed=False)
    elif len(payload) >= 6:
        login_guid = int.from_bytes(payload[:6], "little", signed=False)
    # --------------------------------------------------
    # Account data (MoP: ALWAYS 8 slots)
    # --------------------------------------------------
    session.account_data_times = {
        i: 0 for i in range(8)
    }
    session.account_data_mask = 0
    # --------------------------------------------------
    # Decode LOGIN GUID (48-bit)
    # low32 = character DB guid
    # --------------------------------------------------
    char_guid = _resolve_login_character_guid(
        login_guid=login_guid,
        payload=payload,
        account_id=session.account_id,
        realm_id=session.realm_id,
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
    Logger.info(
        "[GUID MODE]\n"
        f"selected_guid = 0x{selected_world_guid:X}\n"
        f"replay_guid = 0x{int(LOGIN_REPLAY_PLAYER_GUID):X}\n"
        f"session_guid = 0x{int(session.world_guid or 0):X}"
    )
    Logger.info(f"[GUID MODE ACTIVE] player_guid=0x{int(session.player_guid or 0):X}")
    if selected_world_guid != int(LOGIN_REPLAY_PLAYER_GUID):
        Logger.warning(
            "[GUID MODE] raw UPDATE_OBJECT replay still targets replay_guid; "
            "selected character GUID differs from sniffed player GUID"
        )

    # --------------------------------------------------
    # Load character from DB (LIVE DATA)
    # --------------------------------------------------
    row = DatabaseConnection.get_character(char_guid, realm_id)
    if not row:
        Logger.error(
            f"[WorldHandlers] Character not found guid={char_guid} realm={realm_id}"
        )
        return 1, None

    # --------------------------------------------------
    # Map / zone / instance
    # --------------------------------------------------
    session.map_id = int(row.map or 0)
    session.zone = int(row.zone or 0)
    session.instance_id = int(row.instance_id or 0)

    # --------------------------------------------------
    # Position / orientation
    # --------------------------------------------------
    session.x = float(row.position_x or 0.0)
    session.y = float(row.position_y or 0.0)
    session.z = float(row.position_z or 0.0)
    session.orientation = float(row.orientation or 0.0)

    # --------------------------------------------------
    # Movement speeds (MoP defaults)
    # --------------------------------------------------
    session.walk_speed = 2.5
    session.run_speed = 7.0
    session.run_back_speed = 4.5
    session.swim_speed = 4.7
    session.swim_back_speed = 2.5
    session.fly_speed = 7.0
    session.fly_back_speed = 4.5
    session.turn_speed = 3.1415926
    session.pitch_speed = 3.1415926

    # --------------------------------------------------
    # Gameplay state (LIVE)
    # --------------------------------------------------
    session.level = int(row.level or 1)
    session.class_id = int(row.class_ or 0)
    session.race = int(row.race or 0)
    session.gender = int(row.gender or 0)

    session.money = int(row.money or 0)
    session.health = int(row.health or 1)
    session.player_bytes = int(row.playerBytes or 0)
    session.player_bytes2 = int(row.playerBytes2 or 0)
    session.player_flags = int(row.playerFlags or 0)
    session.player_name = str(getattr(row, "name", "") or f"Player{char_guid}")

    # --------------------------------------------------
    # Spells / actions (create info)
    # --------------------------------------------------
    session.known_spells = DatabaseConnection.get_character_spells(char_guid)
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
    session.time_sync_seq = 0
    _reset_login_flow_state(preserve_loading_screen_done=bool(getattr(session, "loading_screen_done", False)))

    _resolve_session_ids()
    _set_login_state(LoginState.PLAYER_LOGIN)

    Logger.success(
        f"[WorldHandlers] PLAYER_LOGIN char_guid={char_guid} "
        f"map={session.map_id} zone={session.zone} realm={realm_id}"
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

    Logger.info("[WorldHandlers] PLAYER_LOGIN queued player login bundle")
    return 0, responses

def handle_CMSG_LOADING_SCREEN_NOTIFY(sock: Any, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    decoded = _log_cmsg("CMSG_LOADING_SCREEN_NOTIFY", payload)
    showing = _decode_loading_screen_showing(decoded, payload)
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

def handle_CMSG_TIME_SYNC_RESPONSE(sock, opcode, payload):
    decoded = dsl_decode("CMSG_TIME_SYNC_RESPONSE", payload, silent=True)

    seq = decoded.get("sequence_id", 0)
    client_ticks = decoded.get("client_ticks", 0)

    session.last_time_sync_seq = seq
    session.time_sync_ok = True

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

def handle_CMSG_DISCARDED_TIME_SYNC_ACKS(sock, opcode, payload):
    Logger.info("[TIME_SYNC] Client discarded pending time sync ACKs")
    return 0, None

def handle_CMSG_OBJECT_UPDATE_FAILED(sock, opcode, payload):
    decoded = _log_cmsg("CMSG_OBJECT_UPDATE_FAILED", payload)
    guid = _parse_guid(decoded.get("guid"))
    if guid in (None, 0):
        guid = 0
        for index in range(8):
            value = _parse_guid(decoded.get(f"guid_{index}"))
            if value is not None:
                guid |= (value & 0xFF) << (index * 8)
    Logger.info(f"[WorldHandlers] OBJECT_UPDATE_FAILED guid=0x{int(guid):X}")
    return 0, None

def handle_CMSG_CREATURE_QUERY(sock: Any, opcode: int, payload: bytes) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    decoded = _log_cmsg("CMSG_CREATURE_QUERY", payload)
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


def handle_CMSG_REQUEST_ACCOUNT_DATA(sock, opcode, payload):
    data_type = payload[0]

    Logger.info(f"[ACCOUNT_DATA] request type={data_type}")

    response = EncoderHandler.encode_packet(
        "SMSG_UPDATE_ACCOUNT_DATA",
        {
            "type": data_type,
            "timestamp": 0,
            "size": 0,
            "data": b"",
        },
    )

    return 0, [("SMSG_UPDATE_ACCOUNT_DATA", response)]

def handle_CMSG_REQUEST_CEMETERY_LIST(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_REQUEST_CEMETERY_LIST")
    response = _build_request_cemetery_list_response_payload([])
    return 0, [("SMSG_REQUEST_CEMETERY_LIST_RESPONSE", response)]


def handle_CMSG_REQUEST_PLAYED_TIME(
    sock: Any,
    opcode: int,
    payload: bytes,
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
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_QUERY_TIME")
    response = build_login_packet("SMSG_QUERY_TIME_RESPONSE", _build_world_login_context())
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_QUERY_TIME_RESPONSE")
        return 1, None
    return 0, [("SMSG_QUERY_TIME_RESPONSE", response)]


def handle_CMSG_REQUEST_FORCED_REACTIONS(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_REQUEST_FORCED_REACTIONS")
    response = build_login_packet("SMSG_SET_FORCED_REACTIONS", _build_world_login_context())
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_SET_FORCED_REACTIONS")
        return 1, None
    return 0, [("SMSG_SET_FORCED_REACTIONS", response)]


def handle_CMSG_WORLD_STATE_UI_TIMER_UPDATE(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_WORLD_STATE_UI_TIMER_UPDATE")
    response = build_login_packet("SMSG_UI_TIME", _build_world_login_context())
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_UI_TIME")
        return 1, None
    return 0, [("SMSG_UI_TIME", response)]


def handle_CMSG_NAME_QUERY(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info(f"[WorldHandlers] CMSG_NAME_QUERY payload={payload.hex(' ')}")
    world_guid = int(session.world_guid or 0)
    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )
    response = _build_name_query_response(
        world_guid,
        name=player_name,
        realm_name=_get_realm_name(),
        race=int(getattr(session, "race", 0) or 0),
        gender=int(getattr(session, "gender", 0) or 0),
        class_id=int(getattr(session, "class_id", 0) or 0),
    )
    Logger.info(
        f"[WorldHandlers] SMSG_QUERY_PLAYER_NAME_RESPONSE guid=0x{world_guid:016X} "
        f"name={player_name!r} size={len(response)}"
    )
    return 0, [("SMSG_QUERY_PLAYER_NAME_RESPONSE", response)]


def handle_CMSG_QUEST_GIVER_STATUS_QUERY(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    guid = _decode_quest_giver_status_query_guid(payload)
    Logger.info(
        f"[WorldHandlers] CMSG_QUEST_GIVER_STATUS_QUERY guid="
        f"0x{int(guid or 0):016X}"
    )
    response = _build_questgiver_status_payload(int(guid or 0), 0)
    return 0, [("SMSG_QUESTGIVER_STATUS", response)]

def handle_CMSG_MESSAGECHAT_SAY_old(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return _handle_chat_message("CMSG_MESSAGECHAT_SAY", payload)

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

def handle_CMSG_MESSAGECHAT_SAY(sock, opcode, payload):

    chat = _decode_chat_message("CMSG_MESSAGECHAT_SAY", payload)
    message = chat["message"]

    if not message:
        return 0, None

    # run chat commands
    command_result = _handle_chat_command(message)
    if command_result is not None:
        return 0, command_result

    name_payload = build_query_player_name_response(session.player_guid)
    chat_payload = build_smsg_messagechat_say(message)

    return 0, [
        ("SMSG_QUERY_PLAYER_NAME_RESPONSE", name_payload),
        ("SMSG_MESSAGECHAT", chat_payload),
    ]

def build_smsg_messagechat_say(message: str) -> bytes:

    name = session.player_name.encode("utf-8")
    msg = message.encode("utf-8")

    payload = bytearray()

    payload += struct.pack("<B", 0)      # CHAT_MSG_SAY
    payload += struct.pack("<I", 1)      # language

    payload += struct.pack("<Q", session.player_guid)
    payload += struct.pack("<I", 0)      # flags

    payload += struct.pack("<I", len(name))
    payload += name

    payload += struct.pack("<Q", 0)      # target guid

    payload += struct.pack("<I", 0)      # target name len

    payload += struct.pack("<I", len(msg))
    payload += msg

    payload += struct.pack("<B", 0)      # chat_tag

    return bytes(payload)
def handle_CMSG_MESSAGECHAT_YELL(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return _handle_chat_message("CMSG_MESSAGECHAT_YELL", payload)


def handle_CMSG_MESSAGECHAT_WHISPER(
    sock: Any,
    opcode: int,
    payload: bytes,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return _handle_chat_message("CMSG_MESSAGECHAT_WHISPER", payload)

def handle_disconnect() -> None:
    _reset_login_flow_state()


def handle_CMSG_REQUEST_HOTFIX(sock, opcode, payload):
    # Suppressed during minimal login debugging to keep the bootstrap surface small.
    if session.login_state != LoginState.IN_WORLD:
        Logger.info(
            f"[WorldHandlers] CMSG_REQUEST_HOTFIX suppressed during login "
            f"(state={session.login_state.value if session.login_state else 'None'})"
        )
        return 0, None
    return _handle_CMSG_REQUEST_HOTFIX(sock, opcode, payload)

def handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES(sock, opcode: int, payload: bytes):
    Logger.info("[WORLD] Client ready for account data times")

    payload = EncoderHandler.encode_packet(
        "SMSG_ACCOUNT_DATA_TIMES",
        {
            "flag": 0,
            "timestamps": [0] * 8,
            "mask": 0,
            "server_time": int(time.time()),
        },
    )

    session.account_data_times_sent = True

    return 0, [("SMSG_ACCOUNT_DATA_TIMES", payload)]

def handle_CMSG_UPDATE_ACCOUNT_DATA(sock, opcode, payload):
    _log_cmsg("CMSG_UPDATE_ACCOUNT_DATA", payload)
    return 0, None


# -----------------------------------------------------------------------------
# Opcode routing table
# -----------------------------------------------------------------------------
def handle_CMSG_SET_ACTIVE_MOVER(sock, opcode, payload):
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
    Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; no additional bootstrap packets sent")
    return 0, None


def handle_movement_packet(sock: Any, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    opcode_name = WORLD_CLIENT_OPCODES.get(opcode, f"0x{opcode:04X}")
    movement = parse_movement_info(opcode_name, payload)
    if movement is None:
        Logger.warning(
            f"[Movement] failed to parse {opcode_name} guid=0x{int(session.world_guid or session.player_guid or 0):X} "
            f"payload_len={len(payload)}"
        )
        return 0, None

    x, y, z, orientation = movement
    session.x = float(x)
    session.y = float(y)
    session.z = float(z)
    session.orientation = float(orientation)

    Logger.info(
        f"[Movement] opcode={opcode_name} guid=0x{int(session.world_guid or session.player_guid or 0):X} "
        f"x={session.x:.3f} y={session.y:.3f} z={session.z:.3f} facing={session.orientation:.3f}"
    )
    return 0, None


opcode_handlers: Dict[str, Callable[[object, int, bytes], Tuple[int, Optional[bytes]]]] = {
    "CMSG_PING": handle_CMSG_PING,
    "CMSG_LOGOUT_REQUEST": handle_CMSG_LOGOUT_REQUEST,
    "CMSG_AUTH_SESSION": handle_CMSG_AUTH_SESSION,
    "CMSG_ENUM_CHARACTERS": handle_CMSG_ENUM_CHARACTERS,
    "CMSG_PLAYER_LOGIN": handle_CMSG_PLAYER_LOGIN,
    "CMSG_LOADING_SCREEN_NOTIFY": handle_CMSG_LOADING_SCREEN_NOTIFY,
    "CMSG_TIME_SYNC_RESPONSE": handle_CMSG_TIME_SYNC_RESPONSE,
    "CMSG_MESSAGECHAT_SAY": handle_CMSG_MESSAGECHAT_SAY,
    "CMSG_MESSAGECHAT_YELL": handle_CMSG_MESSAGECHAT_YELL,
    "CMSG_MESSAGECHAT_WHISPER": handle_CMSG_MESSAGECHAT_WHISPER,
    "CMSG_READY_FOR_ACCOUNT_DATA_TIMES": handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES, 
    "CMSG_UPDATE_ACCOUNT_DATA": handle_CMSG_UPDATE_ACCOUNT_DATA,
    "CMSG_REQUEST_HOTFIX": handle_CMSG_REQUEST_HOTFIX,
    "CMSG_SET_ACTIVE_MOVER": handle_CMSG_SET_ACTIVE_MOVER,
    "CMSG_DISCARDED_TIME_SYNC_ACKS": handle_CMSG_DISCARDED_TIME_SYNC_ACKS,
    "CMSG_OBJECT_UPDATE_FAILED": handle_CMSG_OBJECT_UPDATE_FAILED,
    "CMSG_CREATURE_QUERY": handle_CMSG_CREATURE_QUERY,
  #  "CMSG_REQUEST_ACCOUNT_DATA": handle_CMSG_REQUEST_ACCOUNT_DATA,
    "CMSG_REQUEST_CEMETERY_LIST": handle_CMSG_REQUEST_CEMETERY_LIST,
    "CMSG_REQUEST_PLAYED_TIME": handle_CMSG_REQUEST_PLAYED_TIME,
    "CMSG_QUERY_TIME": handle_CMSG_QUERY_TIME,
    "CMSG_REQUEST_FORCED_REACTIONS": handle_CMSG_REQUEST_FORCED_REACTIONS,
    "CMSG_WORLD_STATE_UI_TIMER_UPDATE": handle_CMSG_WORLD_STATE_UI_TIMER_UPDATE,
    "CMSG_NAME_QUERY": handle_CMSG_NAME_QUERY,
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
    "MSG_MOVE_FALL_LAND": handle_movement_packet,
}
