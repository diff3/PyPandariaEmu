from __future__ import annotations

import json
import math
from pathlib import Path
import struct

from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from shared.PathUtils import get_captures_root
from server.modules.game.guid import CreatureGuid, GameObjectGuid, GuidHelper
from server.modules.handlers.world.bootstrap.gameobjects import (
    _build_gameobject_field_values,
    _build_gameobject_update_payload,
)
from server.modules.handlers.world.login.packets import build_login_packet
from server.session.runtime import session as runtime_session

LOGIN_UPDATE_SEQUENCE = (
    "SMSG_UPDATE_OBJECT_1773586161_0001.json",
    "SMSG_UPDATE_OBJECT_1773586161_0002.json",
    "SMSG_UPDATE_OBJECT_1773586161_0003.json",
    "SMSG_UPDATE_OBJECT_1773586165_0004.json",
)

MOVEMENT_FOCUS_SEQUENCE = (
    ("SMSG_MOVE_SET_ACTIVE_MOVER", "SMSG_MOVE_SET_ACTIVE_MOVER_1773613176_0001.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613176_0002.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613176_0003.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613176_0004.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613181_0005.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613185_0006.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1773613205_0007.json"),
)
LOGIN_WORLD_ENTER_SEQUENCE = (
    ("SMSG_MOVE_SET_ACTIVE_MOVER", "SMSG_MOVE_SET_ACTIVE_MOVER_1773613176_0001.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1775665925_0004.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1775665925_0005.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1775665925_0006.json"),
    ("SMSG_UPDATE_OBJECT", "SMSG_UPDATE_OBJECT_1775665925_0009.json"),
)

USE_RAW_ACTIVE_MOVER = False
USE_EXACT_UPDATE_OBJECT_REPLAY = True
USE_RAW_UPDATE_OBJECT_FALLBACK = False
USE_MINIMAL_UPDATE_OBJECT_REPLAY = True
USE_MINIMAL_PLAYER_VALUE_UPDATE_REPLAY = True
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
    "SMSG_UPDATE_OBJECT_1775665925_0004.json": "SMSG_UPDATE_OBJECT_1775665925_0004",
    "SMSG_UPDATE_OBJECT_1775665925_0005.json": "SMSG_UPDATE_OBJECT_1775665925_0005",
    "SMSG_UPDATE_OBJECT_1775665925_0006.json": "SMSG_UPDATE_OBJECT_1775665925_0006",
    "SMSG_UPDATE_OBJECT_1775665925_0009.json": "SMSG_UPDATE_OBJECT_1775665925_0009",
}

_CAPTURE_DIR = get_captures_root(focus=True) / "debug"
_GAMEOBJECT_VISIBILITY_RADIUS = 120.0
_GAMEOBJECT_PACKET_LIMIT = 200
_CREATURE_VISIBILITY_RADIUS = 120.0
_CREATURE_PACKET_LIMIT = 200
_NPC_BARNCASTLE_CAPTURE = _CAPTURE_DIR / "SMSG_UPDATE_OBJECT_1776420870_1545.json"


def _login_handlers():
    from server.modules.handlers.world.opcodes import login as login_handlers

    return login_handlers


def _build_world_login_context(session):
    return _login_handlers()._build_world_login_context(session)


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


def extract_first_update_object_guid_info(payload: bytes) -> tuple[int, int, bytes] | None:
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


def _current_session():
    return runtime_session


def debug_log_replayed_update_object_guid(payload: bytes, update_index: int | None = None) -> None:
    session = _current_session()
    session_player_guid = int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )
    if session_player_guid <= 0:
        return

    try:
        guid_info = extract_first_update_object_guid_info(payload)
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
        Logger.debug("[GUID MISMATCH] UPDATE_OBJECT GUID does not match session player GUID.")


def debug_verify_update_object_guid(payload: bytes) -> None:
    session = _current_session()
    expected = int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )
    if expected <= 0:
        return

    try:
        guid_info = extract_first_update_object_guid_info(payload)
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
        Logger.debug("WARNING: Player UPDATE_OBJECT GUID mismatch")


def find_player_living_movement_block(payload: bytes) -> dict[str, float] | None:
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


def debug_log_player_movement_flags(payload: bytes, *, update_index: int | None = None) -> None:
    if update_index != 1:
        return

    movement = find_player_living_movement_block(payload)
    if movement is None:
        Logger.debug("[PLAYER MOVEMENT FLAGS] no living player movement block found in UPDATE_OBJECT")
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


def build_single_u32_update_object_payload(*, map_id: int, guid: int, field_index: int, value: int) -> bytes:
    return build_multi_u32_update_object_payload(
        map_id=map_id,
        guid=guid,
        field_updates=[(int(field_index), int(value))],
    )


def build_multi_u32_update_object_payload(*, map_id: int, guid: int, field_updates: list[tuple[int, int]]) -> bytes:
    normalized_updates = [(int(field_index), int(value)) for field_index, value in (field_updates or [])]
    if not normalized_updates:
        return bytes(struct.pack("<HI", int(map_id) & 0xFFFF, 0))

    highest_field_index = max(field_index for field_index, _value in normalized_updates)
    mask_words = (highest_field_index // 32) + 1
    mask = bytearray(mask_words * 4)
    values_by_field = {field_index: value for field_index, value in normalized_updates}
    field_bytes = bytearray()

    for field_index in sorted(values_by_field):
        mask_word = int(field_index) // 32
        mask_bit = int(field_index) % 32
        current_word = struct.unpack_from("<I", mask, mask_word * 4)[0]
        struct.pack_into("<I", mask, mask_word * 4, current_word | (1 << mask_bit))

    for field_index in range(mask_words * 32):
        mask_word = field_index // 32
        mask_bit = field_index % 32
        word_value = struct.unpack_from("<I", mask, mask_word * 4)[0]
        if not (word_value & (1 << mask_bit)):
            continue
        field_bytes += struct.pack("<I", int(values_by_field.get(field_index, 0)) & 0xFFFFFFFF)

    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
    payload += struct.pack("<B", 0)
    payload += GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)
    payload += struct.pack("<B", mask_words)
    payload += bytes(mask)
    payload += bytes(field_bytes)
    payload += struct.pack("<B", 0)
    return bytes(payload)


def make_update_object_response(payload: bytes, *, update_index: int | None = None) -> tuple[str, bytes]:
    debug_log_replayed_update_object_guid(payload, update_index=update_index)
    debug_verify_update_object_guid(payload)
    debug_log_player_movement_flags(payload, update_index=update_index)
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
    _session,
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
        return make_update_object_response(payload, update_index=update_index)
    return opcode_name, payload

def _patch_language(payload: bytes, session) -> bytes:
    # Alliance vs Horde
    if session.race in (1, 3, 4, 7, 11):  # alliance
        target = (1 << 7)  # Common
    else:
        target = (1 << 1)  # Orcish

    target_bytes = target.to_bytes(4, "little")

    # known bad (orcish)
    orcish_bytes = (1 << 1).to_bytes(4, "little")

    Logger.info(f"[LANG PATCH] race={session.race}")

    # replace fallback
    return payload.replace(orcish_bytes, target_bytes)

def send_raw_sniff_packet(
    _session,
    opcode_name: str,
    filepath: str | Path,
    *,
    update_index: int | None = None,
) -> tuple[str, bytes]:
    path = Path(filepath)
    payload = load_sniff_payload(path)
    Logger.info(f"[RAW REPLAY] {opcode_name} payload={len(payload)} bytes source={path.name}")
    payload = _patch_language(payload, _session)
    if opcode_name == "SMSG_UPDATE_OBJECT":
     
        return make_update_object_response(payload, update_index=update_index)
    return opcode_name, payload


def _build_dynamic_active_mover_packet(session) -> tuple[str, bytes]:
    Logger.info("[ACTIVE_MOVER MODE] dynamic")
    payload = build_login_packet("SMSG_MOVE_SET_ACTIVE_MOVER", _build_world_login_context(session))
    if payload is None:
        raise RuntimeError("Missing dynamic builder for SMSG_MOVE_SET_ACTIVE_MOVER")
    return "SMSG_MOVE_SET_ACTIVE_MOVER", payload


def _build_exact_update_object_packet(session, path: Path, *, update_index: int) -> tuple[str, bytes]:
    builder_name = EXACT_UPDATE_OBJECT_BUILDERS.get(path.name)
    if not builder_name:
        raise RuntimeError(f"No exact UPDATE_OBJECT builder registered for {path.name}")
    payload = build_login_packet(builder_name, _build_world_login_context(session))
    if payload is None:
        raise RuntimeError(f"Missing exact UPDATE_OBJECT builder for {builder_name}")
    Logger.info(f"[UPDATE_OBJECT MODE] exact source={path.name} payload={len(payload)} bytes")
    return make_update_object_response(payload, update_index=update_index)


def _should_skip_static_update_object_capture(session, path: Path) -> bool:
    if not USE_MINIMAL_UPDATE_OBJECT_REPLAY:
        return False
    if path.name in STATIC_UPDATE_OBJECT_CAPTURE_NAMES:
        return True
    if USE_MINIMAL_PLAYER_VALUE_UPDATE_REPLAY and path.name in MINIMAL_PLAYER_VALUE_UPDATE_CAPTURE_NAMES:
        return True
    return False


def _u32_from_float(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def _build_create_update_object_entry(*, guid: int, object_type: int, create_flags: bytes, body: bytes) -> bytes:
    payload = bytearray()
    payload += struct.pack("<B", 1)
    payload += GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)
    payload += struct.pack("<B", int(object_type) & 0xFF)
    payload += bytes(create_flags)
    payload += bytes(body)
    return bytes(payload)


def _build_fixed_u32_field_block(fields: dict[int, int], *, mask_blocks: int = 1) -> tuple[bytes, bytes]:
    if not fields:
        return (b"\x00" * (int(mask_blocks) * 4), b"")

    mask = bytearray(int(mask_blocks) * 4)
    field_bytes = bytearray()
    for field_index in sorted(int(index) for index in fields):
        word_index = field_index // 32
        bit_index = field_index % 32
        current_word = struct.unpack_from("<I", mask, word_index * 4)[0]
        struct.pack_into("<I", mask, word_index * 4, current_word | (1 << bit_index))
        field_bytes += struct.pack("<I", int(fields[field_index]) & 0xFFFFFFFF)
    return bytes(mask), bytes(field_bytes)


def _build_creature_create_flags() -> bytes:
    # Exact 12-byte flag block from a valid sniffed living-creature create.
    # The previous synthetic bit layout caused the client to misparse the
    # movement block and ignore the entire NPC create.
    return bytes.fromhex("200000000029CC0000080000")


def _resolve_creature_display_id(entry: dict) -> int:
    display_id = int(entry.get("modelid", 0) or 0)
    if display_id > 0:
        return display_id

    template = entry.get("template")
    if isinstance(template, dict):
        for key in ("modelid1", "modelid2", "modelid3", "modelid4"):
            display_id = int(template.get(key, 0) or 0)
            if display_id > 0:
                return display_id
    return 15476


def _build_creature_field_values(entry: dict, *, world_guid: int) -> dict[int, int]:
    display_id = _resolve_creature_display_id(entry)
    return {
        0: int(world_guid) & 0xFFFFFFFF,
        1: (int(world_guid) >> 32) & 0xFFFFFFFF,
        4: 9,
        5: int(entry.get("entry", 0) or 0),
        6: 0,
        7: _u32_from_float(1.0),
        30: 33554688,
        31: 1,
        33: 17,
        39: 17,
        40: 1000,
        55: 1,
        57: 188,
        61: 768,
        63: 4194304,
        64: 2000,
        65: 2000,
        67: _u32_from_float(0.05),
        68: _u32_from_float(0.15),
        69: int(display_id),
        70: int(display_id),
        71: 0,
        81: _u32_from_float(1.0),
        82: _u32_from_float(1.0),
        87: _u32_from_float(2.0),
        128: 1,
        154: _u32_from_float(1.0),
        157: 1,
    }


def _build_creature_update_payload(*, map_id: int, entry: dict, realm_id: int) -> bytes:
    world_guid = int(
        entry.get("world_guid")
        or CreatureGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), int(realm_id) or 1)
    )
    raw_guid = GuidHelper.to_le_bytes(world_guid)
    mask_bytes, field_bytes = _build_fixed_u32_field_block(
        _build_creature_field_values(entry, world_guid=world_guid),
        mask_blocks=5,
    )

    x = float(entry.get("x", 0.0) or 0.0)
    y = float(entry.get("y", 0.0) or 0.0)
    z = float(entry.get("z", 0.0) or 0.0)
    orientation = float(entry.get("orientation", 0.0) or 0.0)

    body = bytearray()
    body += struct.pack("<B", raw_guid[4])
    body += struct.pack("<f", 7.0)
    body += struct.pack("<B", raw_guid[2])
    body += struct.pack("<B", raw_guid[1])
    body += struct.pack("<f", 3.1415939331054688)
    body += struct.pack("<f", 4.7)
    body += struct.pack("<B", raw_guid[7])
    body += struct.pack("<f", 3.140000104904175)
    body += struct.pack("<f", x)
    body += struct.pack("<f", orientation)
    body += struct.pack("<f", 2.5)
    body += struct.pack("<f", y)
    body += struct.pack("<f", 4.5)
    body += struct.pack("<B", raw_guid[5])
    body += struct.pack("<B", raw_guid[6])
    body += struct.pack("<B", raw_guid[0])
    body += struct.pack("<f", 4.5)
    body += struct.pack("<f", 2.5)
    body += struct.pack("<f", 8.000020027160645)
    body += struct.pack("<f", 4.722221851348877)
    body += struct.pack("<f", z)
    body += struct.pack("<B", len(mask_bytes) // 4)
    body += bytes(mask_bytes)
    body += bytes(field_bytes)
    body += struct.pack("<B", 0)

    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
    payload += _build_create_update_object_entry(
        guid=world_guid,
        object_type=3,
        create_flags=_build_creature_create_flags(),
        body=bytes(body),
    )
    return bytes(payload)


def _load_npc_barncastle_template() -> bytes:
    path = _NPC_BARNCASTLE_CAPTURE
    if not path.exists():
        path = Path(__file__).resolve().parents[5] / "data" / "pandaria548" / "captures" / "focus" / "debug" / _NPC_BARNCASTLE_CAPTURE.name
    return load_sniff_payload(path)

import struct


def _find_position_offset(payload: bytes) -> int | None:
    """
    Try to locate position block (x,y,z) inside SMSG_UPDATE_OBJECT payload.

    Strategy:
    - Look for known float pattern: 1.0, 1.0 (80 3F 00 00 80 3F)
    - Position usually follows shortly after
    """

    pattern = b"\x00\x00\x80\x3F\x00\x00\x80\x3F"  # 1.0f, 1.0f

    idx = payload.find(pattern)
    if idx == -1:
        return None

    # Heuristic: position is usually ~8–32 bytes after this pattern
    search_start = idx + len(pattern)

    for offset in range(search_start, min(search_start + 64, len(payload) - 12), 4):
        try:
            x = struct.unpack_from("<f", payload, offset)[0]
            y = struct.unpack_from("<f", payload, offset + 4)[0]
            z = struct.unpack_from("<f", payload, offset + 8)[0]

            # sanity check (WoW world bounds-ish)
            if -20000 < x < 20000 and -20000 < y < 20000 and -2000 < z < 2000:
                return offset
        except Exception:
            continue

    return None

import random
import struct


def _patch_guid(payload: bytearray):
    """
    Replace first packed GUID block with a new random one.
    This is a hack but works for sandbox.
    """

    # hitta första F7 (packed guid start i din sniff)
    idx = payload.find(b"\xF7")
    if idx == -1:
        Logger.warning("[NPC] GUID not found")
        return

    # generera fake guid (8 bytes)
    guid = random.getrandbits(64)

    struct.pack_into("<Q", payload, idx, guid)

    Logger.info("[NPC] patched GUID at %s -> %s", idx, guid)

def _build_creature_barncastle_payload(*, map_id: int, entry: dict) -> bytes:
    payload = bytearray(_load_npc_barncastle_template())
    _patch_guid(payload)

    x = float(entry.get("x", 0.0) or 0.0)
    y = float(entry.get("y", 0.0) or 0.0)
    z = float(entry.get("z", 0.0) or 0.0)
    o = float(entry.get("orientation", 0.0) or 0.0)

    # --- map id (behåll om det funkar i din template) ---
    try:
        struct.pack_into("<H", payload, 0, int(map_id) & 0xFFFF)
    except Exception:
        pass

    # --- hitta position dynamiskt ---
    offset = _find_position_offset(payload)

    if offset is None:
        Logger.warning("[NPC] position offset not found, fallback to 48")
        offset = 48  # fallback (din gamla)

    # --- skriv coords ---
    struct.pack_into("<f", payload, offset + 0, x)
    struct.pack_into("<f", payload, offset + 4, y)
    struct.pack_into("<f", payload, offset + 8, z)

    # orientation ligger oftast direkt efter
    try:
        struct.pack_into("<f", payload, offset + 12, o)
    except Exception:
        pass

    Logger.info(
        "[NPC] patched pos offset=%s -> (%.2f %.2f %.2f)",
        offset, x, y, z
    )

    return bytes(payload)

def build_database_gameobject_responses(session, *, loaded_guids: set[int] | None = None) -> list[tuple[str, bytes]]:
    from server.modules.database.DatabaseConnection import DatabaseConnection

    if not bool(getattr(session, "gameobjects_visible", True)):
        return []

    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    # Map 0 is valid. Only negative ids mean "no world map".
    if map_id < 0:
        return []

    entries = DatabaseConnection.get_gameobjects_near(
        map_id,
        x,
        y,
        radius=_GAMEOBJECT_VISIBILITY_RADIUS,
        limit=_GAMEOBJECT_PACKET_LIMIT,
    )
    if not entries:
        Logger.info("[WorldLoginReplay] no DB gameobjects near map=%s x=%.1f y=%.1f", map_id, x, y)
        return []

    seen = loaded_guids if isinstance(loaded_guids, set) else None
    filtered_entries: list[dict] = []
    for entry in entries:
        world_guid = int(
            entry.get("world_guid")
            or GameObjectGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), int(realm_id) or 1)
        )
        if seen is not None and world_guid in seen:
            continue
        entry["world_guid"] = world_guid
        filtered_entries.append(entry)
        if seen is not None:
            seen.add(world_guid)

    if not filtered_entries:
        Logger.info("[WorldLoginReplay] DB gameobjects already loaded near map=%s x=%.1f y=%.1f", map_id, x, y)
        return []

    Logger.info(
        "[WorldLoginReplay] loaded %s DB gameobjects near map=%s x=%.1f y=%.1f",
        len(filtered_entries),
        map_id,
        x,
        y,
    )
    return [
        make_update_object_response(
            _build_gameobject_update_payload(map_id=map_id, entry=entry, realm_id=realm_id)
        )
        for entry in filtered_entries
    ]




# START NPC building
import struct
import random
from shared.Logger import Logger

def make_unit_guid(entry: int) -> int:
    counter = random.getrandbits(32)

    b0_3 = counter
    b4_6 = entry & 0xFFFFFF
    b7   = 0xF1

    return (
        b0_3 |
        (b4_6 << 32) |
        (b7 << 56)
    )
    
    
def pack_guid(guid: int) -> bytes:
    mask = 0
    data = bytearray()

    for i in range(8):
        byte = (guid >> (i * 8)) & 0xFF
        if byte != 0:
            mask |= (1 << i)
            data.append(byte)

    return struct.pack("<B", mask) + data


# --- Movement (stabil minimal) ---
def build_movement_block(x, y, z, o):
    return struct.pack(
        "<II I ffff f I ffffff",
        0,  # flags
        0,  # flags2
        0,  # time
        x, y, z, o,
        0.0,  # pitch
        0,    # fall time
        2.5, 7.0, 4.5, 4.7, 2.5, 3.14
    )


# --- Values (minimalt men korrekt) ---
def build_values_block(guid: int):
    buf = bytearray()

    buf += struct.pack("<B", 2)  # mask blocks

    mask1 = 0x00000003  # GUID low + high
    mask2 = 0x00000004  # TYPE

    buf += struct.pack("<II", mask1, mask2)

    buf += struct.pack("<II",
        guid & 0xFFFFFFFF,
        (guid >> 32) & 0xFFFFFFFF
    )

    TYPEMASK_UNIT = 0x08
    buf += struct.pack("<I", TYPEMASK_UNIT)

    return bytes(buf)


# --- CREATE OBJECT BLOCK ---
def build_create_block(entry_id, x, y, z, o):
    guid = make_unit_guid(entry_id)

    buf = bytearray()
    buf += struct.pack("<B", 3)  # CREATE_OBJECT2
    buf += pack_guid(guid)
    buf += struct.pack("<B", 3)  # TYPEID_UNIT

    buf += build_movement_block(x, y, z, o)
    buf += build_values_block(guid)

    return bytes(buf)


# --- UPDATE OBJECT PAYLOAD ---
def build_npc_update_object_payload(map_id: int, spawns: list[dict]) -> bytes:
    payload = bytearray()

    payload += struct.pack("<H", map_id)
    payload += struct.pack("<I", len(spawns))

    for s in spawns:
        payload += build_create_block(
            s["entry"],
            s["x"],
            s["y"],
            s["z"],
            s["orientation"],
        )

    return bytes(payload)


# --- DB → PACKET ---
def build_database_creature_responses(session, *, loaded_guids: set[int] | None = None):
    from server.modules.database.DatabaseConnection import DatabaseConnection

    if not getattr(session, "npcs_visible", False):
        return []

    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)

    entries = DatabaseConnection.get_creatures_near(
        map_id,
        x,
        y,
        radius=_CREATURE_VISIBILITY_RADIUS,
        limit=_CREATURE_PACKET_LIMIT,
    )

    if not entries:
        return []

    seen = loaded_guids if isinstance(loaded_guids, set) else None
    spawns = []

    for entry in entries:
        entry_id = int(entry.get("entry", 1))

        if seen is not None:
            if entry_id in seen:
                continue
            seen.add(entry_id)

        spawn = {
            "entry": entry_id,
            "x": float(entry.get("x", 0.0) or 0.0),
            "y": float(entry.get("y", 0.0) or 0.0),
            "z": float(entry.get("z", 0.0) or 0.0),
            "orientation": float(entry.get("orientation", 0.0) or 0.0),
        }

        Logger.info(
            "[SPAWN_NPC] entry=%s pos=(%.2f %.2f %.2f)",
            spawn["entry"],
            spawn["x"],
            spawn["y"],
            spawn["z"],
        )

        spawns.append(spawn)

    if not spawns:
        return []

    payload = build_npc_update_object_payload(map_id, spawns)

    return [
        make_update_object_response(payload)
    ]




# end of NPC building

def _build_replayed_update_object_packet(session, opcode_name: str, path: Path, *, update_index: int):
    if path.name in EXACT_UPDATE_OBJECT_BUILDERS:
        return _build_exact_update_object_packet(session, path, update_index=update_index)
    if not USE_RAW_UPDATE_OBJECT_FALLBACK:
        raise RuntimeError(
            f"Missing exact UPDATE_OBJECT builder for {path.name} while "
            "USE_RAW_UPDATE_OBJECT_FALLBACK is disabled"
        )
    return send_raw_sniff_packet(session, opcode_name, path, update_index=update_index)


def replay_movement_focus_sequence(session) -> list[tuple[str, bytes]]:
    entries = [(opcode_name, _CAPTURE_DIR / filename) for opcode_name, filename in MOVEMENT_FOCUS_SEQUENCE]

    required_paths: list[Path] = []
    if USE_RAW_ACTIVE_MOVER:
        required_paths.append(entries[0][1])

    for _opcode_name, path in entries[1:]:
        if _should_skip_static_update_object_capture(session, path):
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
            "Missing movement focus captures: " + ", ".join(path.name for path in missing)
        )

    session.player_object_sent = True
    responses: list[tuple[str, bytes]] = []

    if USE_RAW_ACTIVE_MOVER:
        opcode_name, path = entries[0]
        Logger.info("[ACTIVE_MOVER MODE] raw")
        responses.append(send_raw_sniff_packet(session, opcode_name, path))
    else:
        responses.append(_build_dynamic_active_mover_packet(session))

    update_entries = [
        (opcode_name, path)
        for opcode_name, path in entries[1:]
        if not _should_skip_static_update_object_capture(session, path)
    ]
    total = len(update_entries)

    if USE_RAW_UPDATE_OBJECT_FALLBACK:
        Logger.info("[UPDATE_OBJECT MODE] exact-with-raw-fallback")
    else:
        Logger.info("[UPDATE_OBJECT MODE] exact-only")

    for index, (opcode_name, path) in enumerate(update_entries, start=1):
        Logger.info(f"[WorldLoginReplay] packet {index}/{total} opcode={opcode_name}")
        responses.append(
            _build_replayed_update_object_packet(
                session,
                opcode_name,
                path,
                update_index=index,
            )
        )

    responses.extend(build_database_gameobject_responses(session))

    return responses


def replay_login_world_enter_sequence(session) -> list[tuple[str, bytes]]:
    entries = [(opcode_name, _CAPTURE_DIR / filename) for opcode_name, filename in LOGIN_WORLD_ENTER_SEQUENCE]

    session.player_object_sent = True
    responses: list[tuple[str, bytes]] = []
    responses.append(_build_dynamic_active_mover_packet(session))

    total = len(entries) - 1
    Logger.info("[UPDATE_OBJECT MODE] exact-only")

    for index, (opcode_name, path) in enumerate(entries[1:], start=1):
        Logger.info(f"[WorldLoginReplay] packet {index}/{total} opcode={opcode_name}")
        responses.append(
            _build_replayed_update_object_packet(
                session,
                opcode_name,
                path,
                update_index=index,
            )
        )

    return responses


def replay_update_object_sequence(session) -> list[tuple[str, bytes]]:
    paths = [_CAPTURE_DIR / filename for filename in LOGIN_UPDATE_SEQUENCE]

    missing = [path for path in paths if not path.exists()]
    if missing:
        raise RuntimeError(
            f"Missing login UPDATE_OBJECT captures in {_CAPTURE_DIR}: " + ", ".join(path.name for path in missing)
        )

    session.player_object_sent = True
    responses: list[tuple[str, bytes]] = []

    active_paths = [path for path in paths if not _should_skip_static_update_object_capture(path)]
    total = len(active_paths)
    if USE_RAW_UPDATE_OBJECT_FALLBACK:
        Logger.info("[UPDATE_OBJECT MODE] exact-with-raw-fallback")
    else:
        Logger.info("[UPDATE_OBJECT MODE] exact-only")

    for index, path in enumerate(active_paths, start=1):
        Logger.info(f"[WorldLoginReplay] UPDATE_OBJECT {index}/{total}")
        responses.append(
            _build_replayed_update_object_packet(
                session,
                "SMSG_UPDATE_OBJECT",
                path,
                update_index=index,
            )
        )

    return responses
