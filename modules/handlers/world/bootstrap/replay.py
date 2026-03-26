from __future__ import annotations

import json
import math
from pathlib import Path
import struct

from shared.Logger import Logger
from shared.PathUtils import get_captures_root
from server.modules.guid import GuidHelper
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
}

_CAPTURE_DIR = get_captures_root(focus=True) / "debug"


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


def _should_skip_static_update_object_capture(path: Path) -> bool:
    if not USE_MINIMAL_UPDATE_OBJECT_REPLAY:
        return False
    if path.name in STATIC_UPDATE_OBJECT_CAPTURE_NAMES:
        return True
    if USE_MINIMAL_PLAYER_VALUE_UPDATE_REPLAY and path.name in MINIMAL_PLAYER_VALUE_UPDATE_CAPTURE_NAMES:
        return True
    return False


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
            f"Missing movement focus captures in {_CAPTURE_DIR}: " + ", ".join(path.name for path in missing)
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
        if not _should_skip_static_update_object_capture(path)
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
