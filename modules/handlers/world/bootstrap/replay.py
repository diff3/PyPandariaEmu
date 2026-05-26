from __future__ import annotations

import json
from pathlib import Path
import struct

from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from shared.PathUtils import get_captures_root
from server.modules.game.guid import CreatureGuid, GameObjectGuid, GuidHelper, MoTransportGuid
from server.modules.handlers.world.bootstrap.gameobjects import (
    _build_gameobject_field_values,
    _build_gameobject_update_payload,
)
from server.modules.handlers.world.bootstrap.playerobjects import (
    USE_SERVER_BUILT_MINIMAL_PLAYER,
    build_multi_u32_update_object_payload,
    build_server_built_minimal_player_value_update,
    build_single_u32_update_object_payload,
    debug_log_player_movement_flags,
    debug_log_replayed_update_object_guid,
    debug_verify_update_object_guid,
    extract_first_update_object_guid_info,
    find_player_living_movement_block,
    make_update_object_response,
    unpack_guid,
)
from server.modules.handlers.world.transport_runtime import (
    cached_transport_runtime_entry,
    prepare_runtime_transport_entry,
    register_loaded_transport_entry,
    synthetic_transport_entries_near,
)
from server.modules.handlers.world.login.packets import build_login_packet

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


def _build_create_update_object_entry(
    *,
    guid: int,
    object_type: int,
    create_flags: bytes,
    body: bytes,
    update_type: int = 1,
) -> bytes:
    payload = bytearray()
    payload += struct.pack("<B", int(update_type) & 0xFF)
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
    # Living-unit create flags for the 5.4.8 UPDATE_OBJECT layout.
    # Keep this byte-aligned; otherwise the movement block starts mid-bit.
    return bytes.fromhex("200000000029CC00000800004F")


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
    template = entry.get("template")
    template_flags = int(template.get("npcflag", 0) or 0) if isinstance(template, dict) else 0
    npc_flags = int(entry.get("npcflag", 0) or template_flags or 0)
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
        87: npc_flags,
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
        update_type=2,
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
        entries = []

    seen = loaded_guids if isinstance(loaded_guids, set) else None
    filtered_entries: list[dict] = []
    for entry in entries:
        entry = prepare_runtime_transport_entry(entry)
        if int(entry.get("type", 0) or 0) == 15 or bool(entry.get("use_transport_guid")):
            world_guid = int(
                entry.get("world_guid")
                or MoTransportGuid.from_spawn_guid(int(entry.get("guid", 0) or 0))
            )
        else:
            world_guid = int(
                entry.get("world_guid")
                or GameObjectGuid.from_spawn_guid(
                    int(entry.get("guid", 0) or 0),
                    int(realm_id) or 1,
                )
            )
        if seen is not None and world_guid in seen:
            continue
        entry["world_guid"] = world_guid
        if not register_loaded_transport_entry(
            session,
            entry,
            world_guid=world_guid,
            map_id=map_id,
        ):
            continue
        filtered_entries.append(entry)
        if seen is not None:
            seen.add(world_guid)

    for entry in synthetic_transport_entries_near(session, loaded_guids=seen):
        world_guid = int(entry.get("world_guid", 0) or 0)
        if world_guid <= 0:
            continue
        filtered_entries.append(entry)
        register_loaded_transport_entry(
            session,
            entry,
            world_guid=world_guid,
            map_id=int(entry.get("map", map_id) or map_id),
        )
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
    responses: list[tuple[str, bytes]] = []
    for entry in filtered_entries:
        entry = cached_transport_runtime_entry(session, entry)
        payload = _build_gameobject_update_payload(
            map_id=map_id,
            entry=entry,
            realm_id=realm_id,
        )
        if bool(entry.get("synthetic_transport")):
            Logger.info(
                "[WorldTransport] synthetic create guid=%s entry=%s type=%s "
                "payload=%s pos=(%.2f %.2f %.2f) o=%.3f",
                int(entry.get("guid", 0) or 0),
                int(entry.get("entry", 0) or 0),
                int(entry.get("type", 0) or 0),
                len(payload),
                float(entry.get("x", 0.0) or 0.0),
                float(entry.get("y", 0.0) or 0.0),
                float(entry.get("z", 0.0) or 0.0),
                float(entry.get("orientation", 0.0) or 0.0),
            )
        if int(entry.get("type", 0) or 0) == 11:
            Logger.info(
                "[TransportElevator] stream create guid=%s entry=%s payload=%s "
                "pos=(%.2f %.2f %.2f)",
                int(entry.get("guid", 0) or 0),
                int(entry.get("entry", 0) or 0),
                len(payload),
                float(entry.get("x", 0.0) or 0.0),
                float(entry.get("y", 0.0) or 0.0),
                float(entry.get("z", 0.0) or 0.0),
            )
        if int(entry.get("type", 0) or 0) == 15:
            Logger.info(
                "[WorldTransport] stream create guid=%s entry=%s payload=%s "
                "pos=(%.2f %.2f %.2f) o=%.3f",
                int(entry.get("guid", 0) or 0),
                int(entry.get("entry", 0) or 0),
                len(payload),
                float(entry.get("x", 0.0) or 0.0),
                float(entry.get("y", 0.0) or 0.0),
                float(entry.get("z", 0.0) or 0.0),
                float(entry.get("orientation", 0.0) or 0.0),
            )
        responses.append(make_update_object_response(payload))
    return responses




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
    from server.modules.handlers.world.feature_config import npcs_enabled

    if not npcs_enabled():
        return []
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
    responses = []
    realm_id = int(getattr(session, "realm_id", 1) or 1)

    for entry in entries:
        entry_id = int(entry.get("entry", 1))
        spawn_guid = int(entry.get("guid", 0) or 0)
        world_guid = CreatureGuid.from_spawn_guid(spawn_guid, realm_id)

        if seen is not None:
            if world_guid in seen:
                continue
            seen.add(world_guid)

        template = DatabaseConnection.get_creature_template(entry_id) or {}
        template_name = str(template.get("name", "") or "").lower()
        if template_name.startswith("[dnd]") or "trigger" in template_name:
            continue

        spawn = {
            "guid": spawn_guid,
            "entry": entry_id,
            "modelid": int(entry.get("modelid", 0) or 0),
            "npcflag": int(entry.get("npcflag", 0) or template.get("npcflag", 0) or 0),
            "template": template,
            "x": float(entry.get("x", 0.0) or 0.0),
            "y": float(entry.get("y", 0.0) or 0.0),
            "z": float(entry.get("z", 0.0) or 0.0),
            "orientation": float(entry.get("orientation", 0.0) or 0.0),
        }
        npc_flags_by_guid = getattr(session, "npc_flags_by_guid", None)
        if not isinstance(npc_flags_by_guid, dict):
            npc_flags_by_guid = {}
            session.npc_flags_by_guid = npc_flags_by_guid
        npc_flags_by_guid[int(world_guid)] = int(spawn["npcflag"])
        npc_flags_by_guid[int(spawn_guid)] = int(spawn["npcflag"])

        Logger.info(
            "[SPAWN_NPC] guid=%s world_guid=0x%016X entry=%s name=%s display=%s npcflag=0x%X pos=(%.2f %.2f %.2f)",
            spawn["guid"],
            world_guid & 0xFFFFFFFFFFFFFFFF,
            spawn["entry"],
            str(template.get("name", "") or ""),
            _resolve_creature_display_id(spawn),
            int(spawn["npcflag"]),
            spawn["x"],
            spawn["y"],
            spawn["z"],
        )

        payload = _build_creature_update_payload(
            map_id=map_id,
            entry=spawn,
            realm_id=realm_id,
        )
        responses.append(make_update_object_response(payload))

    return responses




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


def _build_hybrid_player_value_update_responses(
    session,
    path: Path,
) -> list[tuple[str, bytes]]:
    """Append a minimal server-built player value update after replayed 0002."""
    if path.name != "SMSG_UPDATE_OBJECT_1773613176_0002.json":
        return []

    if not USE_SERVER_BUILT_MINIMAL_PLAYER:
        Logger.info("[PLAYER HYBRID] replay-only (fallback)")
        return []

    payload = build_server_built_minimal_player_value_update(_build_world_login_context(session))
    if payload is None:
        # fallback to replay/exact path
        Logger.info("[PLAYER HYBRID] replay-only (fallback)")
        return []

    # server-built experimental path
    Logger.info("[PLAYER HYBRID] replay CREATE + server VALUE update")
    return [make_update_object_response(payload)]


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
        response = _build_replayed_update_object_packet(
            session,
            opcode_name,
            path,
            update_index=index,
        )
        responses.append(response)
        responses.extend(_build_hybrid_player_value_update_responses(session, path))

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
