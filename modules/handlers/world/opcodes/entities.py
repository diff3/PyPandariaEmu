from __future__ import annotations

import math
import struct
from typing import Any, Optional, Tuple

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitInterPreter
from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.dispatcher import register
from server.modules.game.guid import GameObjectGuid, GuidHelper
from server.modules.handlers.world.bootstrap.replay import build_single_u32_update_object_payload
from server.modules.handlers.world.opcodes.movement import build_same_map_teleport_payload


MAX_CREATURE_QUEST_ITEMS = 6
MAX_GAMEOBJECT_DATA = 24
MAX_GAMEOBJECT_QUEST_ITEMS = 6
GAMEOBJECT_TYPE_CHAIR = 7
UNIT_FIELD_ANIMTIER = 0x4C
UNIT_STAND_STATE_STAND = 0
UNIT_STAND_STATE_SIT_LOW_CHAIR = 4
UNIT_STAND_STATE_SIT_HIGH_CHAIR = 6
CHAIR_USE_RADIUS = 10.0


def _get_realm_name() -> str:
    try:
        realm = DatabaseConnection.get_realmlist()
        if realm and getattr(realm, "name", None):
            return str(realm.name)
    except Exception:
        pass
    return ""


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


def _player_guid(session) -> int:
    return int(
        getattr(session, "char_guid", 0)
        or getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )


def _decode_gameobject_use_guid(payload: bytes, decoded: dict[str, Any] | None = None) -> Optional[int]:
    decoded = decoded or {}
    for key in ("guid", "object_guid", "gameobject_guid", "go_guid", "target_guid"):
        guid = _parse_guid(decoded.get(key))
        if guid is not None:
            return guid

    payload = bytes(payload or b"")
    if len(payload) < 9:
        return None

    raw_guid = [0] * 8
    byte_pos = 0
    bit_pos = 0
    for index in (6, 1, 3, 4, 0, 5, 7, 2):
        raw_guid[index], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)

    if bit_pos:
        byte_pos += 1

    for index in (0, 1, 6, 2, 3, 4, 5, 7):
        if not raw_guid[index]:
            continue
        if byte_pos >= len(payload):
            return None
        raw_guid[index] ^= payload[byte_pos]
        byte_pos += 1

    return int.from_bytes(bytes(raw_guid), "little", signed=False)


def _find_visible_gameobject(session, world_guid: int) -> Optional[dict]:
    if int(world_guid or 0) <= 0:
        return None

    try:
        decoded = GuidHelper.decode(int(world_guid))
        spawn_guid = int(decoded.low)
    except Exception:
        spawn_guid = int(world_guid) & 0xFFFFFFFF

    realm_id = int(getattr(session, "realm_id", 1) or 1)
    entries = DatabaseConnection.get_gameobjects_near(
        int(getattr(session, "map_id", 0) or 0),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        radius=CHAIR_USE_RADIUS,
        limit=80,
    )
    for entry in entries:
        entry_spawn_guid = int(entry.get("guid", 0) or 0)
        entry_world_guid = int(GameObjectGuid.from_spawn_guid(entry_spawn_guid, realm_id))
        if entry_spawn_guid == spawn_guid or entry_world_guid == int(world_guid):
            result = dict(entry)
            result["realm_id"] = realm_id
            result["world_guid"] = entry_world_guid
            return result
    return None


def _chair_key(entry: dict) -> int:
    world_guid = int(entry.get("world_guid", 0) or 0)
    if world_guid > 0:
        return world_guid
    return int(GameObjectGuid.from_spawn_guid(
        int(entry.get("guid", 0) or 0),
        int(entry.get("realm_id", 0) or 0) or 1,
    ))


def _get_chair_occupancy(session) -> dict:
    state = getattr(session, "global_state", None)
    if state is None:
        occupancy = getattr(session, "chair_occupancy", None)
        if not isinstance(occupancy, dict):
            occupancy = {}
            setattr(session, "chair_occupancy", occupancy)
        return occupancy

    occupancy = getattr(state, "chair_occupancy", None)
    if not isinstance(occupancy, dict):
        occupancy = {}
        setattr(state, "chair_occupancy", occupancy)
    return occupancy


def _release_chair_seat(session, *, reason: str) -> None:
    chair_guid = int(getattr(session, "current_chair", 0) or 0)
    seat = getattr(session, "current_seat", None)
    if chair_guid <= 0 or seat is None:
        return

    seats = _get_chair_occupancy(session).get(chair_guid)
    if isinstance(seats, dict) and int(seats.get(int(seat), 0) or 0) == _player_guid(session):
        seats.pop(int(seat), None)

    setattr(session, "current_chair", None)
    setattr(session, "current_seat", None)
    Logger.debug(
        "[CHAIR] released chair=0x%016X seat=%s player=%s reason=%s",
        chair_guid,
        int(seat),
        int(_player_guid(session)),
        str(reason),
    )


def release_current_chair(session, *, reason: str = "state-change") -> None:
    _release_chair_seat(session, reason=reason)


def _chair_slots(entry: dict) -> int:
    slots = int(entry.get("data0", 0) or 0)
    return max(1, slots)


def _chair_stand_state(entry: dict) -> int:
    height = int(entry.get("data1", 0) or 0)
    height = max(0, min(height, UNIT_STAND_STATE_SIT_HIGH_CHAIR - UNIT_STAND_STATE_SIT_LOW_CHAIR))
    return UNIT_STAND_STATE_SIT_LOW_CHAIR + height


def _chair_seat_position(entry: dict, seat: int, slots: int) -> tuple[float, float, float, float]:
    size = float(entry.get("size", 1.0) or 1.0)
    orientation = float(entry.get("orientation", 0.0) or 0.0)
    relative_distance = (size * int(seat)) - (size * (int(slots) - 1) / 2.0)
    orthogonal_orientation = orientation + (math.pi * 0.5)
    x = float(entry.get("x", 0.0) or 0.0) + relative_distance * math.cos(orthogonal_orientation)
    y = float(entry.get("y", 0.0) or 0.0) + relative_distance * math.sin(orthogonal_orientation)
    z = float(entry.get("z", 0.0) or 0.0)
    return x, y, z, orientation


def _select_chair_seat(session, entry: dict) -> Optional[tuple[int, float, float, float, float]]:
    chair_guid = _chair_key(entry)
    slots = _chair_slots(entry)
    occupied = _get_chair_occupancy(session).setdefault(chair_guid, {})
    player_guid = _player_guid(session)

    for seat, occupant in list(occupied.items()):
        if int(occupant or 0) == player_guid:
            occupied.pop(int(seat), None)

    best = None
    best_dist = float("inf")
    for seat in range(slots):
        if int(occupied.get(seat, 0) or 0) > 0:
            continue

        x, y, z, orientation = _chair_seat_position(entry, seat, slots)
        dx = x - float(getattr(session, "x", 0.0) or 0.0)
        dy = y - float(getattr(session, "y", 0.0) or 0.0)
        dist = (dx * dx) + (dy * dy)
        if dist <= best_dist:
            best = (seat, x, y, z, orientation)
            best_dist = dist

    return best


def _stand_state_update_response(session, stand_state: int) -> tuple[str, bytes]:
    return (
        "SMSG_UPDATE_OBJECT",
        build_single_u32_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=_player_guid(session),
            field_index=UNIT_FIELD_ANIMTIER,
            value=int(stand_state),
        ),
    )


def _send_stand_state_to_peers(session, response: tuple[str, bytes]) -> None:
    state = getattr(session, "global_state", None)
    map_id = int(getattr(session, "map_id", 0) or 0)
    for target in list(getattr(state, "sessions", set()) or ()):
        if target is session:
            continue
        if int(getattr(target, "map_id", 0) or 0) != map_id:
            continue
        sender = getattr(target, "send_response", None)
        if callable(sender):
            sender([response])


def _sit_on_chair(session, entry: dict) -> list[tuple[str, bytes]]:
    selection = _select_chair_seat(session, entry)
    if selection is None:
        Logger.info("[CHAIR] no free seat entry=%s guid=%s", int(entry.get("entry", 0) or 0), int(entry.get("guid", 0) or 0))
        return []

    _release_chair_seat(session, reason="new-chair")
    seat, x, y, z, orientation = selection
    chair_guid = _chair_key(entry)
    player_guid = _player_guid(session)
    _get_chair_occupancy(session).setdefault(chair_guid, {})[int(seat)] = player_guid

    session.x = float(x)
    session.y = float(y)
    session.z = float(z)
    session.orientation = float(orientation)
    movement_state = getattr(session, "movement_state", None)
    if movement_state is not None:
        movement_state.x = float(x)
        movement_state.y = float(y)
        movement_state.z = float(z)
        movement_state.orientation = float(orientation)
        movement_state.flags = 0
        movement_state.flags2 = 0

    stand_state = _chair_stand_state(entry)
    session.player_stand_state = int(stand_state)
    session.current_chair = int(chair_guid)
    session.current_seat = int(seat)
    session.near_teleport_pending = True
    session.teleport_pending = False
    session.worldport_ack_pending = False

    Logger.info(
        "[CHAIR] sit player=%s entry=%s chair=0x%016X seat=%s pos=(%.3f %.3f %.3f %.3f) stand=%s",
        int(player_guid),
        int(entry.get("entry", 0) or 0),
        int(chair_guid),
        int(seat),
        float(x),
        float(y),
        float(z),
        float(orientation),
        int(stand_state),
    )

    stand_response = _stand_state_update_response(session, stand_state)
    _send_stand_state_to_peers(session, stand_response)
    return [
        ("SMSG_MOVE_TELEPORT", build_same_map_teleport_payload(session)),
        stand_response,
    ]


@register("CMSG_GAME_OBJ_REPORT_USE")
@register("CMSG_GAME_OBJ_USE")
def handle_gameobject_use(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    guid = _decode_gameobject_use_guid(bytes(ctx.payload or b""), ctx.decoded or {})
    if guid is None:
        Logger.warning("[GAMEOBJECT_USE] failed to decode guid payload=%s", bytes(ctx.payload or b"").hex())
        return 0, None

    entry = _find_visible_gameobject(session, int(guid))
    if entry is None:
        Logger.debug("[GAMEOBJECT_USE] missing visible gameobject guid=0x%016X", int(guid))
        return 0, None

    Logger.debug(
        "[GAMEOBJECT_USE] guid=0x%016X entry=%s type=%s name=%r",
        int(guid),
        int(entry.get("entry", 0) or 0),
        int(entry.get("type", 0) or 0),
        str(entry.get("name", "") or ""),
    )

    if int(entry.get("type", 0) or 0) != GAMEOBJECT_TYPE_CHAIR:
        return 0, None

    responses = _sit_on_chair(session, entry)
    return 0, (responses or None)


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


def _build_name_query_response(
    guid: int,
    *,
    name: str,
    realm_name: str,
    realm_id: int,
    account_id: int,
    race: int,
    gender: int,
    class_id: int,
    level: int,
    deleted: bool = False,
) -> bytes:
    guid_value = int(guid or 0) & 0xFFFFFFFFFFFFFFFF
    guid_bytes = list(GuidHelper.to_le_bytes(guid_value))
    zero_guid = [0] * 8
    player_name = str(name or "").strip()
    has_name = bool(player_name)

    def write_byte_seq(payload: bytearray, value: int) -> None:
        byte_value = int(value) & 0xFF
        if byte_value != 0:
            payload.append(byte_value ^ 0x01)

    bits = BitWriter()
    payload = bytearray()

    for index in (3, 6, 7, 2, 5, 4, 0, 1):
        bits.write_bits(1 if guid_bytes[index] else 0, 1)

    payload.extend(bits.getvalue())

    for index in (5, 4, 7, 6, 1, 2):
        write_byte_seq(payload, guid_bytes[index])

    payload.append(0 if has_name else 1)

    if has_name:
        payload.extend(struct.pack("<I", int(realm_id) & 0xFFFFFFFF))
        payload.extend(struct.pack("<I", int(account_id or 1) & 0xFFFFFFFF))
        payload.append(int(class_id) & 0xFF)
        payload.append(int(race) & 0xFF)
        payload.append(int(level) & 0xFF)
        payload.append(int(gender) & 0xFF)

    write_byte_seq(payload, guid_bytes[0])
    write_byte_seq(payload, guid_bytes[3])

    if not has_name:
        return bytes(payload)

    bits = BitWriter()
    for value in (
        zero_guid[2],
        zero_guid[7],
        guid_bytes[7],
        guid_bytes[2],
        guid_bytes[0],
        0,  # deleted flag
        zero_guid[4],
        guid_bytes[5],
        zero_guid[1],
        zero_guid[3],
        zero_guid[0],
    ):
        bits.write_bits(1 if value else 0, 1)

    for _ in range(5):
        bits.write_bits(0, 7)

    for value in (guid_bytes[6], guid_bytes[3], zero_guid[5], guid_bytes[1], guid_bytes[4]):
        bits.write_bits(1 if value else 0, 1)

    encoded_name = player_name.encode("utf-8", errors="ignore")
    bits.write_bits(len(encoded_name), 6)
    bits.write_bits(1 if zero_guid[6] else 0, 1)
    payload.extend(bits.getvalue())

    for index in (6, 0):
        write_byte_seq(payload, guid_bytes[index])
    payload.extend(encoded_name)
    for index in (5, 2):
        write_byte_seq(payload, zero_guid[index])
    write_byte_seq(payload, guid_bytes[3])
    for index in (4, 3):
        write_byte_seq(payload, zero_guid[index])
    write_byte_seq(payload, guid_bytes[4])
    write_byte_seq(payload, guid_bytes[2])
    write_byte_seq(payload, zero_guid[7])
    write_byte_seq(payload, zero_guid[6])
    write_byte_seq(payload, guid_bytes[7])
    write_byte_seq(payload, guid_bytes[1])
    write_byte_seq(payload, zero_guid[1])
    write_byte_seq(payload, guid_bytes[5])
    write_byte_seq(payload, zero_guid[0])

    return bytes(payload)


def _build_name_query_response_no_data(guid: int) -> bytes:
    return _build_name_query_response(
        guid,
        name="",
        realm_name="",
        realm_id=0,
        account_id=0,
        race=0,
        gender=0,
        class_id=0,
        level=0,
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


def _decode_name_query_guid(payload: bytes) -> Optional[int]:
    raw = bytes(payload or b"")
    if not raw:
        return None

    try:
        byte_pos = 0
        bit_pos = 0
        guid = [0] * 8

        guid[4], byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        _bit14, byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        guid[6], byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        guid[0], byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        guid[7], byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        guid[1], byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        _bit1c, byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        guid[5], byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        guid[2], byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        guid[3], byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)

        if bit_pos:
            byte_pos += 1
            bit_pos = 0

        for index in (7, 5, 1, 2, 6, 3, 0, 4):
            if not guid[index]:
                continue
            if byte_pos >= len(raw):
                return None
            guid[index] ^= raw[byte_pos]
            byte_pos += 1

        decoded = int.from_bytes(bytes(guid), "little", signed=False)
        if decoded:
            return decoded
    except Exception:
        pass

    for value in reversed(raw):
        candidate = int(value) & 0xFF
        if candidate:
            return candidate
    return None


def _find_session_by_guid(session, guid_hint: int):
    if guid_hint <= 0:
        return None

    state = getattr(session, "global_state", None)
    if state is not None:
        for other in list(getattr(state, "sessions", set()) or ()):
            if int(getattr(other, "world_guid", 0) or 0) == int(guid_hint):
                return other
            if int(getattr(other, "char_guid", 0) or 0) == int(guid_hint):
                return other
            if (int(getattr(other, "char_guid", 0) or 0) & 0xFF) == (int(guid_hint) & 0xFF):
                return other
    return None


def build_query_player_name_response(session, guid: int) -> bytes:
    name = str(getattr(session, "player_name", "") or "").strip()
    realm = _get_realm_name()
    realm_id = int(getattr(session, "realm_id", 0) or 0)
    account_id = int(getattr(session, "account_id", 0) or 0)
    race = int(getattr(session, "race", 0) or 0)
    gender = int(getattr(session, "gender", 0) or 0)
    class_id = int(getattr(session, "class_id", 0) or 0)
    level = int(getattr(session, "level", 0) or 0)
    return _build_name_query_response(
        int(guid),
        name=name,
        realm_name=realm,
        realm_id=realm_id,
        account_id=account_id,
        race=race,
        gender=gender,
        class_id=class_id,
        level=level,
    )


@register("CMSG_OBJECT_UPDATE_FAILED")
def handle_object_update_failed(session, ctx: PacketContext):
    Logger.debug(f"[ENTITY] opcode={ctx.name}")
    decoded = ctx.decoded or {}
    guid = _parse_guid(decoded.get("guid"))
    if guid in (None, 0):
        guid = 0
        for index in range(8):
            value = _parse_guid(decoded.get(f"guid_{index}"))
            if value is not None:
                guid |= (value & 0xFF) << (index * 8)
    Logger.info(f"[WorldHandlers] OBJECT_UPDATE_FAILED guid=0x{int(guid):X}")
    return 0, None


@register("CMSG_CREATURE_QUERY")
def handle_creature_query(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.debug(f"[ENTITY] opcode={ctx.name}")
    decoded = ctx.decoded or {}
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


def _cstring(value: Any) -> bytes:
    text = str(value or "")
    return text.encode("utf-8", errors="ignore") + b"\x00"


def _build_gameobject_query_response_payload(entry: int, info: dict | None) -> bytes:
    payload = bytearray()
    payload.append(0x80 if info else 0x00)
    payload += struct.pack("<I", int(entry) & 0xFFFFFFFF)
    if not info:
        return bytes(payload)

    stats = bytearray()
    stats += struct.pack("<I", int(info.get("type", 0) or 0) & 0xFFFFFFFF)
    stats += struct.pack("<I", int(info.get("displayId", 0) or 0) & 0xFFFFFFFF)
    stats += _cstring(info.get("name", ""))
    stats += b"\x00\x00\x00"
    stats += _cstring(info.get("IconName", ""))
    stats += _cstring(info.get("castBarCaption", ""))
    stats += _cstring(info.get("unk1", ""))

    for index in range(MAX_GAMEOBJECT_DATA):
        stats += struct.pack("<I", int(info.get(f"data{index}", 0) or 0) & 0xFFFFFFFF)

    stats += struct.pack("<f", float(info.get("size", 1.0) or 1.0))
    stats.append(MAX_GAMEOBJECT_QUEST_ITEMS)
    for index in range(1, MAX_GAMEOBJECT_QUEST_ITEMS + 1):
        stats += struct.pack("<I", int(info.get(f"questItem{index}", 0) or 0) & 0xFFFFFFFF)

    stats += struct.pack("<i", int(info.get("unkInt32", 0) or 0))
    payload += struct.pack("<I", len(stats))
    payload += stats
    return bytes(payload)


@register("CMSG_GAMEOBJECT_QUERY")
def handle_gameobject_query(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.debug(f"[ENTITY] opcode={ctx.name}")
    payload = bytes(ctx.payload or b"")
    if len(payload) < 4:
        return 0, None

    entry = struct.unpack_from("<I", payload, 0)[0]
    if entry <= 0:
        return 0, None

    try:
        info = DatabaseConnection.get_gameobject_template(entry)
        response = _build_gameobject_query_response_payload(entry, info)
        if info:
            Logger.info(
                "[WorldHandlers] GAMEOBJECT_QUERY entry=%s name=%r type=%s display=%s",
                entry,
                str(info.get("name", "") or ""),
                int(info.get("type", 0) or 0),
                int(info.get("displayId", 0) or 0),
            )
        else:
            Logger.info(f"[WorldHandlers] GAMEOBJECT_QUERY entry={entry} missing in gameobject_template")
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to encode SMSG_GAMEOBJECT_QUERY_RESPONSE entry={entry}: {exc}")
        return 1, None

    return 0, [("SMSG_GAMEOBJECT_QUERY_RESPONSE", response)]


@register("CMSG_NAME_QUERY")
def handle_name_query(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.debug(f"[ENTITY] opcode={ctx.name}")
    Logger.info(f"[WorldHandlers] CMSG_NAME_QUERY payload={ctx.payload.hex(' ')}")

    requested_guid_hint = _decode_name_query_guid(ctx.payload)
    target_session = _find_session_by_guid(session, int(requested_guid_hint or 0))

    if target_session is not None:
        low_guid = int(getattr(target_session, "char_guid", 0) or 0)
        player_name = (
            str(getattr(target_session, "player_name", "") or "").strip()
            or f"Player{int(getattr(target_session, 'char_guid', 0) or 0)}"
        )
        realm_id = int(getattr(target_session, "realm_id", 0) or 0)
        account_id = int(getattr(target_session, "account_id", 0) or 0)
        race = int(getattr(target_session, "race", 0) or 0)
        gender = int(getattr(target_session, "gender", 0) or 0)
        class_id = int(getattr(target_session, "class_id", 0) or 0)
        level = int(getattr(target_session, "level", 0) or 0)
    else:
        low_guid = int(getattr(session, "char_guid", 0) or 0)
        player_name = (
            str(getattr(session, "player_name", "") or "").strip()
            or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
        )
        realm_id = int(getattr(session, "realm_id", 0) or 0)
        account_id = int(getattr(session, "account_id", 0) or 0)
        race = int(getattr(session, "race", 0) or 0)
        gender = int(getattr(session, "gender", 0) or 0)
        class_id = int(getattr(session, "class_id", 0) or 0)
        level = int(getattr(session, "level", 0) or 0)

    response_guid = int(requested_guid_hint or 0)
    if response_guid <= 0:
        response_guid = int(low_guid or 0)
    world_response = _build_name_query_response(
        response_guid,
        name=player_name,
        realm_name=_get_realm_name(),
        realm_id=realm_id,
        account_id=account_id,
        race=race,
        gender=gender,
        class_id=class_id,
        level=level,
    )
    Logger.info(
        f"[WorldHandlers] SMSG_QUERY_PLAYER_NAME_RESPONSE guid=0x{response_guid:016X} "
        f"name={player_name!r} size={len(world_response)} requested_hint=0x{int(requested_guid_hint or 0):X}"
    )
    return 0, [("SMSG_QUERY_PLAYER_NAME_RESPONSE", world_response)]


@register("CMSG_QUEST_GIVER_STATUS_QUERY")
def handle_quest_giver_status_query(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.debug(f"[ENTITY] opcode={ctx.name}")
    guid = _decode_quest_giver_status_query_guid(ctx.payload)
    Logger.info(
        f"[WorldHandlers] CMSG_QUEST_GIVER_STATUS_QUERY guid="
        f"0x{int(guid or 0):016X}"
    )
    response = _build_questgiver_status_payload(int(guid or 0), 0)
    return 0, [("SMSG_QUESTGIVER_STATUS", response)]
