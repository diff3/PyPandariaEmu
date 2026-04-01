from __future__ import annotations

import struct
from typing import Any, Optional, Tuple

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitInterPreter
from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.dispatcher import register
from server.modules.game.guid import GuidHelper


MAX_CREATURE_QUEST_ITEMS = 6


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
