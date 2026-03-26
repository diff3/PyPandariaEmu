from __future__ import annotations

import struct
import time
import zlib
from typing import Any, Optional

from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.constants.account_data import (
    ACCOUNT_DATA_TYPE_0_DEFAULT,
    ACCOUNT_DATA_TYPE_1_DEFAULT,
    ACCOUNT_DATA_TYPE_2_DEFAULT,
    ACCOUNT_DATA_TYPE_3_DEFAULT,
    ACCOUNT_DATA_TYPE_7_DEFAULT,
    DB_ACCOUNT_DATA_137_TYPES,
    GLOBAL_ACCOUNT_DATA_STORAGE_TYPES,
    PER_CHARACTER_ACCOUNT_DATA_TYPES,
)

USE_DB_ACCOUNT_DATA_137 = True
SEND_ACCOUNT_DATA_TO_CLIENT = True
GLOBAL_ACCOUNT_DATA_TYPES = GLOBAL_ACCOUNT_DATA_STORAGE_TYPES


def _write_guid_mask_bits(bits: BitWriter, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        bits.write_bits(1 if raw_guid[index] else 0, 1)


def _append_guid_byte_seq(payload: bytearray, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        if raw_guid[index]:
            payload.append(raw_guid[index])


def decode_account_data_request_type(payload: bytes) -> int:
    if not payload:
        return 0
    if len(payload) >= 4:
        unpacked = int(struct.unpack_from("<I", payload, 0)[0])
        if 0 <= unpacked < 8:
            return unpacked
    return (int(payload[0]) >> 5) & 0x07


def decode_account_data_update_payload(payload: bytes) -> dict[str, Any]:
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


def build_update_account_data_payload(
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


def account_data_text_for_type(data_type: int, account_name: str = "") -> str:
    if int(data_type) == 0:
        return ACCOUNT_DATA_TYPE_0_DEFAULT
    if int(data_type) == 1:
        return ACCOUNT_DATA_TYPE_1_DEFAULT
    if int(data_type) == 2:
        return ACCOUNT_DATA_TYPE_2_DEFAULT
    if int(data_type) == 3:
        return ACCOUNT_DATA_TYPE_3_DEFAULT
    if int(data_type) == 7:
        return ACCOUNT_DATA_TYPE_7_DEFAULT
    return ""


def is_global_account_data_type(data_type: int) -> bool:
    return int(data_type) in GLOBAL_ACCOUNT_DATA_STORAGE_TYPES


def normalize_account_data_text(data_type: int, data_text: str) -> str:
    text = str(data_text or "")
    if int(data_type) == 3:
        required_fragments = (
            "BINDINGMODE 0\r\n",
            "bind SHIFT-6 ACTIONPAGE6\r\n",
            "bind M TOGGLEWORLDMAP\r\n",
        )
        if not text.strip():
            return ACCOUNT_DATA_TYPE_3_DEFAULT
        if all(fragment in text for fragment in required_fragments):
            return text
        Logger.info("[ACCOUNT_DATA] normalizing type=3 payload to canonical bindings layout")
        return ACCOUNT_DATA_TYPE_3_DEFAULT

    if int(data_type) != 7:
        return text

    if not text.strip():
        return ACCOUNT_DATA_TYPE_7_DEFAULT

    required_fragments = (
        "WINDOW 2\nNAME Combat Log",
        "INSTANCE_CHAT",
        "INSTANCE_CHAT_LEADER",
        "CHANNELS\nEND\n\nZONECHANNELS 2097155",
    )
    if all(fragment in text for fragment in required_fragments) and "LookingForGroup" not in text:
        if text.rstrip("\n") == ACCOUNT_DATA_TYPE_7_DEFAULT.rstrip("\n"):
            return ACCOUNT_DATA_TYPE_7_DEFAULT
        return text

    Logger.info("[ACCOUNT_DATA] normalizing type=7 payload to canonical chat layout")
    return ACCOUNT_DATA_TYPE_7_DEFAULT


def account_data_mask_for_types(data_types: tuple[int, ...]) -> int:
    mask = 0
    for data_type in data_types:
        mask |= (1 << int(data_type))
    return mask


def account_data_times_list_for_types(session, now: int, data_types: tuple[int, ...]) -> list[int]:
    timestamps = [0] * 8
    for data_type in data_types:
        stored = session.account_data_times.get(int(data_type))
        timestamps[int(data_type)] = int(stored if stored is not None else now)
    return timestamps


def load_account_data_scope(session, owner_id: int, *, per_character: bool) -> None:
    if int(owner_id or 0) <= 0:
        return

    loaded = DatabaseConnection.load_account_data(int(owner_id), per_character=per_character)
    data_types = PER_CHARACTER_ACCOUNT_DATA_TYPES if per_character else GLOBAL_ACCOUNT_DATA_STORAGE_TYPES
    seeded_types: list[int] = []
    now = int(time.time())

    for data_type in data_types:
        default_text = account_data_text_for_type(int(data_type), str(session.account_name or ""))
        should_persist = False
        if int(data_type) in loaded:
            timestamp, data_text = loaded[int(data_type)]
            normalized_text = normalize_account_data_text(int(data_type), str(data_text or ""))
            if normalized_text != str(data_text or ""):
                data_text = normalized_text
                timestamp = int(timestamp or now)
                should_persist = bool(
                    USE_DB_ACCOUNT_DATA_137
                    and per_character
                    and int(data_type) in DB_ACCOUNT_DATA_137_TYPES
                )
        elif default_text:
            timestamp, data_text = now, default_text
            should_persist = bool(
                USE_DB_ACCOUNT_DATA_137
                and per_character
                and int(data_type) in DB_ACCOUNT_DATA_137_TYPES
            )
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


def load_global_account_data(session, account_id: int | None = None) -> None:
    owner_id = int(account_id if account_id is not None else getattr(session, "account_id", 0) or 0)
    if owner_id > 0:
        load_account_data_scope(session, owner_id, per_character=False)


def load_character_account_data(session, char_guid: int | None = None) -> None:
    owner_id = int(char_guid if char_guid is not None else getattr(session, "char_guid", 0) or 0)
    if owner_id > 0:
        load_account_data_scope(session, owner_id, per_character=True)


def persist_account_data_entry(session, data_type: int, account_text: str, timestamp: int) -> bool:
    if not 0 <= int(data_type) < 8:
        return False

    if USE_DB_ACCOUNT_DATA_137 and int(data_type) not in DB_ACCOUNT_DATA_137_TYPES:
        return False

    owner_id = int(session.account_id or 0) if is_global_account_data_type(int(data_type)) else int(session.char_guid or 0)
    if owner_id <= 0:
        return False

    return DatabaseConnection.save_account_data(
        owner_id,
        int(data_type),
        int(timestamp or 0),
        str(account_text or ""),
        per_character=not is_global_account_data_type(int(data_type)),
    )


def flush_account_data_types_to_db(
    session,
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
            stored_text = account_data_text_for_type(data_type, str(session.account_name or ""))
            session.account_data[data_type] = stored_text

        timestamp = int(session.account_data_times.get(data_type) or now)
        session.account_data_times[data_type] = timestamp
        if stored_text:
            session.account_data_mask |= (1 << data_type)
        else:
            session.account_data_mask &= ~(1 << data_type)

        if persist_account_data_entry(session, data_type, str(stored_text or ""), timestamp):
            saved_types.append(data_type)

    if saved_types:
        Logger.info("[ACCOUNT_DATA] flushed types=%s to DB" % ",".join(str(v) for v in saved_types))


def build_minimal_post_timesync_account_packets(session) -> list[tuple[str, bytes]]:
    if getattr(session, "account_data_captures_sent", False):
        return []

    responses: list[tuple[str, bytes]] = []
    for data_type in (1, 3, 7):
        stored_text = session.account_data.get(data_type)
        if not stored_text:
            continue

        timestamp = int(session.account_data_times.get(data_type) or time.time())
        payload = build_update_account_data_payload(
            data_type,
            stored_text,
            timestamp=timestamp,
            guid=int(getattr(session, "world_guid", 0) or 0),
        )
        Logger.info(f"[ACCOUNT_DATA][AUTO] type={data_type} size={len(payload)}")
        responses.append(("SMSG_UPDATE_ACCOUNT_DATA", payload))

    session.account_data_captures_sent = True
    return responses
