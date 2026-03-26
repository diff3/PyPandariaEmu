from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from shared.PathUtils import get_captures_root
from server.modules.handlers.world.bootstrap import replay as bootstrap_replay

CHAT_MSG_SAY = 1
CHAT_MSG_SYSTEM = 0
CHAT_MSG_YELL = 6
CHAT_MSG_WHISPER = 7

TEXT_EMOTE_TO_ANIM_EMOTE: dict[int, int] = {
    5: 5,
    34: 10,
    41: 0,
    72: 25,
    77: 14,
    84: 24,
    86: 12,
    87: 13,
    93: 1,
    97: 0,
    100: 4,
    101: 3,
    102: 3,
    141: 26,
}


def build_motd_notification_payload(message: str) -> bytes:
    message_bytes = str(message or "").encode("utf-8", errors="strict")
    bits = BitWriter()
    bits.write_bits(len(message_bytes) & 0xFFF, 12)
    return bits.getvalue() + message_bytes


def decode_chat_message(
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


def build_raw_replay_messagechat_packet(*, profile: str | None) -> Optional[tuple[str, bytes]]:
    profile_name = str(profile or "").strip()
    if not profile_name:
        return None

    path = get_captures_root(profile=profile_name) / "debug" / "SMSG_MESSAGECHAT.json"
    if not path.exists():
        Logger.info(f"[CHAT][RAW] missing capture profile={profile_name!r} path={path}")
        return None

    payload = bootstrap_replay.load_sniff_payload(path)
    Logger.info(
        f"[CHAT][RAW] replaying SMSG_MESSAGECHAT profile={profile_name!r} "
        f"payload={len(payload)} source={path.name}"
    )
    return "SMSG_MESSAGECHAT", payload


def _chat_guid_bytes_for_messagechat(guid: int) -> bytes:
    return int(guid or 0).to_bytes(8, "little", signed=False)


def _write_guid_mask_bits(bits: BitWriter, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        bits.write_bits(1 if raw_guid[index] else 0, 1)


def _append_guid_byte_seq(payload: bytearray, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        value = raw_guid[index]
        if value:
            payload.append((value ^ 1) & 0xFF)


def encode_text_emote_payload(*, player_guid: int, target_guid: int, text_emote: int, emote_num: int) -> bytes:
    player_raw = int(player_guid or 0).to_bytes(8, "little", signed=False)
    target_raw = int(target_guid or 0).to_bytes(8, "little", signed=False)

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
    payload += int(text_emote & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
    _append_guid_byte_seq(payload, player_raw, (6,))
    _append_guid_byte_seq(payload, target_raw, (0,))
    _append_guid_byte_seq(payload, player_raw, (3, 1))
    _append_guid_byte_seq(payload, target_raw, (6,))
    _append_guid_byte_seq(payload, player_raw, (0,))
    _append_guid_byte_seq(payload, target_raw, (3, 5, 4))
    payload += int(emote_num & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
    return bytes(payload)


def _encode_skyfire_messagechat_payload(
    message: str,
    *,
    chat_type: int,
    sender_guid: int = 0,
    receiver_guid: int = 0,
    language: int = 0,
) -> bytes:
    message_bytes = str(message or "").encode("utf-8", errors="strict")
    sender_raw = _chat_guid_bytes_for_messagechat(sender_guid)
    receiver_raw = _chat_guid_bytes_for_messagechat(receiver_guid)
    group_raw = b"\x00" * 8
    guild_raw = b"\x00" * 8
    has_language = int(language or 0) > 0

    bits = BitWriter()
    bits.write_bits(1, 1)
    bits.write_bits(0, 1)
    bits.write_bits(0, 1)
    bits.write_bits(1, 1)
    bits.write_bits(0, 1)
    bits.write_bits(1, 1)
    bits.write_bits(1, 1)
    bits.write_bits(1, 1)

    _write_guid_mask_bits(bits, group_raw, (0, 1, 5, 4, 3, 2, 6, 7))
    bits.write_bits(0, 1)
    _write_guid_mask_bits(bits, receiver_raw, (7, 6, 1, 4, 0, 2, 3, 5))
    bits.write_bits(0, 1)
    bits.write_bits(0 if has_language else 1, 1)
    bits.write_bits(1, 1)
    _write_guid_mask_bits(bits, sender_raw, (0, 3, 7, 2, 1, 5, 4, 6))
    bits.write_bits(1, 1)
    bits.write_bits(0 if message_bytes else 1, 1)
    if message_bytes:
        bits.write_bits(len(message_bytes), 12)
    bits.write_bits(1, 1)
    bits.write_bits(1, 1)
    bits.write_bits(0, 1)
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


def encode_skyfire_messagechat_system_payload(message: str) -> bytes:
    return _encode_skyfire_messagechat_payload(
        message,
        chat_type=CHAT_MSG_SYSTEM,
        sender_guid=0,
        receiver_guid=0,
        language=0,
    )


def encode_messagechat_payload(
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
        payload = _encode_skyfire_messagechat_payload(
            message,
            chat_type=CHAT_MSG_SAY,
            sender_guid=int(sender_guid or 0),
            receiver_guid=int(sender_guid or 0),
            language=int(language or 0),
        )
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
