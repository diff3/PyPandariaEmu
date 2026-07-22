from __future__ import annotations

import struct

from DSL.modules.bitsHandler import BitInterPreter
from shared.Logger import Logger
from server.modules.handlers.world.dispatcher import register
from server.modules.mail.service import (
    build_mail_list_packet,
    build_next_mail_time_packet,
    build_send_mail_result,
    get_mail_service,
)

MAIL_ERR_CANNOT_SEND_TO_SELF = 2
MAIL_ERR_RECIPIENT_NOT_FOUND = 4
MAIL_ERR_INTERNAL_ERROR = 6
MAIL_ERR_TOO_MANY_ATTACHMENTS = 18
MAIL_ACTION_DELETED = 4


def _read_byte_seq(payload: bytes, cursor: int, present: bool) -> tuple[int, int]:
    if not present:
        return 0, cursor
    if cursor >= len(payload):
        raise ValueError("truncated mail guid")
    return payload[cursor] ^ 1, cursor + 1


def parse_send_mail_request(payload: bytes) -> dict:
    """Decode the exact SkyFire 5.4.8 CMSG_SEND_MAIL layout."""
    if len(payload) < 24:
        raise ValueError("truncated send mail request")
    unk1, unk2, cod, money = struct.unpack_from("<IIQQ", payload, 0)
    byte_pos, bit_pos = 24, 0

    def bit() -> int:
        nonlocal byte_pos, bit_pos
        value, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        return value

    def bits(width: int) -> int:
        nonlocal byte_pos, bit_pos
        value, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, width)
        return value

    mailbox_mask = [0] * 8
    for index in (0, 6, 4, 1): mailbox_mask[index] = bit()
    body_length = bits(11)
    mailbox_mask[3] = bit()
    receiver_length = bits(9)
    mailbox_mask[7] = bit()
    mailbox_mask[5] = bit()
    item_count = bits(5)
    if item_count > 12:
        raise ValueError("too_many_attachments")
    item_masks: list[list[int]] = []
    for _ in range(item_count):
        mask = [0] * 8
        for index in (1, 7, 2, 5, 0, 6, 3, 4): mask[index] = bit()
        item_masks.append(mask)
    subject_length = bits(9)
    mailbox_mask[2] = bit()
    cursor = byte_pos + (1 if bit_pos else 0)
    for mask in item_masks:
        cursor += 1  # attachment slot
        for index in (3, 0, 2, 1, 6, 5, 7, 4):
            _value, cursor = _read_byte_seq(payload, cursor, bool(mask[index]))
    mailbox = [0] * 8
    mailbox[1], cursor = _read_byte_seq(payload, cursor, bool(mailbox_mask[1]))
    body = payload[cursor:cursor + body_length].decode("utf-8", "replace")
    cursor += body_length
    mailbox[0], cursor = _read_byte_seq(payload, cursor, bool(mailbox_mask[0]))
    subject = payload[cursor:cursor + subject_length].decode("utf-8", "replace")
    cursor += subject_length
    for index in (2, 6, 5, 7, 3, 4):
        mailbox[index], cursor = _read_byte_seq(payload, cursor, bool(mailbox_mask[index]))
    receiver = payload[cursor:cursor + receiver_length].decode("utf-8", "replace")
    if len(receiver.encode("utf-8")) != receiver_length:
        raise ValueError("truncated recipient")
    return {
        "unk1": unk1, "unk2": unk2, "cod": cod, "money": money,
        "item_count": item_count, "receiver": receiver, "subject": subject, "body": body,
        "mailbox_guid": int.from_bytes(bytes(mailbox), "little"),
    }


def _parse_mailbox_guid(payload: bytes) -> int:
    byte_pos = bit_pos = 0
    mask = [0] * 8
    for index in (6, 3, 7, 5, 4, 1, 2, 0):
        mask[index], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
    cursor = byte_pos + (1 if bit_pos else 0)
    raw = [0] * 8
    for index in (7, 1, 6, 5, 4, 2, 3, 0):
        raw[index], cursor = _read_byte_seq(payload, cursor, bool(mask[index]))
    return int.from_bytes(bytes(raw), "little")


def _has_mailbox_access(session, mailbox_guid: int) -> bool:
    entries = getattr(session, "loaded_gameobject_entries", None)
    if not isinstance(entries, dict):
        return False
    entry = entries.get(int(mailbox_guid))
    return isinstance(entry, dict) and int(entry.get("type", -1) or -1) == 19


@register("CMSG_SEND_MAIL")
def handle_send_mail(session, ctx):
    Logger.info(
        "[Mail] CMSG_SEND_MAIL player=%s payload_size=%s",
        int(getattr(session, "char_guid", 0) or 0),
        len(bytes(getattr(ctx, "payload", b"") or b"")),
    )
    try:
        request = parse_send_mail_request(bytes(getattr(ctx, "payload", b"") or b""))
    except ValueError as exc:
        error = MAIL_ERR_TOO_MANY_ATTACHMENTS if str(exc) == "too_many_attachments" else MAIL_ERR_INTERNAL_ERROR
        return 0, [("SMSG_SEND_MAIL_RESULT", build_send_mail_result(error=error))]
    if request["item_count"] or request["money"] or request["cod"]:
        return 0, [("SMSG_SEND_MAIL_RESULT", build_send_mail_result(error=MAIL_ERR_TOO_MANY_ATTACHMENTS))]
    if not _has_mailbox_access(session, request["mailbox_guid"]):
        Logger.warning(
            "[Mail] send rejected player=%s mailbox=0x%016X reason=no_access",
            int(getattr(session, "char_guid", 0) or 0),
            int(request["mailbox_guid"]),
        )
        return 0, None
    try:
        get_mail_service().send_player(
            int(getattr(session, "char_guid", 0) or 0), request["receiver"],
            request["subject"], request["body"],
        )
    except ValueError as exc:
        error = MAIL_ERR_CANNOT_SEND_TO_SELF if str(exc) == "cannot_send_to_self" else MAIL_ERR_RECIPIENT_NOT_FOUND
        return 0, [("SMSG_SEND_MAIL_RESULT", build_send_mail_result(error=error))]
    except Exception as exc:
        Logger.warning("[Mail] send failed player=%s error=%s", getattr(session, "char_guid", 0), exc)
        return 0, [("SMSG_SEND_MAIL_RESULT", build_send_mail_result(error=MAIL_ERR_INTERNAL_ERROR))]
    return 0, [("SMSG_SEND_MAIL_RESULT", build_send_mail_result())]


@register("CMSG_GET_MAIL_LIST")
def handle_get_mail_list(session, ctx):
    try:
        mailbox_guid = _parse_mailbox_guid(bytes(getattr(ctx, "payload", b"") or b""))
    except (IndexError, ValueError):
        return 0, None
    if not _has_mailbox_access(session, mailbox_guid):
        return 0, None
    service = get_mail_service()
    messages = service.list_mail(int(getattr(session, "char_guid", 0) or 0))
    return 0, [("SMSG_MAIL_LIST_RESULT", build_mail_list_packet(
        messages, realm_id=int(getattr(session, "realm_id", 1) or 1)
    ))]


@register("CMSG_MAIL_QUERY_NEXT_TIME")
def handle_query_next_mail_time(session, _ctx):
    messages = get_mail_service().list_mail(int(getattr(session, "char_guid", 0) or 0))
    return 0, [("SMSG_MAIL_QUERY_NEXT_TIME_RESULT", build_next_mail_time_packet(messages))]


@register("CMSG_MAIL_MARK_AS_READ")
def handle_mark_mail_read(session, ctx):
    payload = bytes(getattr(ctx, "payload", b"") or b"")
    if len(payload) < 4:
        return 0, None
    service = get_mail_service()
    service.mark_read(int(getattr(session, "char_guid", 0) or 0), struct.unpack_from("<I", payload)[0])
    messages = service.list_mail(int(getattr(session, "char_guid", 0) or 0))
    return 0, [("SMSG_MAIL_QUERY_NEXT_TIME_RESULT", build_next_mail_time_packet(messages))]


@register("CMSG_MAIL_DELETE")
def handle_delete_mail(session, ctx):
    payload = bytes(getattr(ctx, "payload", b"") or b"")
    if len(payload) < 8:
        return 0, [("SMSG_SEND_MAIL_RESULT", build_send_mail_result(
            error=MAIL_ERR_INTERNAL_ERROR,
            action=MAIL_ACTION_DELETED,
        ))]
    mail_id, _mail_template_id = struct.unpack_from("<II", payload)
    get_mail_service().delete_mail(
        int(getattr(session, "char_guid", 0) or 0),
        int(mail_id),
    )
    return 0, [("SMSG_SEND_MAIL_RESULT", build_send_mail_result(
        mail_id=int(mail_id),
        action=MAIL_ACTION_DELETED,
    ))]
