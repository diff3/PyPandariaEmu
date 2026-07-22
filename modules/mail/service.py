from __future__ import annotations

from dataclasses import dataclass
import struct
import time

from sqlalchemy import text

from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import GuidHelper, PlayerGuid

MAIL_NORMAL = 0
MAIL_CREATURE = 3
MAIL_STATIONERY_DEFAULT = 41
MAIL_STATIONERY_GM = 61
MAIL_SYSTEM_SENDER_ENTRY = 34337  # The Postmaster
MAIL_CHECK_READ = 0x01
MAIL_CHECK_HAS_BODY = 0x10
MAIL_EXPIRE_SECONDS = 30 * 24 * 60 * 60


@dataclass(frozen=True, slots=True)
class MailMessage:
    id: int
    message_type: int
    sender: int
    receiver: int
    subject: str
    body: str
    deliver_time: int
    expire_time: int
    checked: int
    stationery: int

    @property
    def is_read(self) -> bool:
        return bool(self.checked & MAIL_CHECK_READ)


def build_received_mail_packet() -> bytes:
    # SkyFire 5.4.8 Player::SendNewMail: float delivery delay.
    return struct.pack("<f", 0.0)


def build_send_mail_result(mail_id: int = 0, *, error: int = 0, action: int = 0) -> bytes:
    # SkyFire 5.4.8 Player::SendMailResult.
    return struct.pack("<6I", int(mail_id), 0, int(error), int(action), 0, 0)


def build_next_mail_time_packet(messages: list[MailMessage], *, now: int | None = None) -> bytes:
    current = int(time.time() if now is None else now)
    unread = [mail for mail in messages if not mail.is_read and mail.deliver_time <= current][:3]
    bits = BitWriter()
    bits.write_bits(len(unread), 20)
    body = bytearray()
    for mail in unread:
        sender_guid = PlayerGuid.from_db_guid(mail.sender, 1) if mail.message_type == MAIL_NORMAL else 0
        raw = GuidHelper.to_le_bytes(sender_guid)
        for index in (3,): bits.write_bits(bool(raw[index]), 1)
        bits.write_bits(0, 1)  # no virtual realm address
        bits.write_bits(bool(raw[2]), 1)
        bits.write_bits(0, 1)  # no native realm address
        for index in (6, 1, 4, 0, 5, 7): bits.write_bits(bool(raw[index]), 1)
        body += struct.pack("<I", mail.sender if mail.message_type != MAIL_NORMAL else 0)
        for index in (5, 4, 6, 1):
            if raw[index]: body.append(raw[index] ^ 1)
        body += struct.pack("<B", mail.message_type)
        if raw[0]: body.append(raw[0] ^ 1)
        body += struct.pack("<fI", float(mail.deliver_time - current), mail.stationery)
        for index in (3, 2, 7):
            if raw[index]: body.append(raw[index] ^ 1)
    bits.flush_to_byte()
    return bytes(bits.buffer) + bytes(body) + struct.pack("<f", 0.0 if unread else -1.0)


def build_mail_list_packet(messages: list[MailMessage], *, realm_id: int = 1, now: int | None = None) -> bytes:
    current = int(time.time() if now is None else now)
    delivered = [mail for mail in messages if mail.deliver_time <= current][:50]
    bits = BitWriter()
    bits.write_bits(len(delivered), 18)
    records = bytearray()
    for mail in delivered:
        subject = mail.subject.encode("utf-8")[:255]
        body = mail.body.encode("utf-8")[:8191]
        sender_guid = PlayerGuid.from_db_guid(mail.sender, realm_id) if mail.message_type == MAIL_NORMAL else 0
        raw = GuidHelper.to_le_bytes(sender_guid)
        bits.write_bits(mail.message_type != MAIL_NORMAL, 1)
        bits.write_bits(len(subject), 8)
        bits.write_bits(len(body), 13)
        bits.write_bits(0, 1)
        bits.write_bits(0, 1)
        bits.write_bits(0, 17)  # attachments
        bits.write_bits(1, 1)   # has sender guid field
        for index in (2, 6, 7, 0, 5, 3, 1, 4):
            bits.write_bits(bool(raw[index]), 1)

        records += body
        records += struct.pack("<I", mail.id)
        for index in (4, 0, 5, 3, 1, 7, 2, 6):
            if raw[index]: records.append(raw[index] ^ 1)
        records += struct.pack("<IQ", 0, 0)  # template, COD
        records += subject
        remaining_days = max(0.0, float(mail.expire_time - current) / 86400.0)
        records += struct.pack("<IfQI", mail.stationery, remaining_days, 0, mail.checked)
        if mail.message_type != MAIL_NORMAL:
            records += struct.pack("<I", mail.sender)
        records += struct.pack("<BI", mail.message_type, 0)
    bits.flush_to_byte()
    return struct.pack("<I", len(delivered)) + bytes(bits.buffer) + bytes(records)


class MailService:
    """Canonical owner of persisted mail and unread notification orchestration."""

    def _session(self):
        return DatabaseConnection.chars()

    def resolve_recipient(self, recipient: str | int) -> dict | None:
        db = self._session()
        with db.get_bind().connect() as connection:
            if isinstance(recipient, int) or str(recipient).strip().isdigit():
                row = connection.execute(
                    text("SELECT guid, realm, name FROM characters WHERE guid=:guid AND deleteDate IS NULL LIMIT 1"),
                    {"guid": int(recipient)},
                ).mappings().first()
            else:
                row = connection.execute(
                    text("SELECT guid, realm, name FROM characters WHERE LOWER(name)=LOWER(:name) AND deleteDate IS NULL LIMIT 1"),
                    {"name": str(recipient).strip()},
                ).mappings().first()
        return dict(row) if row else None

    def send_player(self, sender_guid: int, recipient: str | int, subject: str, body: str) -> MailMessage:
        target = self.resolve_recipient(recipient)
        if target is None:
            raise ValueError("recipient_not_found")
        if int(target["guid"]) == int(sender_guid):
            raise ValueError("cannot_send_to_self")
        return self._create(
            sender=int(sender_guid), receiver=int(target["guid"]), message_type=MAIL_NORMAL,
            stationery=MAIL_STATIONERY_DEFAULT, subject=subject, body=body,
        )

    def send_system(self, recipient: str | int, subject: str, body: str) -> MailMessage:
        target = self.resolve_recipient(recipient)
        if target is None:
            raise ValueError("recipient_not_found")
        return self._create(
            sender=MAIL_SYSTEM_SENDER_ENTRY,
            receiver=int(target["guid"]), message_type=MAIL_CREATURE,
            # Use the normal readable parchment. The sender type/entry already
            # identifies this as Postmaster-generated server mail.
            stationery=MAIL_STATIONERY_DEFAULT, subject=subject, body=body,
        )

    def _create(self, *, sender: int, receiver: int, message_type: int, stationery: int, subject: str, body: str) -> MailMessage:
        normalized_subject = str(subject or "").strip()[:255]
        normalized_body = str(body or "")[:8191]
        if not normalized_subject:
            raise ValueError("subject_required")
        now = int(time.time())
        db = self._session()
        try:
            bind = db.get_bind() if callable(getattr(db, "get_bind", None)) else None
            lock_suffix = " FOR UPDATE" if getattr(getattr(bind, "dialect", None), "name", "mysql") == "mysql" else ""
            last = db.execute(text("SELECT id FROM mail ORDER BY id DESC LIMIT 1" + lock_suffix)).scalar()
            mail_id = int(last or 0) + 1
            checked = MAIL_CHECK_HAS_BODY if normalized_body else 0
            db.execute(text("""
                INSERT INTO mail
                    (id, messageType, stationery, mailTemplateId, sender, receiver,
                     subject, body, has_items, expire_time, deliver_time, money, cod, checked)
                VALUES
                    (:id, :message_type, :stationery, 0, :sender, :receiver,
                     :subject, :body, 0, :expire_time, :deliver_time, 0, 0, :checked)
            """), {
                "id": mail_id, "message_type": message_type, "stationery": stationery,
                "sender": sender, "receiver": receiver, "subject": normalized_subject,
                "body": normalized_body, "expire_time": now + MAIL_EXPIRE_SECONDS,
                "deliver_time": now, "checked": checked,
            })
            db.commit()
        except Exception:
            db.rollback()
            raise
        message = MailMessage(mail_id, message_type, sender, receiver, normalized_subject,
                              normalized_body, now, now + MAIL_EXPIRE_SECONDS, checked, stationery)
        Logger.info("[Mail] created id=%s sender=%s recipient=%s", mail_id, sender, receiver)
        self.notify_recipient(receiver)
        Logger.info("[Mail] delivered id=%s recipient=%s", mail_id, receiver)
        return message

    def list_mail(self, receiver: int) -> list[MailMessage]:
        db = self._session()
        with db.get_bind().connect() as connection:
            rows = connection.execute(text("""
                SELECT id, messageType,
                       CASE
                           WHEN messageType=:creature_type AND sender=0
                               THEN :system_sender
                           ELSE sender
                       END AS sender,
                       receiver, subject, body, deliver_time, expire_time, checked,
                       CASE
                           WHEN messageType=:creature_type AND stationery=:gm_stationery
                               THEN :default_stationery
                           ELSE stationery
                       END AS stationery
                FROM mail WHERE receiver=:receiver AND expire_time>:now ORDER BY id
            """), {
                "receiver": int(receiver),
                "now": int(time.time()),
                "creature_type": MAIL_CREATURE,
                "system_sender": MAIL_SYSTEM_SENDER_ENTRY,
                "gm_stationery": MAIL_STATIONERY_GM,
                "default_stationery": MAIL_STATIONERY_DEFAULT,
            }).mappings().all()
        return [MailMessage(int(r["id"]), int(r["messageType"]), int(r["sender"]),
                            int(r["receiver"]), str(r["subject"] or ""), str(r["body"] or ""),
                            int(r["deliver_time"]), int(r["expire_time"]), int(r["checked"]),
                            int(r["stationery"])) for r in rows]

    def unread_count(self, receiver: int) -> int:
        db = self._session()
        with db.get_bind().connect() as connection:
            return int(connection.execute(text("""
                SELECT COUNT(*) FROM mail
                WHERE receiver=:receiver AND deliver_time<=:now AND expire_time>:now
                  AND (checked & :read_mask)=0
            """), {"receiver": int(receiver), "now": int(time.time()), "read_mask": MAIL_CHECK_READ}).scalar() or 0)

    def mark_read(self, receiver: int, mail_id: int) -> bool:
        db = self._session()
        result = db.execute(text("""
            UPDATE mail SET checked=(checked | :read_mask)
            WHERE id=:id AND receiver=:receiver AND (checked & :read_mask)=0
        """), {"id": int(mail_id), "receiver": int(receiver), "read_mask": MAIL_CHECK_READ})
        db.commit()
        changed = int(result.rowcount or 0) > 0
        if changed:
            Logger.info("[Mail] read id=%s recipient=%s", mail_id, receiver)
            Logger.info("[Mail] unread count changed recipient=%s count=%s", receiver, self.unread_count(receiver))
        return changed

    def delete_mail(self, receiver: int, mail_id: int) -> bool:
        db = self._session()
        result = db.execute(
            text("DELETE FROM mail WHERE id=:id AND receiver=:receiver AND cod=0"),
            {"id": int(mail_id), "receiver": int(receiver)},
        )
        db.commit()
        changed = int(result.rowcount or 0) > 0
        if changed:
            Logger.info("[Mail] deleted id=%s recipient=%s", mail_id, receiver)
            Logger.info(
                "[Mail] unread count changed recipient=%s count=%s",
                receiver,
                self.unread_count(receiver),
            )
        return changed

    def notify_recipient(self, receiver: int) -> None:
        from server.modules.handlers.world.state.runtime import dispatch_responses_to_sessions, iter_in_world_sessions
        targets = [s for s in iter_in_world_sessions() if int(getattr(s, "char_guid", 0) or 0) == int(receiver)]
        if targets:
            for target in targets:
                dispatch_responses_to_sessions(
                    [target],
                    self.live_notification_packets(
                        int(receiver),
                        realm_id=int(getattr(target, "realm_id", 1) or 1),
                    ),
                )
            Logger.info("[Mail] mailbox notification updated recipient=%s unread=%s", receiver, self.unread_count(receiver))

    def notification_packets(self, receiver: int) -> list[tuple[str, bytes]]:
        messages = self.list_mail(receiver)
        unread = sum(1 for mail in messages if not mail.is_read and mail.deliver_time <= int(time.time()))
        Logger.info("[Mail] mailbox notification updated recipient=%s unread=%s", receiver, unread)
        if unread:
            return [("SMSG_RECEIVED_MAIL", build_received_mail_packet())]
        return [("SMSG_MAIL_QUERY_NEXT_TIME_RESULT", build_next_mail_time_packet(messages))]

    def live_notification_packets(self, receiver: int, *, realm_id: int = 1) -> list[tuple[str, bytes]]:
        """Build the canonical live icon update when unread state changes."""
        messages = self.list_mail(receiver)
        unread = sum(1 for mail in messages if not mail.is_read and mail.deliver_time <= int(time.time()))
        if unread:
            packets = [("SMSG_RECEIVED_MAIL", build_received_mail_packet())]
        else:
            packets = [("SMSG_MAIL_QUERY_NEXT_TIME_RESULT", build_next_mail_time_packet(messages))]
        Logger.info("[Mail] mailbox notification updated recipient=%s unread=%s", receiver, unread)
        return packets


_MAIL_SERVICE = MailService()


def get_mail_service() -> MailService:
    return _MAIL_SERVICE
