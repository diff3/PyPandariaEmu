from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from DSL.modules.bitsHandler import BitWriter

from server.modules.handlers.world.opcodes.mail import parse_send_mail_request
from server.modules.mail.api import MailAPI
from server.modules.mail.service import (
    MailService,
    build_mail_list_packet,
    build_next_mail_time_packet,
    build_received_mail_packet,
)
from server.modules.opcodes.WorldOpcodes import WORLD_SERVER_OPCODES


@pytest.fixture()
def mail_service(monkeypatch):
    engine = create_engine("sqlite+pysqlite:///:memory:")
    db = Session(engine)
    db.execute(text("""
        CREATE TABLE characters (
            guid INTEGER PRIMARY KEY, realm INTEGER NOT NULL, name TEXT NOT NULL,
            deleteDate INTEGER NULL
        )
    """))
    db.execute(text("""
        CREATE TABLE mail (
            id INTEGER PRIMARY KEY, messageType INTEGER NOT NULL, stationery INTEGER NOT NULL,
            mailTemplateId INTEGER NOT NULL, sender INTEGER NOT NULL, receiver INTEGER NOT NULL,
            subject TEXT, body TEXT, has_items INTEGER NOT NULL, expire_time INTEGER NOT NULL,
            deliver_time INTEGER NOT NULL, money INTEGER NOT NULL, cod INTEGER NOT NULL,
            checked INTEGER NOT NULL
        )
    """))
    db.execute(text("INSERT INTO characters VALUES (1, 1, 'Sender', NULL), (2, 1, 'Receiver', NULL)"))
    db.commit()
    service = MailService()
    monkeypatch.setattr(service, "_session", lambda: db)
    monkeypatch.setattr(service, "notify_recipient", lambda _receiver: None)
    return service


def test_player_mail_persists_and_tracks_unread(mail_service):
    created = mail_service.send_player(1, "Receiver", "Hello", "Persisted body")

    assert created.sender == 1
    assert mail_service.unread_count(2) == 1
    loaded = mail_service.list_mail(2)
    assert [(mail.subject, mail.body, mail.is_read) for mail in loaded] == [
        ("Hello", "Persisted body", False)
    ]


def test_server_can_send_mail_without_player_session(mail_service):
    created = mail_service.send_system("Receiver", "Welcome", "From the server")

    assert created.sender == 0
    assert created.message_type == 3
    assert mail_service.list_mail(2)[0].subject == "Welcome"


def test_marking_last_mail_read_clears_unread_notification(mail_service):
    created = mail_service.send_system(2, "Notice", "Read me")
    assert mail_service.mark_read(2, created.id) is True
    assert mail_service.mark_read(2, created.id) is False
    assert mail_service.unread_count(2) == 0
    packet = build_next_mail_time_packet(mail_service.list_mail(2))
    assert packet[-4:] == struct.pack("<f", -1.0)


def test_mail_packets_serialize_canonical_minimal_fields(mail_service):
    created = mail_service.send_player(1, 2, "Subject", "Body")

    assert build_received_mail_packet() == struct.pack("<f", 0.0)
    packet = build_mail_list_packet([created], realm_id=1, now=created.deliver_time)
    assert struct.unpack_from("<I", packet)[0] == 1
    assert b"Subject" in packet
    assert b"Body" in packet


def test_mail_api_works_without_player_session(mail_service, monkeypatch):
    monkeypatch.setattr("server.modules.mail.api.get_mail_service", lambda: mail_service)

    created = MailAPI.send("Receiver", "API", "Message")

    assert created.receiver == 2
    assert mail_service.unread_count(2) == 1


def test_recipient_notification_is_sent_to_online_session(mail_service, monkeypatch):
    sent = []
    online = SimpleNamespace(char_guid=2, send_response=lambda packets: sent.extend(packets))
    monkeypatch.setattr(
        "server.modules.handlers.world.state.runtime.iter_in_world_sessions",
        lambda: [online],
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.state.runtime.dispatch_responses_to_sessions",
        lambda targets, packets: [target.send_response(packets) for target in targets],
    )
    monkeypatch.setattr(
        mail_service,
        "notify_recipient",
        MailService.notify_recipient.__get__(mail_service, MailService),
    )

    mail_service.send_system(2, "Online", "Notification")

    assert sent == [("SMSG_RECEIVED_MAIL", struct.pack("<f", 0.0))]


def test_skyfire_send_mail_request_decodes_text_mail():
    receiver = b"Receiver"
    subject = b"Subject"
    body = b"Body"
    bits = BitWriter()
    bits.write_bits(0, 4)  # mailbox guid bytes 0, 6, 4, 1
    bits.write_bits(len(body), 11)
    bits.write_bits(0, 1)  # mailbox byte 3
    bits.write_bits(len(receiver), 9)
    bits.write_bits(0, 2)  # mailbox bytes 7, 5
    bits.write_bits(0, 5)  # item count
    bits.write_bits(len(subject), 9)
    bits.write_bits(0, 1)  # mailbox byte 2
    bits.flush_to_byte()
    payload = struct.pack("<IIQQ", 0, 0, 0, 0) + bytes(bits.buffer) + body + subject + receiver

    decoded = parse_send_mail_request(payload)

    assert decoded["receiver"] == "Receiver"
    assert decoded["subject"] == "Subject"
    assert decoded["body"] == "Body"
    assert decoded["item_count"] == 0


def test_next_mail_time_result_is_registered_as_server_opcode():
    assert WORLD_SERVER_OPCODES[0x089B] == "SMSG_MAIL_QUERY_NEXT_TIME_RESULT"
