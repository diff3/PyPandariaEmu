from __future__ import annotations

from types import SimpleNamespace

from server.modules.mail.notification_runtime import MailNotificationService


class FakeMailService:
    def __init__(self):
        self.unread = 0
        self.packet_calls = []

    def unread_count(self, receiver):
        return self.unread

    def live_notification_packets(self, receiver, *, realm_id=1):
        self.packet_calls.append((receiver, realm_id, self.unread))
        return [("MAIL_REFRESH", bytes([self.unread]))]


def test_online_mail_notification_is_emitted_only_when_unread_state_changes(monkeypatch):
    mail = FakeMailService()
    session = SimpleNamespace(char_guid=7, realm_id=2)
    sent = []
    monkeypatch.setattr(
        "server.modules.handlers.world.state.runtime.iter_in_world_sessions",
        lambda: [session],
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.state.runtime.dispatch_responses_to_sessions",
        lambda targets, packets: sent.append((targets, packets)),
    )
    runtime = MailNotificationService(mail_service=mail)

    assert runtime.tick_once() == 0
    mail.unread = 1
    assert runtime.tick_once() == 1
    assert runtime.tick_once() == 0
    mail.unread = 0
    assert runtime.tick_once() == 1

    assert mail.packet_calls == [(7, 2, 1), (7, 2, 0)]
    assert [packets for _targets, packets in sent] == [
        [("MAIL_REFRESH", b"\x01")],
        [("MAIL_REFRESH", b"\x00")],
    ]


def test_reconnected_session_receives_existing_unread_notification(monkeypatch):
    mail = FakeMailService()
    mail.unread = 1
    sessions = [SimpleNamespace(char_guid=7, realm_id=1)]
    sent = []
    monkeypatch.setattr(
        "server.modules.handlers.world.state.runtime.iter_in_world_sessions",
        lambda: list(sessions),
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.state.runtime.dispatch_responses_to_sessions",
        lambda targets, packets: sent.append((targets, packets)),
    )
    runtime = MailNotificationService(mail_service=mail)

    assert runtime.tick_once() == 1
    sessions.clear()
    assert runtime.tick_once() == 0
    sessions.append(SimpleNamespace(char_guid=7, realm_id=1))
    assert runtime.tick_once() == 1
    assert len(sent) == 2
