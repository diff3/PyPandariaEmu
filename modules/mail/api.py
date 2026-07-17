from __future__ import annotations

from server.modules.mail.service import MailMessage, get_mail_service


class MailAPI:
    """Stable gameplay/plugin API; callers never access the mail database directly."""

    @staticmethod
    def send(
        recipient: str | int,
        subject: str,
        body: str,
        *,
        sender_guid: int | None = None,
    ) -> MailMessage:
        if sender_guid is None:
            return get_mail_service().send_system(recipient, subject, body)
        return get_mail_service().send_player(sender_guid, recipient, subject, body)

    @staticmethod
    def send_system(recipient: str | int, subject: str, body: str) -> MailMessage:
        return get_mail_service().send_system(recipient, subject, body)
