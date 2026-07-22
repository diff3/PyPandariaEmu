#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import threading

from shared.Logger import Logger
from server.modules.mail.service import get_mail_service


MAIL_NOTIFICATION_INTERVAL_SECONDS = 2.0


class MailNotificationService:
    """World-owned cadence for detecting mail created outside WorldServer."""

    def __init__(self, *, mail_service=None, interval_seconds: float = MAIL_NOTIFICATION_INTERVAL_SECONDS):
        self._mail_service = mail_service or get_mail_service()
        self._interval_seconds = float(interval_seconds)
        self._last_unread: dict[tuple[int, int], int] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def tick_once(self) -> int:
        from server.modules.handlers.world.state.runtime import (
            dispatch_responses_to_sessions,
            iter_in_world_sessions,
        )

        active_keys: set[tuple[int, int]] = set()
        notifications = 0
        for session in iter_in_world_sessions():
            receiver = int(getattr(session, "char_guid", 0) or 0)
            if receiver <= 0:
                continue
            key = (id(session), receiver)
            active_keys.add(key)
            try:
                unread = self._mail_service.unread_count(receiver)
                previous = self._last_unread.get(key)
                self._last_unread[key] = unread
                if unread == previous or (previous is None and unread == 0):
                    continue
                packets = self._mail_service.live_notification_packets(
                    receiver,
                    realm_id=int(getattr(session, "realm_id", 1) or 1),
                )
                dispatch_responses_to_sessions([session], packets)
                notifications += 1
            except Exception as exc:
                Logger.warning(
                    "[Mail] notification check failed recipient=%s err=%s",
                    receiver,
                    exc,
                )

        for key in set(self._last_unread) - active_keys:
            self._last_unread.pop(key, None)
        return notifications

    def _run(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            self.tick_once()

    def start(self) -> bool:
        if self._thread is not None and self._thread.is_alive():
            return True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="mail-notification-service",
        )
        self._thread.start()
        Logger.info(
            "[Mail] notification service started interval=%.1fs",
            self._interval_seconds,
        )
        return True

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        self._last_unread.clear()
        Logger.info("[Mail] notification service stopped")


_MAIL_NOTIFICATION_SERVICE = MailNotificationService()


def get_mail_notification_service() -> MailNotificationService:
    return _MAIL_NOTIFICATION_SERVICE


def start_mail_notification_service() -> bool:
    return _MAIL_NOTIFICATION_SERVICE.start()


def stop_mail_notification_service() -> None:
    _MAIL_NOTIFICATION_SERVICE.stop()
