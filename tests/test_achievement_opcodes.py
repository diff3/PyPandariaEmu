#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from types import SimpleNamespace

from server.modules.handlers.world.dispatcher import HANDLERS
from server.modules.handlers.world.opcodes import achievements


def test_achievement_handlers_are_registered():
    assert HANDLERS["CMSG_GUILD_SET_ACHIEVEMENT_TRACKING"] is (
        achievements.handle_guild_set_achievement_tracking
    )
    assert HANDLERS["CMSG_QUERY_INSPECT_ACHIEVEMENTS"] is (
        achievements.handle_query_inspect_achievements
    )
    assert HANDLERS["CMSG_SET_HIDE_ACHIEVEMENTS"] is achievements.handle_set_hide_achievements


def test_set_hide_achievements_updates_session_flag(monkeypatch):
    monkeypatch.setattr(achievements, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    session = SimpleNamespace()
    ctx = SimpleNamespace(payload=b"\x01")

    status, responses = achievements.handle_set_hide_achievements(session, ctx)

    assert status == 0
    assert responses is None
    assert session.hide_achievements is True
