#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal achievement opcode handlers."""

from __future__ import annotations

from shared.Logger import Logger
from server.modules.handlers.world.dispatcher import register
from server.modules.protocol.PacketContext import PacketContext


@register("CMSG_GUILD_SET_ACHIEVEMENT_TRACKING")
def handle_guild_set_achievement_tracking(session, ctx: PacketContext):
    """Accept guild achievement tracking updates without side effects."""
    Logger.info(
        "[Achievements] CMSG_GUILD_SET_ACHIEVEMENT_TRACKING len=%s",
        len(bytes(getattr(ctx, "payload", b"") or b"")),
    )
    return 0, None


@register("CMSG_QUERY_INSPECT_ACHIEVEMENTS")
def handle_query_inspect_achievements(session, ctx: PacketContext):
    """Acknowledge inspect achievement queries until inspect data exists."""
    Logger.info(
        "[Achievements] CMSG_QUERY_INSPECT_ACHIEVEMENTS len=%s",
        len(bytes(getattr(ctx, "payload", b"") or b"")),
    )
    return 0, None


@register("CMSG_SET_HIDE_ACHIEVEMENTS")
def handle_set_hide_achievements(session, ctx: PacketContext):
    """Store the client hide-achievements preference for this session."""
    payload = bytes(getattr(ctx, "payload", b"") or b"")
    session.hide_achievements = bool(payload[0]) if payload else False
    Logger.info(
        "[Achievements] CMSG_SET_HIDE_ACHIEVEMENTS hidden=%s len=%s",
        int(bool(getattr(session, "hide_achievements", False))),
        len(payload),
    )
    return 0, None
