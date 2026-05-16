#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Title opcode handlers."""

from __future__ import annotations

import struct

from shared.Logger import Logger
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.title_service import (
    resolve_title_bit,
    select_known_title,
)
from server.modules.protocol.PacketContext import PacketContext


@register("CMSG_SET_TITLE")
def handle_set_title(session, ctx: PacketContext):
    """Apply a client-selected title if the character already knows it."""
    payload = bytes(getattr(ctx, "payload", b"") or b"")
    if len(payload) < 4:
        Logger.warning("[Title] CMSG_SET_TITLE too short len=%s", len(payload))
        return 0, None

    raw_title = int(struct.unpack_from("<i", payload, 0)[0])
    bit_index = resolve_title_bit(raw_title) if raw_title > 0 else 0
    responses = select_known_title(session, bit_index)
    Logger.info(
        "[Title] CMSG_SET_TITLE raw=%s bit=%s accepted=%s chosen=%s",
        raw_title,
        bit_index,
        bool(responses or bit_index <= 0),
        int(getattr(session, "chosen_title", 0) or 0),
    )
    return 0, responses or None
