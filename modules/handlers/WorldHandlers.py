#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Thin world opcode router.

Movement and spell handlers are extracted into dedicated world.handler modules.
The remaining opcode domains are registered through small wrapper modules that
delegate to the legacy implementation until later extraction phases.
"""

from __future__ import annotations

from pathlib import Path

from server.modules.PacketContext import PacketContext
from server.modules.handlers import world_legacy as legacy
from world.dispatcher import HANDLERS, dispatch

from world.handlers import chat as _chat  # noqa: F401
from world.handlers import entities as _entities  # noqa: F401
from world.handlers import inventory as _inventory  # noqa: F401
from world.handlers import login as _login  # noqa: F401
from world.handlers import misc as _misc  # noqa: F401
from world.handlers import movement as _movement  # noqa: F401
from world.handlers import spells as _spells  # noqa: F401

BASE_DIR = Path(__file__).resolve().parents[3]


def handle_packet(ctx: PacketContext):
    """Dispatch one PacketContext through the world dispatcher."""
    return dispatch(ctx.session, ctx.name, ctx)


opcode_handlers = {
    opcode: handle_packet
    for opcode in HANDLERS.keys()
}

get_auth_challenge = legacy.get_auth_challenge
reset_state = legacy.reset_state
preload_cache = legacy.preload_cache
handle_disconnect = legacy.handle_disconnect
