#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import random
from typing import Optional

from DSL.modules.EncoderHandler import EncoderHandler
from shared.Logger import Logger
from server.modules.handlers.world.characters.characters import preload_cache as preload_character_cache
from server.session.runtime import session
from server.modules.handlers.world.opcodes import login as login_handlers
from server.modules.handlers.world.opcodes.movement import (
    _save_current_position_like_command as save_current_position_like_command,
)
from server.modules.handlers.world.state.global_state import global_state
from server.modules.handlers.world.state.runtime import broadcast_player_remove


def get_auth_challenge() -> Optional[tuple[str, bytes]]:
    fields = {
        "uint16_0": 0,
        "uint32_zeros": [random.getrandbits(32) for _ in range(8)],
        "uint8_value": 1,
        "seed": random.getrandbits(32),
    }
    payload = EncoderHandler.encode_packet("SMSG_AUTH_CHALLENGE", fields)
    if len(payload) != 39:
        raise ValueError(
            f"SMSG_AUTH_CHALLENGE payload size is {len(payload)}, expected 39"
        )
    return "SMSG_AUTH_CHALLENGE", payload


def reset_state() -> None:
    region = getattr(session, "region", None)
    if region is not None:
        region.players.discard(session)
    state = getattr(session, "global_state", None)
    if state is not None:
        state.chat_channels.setdefault("world", set()).discard(session)
        getattr(state, "sessions", set()).discard(session)
    session.region = None
    session.global_state = global_state
    session.account_id = None
    session.account_name = None
    session.realm_id = None
    session.player_guid = None
    session.world_guid = None
    session.char_guid = None
    session.time_sync_seq = 0
    session.last_position_save_at = 0.0
    session.position_dirty = False
    session.persist_map_id = 0
    session.persist_zone = 0
    session.persist_instance_id = 0
    session.persist_x = 0.0
    session.persist_y = 0.0
    session.persist_z = 0.0
    session.persist_orientation = 0.0
    session.last_saved_map_id = 0
    session.last_saved_zone = 0
    session.last_saved_instance_id = 0
    session.last_saved_x = 0.0
    session.last_saved_y = 0.0
    session.last_saved_z = 0.0
    session.last_saved_orientation = 0.0
    session.visible_guids.clear()
    login_handlers._reset_login_flow_state(session)


def preload_cache() -> None:
    try:
        preload_character_cache()
    except Exception as exc:
        Logger.warning(f"[WorldHandlers] preload_cache failed: {exc}")


def handle_disconnect() -> None:
    handle_disconnect_session(session)


def handle_disconnect_session(target_session) -> None:
    if target_session is None or bool(getattr(target_session, "_disconnect_handled", False)):
        return

    target_session._disconnect_handled = True
    broadcast_player_remove(target_session)
    save_current_position_like_command(target_session, reason="disconnect", online=0, force=True)
    region = getattr(target_session, "region", None)
    if region is not None:
        region.players.discard(target_session)
    state = getattr(target_session, "global_state", None)
    if state is not None:
        state.chat_channels.setdefault("world", set()).discard(target_session)
        getattr(state, "sessions", set()).discard(target_session)
    target_session.region = None
    target_session.send_response = None
    target_session.visible_guids.clear()
    login_handlers._reset_login_flow_state(target_session)
