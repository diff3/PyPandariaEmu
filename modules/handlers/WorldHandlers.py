#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""World handler entrypoint plus compatibility wrapper surface."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from server.modules.protocol.PacketContext import PacketContext
from server.modules.handlers.world.characters.characters import (
    handle_CMSG_CHAR_CREATE,
    handle_CMSG_CHAR_DELETE,
    handle_CMSG_REORDER_CHARACTERS,
)
from server.session.runtime import session
from server.modules.handlers.world.dispatcher import HANDLERS, dispatch
from server.modules.handlers.world.runtime.lifecycle import (
    get_auth_challenge,
    handle_disconnect,
    preload_cache,
    reset_state,
)

from server.modules.handlers.world.opcodes import chat as _chat  # noqa: F401
from server.modules.handlers.world.opcodes import entities as _entities  # noqa: F401
from server.modules.handlers.world.opcodes import inventory as _inventory  # noqa: F401
from server.modules.handlers.world.opcodes import login as _login  # noqa: F401
from server.modules.handlers.world.opcodes import misc as _misc  # noqa: F401
from server.modules.handlers.world.opcodes import movement as _movement  # noqa: F401
from server.modules.handlers.world.opcodes import spells as _spells  # noqa: F401
from server.modules.handlers.world.opcodes import chat as chat_handlers
from server.modules.handlers.world.opcodes import entities as entities_handlers
from server.modules.handlers.world.opcodes import login as login_handlers
from server.modules.handlers.world.opcodes import misc as misc_handlers
from server.modules.handlers.world.opcodes import movement as movement_handlers
from server.modules.handlers.world.opcodes import spells as spells_handlers

BASE_DIR = Path(__file__).resolve().parents[3]


def handle_packet(ctx: PacketContext):
    """Dispatch one PacketContext through the world dispatcher."""
    return dispatch(ctx.session, ctx.name, ctx)


opcode_handlers = {
    opcode: handle_packet
    for opcode in HANDLERS.keys()
}


def handle_CMSG_PING(ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    return misc_handlers.handle_ping(ctx.session or session, ctx)


def handle_CMSG_LOGOUT_REQUEST(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return misc_handlers.handle_logout_request(ctx.session or session, ctx)


def handle_CMSG_AUTH_SESSION(ctx: PacketContext):
    return login_handlers.handle_auth_session(ctx.session or session, ctx)


def handle_CMSG_ENUM_CHARACTERS(ctx: PacketContext):
    return login_handlers.handle_enum_characters(ctx.session or session, ctx)


def handle_CMSG_PLAYER_LOGIN(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return login_handlers.handle_player_login(ctx.session or session, ctx)


def handle_CMSG_LOADING_SCREEN_NOTIFY(ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    return login_handlers.handle_loading_screen_notify(ctx.session or session, ctx)


def handle_CMSG_TIME_SYNC_RESPONSE(ctx: PacketContext):
    return misc_handlers.handle_time_sync_response(ctx.session or session, ctx)


def handle_CMSG_DISCARDED_TIME_SYNC_ACKS(ctx: PacketContext):
    return misc_handlers.handle_discarded_time_sync_acks(ctx.session or session, ctx)


def handle_CMSG_OBJECT_UPDATE_FAILED(ctx: PacketContext):
    return entities_handlers.handle_object_update_failed(ctx.session or session, ctx)


def handle_CMSG_CREATURE_QUERY(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return entities_handlers.handle_creature_query(ctx.session or session, ctx)


def handle_CMSG_REQUEST_ACCOUNT_DATA(ctx: PacketContext):
    return misc_handlers.handle_request_account_data(ctx.session or session, ctx)


def handle_CMSG_REQUEST_CEMETERY_LIST(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return misc_handlers.handle_request_cemetery_list(ctx.session or session, ctx)


def handle_CMSG_REQUEST_PLAYED_TIME(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return misc_handlers.handle_request_played_time(ctx.session or session, ctx)


def handle_CMSG_QUERY_TIME(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return misc_handlers.handle_query_time(ctx.session or session, ctx)


def handle_CMSG_REQUEST_FORCED_REACTIONS(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return misc_handlers.handle_request_forced_reactions(ctx.session or session, ctx)


def handle_CMSG_WORLD_STATE_UI_TIMER_UPDATE(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return misc_handlers.handle_world_state_ui_timer_update(ctx.session or session, ctx)


def handle_CMSG_NAME_QUERY(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return entities_handlers.handle_name_query(ctx.session or session, ctx)


def handle_CMSG_QUEST_GIVER_STATUS_QUERY(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return entities_handlers.handle_quest_giver_status_query(ctx.session or session, ctx)


def build_query_player_name_response(guid: int) -> bytes:
    return entities_handlers.build_query_player_name_response(session, guid)


def handle_CMSG_MESSAGECHAT_SAY(ctx: PacketContext):
    return chat_handlers.handle_messagechat_say(ctx.session or session, ctx)


def handle_CMSG_MESSAGECHAT_YELL(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return chat_handlers.handle_messagechat_yell(ctx.session or session, ctx)


def handle_CMSG_MESSAGECHAT_WHISPER(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return chat_handlers.handle_messagechat_whisper(ctx.session or session, ctx)


def handle_CMSG_SEND_TEXT_EMOTE(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return chat_handlers.handle_send_text_emote(ctx.session or session, ctx)


def handle_CMSG_EMOTE(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return chat_handlers.handle_emote(ctx.session or session, ctx)


def handle_CMSG_CHAT_JOIN_CHANNEL(
    ctx: PacketContext,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    return chat_handlers.handle_chat_join_channel(ctx.session or session, ctx)


def handle_CMSG_REQUEST_HOTFIX(ctx: PacketContext):
    return misc_handlers.handle_request_hotfix(ctx.session or session, ctx)


def handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES(ctx: PacketContext):
    return misc_handlers.handle_ready_for_account_data_times(ctx.session or session, ctx)


def handle_CMSG_UPDATE_ACCOUNT_DATA(ctx: PacketContext):
    return misc_handlers.handle_update_account_data(ctx.session or session, ctx)


def handle_CMSG_SET_ACTIVE_MOVER(ctx: PacketContext):
    return login_handlers.handle_set_active_mover(ctx.session or session, ctx)


def handle_CMSG_CAST_SPELL(ctx: PacketContext):
    return spells_handlers.handle_cast_spell(ctx.session or session, ctx)


def handle_CMSG_CANCEL_AURA(ctx: PacketContext):
    return spells_handlers.handle_cancel_aura(ctx.session or session, ctx)


def handle_CMSG_CANCEL_MOUNT_AURA(ctx: PacketContext):
    return spells_handlers.handle_cancel_mount_aura(ctx.session or session, ctx)


def handle_movement_packet(ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    return movement_handlers.handle_movement_packet(ctx.session or session, ctx)


def handle_MSG_MOVE_SET_FACING(ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    return movement_handlers.handle_msg_move_set_facing(ctx.session or session, ctx)
