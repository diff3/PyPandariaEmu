#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WorldLogin packet bundle definitions.

This module only defines packet groups as ordered bundles of
``(opcode_name, payload)`` tuples. It does not mutate session state,
drive phase transitions, or emit packets directly.
"""

"""
Login flow overview (MoP 5.4):

AUTH_SESSION
    -> CHAR_SCREEN_PACKETS

ENUM_CHARACTERS

PLAYER_LOGIN
    -> PLAYER_LOGIN_PACKETS

LOADING_SCREEN_NOTIFY(show=1)

LOADING_SCREEN_NOTIFY(show=0)
    -> PRE_UPDATE_OBJECT_PACKETS
    -> UPDATE_OBJECT replay sequence
    -> POST_UPDATE_OBJECT_PACKETS
    -> WORLD_BOOTSTRAP_PACKETS

CMSG_SET_ACTIVE_MOVER
    -> login_state = IN_WORLD

This module only defines packet ordering.
WorldHandlers drives the actual state transitions.
"""

from server.modules.handlers.worldLogin.context import WorldLoginContext
from server.modules.handlers.worldLogin.packets import build_login_packet
from shared.Logger import Logger


def build_packet_bundle(
    ctx: WorldLoginContext,
    opcode_names: tuple[str, ...],
) -> list[tuple[str, bytes]]:
    packets: list[tuple[str, bytes]] = []

    for opcode_name in opcode_names:
        payload = build_login_packet(opcode_name, ctx)
        if payload is None:
            Logger.warning(
                f"[WorldLogin] missing packet builder for {opcode_name}"
            )
            continue
        packets.append((opcode_name, payload))

    return packets

CHAR_SCREEN_PACKETS = (
    "SMSG_AUTH_RESPONSE",
    "SMSG_CLIENTCACHE_VERSION",
    "SMSG_TUTORIAL_FLAGS",
    "SMSG_SET_TIME_ZONE_INFORMATION",
)

PLAYER_LOGIN_PACKETS = (
    "SMSG_SET_DUNGEON_DIFFICULTY",
)

PRE_UPDATE_OBJECT_PACKETS = (
    "SMSG_CLIENTCACHE_VERSION",
    # "SMSG_ACCOUNT_DATA_TIMES",
    "SMSG_TUTORIAL_FLAGS",
    "SMSG_FEATURE_SYSTEM_STATUS",
    "SMSG_MOTD",
    "SMSG_SEND_KNOWN_SPELLS",
    "SMSG_SEND_UNLEARN_SPELLS",
    "SMSG_UPDATE_ACTION_BUTTONS",
    "SMSG_LOGIN_VERIFY_WORLD",
    "SMSG_LOGIN_SET_TIME_SPEED",
    "SMSG_BIND_POINT_UPDATE",
)

POST_UPDATE_OBJECT_PACKETS = (
    # Reserved for world-enter acknowledgements that must be sent
    # after the spawn batch and before ACTIVE_MOVER/TIME_SYNC.
    # "SMSG_LOGIN_COMPLETE",
)

POST_LOADING_PACKETS = (
    # Disabled for minimal UPDATE_OBJECT debugging:
    # "SMSG_CLIENTCACHE_VERSION",
    # "SMSG_ACCOUNT_DATA_TIMES",
    # "SMSG_FEATURE_SYSTEM_STATUS",
    # "SMSG_TUTORIAL_FLAGS",
    # "SMSG_MOTD",
    # "SMSG_PVP_SEASON",
    # "SMSG_SET_TIME_ZONE_INFORMATION",
    # "SMSG_CONTACT_LIST",
    # "SMSG_BIND_POINT_UPDATE",
    # "SMSG_UPDATE_TALENT_DATA",
    # "SMSG_WORLD_SERVER_INFO",
    # "SMSG_SEND_KNOWN_SPELLS",
    # "SMSG_SEND_UNLEARN_SPELLS",
    # "SMSG_UPDATE_ACTION_BUTTONS",
    # "SMSG_INITIALIZE_FACTIONS",
    # "SMSG_ALL_ACHIEVEMENT_DATA",
    # "SMSG_LOAD_EQUIPMENT_SET",
    # "SMSG_LOGIN_SET_TIME_SPEED",
    # "SMSG_SET_FORCED_REACTIONS",
    # "SMSG_SETUP_CURRENCY",
)

WORLD_BOOTSTRAP_PACKETS = (
    "SMSG_MOVE_SET_ACTIVE_MOVER",
    "SMSG_TIME_SYNC_REQUEST",

    # Disabled for minimal UPDATE_OBJECT debugging:
    # "SMSG_PHASE_SHIFT_CHANGE",
    # "SMSG_INIT_WORLD_STATES",
    # "SMSG_UPDATE_WORLD_STATE",
    # "SMSG_WEATHER",
    # "SMSG_QUERY_TIME_RESPONSE",
    # "SMSG_UI_TIME",
    # "SMSG_LOAD_CUF_PROFILES",
    # "SMSG_BATTLE_PET_JOURNAL",
    # "SMSG_BATTLE_PET_JOURNAL_LOCK_ACQUIRED",
    # "SMSG_SPELL_GO",
    # "SMSG_UPDATE_ACCOUNT_DATA",
    # "SMSG_HOTFIX_NOTIFY_BLOB",
)


def build_char_screen_packets(ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    return build_packet_bundle(ctx, CHAR_SCREEN_PACKETS)


def build_player_login_packets(ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    return build_packet_bundle(ctx, PLAYER_LOGIN_PACKETS)


def build_pre_update_object_packets(ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    return build_packet_bundle(ctx, PRE_UPDATE_OBJECT_PACKETS)


def build_post_update_object_packets(ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    return build_packet_bundle(ctx, POST_UPDATE_OBJECT_PACKETS)


def build_post_loading_packets(ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    return build_packet_bundle(ctx, POST_LOADING_PACKETS)


def build_world_bootstrap_packets(ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    return build_packet_bundle(ctx, WORLD_BOOTSTRAP_PACKETS)
