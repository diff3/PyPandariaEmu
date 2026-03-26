#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Constants for the world login flow.

This file is intentionally boring.
No logic. No encoding. No sockets.
Only names, order, and expectations.
"""

# Sent immediately after CMSG_PLAYER_LOGIN
PRE_WORLD_PACKETS = (
    "SMSG_SET_DUNGEON_DIFFICULTY",
)

# Sent after the client acknowledges loading screen
PRE_LOADING_PACKETS = (
    "SMSG_CLIENTCACHE_VERSION",
    "SMSG_ACCOUNT_DATA_TIMES",
    "SMSG_TUTORIAL_FLAGS",
    "SMSG_FEATURE_SYSTEM_STATUS",
    "SMSG_LOGIN_VERIFY_WORLD",
    "SMSG_LOGIN_SET_TIME_SPEED",
    "SMSG_MOTD",
    "SMSG_PVP_SEASON",
    "SMSG_SET_TIME_ZONE_INFORMATION",
    "SMSG_HOTFIX_NOTIFY_BLOB",
    "SMSG_CONTACT_LIST",
    "SMSG_BIND_POINT_UPDATE",
    "SMSG_UPDATE_TALENT_DATA",
    "SMSG_WORLD_SERVER_INFO",
    "SMSG_SEND_KNOWN_SPELLS",
    "SMSG_SEND_UNLEARN_SPELLS",
    "SMSG_UPDATE_ACTION_BUTTONS",
    "SMSG_INITIALIZE_FACTIONS",
    "SMSG_ALL_ACHIEVEMENT_DATA",
    "SMSG_LOAD_EQUIPMENT_SET",
    "SMSG_SET_FORCED_REACTIONS",
    "SMSG_SETUP_CURRENCY",
)

RACES_MOP = [
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    22,
    24,
    25,
    26,
]

CLASSES_MOP = [
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
]

ONE_SHOT_PACKETS = {
    "SMSG_LOGIN_VERIFY_WORLD",
    "SMSG_UPDATE_OBJECT",
}

EXPECTED_POST_LOGIN_CMSG = {
    "CMSG_LOADING_SCREEN_NOTIFY",
    "CMSG_TIME_SYNC_RESPONSE",
    "CMSG_CHAT_JOIN_CHANNEL",
}

LOGIN_FEATURE_FLAGS = {
    "enable_movement": False,
    "enable_vehicles": False,
    "enable_battle_pets": True,
    "enable_guilds": False,
    "enable_combat": False,
}

DEFAULT_PLAYER_STATE = {
    "walk_speed": 2.5,
    "run_speed": 7.0,
    "run_back_speed": 4.5,
    "swim_speed": 4.5,
    "swim_back_speed": 4.5,
    "fly_speed": 7.0,
    "fly_back_speed": 4.5,
    "turn_speed": 3.14159,
    "pitch_speed": 3.14159,
}

IDEMPOTENT_PACKETS = {
    "SMSG_TIME_SYNC_REQUEST",
    "SMSG_UPDATE_WORLD_STATE",
}

OPTIONAL_PACKETS = {
    "SMSG_SPELL_GO",
    "SMSG_SPELL_EXECUTE_LOG",
    "SMSG_ON_MONSTER_MOVE",
}
