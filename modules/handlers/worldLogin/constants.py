#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Constants for the World Login flow.

This file is intentionally boring.
No logic. No encoding. No sockets.
Only names, order, and expectations.

Think of this as the *specification* of the login process.

NOTE:
LOGIN_PACKET_SEQUENCE is intentionally duplicated for readability.
Canonical definitions live in PRE_* blocks.
"""

# ------------------------------------------------------------
# Packet order – what the client expects, in sequence
# ------------------------------------------------------------

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

# Sent after the world is considered fully entered

# Playable races in MoP (5.4.8)
RACES_MOP = [
    1,   # Human
    2,   # Orc
    3,   # Dwarf
    4,   # Night Elf
    5,   # Undead
    6,   # Tauren
    7,   # Gnome
    8,   # Troll
    9,   # Goblin
    10,  # Blood Elf
    11,  # Draenei
    22,  # Worgen
    24,  # Pandaren Neutral
    25,  # Pandaren Alliance
    26,  # Pandaren Horde
]

# Playable classes in MoP
CLASSES_MOP = [
    1,   # Warrior
    2,   # Paladin
    3,   # Hunter
    4,   # Rogue
    5,   # Priest
    6,   # Death Knight
    7,   # Shaman
    8,   # Mage
    9,   # Warlock
    10,  # Monk (MoP)
    11,  # Druid
]

# ------------------------------------------------------------
# One-shot packets (must never be sent twice)
# ------------------------------------------------------------

ONE_SHOT_PACKETS = {
    "SMSG_LOGIN_VERIFY_WORLD",
    "SMSG_UPDATE_OBJECT",
}

# ------------------------------------------------------------
# Client packets expected during / after login
# ------------------------------------------------------------

EXPECTED_POST_LOGIN_CMSG = {
    "CMSG_LOADING_SCREEN_NOTIFY",
    "CMSG_TIME_SYNC_RESPONSE",
    "CMSG_CHAT_JOIN_CHANNEL",
}

# ------------------------------------------------------------
# Feature profile (intentional simplifications)
# ------------------------------------------------------------

LOGIN_FEATURE_FLAGS = {
    "enable_movement": False,      # Player stands still
    "enable_vehicles": False,
    "enable_battle_pets": True,    # Client expects these packets
    "enable_guilds": False,
    "enable_combat": False,
}

# ------------------------------------------------------------
# Default player state used during login
# (Server memory defaults, not DSL definitions)
# ------------------------------------------------------------

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

# ------------------------------------------------------------
# Debug / sanity helpers
# ------------------------------------------------------------

# Packets that are known to be noisy but harmless if repeated
IDEMPOTENT_PACKETS = {
    "SMSG_TIME_SYNC_REQUEST",
    "SMSG_UPDATE_WORLD_STATE",
}

# Packets that are often missing in minimal servers but tolerated
OPTIONAL_PACKETS = {
    "SMSG_SPELL_GO",
    "SMSG_SPELL_EXECUTE_LOG",
    "SMSG_ON_MONSTER_MOVE",
}
