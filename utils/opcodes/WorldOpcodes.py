#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from enum import IntEnum


@dataclass
class WorldClientPktHeader:
    size: int
    cmd: int


class WorldOpcodes(IntEnum):
    CMSG_ACCEPT_LEVEL_GRANT = 0x02FB
    CMSG_ACCEPT_TRADE = 0x144D
    CMSG_ACTIVATE_TAXI = 0x03C9
    CMSG_ACTIVATE_TAXI_EXPRESS = 0x06FB
    CMSG_ADDON_REGISTERED_PREFIXES = 0x040E
    CMSG_ADD_FRIEND = 0x09A6
    CMSG_ADD_IGNORE = 0x0D20
    CMSG_ALTER_APPEARANCE = 0x07F0
    CMSG_AREATRIGGER = 0x1C44
    CMSG_AREA_SPIRIT_HEALER_QUERY = 0x03F1
    CMSG_AREA_SPIRIT_HEALER_QUEUE = 0x12D8
    CMSG_ATTACKSTOP = 0x0345
    CMSG_ATTACKSWING = 0x02E7
    CMSG_AUCTION_HELLO_REQUEST = 0x0379
    CMSG_AUCTION_LIST_BIDDER_ITEMS = 0x12D0
    CMSG_AUCTION_LIST_ITEMS = 0x02EA
    CMSG_AUCTION_LIST_OWNER_ITEMS = 0x0361
    CMSG_AUCTION_PLACE_BID = 0x03C8
    CMSG_AUCTION_REMOVE_ITEM = 0x0259
    CMSG_AUCTION_SELL_ITEM = 0x02EB
    CMSG_AUTH_CONTINUED_SESSION = 0x0F49
    CMSG_AUTH_SESSION = 0x00B2
    CMSG_AUTOBANK_ITEM = 0x066D
    CMSG_AUTOEQUIP_ITEM = 0x025F
    CMSG_AUTOEQUIP_ITEM_SLOT = 0x036F
    CMSG_AUTOSTORE_BAG_ITEM = 0x067C
    CMSG_AUTOSTORE_BANK_ITEM = 0x02CF
    CMSG_AUTOSTORE_LOOT_ITEM = 0x0354
    CMSG_AUTO_DECLINE_GUILD_INVITES = 0x06CB
    CMSG_BANKER_ACTIVATE = 0x02E9
    CMSG_BATTLEFIELD_LEAVE = 0x0257
    CMSG_BATTLEFIELD_LIST = 0x1C41
    CMSG_BATTLEFIELD_MGR_ENTRY_INVITE_RESPONSE = 0x1806
    CMSG_BATTLEFIELD_MGR_EXIT_REQUEST = 0x08B3
    CMSG_BATTLEFIELD_MGR_QUEUE_INVITE_RESPONSE = 0x0A97
    CMSG_BATTLEFIELD_PORT = 0x1379
    CMSG_BATTLEFIELD_RATED_INFO_REQUEST = 0x0826
    CMSG_BATTLEFIELD_STATUS = 0x1F9E
    CMSG_BATTLEMASTER_JOIN = 0x0769
    CMSG_BATTLEMASTER_JOIN_ARENA = 0x02D2
    CMSG_BATTLE_CHAR_BOOST = 0x08E3
    CMSG_BATTLE_PET_DELETE_PET = 0x18B6
    CMSG_BATTLE_PET_MODIFY_NAME = 0x1887
    CMSG_BATTLE_PET_QUERY_NAME = 0x1CE0
    CMSG_BATTLE_PET_SET_BATTLE_SLOT = 0x0163
    CMSG_BATTLE_PET_SET_FLAGS = 0x17AC
    CMSG_BATTLE_PET_SUMMON_COMPANION = 0x1896
    CMSG_BATTLE_PET_WILD_REQUEST = 0x06C5
    CMSG_BEGIN_TRADE = 0x1CE3
    CMSG_BINDER_ACTIVATE = 0x1248
    CMSG_BLACKMARKET_BID = 0x12C8
    CMSG_BLACKMARKET_HELLO = 0x075A
    CMSG_BLACKMARKET_REQUEST_ITEMS = 0x127A
    CMSG_BUG = 0x09E1
    CMSG_BUYBACK_ITEM = 0x0661
    CMSG_BUY_BANK_SLOT = 0x12F2
    CMSG_BUY_ITEM = 0x02E2
    CMSG_CALENDAR_ADD_EVENT = 0x0A37
    CMSG_CALENDAR_COMPLAIN = 0x1F8F
    CMSG_CALENDAR_COPY_EVENT = 0x1A97
    CMSG_CALENDAR_EVENT_INVITE = 0x1D8E
    CMSG_CALENDAR_EVENT_MODERATOR_STATUS = 0x0708
    CMSG_CALENDAR_EVENT_REMOVE_INVITE = 0x0962
    CMSG_CALENDAR_EVENT_RSVP = 0x1FB8
    CMSG_CALENDAR_EVENT_SIGNUP = 0x01E3
    CMSG_CALENDAR_EVENT_STATUS = 0x1AB3
    CMSG_CALENDAR_GET_CALENDAR = 0x1F9F
    CMSG_CALENDAR_GET_EVENT = 0x030C
    CMSG_CALENDAR_GET_NUM_PENDING = 0x0813
    CMSG_CALENDAR_REMOVE_EVENT = 0x0C61
    CMSG_CALENDAR_UPDATE_EVENT = 0x1F8D
    CMSG_CANCEL_AURA = 0x1861
    CMSG_CANCEL_AUTO_REPEAT_SPELL = 0x1272
    CMSG_CANCEL_CAST = 0x18C0
    CMSG_CANCEL_CHANNELLING = 0x08C0
    CMSG_CANCEL_MOUNT_AURA = 0x10E3
    CMSG_CANCEL_TEMP_ENCHANTMENT = 0x024B
    CMSG_CANCEL_TRADE = 0x1941
    CMSG_CAST_SPELL = 0x0206
    CMSG_CHANGE_SEATS_ON_CONTROLLED_VEHICLE = 0x08F8
    CMSG_CHANNEL_ANNOUNCEMENTS = 0x06AF
    CMSG_CHANNEL_BAN = 0x08BF
    CMSG_CHANNEL_INVITE = 0x10AB
    CMSG_CHANNEL_KICK = 0x0E0B
    CMSG_CHANNEL_LIST = 0x0C1B
    CMSG_CHANNEL_MODERATOR = 0x00AE
    CMSG_CHANNEL_MUTE = 0x000A
    CMSG_CHANNEL_OWNER = 0x00AF
    CMSG_CHANNEL_PASSWORD = 0x0A1E
    CMSG_CHANNEL_SET_OWNER = 0x141A
    CMSG_CHANNEL_UNBAN = 0x081F
    CMSG_CHANNEL_UNMODERATOR = 0x041E
    CMSG_CHANNEL_UNMUTE = 0x022A
    CMSG_CHAR_CREATE = 0x0F1D
    CMSG_CHAR_CUSTOMIZE = 0x0A13
    CMSG_CHAR_DELETE = 0x04E2
    CMSG_CHAR_FACTION_OR_RACE_CHANGE = 0x0329
    CMSG_CHAR_RENAME = 0x0963
    CMSG_CHAT_IGNORED = 0x048A
    CMSG_CHAT_JOIN_CHANNEL = 0x148E
    CMSG_CHAT_MESSAGE_AFK = 0x0EAB
    CMSG_CLEAR_TRADE_ITEM = 0x00A7
    CMSG_COMPLAIN = 0x0319
    CMSG_COMPLETE_CINEMATIC = 0x1F34
    CMSG_CONFIRM_RESPEC_WIPE = 0x0275
    CMSG_CONTACT_LIST = 0x0BB4
    CMSG_CORPSE_MAP_POSITION_QUERY = 0x0A16
    CMSG_CORPSE_QUERY = 0x1FBE
    CMSG_CREATURE_QUERY = 0x0842
    CMSG_DEL_FRIEND = 0x1103
    CMSG_DEL_IGNORE = 0x0737
    CMSG_DESTROY_ITEM = 0x0026
    CMSG_DISCARDED_TIME_SYNC_ACKS = 0x115B
    CMSG_DISMISS_CONTROLLED_VEHICLE = 0x09FA
    CMSG_DISMISS_CRITTER = 0x12DB
    CMSG_DUEL_PROPOSED = 0x1A26
    CMSG_DUEL_RESPONSE = 0x03E2
    CMSG_EJECT_PASSENGER = 0x06E7
    CMSG_EMOTE = 0x1924
    CMSG_ENABLE_TAXI = 0x0741
    CMSG_ENUM_CHARACTERS = 0x00E0
    CMSG_EQUIPMENT_SET_DELETE = 0x02E8
    CMSG_EQUIPMENT_SET_SAVE = 0x0669
    CMSG_EQUIPMENT_SET_USE = 0x036E
    CMSG_FAR_SIGHT = 0x1341
    CMSG_FORCE_MOVE_ROOT_ACK = 0x107A
    CMSG_FORCE_MOVE_UNROOT_ACK = 0x1051
    CMSG_GAMEOBJECT_QUERY = 0x1461
    CMSG_GAME_OBJ_REPORT_USE = 0x06D8
    CMSG_GAME_OBJ_USE = 0x06D9
    CMSG_GET_ITEM_PURCHASE_DATA = 0x1258
    CMSG_GET_MAIL_LIST = 0x077A
    CMSG_GET_MIRROR_IMAGE_DATA = 0x02A3
    CMSG_GM_TICKET_CASE_STATUS = 0x15A8
    CMSG_GM_TICKET_CREATE = 0x1A86
    CMSG_GM_TICKET_DELETE_TICKET = 0x1A23
    CMSG_GM_TICKET_GET_TICKET = 0x1F89
    CMSG_GM_TICKET_SYSTEM_STATUS = 0x0A82
    CMSG_GM_TICKET_UPDATE_TEXT = 0x0A26
    CMSG_GM_RESPONSE_RESOLVE = 0x033D
    CMSG_GM_SURVEY_SUBMIT = 0x073C
    CMSG_GOSSIP_HELLO = 0x12F3
    CMSG_GOSSIP_SELECT_OPTION = 0x0748
    CMSG_GRANT_LEVEL = 0x0662
    CMSG_GROUP_ASSISTANT_LEADER = 0x1897
    CMSG_GROUP_CHANGE_SUB_GROUP = 0x1799
    CMSG_GROUP_DISBAND = 0x1798
    CMSG_GROUP_INITIATE_ROLE_POLL = 0x1882
    CMSG_GROUP_INVITE = 0x072D
    CMSG_GROUP_INVITE_RESPONSE = 0x0D61
    CMSG_GROUP_RAID_CONVERT = 0x032C
    CMSG_GROUP_SET_LEADER = 0x15BB
    CMSG_GROUP_SET_ROLES = 0x1A92
    CMSG_GROUP_UNINVITE_GUID = 0x0CE1
    CMSG_GUILD_ACCEPT = 0x18A2
    CMSG_GUILD_ACHIEVEMENT_PROGRESS_QUERY = 0x1552
    CMSG_GUILD_ADD_RANK = 0x047A
    CMSG_GUILD_ASSIGN_MEMBER_RANK = 0x05D0
    CMSG_GUILD_BANKER_ACTIVATE = 0x0372
    CMSG_GUILD_BANK_BUY_TAB = 0x0251
    CMSG_GUILD_BANK_DEPOSIT_MONEY = 0x0770
    CMSG_GUILD_BANK_LOG_QUERY = 0x0CD3
    CMSG_GUILD_BANK_MONEY_WITHDRAWN_QUERY = 0x14DB
    CMSG_GUILD_BANK_NOTE = 0x04D9
    CMSG_GUILD_BANK_QUERY_TAB = 0x1372
    CMSG_GUILD_BANK_QUERY_TEXT = 0x0550
    CMSG_GUILD_BANK_SWAP_ITEMS = 0x136A
    CMSG_GUILD_BANK_UPDATE_TAB = 0x07C2
    CMSG_GUILD_BANK_WITHDRAW_MONEY = 0x07EA
    CMSG_GUILD_DECLINE = 0x147B
    CMSG_GUILD_DEL_RANK = 0x0D79
    CMSG_GUILD_DEMOTE = 0x1553
    CMSG_GUILD_DISBAND = 0x0D73
    CMSG_GUILD_EVENT_LOG_QUERY = 0x15D9
    CMSG_GUILD_INFO_TEXT = 0x0C70
    CMSG_GUILD_INVITE = 0x0869
    CMSG_GUILD_LEAVE = 0x04D8
    CMSG_GUILD_MOTD = 0x1473
    CMSG_GUILD_NEWS_UPDATE_STICKY = 0x04D1
    CMSG_GUILD_PERMISSIONS = 0x145A
    CMSG_GUILD_PROMOTE = 0x0571
    CMSG_GUILD_QUERY = 0x1AB6
    CMSG_GUILD_QUERY_NEWS = 0x1C58
    CMSG_GUILD_QUERY_RANKS = 0x0D50
    CMSG_GUILD_REMOVE = 0x0CD8
    CMSG_GUILD_REPLACE_GUILD_MASTER = 0x0CD0
    CMSG_GUILD_REQUEST_CHALLENGE_UPDATE = 0x147A
    CMSG_GUILD_REQUEST_PARTY_STATE = 0x10C3
    CMSG_GUILD_ROSTER = 0x1459
    CMSG_GUILD_SET_GUILD_MASTER = 0x1A83
    CMSG_GUILD_SET_NOTE = 0x05DA
    CMSG_GUILD_SET_RANK_PERMISSIONS = 0x0C7A
    CMSG_HEARTH_AND_RESURRECT = 0x0360
    CMSG_IGNORE_TRADE = 0x0276
    CMSG_INITIATE_TRADE = 0x0267
    CMSG_INSPECT = 0x1259
    CMSG_INSPECT_HONOR_STATS = 0x19C3
    CMSG_INSTANCE_LOCK_WARNING_RESPONSE = 0x12C0
    CMSG_ITEM_REFUND = 0x074B
    CMSG_ITEM_TEXT_QUERY = 0x0123
    CMSG_KEEP_ALIVE = 0x1A87
    CMSG_LEARN_TALENT = 0x02A7
    CMSG_LEAVE_CHANNEL = 0x042A
    CMSG_LFD_JOIN = 0x046B
    CMSG_LFD_LEAVE = 0x01E0
    CMSG_LFD_LOCK_INFO_REQUEST = 0x006B
    CMSG_LFD_PROPOSAL_RESULT = 0x1D9D
    CMSG_LFD_SET_BOOT_VOTE = 0x17BE
    CMSG_LFD_TELEPORT = 0x1AA6
    CMSG_LFG_GET_STATUS = 0x032D
    CMSG_LFG_SET_ROLES = 0x08A2
    CMSG_LF_GUILD_ADD_APPLICATION = 0x0C63
    CMSG_LF_GUILD_BROWSE = 0x159A
    CMSG_LF_GUILD_DECLINE_RECRUIT = 0x14F3
    CMSG_LF_GUILD_GET_APPLICATIONS = 0x0558
    CMSG_LF_GUILD_GET_RECRUITS = 0x057A
    CMSG_LF_GUILD_REMOVE_APPLICATION = 0x1C53
    CMSG_LF_GUILD_SET_GUILD_POST = 0x1D9F
    CMSG_LIST_INVENTORY = 0x02D8
    CMSG_LOADING_SCREEN_NOTIFY = 0x1DBD
    CMSG_LOGOUT_CANCEL = 0x06C1
    CMSG_LOGOUT_REQUEST = 0x1349
    CMSG_LOG_DISCONNECT = 0x10B3
    CMSG_LOOT = 0x1CE2
    CMSG_LOOT_METHOD = 0x0DE1
    CMSG_LOOT_MONEY = 0x02F6
    CMSG_LOOT_RELEASE = 0x0840
    CMSG_LOOT_ROLL = 0x15C2
    CMSG_MAIL_CREATE_TEXT_ITEM = 0x1270
    CMSG_MAIL_DELETE = 0x14E2
    CMSG_MAIL_MARK_AS_READ = 0x0241
    CMSG_MAIL_QUERY_NEXT_TIME = 0x077B
    CMSG_MAIL_RETURN_TO_SENDER = 0x1FA8
    CMSG_MAIL_TAKE_ITEM = 0x1371
    CMSG_MAIL_TAKE_MONEY = 0x06FA
    CMSG_MESSAGECHAT_ADDON_WHISPER = 0x0EBB
    CMSG_MESSAGECHAT_CHANNEL = 0x00BB
    CMSG_MESSAGECHAT_DND = 0x002E
    CMSG_MESSAGECHAT_EMOTE = 0x103E
    CMSG_MESSAGECHAT_GUILD = 0x0CAE
    CMSG_MESSAGECHAT_OFFICER = 0x0ABF
    CMSG_MESSAGECHAT_PARTY = 0x109A
    CMSG_MESSAGECHAT_RAID = 0x083E
    CMSG_MESSAGECHAT_RAID_WARNING = 0x16AB
    CMSG_MESSAGECHAT_SAY = 0x0A9A
    CMSG_MESSAGECHAT_WHISPER = 0x123E
    CMSG_MESSAGECHAT_YELL = 0x04AA
    CMSG_MINIMAP_PING = 0x0837
    CMSG_MOUNTSPECIAL_ANIM = 0x0082
    CMSG_MOVE_APPLY_MOVEMENT_FORCE_ACK = 0x08D3
    CMSG_MOVE_CHNG_TRANSPORT = 0x09DB
    CMSG_MOVE_FALL_RESET = 0x00D9
    CMSG_MOVE_FEATHER_FALL_ACK = 0x08D0
    CMSG_MOVE_FORCE_FLIGHT_BACK_SPEED_CHANGE_ACK = 0x105B
    CMSG_MOVE_FORCE_FLIGHT_SPEED_CHANGE_ACK = 0x09DA
    CMSG_MOVE_FORCE_PITCH_RATE_CHANGE_ACK = 0x0172
    CMSG_MOVE_FORCE_RUN_BACK_SPEED_CHANGE_ACK = 0x0158
    CMSG_MOVE_FORCE_RUN_SPEED_CHANGE_ACK = 0x10F3
    CMSG_MOVE_FORCE_SWIM_BACK_SPEED_CHANGE_ACK = 0x10D1
    CMSG_MOVE_FORCE_SWIM_SPEED_CHANGE_ACK = 0x1853
    CMSG_MOVE_FORCE_TURN_RATE_CHANGE_ACK = 0x185A
    CMSG_MOVE_FORCE_WALK_SPEED_CHANGE_ACK = 0x00DB
    CMSG_MOVE_GRAVITY_DISABLE_ACK = 0x09D3
    CMSG_MOVE_GRAVITY_ENABLE_ACK = 0x11D8
    CMSG_MOVE_HOVER_ACK = 0x0858
    CMSG_MOVE_KNOCK_BACK_ACK = 0x00F2
    CMSG_MOVE_REMOVE_MOVEMENT_FORCE_ACK = 0x10DB
    CMSG_MOVE_SET_CAN_FLY_ACK = 0x1052
    CMSG_MOVE_SET_FLY = 0x01F1
    CMSG_MOVE_SPLINE_DONE = 0x11D9
    CMSG_MOVE_TELEPORT_ACK = 0x0078
    CMSG_MOVE_TIME_SKIPPED = 0x0150
    CMSG_MOVE_WATER_WALK_ACK = 0x10F2
    CMSG_NAME_QUERY = 0x0328
    CMSG_NPC_TEXT_QUERY = 0x0287
    CMSG_OBJECT_UPDATE_FAILED = 0x1061
    CMSG_OFFER_PETITION = 0x15BE
    CMSG_OPENING_CINEMATIC = 0x0130
    CMSG_OPEN_ITEM = 0x1D10
    CMSG_OPT_OUT_OF_LOOT = 0x06E0
    CMSG_PAGE_TEXT_QUERY = 0x1022
    CMSG_PETITION_BUY = 0x12D9
    CMSG_PETITION_DECLINE = 0x1279
    CMSG_PETITION_QUERY = 0x0255
    CMSG_PETITION_RENAME = 0x1F9A
    CMSG_PETITION_SHOWLIST = 0x037B
    CMSG_PETITION_SHOW_SIGNATURES = 0x136B
    CMSG_PETITION_SIGN = 0x06DA
    CMSG_PET_ABANDON = 0x07D0
    CMSG_PET_ACTION = 0x025B
    CMSG_PET_BATTLE_START_PVP_MATCHMAKING = 0x06D4
    CMSG_PET_BATTLE_STOP_PVP_MATCHMAKING = 0x08C1
    CMSG_PET_CAST_SPELL = 0x044D
    CMSG_PET_NAME_QUERY = 0x1C62
    CMSG_PET_RENAME = 0x0A32
    CMSG_PET_SET_ACTION = 0x12E9
    CMSG_PET_SPELL_AUTOCAST = 0x06F0
    CMSG_PET_STOP_ATTACK = 0x065B
    CMSG_PING = 0x0012
    CMSG_PLAYER_LOGIN = 0x158F
    CMSG_PUSHQUESTTOPARTY = 0x03D2
    CMSG_PVP_LOG_DATA = 0x14C2
    CMSG_QUERY_GUILD_REWARDS = 0x06C4
    CMSG_QUERY_GUILD_XP = 0x05F8
    CMSG_QUERY_INSPECT_ACHIEVEMENTS = 0x0373
    CMSG_QUERY_TIME = 0x0640
    CMSG_QUESTLOG_REMOVE_QUEST = 0x0779
    CMSG_QUEST_CONFIRM_ACCEPT = 0x124B
    CMSG_QUEST_GIVER_ACCEPT_QUEST = 0x06D1
    CMSG_QUEST_GIVER_CHOOSE_REWARD = 0x07CB
    CMSG_QUEST_GIVER_COMPLETE_QUEST = 0x0659
    CMSG_QUEST_GIVER_HELLO = 0x02DB
    CMSG_QUEST_GIVER_QUERY_QUEST = 0x12F0
    CMSG_QUEST_GIVER_REQUEST_REWARD = 0x0378
    CMSG_QUEST_GIVER_STATUS_MULTIPLE_QUERY = 0x02F1
    CMSG_QUEST_GIVER_STATUS_QUERY = 0x036A
    CMSG_QUEST_NPC_QUERY = 0x1DAE
    CMSG_QUEST_POI_QUERY = 0x10C2
    CMSG_QUEST_QUERY = 0x02D5
    CMSG_RAID_READY_CHECK = 0x0817
    CMSG_RAID_READY_CHECK_CONFIRM = 0x158B
    CMSG_RAID_TARGET_UPDATE = 0x0886
    CMSG_RANDOMIZE_CHAR_NAME = 0x0B1C
    CMSG_RANDOM_ROLL = 0x08A3
    CMSG_READY_FOR_ACCOUNT_DATA_TIMES = 0x031C
    CMSG_READ_ITEM = 0x0D00
    CMSG_REALM_NAME_QUERY = 0x1A16
    CMSG_RECLAIM_CORPSE = 0x03D3
    CMSG_REFORGE_ITEM = 0x0C4F
    CMSG_REORDER_CHARACTERS = 0x08A7
    CMSG_REPAIR_ITEM = 0x02C1
    CMSG_REPOP_REQUEST = 0x134A
    CMSG_REPORT_PVP_AFK = 0x06F9
    CMSG_REQUEST_ACCOUNT_DATA = 0x1D8A
    CMSG_REQUEST_CATEGORY_COOLDOWNS = 0x1203
    CMSG_REQUEST_CEMETERY_LIST = 0x06E4
    CMSG_REQUEST_CONQUEST_FORMULA_CONSTANTS = 0x0365
    CMSG_REQUEST_FORCED_REACTIONS = 0x06F5
    CMSG_REQUEST_HOTFIX = 0x158D
    CMSG_REQUEST_PARTY_MEMBER_STATS = 0x0806
    CMSG_REQUEST_PLAYED_TIME = 0x03F6
    CMSG_REQUEST_PVP_OPTIONS_ENABLED = 0x0A22
    CMSG_REQUEST_PVP_REWARDS = 0x0375
    CMSG_REQUEST_RAID_INFO = 0x0A87
    CMSG_REQUEST_STABLED_PETS = 0x02CA
    CMSG_REQUEST_VEHICLE_EXIT = 0x1DC3
    CMSG_REQUEST_VEHICLE_NEXT_SEAT = 0x0141
    CMSG_REQUEST_VEHICLE_PREV_SEAT = 0x03C4
    CMSG_REQUEST_VEHICLE_SWITCH_SEAT = 0x1143
    CMSG_RESET_INSTANCES = 0x0C69
    CMSG_RESURRECT_RESPONSE = 0x0B0C
    CMSG_RETURN_TO_GRAVEYARD = 0x12EA
    CMSG_RIDE_VEHICLE_INTERACT = 0x0277
    CMSG_SAVE_CUF_PROFILES = 0x06E6
    CMSG_SCENE_COMPLETED = 0x0087
    CMSG_SELECT_FACTION = 0x0027
    CMSG_SELF_RES = 0x0360
    CMSG_SELL_ITEM = 0x1358
    CMSG_SEND_MAIL = 0x1DBA
    CMSG_SEND_TEXT_EMOTE = 0x07E9
    CMSG_SETSHEATHED = 0x0249
    CMSG_SET_ACTIONBAR_TOGGLES = 0x0672
    CMSG_SET_ACTION_BUTTON = 0x1F8C
    CMSG_SET_ACTIVE_MOVER = 0x09F0
    CMSG_SET_CONTACT_NOTES = 0x0937
    CMSG_SET_DUNGEON_DIFFICULTY = 0x1A36
    CMSG_SET_EVERYONE_IS_ASSISTANT = 0x01E1
    CMSG_SET_FACTION_ATWAR = 0x027B
    CMSG_SET_FACTION_INACTIVE = 0x0778
    CMSG_SET_FACTION_NOTATWAR = 0x064B
    CMSG_SET_LFG_BONUS_FACTION_ID = 0x0247
    CMSG_SET_PARTY_ASSIGNMENT = 0x1802
    CMSG_SET_PET_TALENT_TREE = 0x1463
    CMSG_SET_PLAYER_DECLINED_NAMES = 0x09E2
    CMSG_SET_PRIMARY_TALENT_TREE = 0x06C6
    CMSG_SET_PVP = 0x02C5
    CMSG_SET_RAID_DIFFICULTY = 0x0591
    CMSG_SET_SELECTION = 0x0740
    CMSG_SET_TAXI_BENCHMARK_MODE = 0x0762
    CMSG_SET_TITLE = 0x03C7
    CMSG_SET_TRADE_GOLD = 0x14E3
    CMSG_SET_TRADE_ITEM = 0x03D5
    CMSG_SET_VEHICLE_REC_ID_ACK = 0x185B
    CMSG_SET_WATCHED_FACTION = 0x06C9
    CMSG_SHOWING_CLOAK = 0x02F2
    CMSG_SHOWING_HELM = 0x126B
    CMSG_SOCKET_GEMS = 0x02CB
    CMSG_SPELLCLICK = 0x067A
    CMSG_SPIRIT_HEALER_ACTIVATE = 0x0340
    CMSG_SPLIT_ITEM = 0x02EC
    CMSG_STAND_STATE_CHANGE = 0x03E6
    CMSG_SUBMIT_BUG = 0x0861
    CMSG_SUGGESTION_SUBMIT = 0x0A12
    CMSG_SUMMON_RESPONSE = 0x0A33
    CMSG_SWAP_INV_ITEM = 0x03DF
    CMSG_SWAP_ITEM = 0x035D
    CMSG_TAXI_NODE_STATUS_QUERY = 0x02E1
    CMSG_TAXI_QUERY_AVAILABLE_NODES = 0x02E3
    CMSG_TIME_SYNC_RESPONSE = 0x01DB
    CMSG_TOGGLE_PVP = 0x0644
    CMSG_TOTEM_DESTROYED = 0x1263
    CMSG_TRAINER_BUY_SPELL = 0x0352
    CMSG_TRAINER_LIST = 0x034B
    CMSG_TRANSMOGRIFY_ITEMS = 0x06D7
    CMSG_TURN_IN_PETITION = 0x0673
    CMSG_TUTORIAL_CLEAR = 0x0F23
    CMSG_TUTORIAL_FLAG = 0x1D36


class opcodes:

    @staticmethod
    def getCodeName(enum_class, enum_value):
        if isinstance(enum_class, type) and issubclass(enum_class, IntEnum):
            for name, member in enum_class.__members__.items():
                if member.value == enum_value:
                    return name
                
        return ""
        # return f"No defined handler for opcode [UNKNOWN OPCODE {hex(enum_value)} {enum_value})"
