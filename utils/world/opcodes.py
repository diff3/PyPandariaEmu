#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from enum import IntEnum


class WorldOpcodes(IntEnum):
    CMSG_MESSAGECHAT_ADDON_GUILD = 0x0E3B
    CMSG_MESSAGECHAT_ADDON_INSTANCE_CHAT = 0x08AF
    CMSG_MESSAGECHAT_ADDON_OFFICER = 0x180B
    CMSG_MESSAGECHAT_ADDON_PARTY = 0x028E
    CMSG_MESSAGECHAT_ADDON_RAID = 0x009A
    CMSG_MESSAGECHAT_ADDON_WHISPER = 0x0EBB
    CMSG_MESSAGECHAT_AFK = 0x0EAB
    CMSG_MESSAGECHAT_BATTLEGROUND = 0x0000
    CMSG_MESSAGECHAT_CHANNEL = 0x00BB
    CMSG_MESSAGECHAT_DND = 0x002E
    CMSG_MESSAGECHAT_EMOTE = 0x103E
    CMSG_MESSAGECHAT_GUILD = 0x0CAE
    CMSG_MESSAGECHAT_INSTANCE = 0x162A
    CMSG_MESSAGECHAT_OFFICER = 0x0ABF
    CMSG_MESSAGECHAT_PARTY = 0x109A
    CMSG_MESSAGECHAT_RAID = 0x083E
    CMSG_MESSAGECHAT_RAID_WARNING = 0x16AB
    CMSG_MESSAGECHAT_SAY = 0x0A9A
    CMSG_MESSAGECHAT_WHISPER = 0x123E
    CMSG_MESSAGECHAT_YELL = 0x04AA


class opcodes:

    @staticmethod
    def getCodeName(enum_class, enum_value):
        if isinstance(enum_class, type) and issubclass(enum_class, IntEnum):
            for name, member in enum_class.__members__.items():
                # print(name) 
                # print(member.value) 
                # print(int(enum_value.hex(), 16))
                if member.value == int(enum_value.hex(), 16):
                    return name
                
        return None


