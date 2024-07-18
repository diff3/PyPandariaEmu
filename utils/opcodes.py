#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from enum import IntEnum


class AuthCode(IntEnum):
    AUTH_LOGON_CHALLENGE = 0x00
    AUTH_LOGON_PROOF = 0x01
    AUTH_RECONNECT_CHALLENGE = 0x02
    AUTH_RECONNECT_PROOF = 0x03
    REALM_LIST = 0x10


class AuthResult(IntEnum):
    WOW_SUCCESS = 0x00
    WOW_FAIL_BANNED = 0x03
    WOW_FAIL_UNKNOWN_ACCOUNT = 0x04
    WOW_FAIL_INCORRECT_PASSWORD = 0x05
    WOW_FAIL_ALREADY_ONLINE = 0x06
    WOW_FAIL_NO_TIME = 0x07
    WOW_FAIL_DB_BUSY = 0x08
    WOW_FAIL_VERSION_INVALID = 0x09
    WOW_FAIL_VERSION_UPDATE = 0x0A
    WOW_FAIL_INVALID_SERVER = 0x0B
    WOW_FAIL_SUSPENDED = 0x0C
    WOW_FAIL_FAIL_NOACCESS = 0x0D
    WOW_SUCCESS_SURVEY = 0x0E
    WOW_FAIL_PARENTCONTROL = 0x0F
    WOW_FAIL_LOCKED_ENFORCED = 0x10
    WOW_FAIL_TRIAL_ENDED = 0x11
    WOW_FAIL_OVERMIND_CONVERTED = 0x12
    WOW_FAIL_ANTI_INDULGENCE = 0x13
    WOW_FAIL_EXPIRED = 0x14
    WOW_FAIL_NO_GAME_ACCOUNT = 0x15
    WOW_FAIL_BILLING_LOCK = 0x16
    WOW_FAIL_IGR_WITHOUT_BNET = 0x17
    WOW_FAIL_AA_LOCK = 0x18
    WOW_FAIL_UNLOCKABLE_LOCK = 0x19
    WOW_FAIL_MUST_USE_BNET = 0x20
    WOW_FAIL_OTHER = 0xFF


class opcodes:

    @staticmethod
    def getCodeName(enum_class, enum_value):
        if isinstance(enum_class, type) and issubclass(enum_class, IntEnum):
            for name, member in enum_class.__members__.items():
                if member.value == enum_value:
                    return name
                
        return None