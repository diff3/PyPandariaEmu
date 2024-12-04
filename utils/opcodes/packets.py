#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass


@dataclass
class AuthLogonChallengeC:
    # <BBH4sBBBH4s4s4sIIB
    cmd: int
    error: int
    size: int
    gamename: str
    version1: int
    version2: int
    version3: int
    build: int
    platform: str
    os: str
    country: str
    timezone_bias: int
    ip: str
    I_len: int
    I: str


@dataclass
class AuthLogonChallengeS:
    # BBB32sBBB32s32s16sB
    cmd: int
    error: int
    success: int
    B: str
    l: int
    g: int
    blob: str
    N: str
    s: str
    unk3: int
    securityFlags: int 


@dataclass 
class AuthLogonProofC:
    # B32s20s20sBB
    cmd: int
    A: str
    M1: str
    crc_hash: str
    number_of_keys: int
    security_flags: int 

    
@dataclass
class AuthLogonProofS:
    # >BB20sIIH
    cmd: int
    error: int
    M2: str
    unk1: int
    unk2: int
    unk3: int


@dataclass
class AuthReconnectChallangeS:
    # Length is defined in header, and contains AuthLogonChallengeC
    # BIs?
    cmd: int
    header: int
    packets: str


@dataclass
class AuthReconnectProofC:
    # Bs16s20s20B
    cmd: int
    R1: str
    R2: str
    R3: str
    number_of_keys: int


@dataclass
class Realm:
    # 16s64sBIBIfI
    ExternalAddress: str
    name: str
    icon: int
    flag: int
    imezone: int
    m_ID: int
    allowedSecurityLevel: int
    populationLevel: float
    gamebuild: int


@dataclass
class RealmListC:
    # B
    cmd: int


@dataclass
class RealmListS:
    pass


@dataclass
class Xfer_init:
    # BB5sQ16s
    cmd: int
    fileNameLen: int
    fileName: bytes
    file_size: int
    md5: str


@dataclass
class Xfer_data:
    # BH1024s
    opcide: int
    data_size: int
    data: str
