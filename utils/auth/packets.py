#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass


@dataclass
class AuthLogonChallengeC:
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
    cmd: int
    A: str
    M1: str
    crc_hash: str
    number_of_keys: int
    security_flags: int 

    
@dataclass
class AuthLogonProofS:
    cmd: int
    error: int
    M2: str
    unk1: int
    unk2: int
    unk3: int


@dataclass
class RealmListC:
    cmd: int