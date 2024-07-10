#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

from dataclasses import dataclass
import struct
import socket


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
    
    @classmethod
    def unpack(cls, data):
        fixed_size_format = '<BBH4sBBBH4s4s4sIIB'
        fixed_size_length = struct.calcsize(fixed_size_format)
    
        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))
        unpacked_data[3] = unpacked_data[3].decode('utf-8').rstrip('\x00')
        unpacked_data[8] = unpacked_data[8].decode('utf-8').rstrip('\x00').strip('\x00')[::-1]
        unpacked_data[9] = unpacked_data[9].decode('utf-8').rstrip('\x00').strip('\x00')[::-1]
        unpacked_data[10] = unpacked_data[10][::-1].decode('utf-8').rstrip('\x00')
        unpacked_data[12] = socket.inet_ntoa(struct.pack('<I', unpacked_data[12]))
        unpacked_data.append(data[fixed_size_length:].decode('utf-8'))
    
        return cls(*unpacked_data)


@dataclass 
class AuthLogonProofC:
    cmd: int
    A: str
    M1: str
    crc_hash: str
    number_of_keys: int
    security_flags: int 

    @classmethod
    def unpack(cls, data):
        fixed_size_format = 'B32s20s20sBB'
        fixed_size_length = struct.calcsize(fixed_size_format)
    
        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))
        return cls(*unpacked_data)
        

if __name__ == "__main__":   
    pass