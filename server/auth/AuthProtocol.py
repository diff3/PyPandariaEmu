#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from utils.auth.packets import AuthLogonChallengeC, AuthLogonChallengeS, AuthLogonProofC, AuthLogonProofS, RealmListC
import socket
import struct


@dataclass
class AuthLogonChallengeClient:
    
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
    
        return AuthLogonChallengeC(*unpacked_data)


@dataclass
class AuthLogonChallengeServer:
    
    @classmethod
    def unpack(cls, data):
        fixed_size_format = 'BBB32sBBB32s32s16sB'
        fixed_size_length = struct.calcsize(fixed_size_format)
        
        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))

        return AuthLogonChallengeS(*unpacked_data)

    @classmethod
    def pack(cls, data):
        fixed_size_format = 'BBB32sBBB32s32s16sB'
        pkt = struct.pack(fixed_size_format,
                          data['cmd'],
                          data['error'],
                          data['success'],
                          data['B'],
                          data['l'],
                          data['g'],
                          data['blob'],
                          data['N'],
                          data['s'],
                          data['unk3'],
                          data['securityFlags'])
        return pkt


@dataclass 
class AuthLogonProofClient:
    fixed_size_format = 'B32s20s20sBB'

    @classmethod
    def unpack(cls, data):
        fixed_size_length = struct.calcsize(AuthLogonProofClient.fixed_size_format)
        unpacked_data = list(struct.unpack(AuthLogonProofClient.fixed_size_format, data[:fixed_size_length]))

        return AuthLogonProofC(*unpacked_data)


@dataclass
class AuthLogonProofServer:
    fixed_size_format = '>BB20sIIH'

    @classmethod
    def unpack(cls, data):
        fixed_size_length = struct.calcsize(cls.fixed_size_format)
        unpacked_data = list(struct.unpack(cls.fixed_size_format, data[:fixed_size_length]))

        return AuthLogonProofS(*unpacked_data)

    @classmethod
    def pack(cls, data):
        pkt = struct.pack(cls.fixed_size_format,
                          data['cmd'],
                          data['error'],
                          data['M2'],
                          data['unk1'],
                          data['unk2'],
                          data['unk3'])
                
        return pkt     

    @classmethod
    def right_length(cls, data):
        fixed_size_length = struct.calcsize(cls.fixed_size_format)
        if len(data) != fixed_size_length:
            return False

        return True


@dataclass
class RealmListClient:
  
    @classmethod
    def unpack(cls, data):
        fixed_size_format = 'B'
        fixed_size_length = struct.calcsize(fixed_size_format)

        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))

        return RealmListC(*unpacked_data)