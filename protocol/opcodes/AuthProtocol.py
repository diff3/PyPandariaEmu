#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from utils.Logger import Logger
from protocol.opcodes.AuthPackets import AuthLogonChallengeC, AuthLogonChallengeS, AuthLogonProofC, AuthLogonProofS, RealmListC, AuthReconnectProofC
import socket
import struct


@dataclass
class AuthLogonChallengeClient:
    name = "AuthLogonChallengeClient"
    fixed_size_format = '<BBH4sBBBH4s4s4sIIB'
    fixed_size_length = struct.calcsize(fixed_size_format)
   
    @classmethod
    def unpack(cls, data):
        unpacked_data = list(struct.unpack(cls.fixed_size_format, data[:cls.fixed_size_length]))
        unpacked_data[3] = unpacked_data[3].decode('utf-8').rstrip('\x00')
        unpacked_data[8] = unpacked_data[8].decode('utf-8').rstrip('\x00').strip('\x00')[::-1]
        unpacked_data[9] = unpacked_data[9].decode('utf-8').rstrip('\x00').strip('\x00')[::-1]
        unpacked_data[10] = unpacked_data[10][::-1].decode('utf-8').rstrip('\x00')
        unpacked_data[12] = socket.inet_ntoa(struct.pack('<I', unpacked_data[12]))
        unpacked_data.append(data[cls.fixed_size_length:].decode('utf-8'))
    
        return AuthLogonChallengeC(*unpacked_data)

    @classmethod
    def validate(cls, data):
        if not data:
            Logger.warning(f"{cls.name}: client didn't send any data.")
            return False

        if len(data) < cls.fixed_size_length:
            Logger.warning(f"{cls.name}: data is shorter then expected fixed size length ({cls.fixed_size_length} bytes).")
            return False
        
        try:
           struct.unpack(cls.fixed_size_format, data[:cls.fixed_size_length])
        except struct.error as e:
            Logger.warning(f"{cls.name}: Error unpacking data with format {cls.fixed_size_format} : {e}.")
            return False
        
        unpacked_data = list(struct.unpack(cls.fixed_size_format, data[:cls.fixed_size_length]))
        expected_remaining_length = unpacked_data[13]

        actual_remaining_length = len(data) - cls.fixed_size_length
        
        if actual_remaining_length != expected_remaining_length:
            Logger.warning(f"{cls.name}: Expected remaining length is {expected_remaining_length} bytes, but found {actual_remaining_length} bytes.")
            return False
        
        return True


class AuthLogonChallengeServer:
    fixed_size_format = 'BBB32sBBB32s32s16sB'
    fixed_size_length = struct.calcsize(fixed_size_format)
    
    @classmethod
    def unpack(cls, data):
        unpacked_data = list(struct.unpack(cls.fixed_size_format, data[:cls.fixed_size_length]))

        return AuthLogonChallengeS(*unpacked_data)

    @classmethod
    def pack(cls, data):
        pkt = struct.pack(cls.fixed_size_format,
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
    name = "AuthLogonProofClient"
    fixed_size_format = 'B32s20s20sBB'
    fixed_size_length = struct.calcsize(fixed_size_format)

    @classmethod
    def unpack(cls, data):
        unpacked_data = list(struct.unpack(cls.fixed_size_format, data[:cls.fixed_size_length]))

        return AuthLogonProofC(*unpacked_data)
    
    @classmethod
    def validate(cls, data):
        if not data:
            Logger.warning(f"{cls.name}: client didn't send any data.")
            return False

        if not len(data) == cls.fixed_size_length:
            Logger.warning(f"{cls.name}: datadoes not match the expected fixed size length ({cls.fixed_size_length} bytes).")
            return False
        
        try:
           struct.unpack(cls.fixed_size_format, data[:cls.fixed_size_length])
        except struct.error as e:
            Logger.warning(f"{cls.name}: Error unpacking data with format {cls.fixed_size_format} : {e}.")
            return False
        
        return True


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
    def validate(cls, data):
        fixed_size_length = struct.calcsize(cls.fixed_size_format)

        if len(data) != fixed_size_length:
            return False

        return True


class AuthRecconectProofClient:
    fixed_size_format = 'B16s20s20sB'
    fixed_size_length = struct.calcsize(fixed_size_format)

    @classmethod
    def unpack(cls, data):
        unpacked_data = struct.unpack(cls.fixed_size_format, data[:cls.fixed_size_length])

        return AuthReconnectProofC(*unpacked_data)


@dataclass
class RealmListClient:
    fixed_size_format = 'B'
    fixed_size_length = struct.calcsize(fixed_size_format)
  
    @classmethod
    def unpack(cls, data):


        unpacked_data = list(struct.unpack(cls.fixed_size_format, data[:cls.fixed_size_length]))

        return RealmListC(*unpacked_data)