#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mist of Pandaria Opcodes Decoder
 
This script handles all opcodes from the Character login screen up to the execution of "/yell HELLO WORLD" in Ironforge.
Since ARC4 is a stream cipher, it is crucial to remain synchronized with the server. Thus, decoding all
opcodes in the correct order is necessary to avoid decoding errors.
 
MoP uses ARC4 with a key derived from an HMAC-SHA1 hash. This hash combines a static key 
with the session key (K) to perform encryption and decryption.
"""

import hashlib
import hmac
import struct
from Crypto.Cipher import ARC4
from utils.opcodes.WorldOpcodes import *


class handle_input_header:
    _serverEncrypt = None
    _clientDecrypt = None

    drop = 1024
    offset = 0

    ServerEncryptionKey = bytes([
        0x08, 0xF1, 0x95, 0x9F, 0x47, 0xE5, 0xD2, 0xDB,
        0xA1, 0x3D, 0x77, 0x8F, 0x3F, 0x3E, 0xE7, 0x00
    ])

    ServerDecryptionKey = bytes([
        0x40, 0xAA, 0xD3, 0x92, 0x26, 0x71, 0x43, 0x47,
        0x3A, 0x31, 0x08, 0xA6, 0xE7, 0xDC, 0x98, 0x2A
    ])
    
    def __init__(self):
        pass

    def initArc4(self, K, Direction):
        self.direction = Direction
        # K needs to be mirrored from database [::-1] 
        encrypt_hash = hmac.new(self.ServerEncryptionKey, bytes.fromhex(K), hashlib.sha1).digest()
        decrypt_hash = hmac.new(self.ServerDecryptionKey, bytes.fromhex(K), hashlib.sha1).digest()

        # print(f'Encrypt hash: {encrypt_hash.hex()}')
        # print(f'Decrypt hash: {decrypt_hash.hex()}')
        
        self._serverEncrypt = ARC4.new(key=encrypt_hash, drop=self.drop)
        self._clientDecrypt = ARC4.new(key=decrypt_hash, drop=self.drop)

    def decryptRecv(self, header):
        self.offset += 4
        # print(f'{self.direction}, Drop: {self.drop + self.offset}')
        return self._clientDecrypt.decrypt(header)
    
    def encryptSend(self, header):
        return self._serverEncrypt.encrypt(header)
    
    def unpack_data(self, data: bytes) -> WorldClientPktHeader:
        """
        Unpacks a 32-bit value from the provided byte data to extract the command and size.

        The data is expected to be at least 4 bytes long. The method interprets the first 4 bytes 
        of the data as a little-endian unsigned integer (32-bit). It then extracts the 'cmd' and 
        'size' values using bitwise operations based on the format defined for the packet header.

        Parameters:
        - data (bytes): The byte data containing the packed 32-bit value.

        Returns:
        - WorldClientPktHeader: A dataclass instance containing the unpacked 'cmd' and 'size'.
        """
            
        value = struct.unpack('<I', data[:4])[0]
        
        cmd = value & 0x1FFF
        size = (value & 0xFFFFE000) >> 13
        
        return WorldClientPktHeader(cmd=cmd, size=size)

    def getOpCodeName(self, cmd):
        return opcodes.getCodeName(WorldOpcodes, cmd)


if __name__ == "__main__":   

    # Working test data from Server
    K = "45b3fc47955fce099c75a2472beba082cb04374df98fde0c6f24290b917215869fc2b06fcdc989ab"
    
    headers = ['172cb129', 'c5fc3f3b', '65fd4898', '73497b67', 'ec3484c6', 
               '9301c210', '89d5f3b7', '7f51a90d', '09eaee42', '916a11c1', 
               'b1343f4e', '0dc775bd', '4bb7de4b', '34a166c7', '2a683825', 
               'aa7402c8', 'd8a01851', '5e2cd5cd', '236fcd6c', '57f78fd8', 
               'f54f50b7', '96e8c57f', '0a133cd5', '7906ff5c', '264dced8', 
               '3e62ad76', '779c79fd', 'f4215145', '3d7983ba', '9062a7b9', 
               'b23cbfa5', '5813837c', 'be1a1a28', 'ecf896c0', 'b9aaa6fd', 
               'd094c8f1', '3a42dbdd', 'a09fefb4', 'ec02641f', '77a44248', 
               '98169b10', '7e314f78', 'ba8b7f3b', 'b075aa96', '1f71ce87', 
               '0d6fccb2', '84b247bf', 'd1032a51', 'e751f0b1', '09c5727f', 
               '0e5455fb', 'b9a0891f', 'b57472ed', '386c1b5a', 'b33e7787', 
               'e5160936', 'f32fe207', 'e0c70eed', '55a4f269', '6014a405', 
               '5a394cb5', '77b9b6b2', '1844f257', 'f692dfe0', '34ea71bb', 
               '8cd6c338', '1953ad5f', '708247c8']

    # Test data from Proxy, you can use create_list.py to generate data from logfiles.



    IH = handle_input_header()
    IH.initArc4(K)

    print(f'K: {K}')

    for header_data in headers:
        decrypted_header = IH.decryptRecv(bytes.fromhex(header_data))
        header = IH.unpack_data(decrypted_header)
        opname = opcodes.getCodeName(WorldOpcodes, header.cmd)

        print(f'Header (hex): {header_data}, CMD: {hex(header.cmd)[2:]},\t({header.cmd}) \t{opname}')