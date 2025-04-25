#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This protocol uses a stream cipher (ARC4) where synchronization between client and server is essential.  
To maintain proper decryption, headers must be decoded in the correct sequence.

Encryption is based on ARC4 with a key derived from an HMAC-SHA1 function.  
The HMAC combines a static component with a session-specific key to initialize the cipher context.
"""

import hashlib
import hmac
import struct
from Crypto.Cipher import ARC4
from utils.Logger import Logger
from protocol.opcodes.WorldOpcodes import WorldClientPktHeader


class Arc4CryptoHandler:
    _serverEncrypt = None
    _clientDecrypt = None

    ARC4_DROP_BYTES = 1024

    SERVER_ENCRYPTION_KEY = bytes([
        0x08, 0xF1, 0x95, 0x9F, 0x47, 0xE5, 0xD2, 0xDB,
        0xA1, 0x3D, 0x77, 0x8F, 0x3F, 0x3E, 0xE7, 0x00
    ])

    SERVER_DECRYPTION_KEY = bytes([
        0x40, 0xAA, 0xD3, 0x92, 0x26, 0x71, 0x43, 0x47,
        0x3A, 0x31, 0x08, 0xA6, 0xE7, 0xDC, 0x98, 0x2A
    ])
    
    def __init__(self):
        pass

    def init_arc4(self, K):
        """
        Initializes ARC4 encryption and decryption with a session key (K).

        The session key is mirrored (reversed) to match the server's internal representation if required.
        Uncomment the K = K[::-1] line if your server requires it.

        Parameters:
        - K (str): A hexadecimal string representing the session key.

        Raises:
        - ValueError: If the session key is not a valid hexadecimal string.
        """
        encrypt_hash = hmac.new(self.SERVER_ENCRYPTION_KEY, bytes.fromhex(K), hashlib.sha1).digest()
        decrypt_hash = hmac.new(self.SERVER_DECRYPTION_KEY, bytes.fromhex(K), hashlib.sha1).digest()

        self._serverEncrypt = ARC4.new(key=encrypt_hash, drop=self.ARC4_DROP_BYTES)
        self._clientDecrypt = ARC4.new(key=decrypt_hash, drop=self.ARC4_DROP_BYTES)

    def decrypt_recv(self, header):
        try:
            return self._clientDecrypt.decrypt(header)
        except Exception as e:
            Logger.error(f"Decryption failed: {e}. Returning original header.")
            return header
    
    def encrypt_send(self, header):
        try:
            return self._serverEncrypt.encrypt(header)
        except Exception as e:
            Logger.error(f"Encryption failed: {e}. Returning original header.")
            return header


    def pack_data(self, cmd, size):
        try:
            # Kombinera cmd och size till ett 32-bitars värde
            value = (size << 13) | (cmd & 0x1FFF)
            # Packa det kombinerade värdet till en bytearray i liten endian
            packed_data = struct.pack('<I', value)
            return packed_data
        except Exception as e:
            print(f"Error while packing: {e}")
            return None


    def unpack_data(self, data: bytes) -> WorldClientPktHeader:
        """
        Unpacks a 32-bit value from the provided byte data to extract the command and size.

        The data is expected to be at least 4 bytes long. The method interprets the first 4 bytes 
        of the data as a little-endian unsigned integer (32-bit). It then extracts the 'cmd' and 
        'size' values using bitwise operations based on the format defined for the packet header.

        Note: The input data must be at least 4 bytes long; otherwise, an exception will be raised.

        Parameters:
        - data (bytes): The byte data containing the packed 32-bit value.

        Returns:
        - WorldClientPktHeader: A dataclass instance containing the unpacked 'cmd' and 'size'.
        """
        
        try:
            value = struct.unpack('<I', data[:4])[0]
            cmd = value & 0x1FFF
            size = (value & 0xFFFFE000) >> 13
            return WorldClientPktHeader(cmd=cmd, size=size)
        except Exception as e:
            Logger.error(f"Failed to unpack data: {e}. Returning placeholder header.")
            return WorldClientPktHeader(cmd=0, size=0)