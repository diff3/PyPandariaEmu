#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ARC4 header encryption helpers for WoW world traffic.

This module implements the ARC4 stream setup used for WoW world packet headers.
Only the 4-byte headers are encrypted; payloads remain plaintext.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import ARC4

from shared.Logger import Logger


@dataclass
class WorldClientPktHeader:
    """Unpacked world header fields."""

    cmd: int
    size: int


class Arc4CryptoHandler:
    """ARC4 stream helper for world header encryption/decryption."""

    _serverEncrypt: Optional[ARC4.ARC4Cipher] = None
    _clientDecrypt: Optional[ARC4.ARC4Cipher] = None

    ARC4_DROP_BYTES = 1024

    SERVER_ENCRYPTION_KEY = bytes([
        0x08, 0xF1, 0x95, 0x9F, 0x47, 0xE5, 0xD2, 0xDB,
        0xA1, 0x3D, 0x77, 0x8F, 0x3F, 0x3E, 0xE7, 0x00
    ])

    SERVER_DECRYPTION_KEY = bytes([
        0x40, 0xAA, 0xD3, 0x92, 0x26, 0x71, 0x43, 0x47,
        0x3A, 0x31, 0x08, 0xA6, 0xE7, 0xDC, 0x98, 0x2A
    ])

    def __init__(self) -> None:
        """Initialize an empty ARC4 context."""
        return None

    def init_arc4(self, K: str) -> None:
        """Initialize ARC4 streams from a session key hex string.

        Args:
            K (str): Session key hex string (SRP6-derived).
        """
        try:
            key_bytes = bytes.fromhex(K)
        except ValueError:
            raise ValueError(f"Invalid session key hex string: {K}")

        # Direction-specific keys are derived via HMAC-SHA1.
        encrypt_hash = hmac.new(self.SERVER_ENCRYPTION_KEY, key_bytes, hashlib.sha1).digest()
        decrypt_hash = hmac.new(self.SERVER_DECRYPTION_KEY, key_bytes, hashlib.sha1).digest()

        # ARC4 drop protects against weak initial keystream output.
        self._serverEncrypt = ARC4.new(key=encrypt_hash, drop=self.ARC4_DROP_BYTES)
        self._clientDecrypt = ARC4.new(key=decrypt_hash, drop=self.ARC4_DROP_BYTES)

    def decrypt_recv(self, header: bytes) -> bytes:
        """Decrypt a client→server header."""
        try:
            return self._clientDecrypt.decrypt(header)  # type: ignore[union-attr]
        except Exception as e:
            Logger.error(f"Decryption failed: {e}. Returning original header.")
            return header

    def encrypt_send(self, header: bytes) -> bytes:
        """Decrypt a server→client header using the outbound stream."""
        try:
            return self._serverEncrypt.encrypt(header)  # type: ignore[union-attr]
        except Exception as e:
            Logger.error(f"Encryption failed: {e}. Returning original header.")
            return header

    def pack_data(self, cmd: int, size: int) -> Optional[bytes]:
        """Pack a world header (size/cmd) into 4 bytes little-endian."""
        try:
            value = (size << 13) | (cmd & 0x1FFF)
            packed_data = struct.pack('<I', value)
            return packed_data
        except Exception as e:
            Logger.error(f"Error while packing: {e}")
            return None

    def unpack_data(self, data: bytes) -> WorldClientPktHeader:
        """Unpack a 4-byte world header into cmd and size."""
        try:
            value = struct.unpack('<I', data[:4])[0]
            cmd = value & 0x1FFF
            size = (value & 0xFFFFE000) >> 13
            return WorldClientPktHeader(cmd=cmd, size=size)
        except Exception as e:
            Logger.error(f"Failed to unpack data: {e}. Returning placeholder header.")
            return WorldClientPktHeader(cmd=0, size=0)
