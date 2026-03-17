#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Encrypted world stream parser for ARC4-wrapped headers."""

from typing import Any, Dict, List, Optional, Tuple
from shared.Logger import Logger


class EncryptedWorldStream:
    """Incrementally parses ARC4-encrypted world headers and payloads."""

    AUTH_RESPONSE_OPCODE = 0x01F6

    def __init__(self) -> None:
        """Initialize per-direction pending header state."""
        self._pending: Dict[str, Optional[Dict[str, Any]]] = {"C": None, "S": None}

    def feed(self, raw_buf: bytearray, *, crypto, direction: str) -> List[Tuple[bytes, Any, bytes]]:
        """
        Consume bytes from an encrypted stream and emit complete packets.

        Args:
            raw_buf: Buffer containing encrypted data; consumed in-place.
            crypto: ARC4 handler with decrypt/encrypt helpers.
            direction: 'C' for client→server, 'S' for server→client.

        Returns:
            List of tuples: (raw_header, header_obj, payload).
        """
        packets: List[Tuple[bytes, Any, bytes]] = []

        while True:
            pending = self._pending[direction]

            if pending is None:
                if len(raw_buf) < 4:
                    break

                enc_header = bytes(raw_buf[:4])
                del raw_buf[:4]

                dec_header = (
                    crypto.decrypt_recv(enc_header)
                    if direction == "C"
                    else crypto.encrypt_send(enc_header)
                )

                header = crypto.unpack_data(dec_header)
                size = header.size
                cmd = header.cmd

                if cmd == self.AUTH_RESPONSE_OPCODE:
                    size = max(0, size - 4)

                self._pending[direction] = {
                    "size": size,
                    "cmd": cmd,
                    "raw": dec_header,
                }
                pending = self._pending[direction]

            size = pending["size"]
            if len(raw_buf) < size:
                break

            payload = bytes(raw_buf[:size])
            del raw_buf[:size]

            class Header:
                pass

            h = Header()
            h.size = size
            h.cmd = pending["cmd"]
            h.hex = f"0x{h.cmd:04X}"
            h.header_raw = pending["raw"]

            packets.append((h.header_raw, h, payload))
            self._pending[direction] = None

        return packets


class ClientWorldStream:
    """
    World stream parser for a real client.
    - Headers are ARC4-decrypted (recv)
    - Payloads are plaintext
    """

    AUTH_RESPONSE_OPCODE = 0x01F6

    def __init__(self):
        self._pending = None

    def feed(self, raw_buf: bytearray, *, crypto, direction: str = "S"):
        packets = []

        while True:
            if self._pending is None:
                if len(raw_buf) < 4:
                    break

                enc_header = bytes(raw_buf[:4])
                del raw_buf[:4]

                # CLIENT ONLY: decrypt direction-aware (S→C uses encrypt_send stream)
                dec_header = (
                    crypto.encrypt_send(enc_header)
                    if direction == "S"
                    else crypto.decrypt_recv(enc_header)
                )

                header = crypto.unpack_data(dec_header)
                size = header.size
                cmd = header.cmd

                if cmd == self.AUTH_RESPONSE_OPCODE:
                    size = max(0, size - 4)

                self._pending = {
                    "size": size,
                    "cmd": cmd,
                    "raw": dec_header,
                }

            size = self._pending["size"]
            if len(raw_buf) < size:
                break

            payload = bytes(raw_buf[:size])
            del raw_buf[:size]

            class Header:
                pass

            h = Header()
            h.size = size
            h.cmd = self._pending["cmd"]
            h.hex = f"0x{h.cmd:04X}"
            h.header_raw = self._pending["raw"]

            packets.append((h.header_raw, h, payload))
            self._pending = None

        return packets
