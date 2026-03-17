#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Plain world packet parsing helpers (pre-ARC4)."""

from typing import Any, List, Optional, Tuple


def parse_header(header: bytes) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """
    Parse a plaintext world header (size/opcode, little-endian).

    Returns:
        (size, opcode, hex_opcode) or (None, None, None) if invalid.
    """
    if len(header) < 4:
        return None, None, None
    size = int.from_bytes(header[0:2], "little")
    opcode = int.from_bytes(header[2:4], "little")
    return size, opcode, f"0x{opcode:04X}"

def parse_world_header(header: bytes):
    """
    MoP world header (packed uint32):
        bits  0–12  opcode
        bits 13–31  size
    """
    if len(header) != 4:
        return None, None, None

    raw = int.from_bytes(header, "little")
    opcode = raw & 0x1FFF
    size = raw >> 13

    if opcode == 0 and size == 0:
        return None, None, None

    return size, opcode, f"0x{opcode:04X}"




def parse_plain_packets(raw_data: bytes, direction: str) -> List[Tuple[bytes, Any, bytes]]:
    """
    Parse plaintext world packets before ARC4 is active.

    Mimics the legacy `parse_multi_header_payloads`:
      - No persistent buffer.
      - Allows payload shorter than header size.
      - Returns list of (orig_header, header_obj, payload).
    """
    _ = direction  # kept for API parity; currently unused
    packets: List[Tuple[bytes, Any, bytes]] = []

    while raw_data:
        if len(raw_data) < 4:
            break

        header = raw_data[:4]
        orig = header

        # Handshake special-case: emit whole buffer as one packet
        if b"WORLD OF WARCRAFT" in raw_data:
            class Header: ...

            h = Header()
            h.size = len(raw_data)
            h.cmd = -1
            h.hex = "HANDSHAKE"
            h.header_raw = header
            packets.append((orig, h, raw_data))
            break

        size, cmd, hexop = parse_header(header)
        if size is None:
            break

        # Header size includes opcode (2 bytes) in plain mode
        adj_size = max(0, size - 2)
        # MoP special: SMSG_AUTH_RESPONSE size includes full header
        if cmd == 0x01F6:
            adj_size = max(0, size - 4)

        payload = raw_data[4:4 + adj_size]  # may be shorter than adj_size
        raw_data = raw_data[4 + adj_size:]

        class Header: ...

        h = Header()
        h.size = adj_size
        h.cmd = cmd
        h.hex = hexop
        h.header_raw = header

        packets.append((orig, h, payload))

    return packets
