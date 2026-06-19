#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import struct

from DSL.modules.bitsHandler import BitWriter


def _session_guid(session) -> int:
    return int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or getattr(session, "char_guid", 0)
        or 0
    ) & 0xFFFFFFFFFFFFFFFF


def _guid_bytes(guid: int) -> list[int]:
    value = int(guid) & 0xFFFFFFFFFFFFFFFF
    return [(value >> (index * 8)) & 0xFF for index in range(8)]


def build_pet_battle_queue_status_payload(session, *, status: int) -> bytes:
    guid_bytes = _guid_bytes(_session_guid(session))
    writer = BitWriter()

    for index in (7, 2, 6, 1):
        writer.write_bit(1 if guid_bytes[index] else 0)
    writer.write_bit(0)  # hasAverageWaitTime
    writer.write_bit(1 if guid_bytes[4] else 0)
    writer.write_bits(0, 22)
    writer.write_bit(1 if guid_bytes[0] else 0)
    writer.write_bit(0)  # hasClientWaitTime
    for index in (3, 5):
        writer.write_bit(1 if guid_bytes[index] else 0)

    payload = bytearray(writer.flush())
    payload += bytes([guid_bytes[2], guid_bytes[4]])
    payload += struct.pack("<I", 0)  # CliRideTicket.Time
    payload += bytes([guid_bytes[3]])
    payload += struct.pack("<I", int(status) & 0xFFFFFFFF)
    payload += bytes([guid_bytes[6]])
    payload += bytes([guid_bytes[1]])
    payload += struct.pack("<I", 0)  # CliRideTicket.Type
    payload += bytes([guid_bytes[5], guid_bytes[7]])
    payload += struct.pack("<I", 0)  # CliRideTicket.Id
    payload += bytes([guid_bytes[0]])

    for _ in range(3):
        payload += struct.pack("<I", 1)  # SlotResult

    return bytes(payload)


def build_battle_pet_location_finalize_payload(session) -> bytes:
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)

    payload = bytearray()
    payload += struct.pack("<f", x)
    payload += struct.pack("<f", y)

    for _ in range(2):
        payload += struct.pack("<f", y)
        payload += struct.pack("<f", x)
        payload += struct.pack("<f", z)

    payload += struct.pack("<f", z)

    writer = BitWriter()
    writer.write_bit(0)  # hasOrientation
    writer.write_bit(0)  # hasLocationResult
    payload += writer.flush()
    return bytes(payload)
