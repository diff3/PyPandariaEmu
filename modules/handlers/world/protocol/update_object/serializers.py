#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import struct

from server.modules.game.guid import GuidHelper


def u32_from_float(value: float) -> int:
    """Pack a float into the uint32 representation used by update fields."""
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def build_fixed_u32_field_block(
    fields: dict[int, int],
    *,
    mask_blocks: int = 1,
) -> tuple[bytes, bytes]:
    """Build a fixed-size update mask and packed uint32 field payload."""
    if not fields:
        return (b"\x00" * (int(mask_blocks) * 4), b"")

    mask = bytearray(int(mask_blocks) * 4)
    field_bytes = bytearray()
    for field_index in sorted(int(index) for index in fields):
        word_index = field_index // 32
        bit_index = field_index % 32
        current_word = struct.unpack_from("<I", mask, word_index * 4)[0]
        struct.pack_into("<I", mask, word_index * 4, current_word | (1 << bit_index))
        field_bytes += struct.pack("<I", int(fields[field_index]) & 0xFFFFFFFF)
    return bytes(mask), bytes(field_bytes)


def serialize_create_object_entry(
    *,
    guid: int,
    object_type: int,
    create_flags: bytes,
    body: bytes,
    update_type: int = 1,
) -> bytes:
    """Serialize one CREATE_OBJECT entry body for an UPDATE_OBJECT packet."""
    payload = bytearray()
    payload += struct.pack("<B", int(update_type) & 0xFF)
    payload += GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)
    payload += struct.pack("<B", int(object_type) & 0xFF)
    payload += bytes(create_flags)
    payload += bytes(body)
    return bytes(payload)
