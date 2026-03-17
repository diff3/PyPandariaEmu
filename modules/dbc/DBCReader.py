#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable

from shared.Logger import Logger


_DBC_MAGIC = b"WDBC"


def _read_header(f) -> tuple[int, int, int, int]:
    header = f.read(4)
    if header != _DBC_MAGIC:
        raise RuntimeError(f"Invalid DBC header: {header!r}")
    return struct.unpack("<4I", f.read(16))


def _read_string_block(f, size: int) -> bytes:
    if size <= 0:
        return b""
    return f.read(size)


def _decode_string(block: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(block):
        return ""
    end = block.find(b"\x00", offset)
    if end == -1:
        end = len(block)
    return block[offset:end].decode("utf-8", errors="ignore")


def _parse_record(data: bytes, fmt: str, string_block: bytes | None) -> list:
    offset = 0
    values: list = []
    for ch in fmt:
        if ch == "b":
            values.append(struct.unpack_from("<B", data, offset)[0])
            offset += 1
        elif ch == "X":
            offset += 1
        elif ch in ("i", "d", "n"):
            values.append(struct.unpack_from("<i", data, offset)[0])
            offset += 4
        elif ch == "f":
            values.append(struct.unpack_from("<f", data, offset)[0])
            offset += 4
        elif ch == "s":
            raw_offset = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if string_block is None:
                values.append(raw_offset)
            else:
                values.append(_decode_string(string_block, raw_offset))
        elif ch == "x":
            offset += 4
        else:
            raise RuntimeError(f"Unsupported DBC format char: {ch}")
    return values


def read_dbc(path: str | Path, fmt: str) -> list[list]:
    """
    Read a WDBC file using a SkyFire-style DBC format string.

    Format chars:
      b: uint8
      X: skip uint8
      i/d/n: int32 (d/n are treated like i)
      f: float32
      s: string offset (resolved via string block)
      x: skip uint32
    """
    dbc_path = Path(path)
    with dbc_path.open("rb") as f:
        record_count, field_count, record_size, string_block_size = _read_header(f)
        if field_count != len(fmt):
            Logger.warning(
                f"[DBC] Field count mismatch: header={field_count}, fmt={len(fmt)}"
            )

        records: list[list] = []
        for _ in range(record_count):
            data = f.read(record_size)
            if len(data) != record_size:
                raise RuntimeError("Unexpected EOF while reading DBC records.")
            records.append(_parse_record(data, fmt, None))

        string_block = _read_string_block(f, string_block_size)

    if "s" in fmt:
        resolved = []
        for record in records:
            resolved_record = []
            for value, ch in zip(record, fmt):
                if ch == "s":
                    resolved_record.append(_decode_string(string_block, int(value)))
                else:
                    resolved_record.append(value)
            resolved.append(resolved_record)
        return resolved

    return records


def iter_records(path: str | Path, fmt: str) -> Iterable[list]:
    """Yield records without loading all into memory."""
    dbc_path = Path(path)
    with dbc_path.open("rb") as f:
        record_count, field_count, record_size, string_block_size = _read_header(f)
        if field_count != len(fmt):
            Logger.warning(
                f"[DBC] Field count mismatch: header={field_count}, fmt={len(fmt)}"
            )

        records = []
        for _ in range(record_count):
            data = f.read(record_size)
            if len(data) != record_size:
                raise RuntimeError("Unexpected EOF while reading DBC records.")
            records.append(_parse_record(data, fmt, None))

        string_block = _read_string_block(f, string_block_size)

    if "s" in fmt:
        for record in records:
            resolved = []
            for value, ch in zip(record, fmt):
                if ch == "s":
                    resolved.append(_decode_string(string_block, int(value)))
                else:
                    resolved.append(value)
            yield resolved
    else:
        for record in records:
            yield record
