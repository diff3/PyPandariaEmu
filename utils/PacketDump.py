#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
from itertools import count
from pathlib import Path
from threading import Lock
from datetime import datetime
from utils.ConfigLoader import ConfigLoader
from utils.PathUtils import get_captures_root
from protocols.wow.shared.modules.crypto.ARC4Crypto import Arc4CryptoHandler


_focus_capture_counter = count(1)
_focus_capture_counter_lock = Lock()


def bytes_to_spaced_hex(data: bytes) -> str:
    h = data.hex().upper()
    return " ".join(a + b for a, b in zip(h[0::2], h[1::2]))


def bytes_to_bits(data: bytes) -> str:
    return " ".join(f"{b:08b}" for b in data)


def bytes_to_hex_offsets(data: bytes, width=16):
    out = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset+width]

        hex_part = " ".join(f"{b:02X}" for b in chunk)
        pad = "   " * (width - len(chunk))
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)

        out.append(f"{offset:04X}: {hex_part}{pad}  {ascii_part}")

    return out


def bytes_to_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def parse_world_header(raw_header: bytes, payload_len: int = None):
    """
    Supports both plain (size, opcode) and bitpacked (size<<13 | opcode) headers.
    Chooses a mode heuristically based on payload length when available.
    Uses Arc4CryptoHandler.unpack_data for bitpacked parsing to stay aligned with crypto.
    """
    # Auth packets use 1-byte opcode; handle gracefully.
    if len(raw_header) == 1:
        opcode = raw_header[0]
        return {
            "mode": "auth1b",
            "size": payload_len,
            "opcode": opcode,
            "size_plain": payload_len,
            "opcode_plain": opcode,
            "size_packed": payload_len,
            "opcode_packed": opcode,
        }

    if len(raw_header) < 4:
        return {
            "mode": "unknown",
            "size": None,
            "opcode": None,
            "size_plain": None,
            "opcode_plain": None,
            "size_packed": None,
            "opcode_packed": None,
        }

    value = int.from_bytes(raw_header[:4], "little")
    size_plain = int.from_bytes(raw_header[0:2], "little")
    opcode_plain = int.from_bytes(raw_header[2:4], "little")

    try:
        unpacked = Arc4CryptoHandler().unpack_data(raw_header)
        opcode_packed = unpacked.cmd
        size_packed = unpacked.size
    except Exception:
        opcode_packed = value & 0x1FFF
        size_packed = value >> 13

    mode = "packed" if size_packed > 0 else "plain"
    if payload_len is not None:
        if size_packed == payload_len and size_plain != payload_len:
            mode = "packed"
        elif size_plain == payload_len and size_packed != payload_len:
            mode = "plain"

    opcode = opcode_packed if mode == "packed" else opcode_plain
    size = size_packed if mode == "packed" else size_plain

    return {
        "mode": mode,
        "size": size,
        "opcode": opcode,
        "size_plain": size_plain,
        "opcode_plain": opcode_plain,
        "size_packed": size_packed,
        "opcode_packed": opcode_packed,
    }


class PacketDump:
    """Handles writing of:
       - raw bin
       - parsed json
       - debug json (hex/ascii/offsets/bits)
    """

    def __init__(self, root):
        self.root = Path(root)
        (self.root / "json").mkdir(parents=True, exist_ok=True)
        (self.root / "debug").mkdir(parents=True, exist_ok=True)

        cfg = ConfigLoader.load_config()
        self.program = cfg.get("program")
        self.expansion = cfg.get("expansion")
        self.version = cfg.get("version")

    # -----------------------------------------------------

    def dump_bin(self, name: str, ts: int, data: bytes) -> None:
        """Binary dumps are disabled; debug JSON contains raw payload data."""
        return None

    # -----------------------------------------------------

    def dump_json(self, name: str, ts: int, decoded: dict) -> Path:
        path = self.root / "json" / f"{ts}_{name}.json"
        path.write_text(json.dumps(decoded, indent=2))
        return path

    # -----------------------------------------------------
    # UPDATED: now accepts raw_header + payload
    # -----------------------------------------------------

    def dump_debug(self, name: str, ts: int, raw_header: bytes, payload: bytes) -> Path:
        full = raw_header + payload

        header_info = parse_world_header(raw_header, len(payload))
        opcode = header_info["opcode"]
        size = header_info["size"]
        payload_len = len(payload)

        opcode_hex = f"0x{opcode:04X}" if opcode is not None else None
        size_hex = f"0x{size:04X}" if size is not None else None

        info = {
            "name": name,
            "program": self.program,
            "expansion": self.expansion,
            "version": self.version,
            "timestamp_ms": ts,
            "timestamp_iso": datetime.fromtimestamp(ts / 1000).isoformat(),

            # NEW FIELDS
            "raw_header_hex": bytes_to_spaced_hex(raw_header),
            "raw_opcode_int": opcode,
            "raw_opcode_hex": opcode_hex,
            "raw_size_int": size,
            "raw_size_hex": size_hex,
            "header_mode": header_info["mode"],
            "opcode_plain": header_info["opcode_plain"],
            "opcode_packed": header_info["opcode_packed"],
            "size_plain": header_info["size_plain"],
            "size_packed": header_info["size_packed"],
            "payload_len": payload_len,
            "size_matches_payload": (size == payload_len) if size is not None else None,
            "raw_data_hex": bytes_to_spaced_hex(full),
            "raw_data_bytes": repr(full),

            # OLD FIELDS
            "hex_spaced": bytes_to_spaced_hex(payload),
            "hex_compact": payload.hex().upper(),
            "hex_offsets": bytes_to_hex_offsets(payload),
            "ascii": bytes_to_ascii(payload),
            "bits": bytes_to_bits(payload),
            "size_bytes": len(payload),
        }

        path = self.root / "debug" / f"{ts}_{name}.json"
        path.write_text(json.dumps(info, indent=2))
        return path

    # -----------------------------------------------------
    def dump_fixed(self, case_name: str, raw_header: bytes, payload: bytes, decoded: dict):
        """
        Write expected JSON/debug under protocols/... (no timestamps).
        """
        # bin (disabled)
        bin_path = None

        # json
        json_path = self.root / "json" / f"{case_name}.json"
        json_path.write_text(json.dumps(decoded, indent=2))

        # debug
        full = raw_header + payload
        header_info = parse_world_header(raw_header, len(payload))
        opcode = header_info["opcode"]
        size = header_info["size"]
        payload_len = len(payload)

        opcode_hex = f"0x{opcode:04X}" if opcode is not None else None
        size_hex = f"0x{size:04X}" if size is not None else None

        dbg = {
            "name": case_name,
            "program": self.program,
            "expansion": self.expansion,
            "version": self.version,
            "timestamp_ms": None,
            "timestamp_iso": None,

            "raw_header_hex": bytes_to_spaced_hex(raw_header),
            "raw_opcode_int": opcode,
            "raw_opcode_hex": opcode_hex,
            "raw_size_int": size,
            "raw_size_hex": size_hex,
            "header_mode": header_info["mode"],
            "opcode_plain": header_info["opcode_plain"],
            "opcode_packed": header_info["opcode_packed"],
            "size_plain": header_info["size_plain"],
            "size_packed": header_info["size_packed"],
            "payload_len": payload_len,
            "size_matches_payload": (size == payload_len) if size is not None else None,
            "raw_data_hex": bytes_to_spaced_hex(full),
            "raw_data_bytes": repr(full),

            "hex_spaced": bytes_to_spaced_hex(payload),
            "hex_compact": payload.hex().upper(),
            "hex_offsets": bytes_to_hex_offsets(payload),
            "ascii": bytes_to_ascii(payload),
            "bits": bytes_to_bits(payload),
            "size_bytes": len(payload),
        }

        dbg_path = self.root / "debug" / f"{case_name}.json"
        dbg_path.write_text(json.dumps(dbg, indent=2))

        return bin_path, json_path, dbg_path


# ==============================================================
# CAPTURE DUMPER — writes into protocol-specific captures
# ==============================================================

def dump_capture(
    case_name: str,
    raw_header: bytes,
    payload: bytes,
    decoded: dict,
    root: str | Path | None = None,
    ts: int | None = None,
    debug_only: bool = False,
):
    root = Path(root) if root else get_captures_root()
    (root / "json").mkdir(parents=True, exist_ok=True)
    (root / "debug").mkdir(parents=True, exist_ok=True)

    full = raw_header + payload
    header_info = parse_world_header(raw_header, len(payload))
    opcode = header_info["opcode"]
    size = header_info["size"]
    payload_len = len(payload)
    opcode_hex = f"0x{opcode:04X}" if opcode is not None else None
    size_hex = f"0x{size:04X}" if size is not None else None

    cfg = ConfigLoader.load_config()
    program = cfg.get("program")
    expansion = cfg.get("expansion")
    version = cfg.get("version")

    # Use timestamped names when provided (focus-dump), otherwise legacy name.
    ts = ts if ts is not None else None
    if ts is None:
        suffix = f"{case_name}.json"
    else:
        with _focus_capture_counter_lock:
            counter_value = next(_focus_capture_counter)
            suffix = f"{case_name}_{ts}_{counter_value:04d}.json"
            while (root / "debug" / suffix).exists() or (root / "json" / suffix).exists():
                counter_value = next(_focus_capture_counter)
                suffix = f"{case_name}_{ts}_{counter_value:04d}.json"

    bin_path = None
    json_path = root / "json" / suffix
    dbg_path = root / "debug" / suffix

    if not debug_only:
        json_path.write_text(json.dumps(decoded, indent=2))


    dbg = {
        "name": case_name,
        "program": program,
        "expansion": expansion,
        "version": version,

        "raw_header_hex": bytes_to_spaced_hex(raw_header),
        "raw_opcode_int": opcode,
        "raw_opcode_hex": opcode_hex,
        "raw_size_int": size,
        "raw_size_hex": size_hex,
        "header_mode": header_info["mode"],
        "opcode_plain": header_info["opcode_plain"],
        "opcode_packed": header_info["opcode_packed"],
        "size_plain": header_info["size_plain"],
        "size_packed": header_info["size_packed"],
        "payload_len": payload_len,
        "size_matches_payload": (size == payload_len) if size is not None else None,
        "raw_data_hex": bytes_to_spaced_hex(full),
        "raw_data_bytes": repr(full),

        "hex_spaced": bytes_to_spaced_hex(payload),
        "hex_compact": payload.hex().upper(),
        "hex_offsets": bytes_to_hex_offsets(payload),
        "ascii": bytes_to_ascii(payload),
        "bits": bytes_to_bits(payload),
        "size_bytes": len(payload),
    }

    dbg_path.write_text(json.dumps(dbg, indent=2))
    return bin_path, json_path, dbg_path
