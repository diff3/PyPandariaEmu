#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from pathlib import Path

from server.modules.handlers.world.protocol.update_object.serializers import (
    build_fixed_u32_field_block,
)


def _login_handlers():
    from server.modules.handlers.world.opcodes import login as login_handlers

    return login_handlers


def _build_world_login_context(session):
    return _login_handlers()._build_world_login_context(session)


def load_sniff_payload(filepath: str | Path) -> bytes:
    path = Path(filepath)
    data = json.loads(path.read_text(encoding="utf-8"))

    payload_hex = data.get("hex_compact") or data.get("hex_spaced")
    if payload_hex:
        return bytes.fromhex(payload_hex.replace(" ", ""))

    raw_hex = data.get("raw_data_hex")
    header_hex = data.get("raw_header_hex")
    if not raw_hex or not header_hex:
        raise RuntimeError(f"Missing payload data in {path}")
    raw_bytes = bytes.fromhex(raw_hex.replace(" ", ""))
    header_len = len(bytes.fromhex(header_hex.replace(" ", "")))
    return raw_bytes[header_len:]


def _build_fixed_u32_field_block(fields: dict[int, int], *, mask_blocks: int = 1) -> tuple[bytes, bytes]:
    return build_fixed_u32_field_block(fields, mask_blocks=mask_blocks)
