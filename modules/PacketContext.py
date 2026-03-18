#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PacketContext:
    sock: Any
    direction: str
    opcode: int
    name: str
    payload: bytes
    decoded: dict[str, Any] = field(default_factory=dict)
    session: Any = None
    account_id: int | None = None
    realm_id: int | None = None


def has_decoded(ctx: PacketContext) -> bool:
    return bool(ctx.decoded)
