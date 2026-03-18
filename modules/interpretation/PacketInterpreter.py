#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Packet interpretation helpers: decode, normalize, and dump."""

import time
from typing import Any, Iterable, Optional

from server.modules.interpretation.utils import dump_capture, to_safe_json, dsl_decode, initialize_dsl_runtime
from shared.PathUtils import get_captures_root


class PacketInterpreter:
    """Coordinates decoding, normalization, and optional dumping of packets."""

    def __init__(self, decoder: "DslDecoder", normalizer: "JsonNormalizer", policy: "DumpPolicy", dumper: "PacketDumper") -> None:
        """Initialize interpreter with collaborators."""
        self.decoder = decoder
        self.normalizer = normalizer
        self.policy = policy
        self.dumper = dumper

    def interpret(self, name: str, raw_header: bytes, payload: bytes, policy: "DumpPolicy" = None) -> dict:
        """
        Decode and normalize a packet, then dump/update if policy allows.

        Args:
            name: Packet name (opcode resolved).
            raw_header: Raw header bytes.
            payload: Raw payload bytes.

        Returns:
            JSON-safe decoded structure.
        """
        active_policy = policy or self.policy
        decoded = self.decoder.decode(name, payload)
        safe = self.normalizer.normalize(decoded)

        if active_policy.allows(name):
            if active_policy.update:
                self.dumper.update(name, raw_header, payload, safe)
            if active_policy.dump or active_policy.focus_dump is not None:
                # Focus mode: dump into the configured capture root with timestamped debug JSON.
                root = get_captures_root(focus=True) if active_policy.focus_dump is not None else None
                ts = active_policy.timestamp() if active_policy.focus_dump is not None else None
                debug_only = active_policy.focus_dump is not None
                self.dumper.dump(name, raw_header, payload, safe, root=root, ts=ts, debug_only=debug_only)

        return safe


class PacketDumper:
    """Wraps dump/update operations for decoded packets."""

    def __init__(self, dumper: Any) -> None:
        self.dumper = dumper

    def dump(self, name: str, raw_header: bytes, payload: bytes, safe: dict, *, root=None, ts=None, debug_only: bool = False) -> None:
        dump_capture(name, raw_header, payload, safe, root=root, ts=ts, debug_only=debug_only)

    def update(self, name: str, raw_header: bytes, payload: bytes, safe: dict) -> None:
        self.dumper.dump_fixed(name, raw_header, payload, safe)


class DumpPolicy:
    """Controls whether packets are dumped or updated."""

    def __init__(self, dump: bool = False, update: bool = False, focus_dump: Optional[Iterable[str]] = None) -> None:
        self.dump = dump
        self.update = update
        self.focus_dump = set(focus_dump) if focus_dump else None

    def allows(self, name: str) -> bool:
        return self.focus_dump is None or name in self.focus_dump

    def timestamp(self) -> int:
        """Return a timestamp for focus dumps."""
        return int(time.time())


class JsonNormalizer:
    """Converts decoded values into JSON-safe structures."""

    def normalize(self, value: Any) -> Any:
        return to_safe_json(value)


class DslDecoder:
    """
    Thin wrapper around DSL decode.
    Forces DSL runtime initialization at construction time.
    """

    def __init__(self):
        initialize_dsl_runtime(watch=True)

    def decode(self, name: str, payload: bytes) -> dict:
        return dsl_decode(name, payload, silent=True) or {}
