#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Utility helpers for interpretation: JSON normalization and DSL decode."""

from typing import Any, Dict, Optional

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.PacketDump import dump_capture
from DSL.modules.DslRuntime import DslRuntime


cfg = ConfigLoader.load_config()
cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"

_dsl_runtime: Optional[DslRuntime] = None


# ------------------------------------------------------------------
# DSL RUNTIME
# ------------------------------------------------------------------

def set_dsl_runtime(runtime: Optional[DslRuntime]) -> None:
    """Inject shared DSL runtime."""
    global _dsl_runtime
    _dsl_runtime = runtime


def _get_dsl_runtime() -> DslRuntime:
    """Lazy init of DSL runtime."""
    global _dsl_runtime

    if _dsl_runtime is None:
        try:
            # No program/version dependency anymore
            rt = DslRuntime(watch=True)
            rt.load_runtime_all()
            _dsl_runtime = rt
            Logger.info("[DSL] Runtime ready (watch enabled)")
        except Exception as exc:
            Logger.error(f"[DSL] Runtime init failed (watch disabled): {exc}")
            rt = DslRuntime(watch=False)
            rt.load_runtime_all()
            _dsl_runtime = rt

    return _dsl_runtime


# ------------------------------------------------------------------
# DSL DECODE
# ------------------------------------------------------------------

def dsl_decode(def_name: str, payload: bytes, silent: bool = False) -> Dict[str, Any]:
    """Safe DSL decode."""
    try:
        rt = _get_dsl_runtime()
        return rt.decode(def_name, payload, silent=silent)
    except Exception as exc:
        if not silent:
            Logger.error(f"[DSL] decode {def_name} failed: {exc}")
        return {}


# ------------------------------------------------------------------
# JSON NORMALIZATION
# ------------------------------------------------------------------

def to_safe_json(value: Any, key: Optional[str] = None) -> Any:
    """
    Convert DSL output to JSON-safe format.
    """
    if isinstance(value, int):
        if key and "guid" in key.lower():
            hexstr = hex(value)[2:]
            if len(hexstr) % 2:
                hexstr = "0" + hexstr
            return "0x" + hexstr.upper()
        return value

    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()

    if isinstance(value, dict):
        return {k: to_safe_json(v, k) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [to_safe_json(v, key) for v in value]

    return value


# ------------------------------------------------------------------
# WORLD HEADER HELPERS
# ------------------------------------------------------------------

def build_world_header(opcode: int, payload: bytes) -> bytes:
    """Compressed world header."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    size = len(payload) + 2
    raw = ((size & 0x7FFFF) << 13) | (opcode & 0x1FFF)
    return raw.to_bytes(4, "little")


def build_world_header_plain(opcode: int, payload: bytes) -> bytes:
    """Plain (non-compressed) world header."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    size = len(payload) + 2
    return size.to_bytes(2, "little") + opcode.to_bytes(2, "little")
