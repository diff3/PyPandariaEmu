#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""Utility helpers for interpretation: JSON normalization and DSL decode."""

import importlib
from typing import Any, Dict, Optional

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.PacketDump import dump_capture
from DSL.modules.dsl.DslRuntime import DslRuntime


cfg = ConfigLoader.load_config()
cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"

program = cfg["program"]
expansion = cfg.get("expansion")
version = cfg["version"]

# mod = importlib.import_module(
  #  f"protocols.{program}.{expansion}.{version}.modules.database.DatabaseConnection"
#)

from server.modules.database.DatabaseConnection import DatabaseConnection
# DatabaseConnection = getattr(mod, "DatabaseConnection")

_dsl_runtime: Optional[DslRuntime] = None


def set_dsl_runtime(runtime: Optional[DslRuntime]) -> None:
    """Inject a shared DSL runtime to avoid duplicate initialization."""
    global _dsl_runtime
    _dsl_runtime = runtime


def to_safe_json(value: Any, key: Optional[str] = None) -> Any:
    """
    Convert DSL-returned structures to JSON-safe types.

    - GUID ints become "0xDEADBEEF..."
    - bytes/bytearray become hex strings
    - dicts/lists are normalized recursively
    """
    if isinstance(value, int):
        if key and ("guid" in key.lower()):
            hexstr = hex(value)[2:]
            if len(hexstr) % 2 == 1:
                hexstr = "0" + hexstr
            return "0x" + hexstr.upper()
        return value

    if isinstance(value, (bytearray, bytes)):
        return bytes(value).hex()

    if isinstance(value, dict):
        return {k: to_safe_json(v, k) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [to_safe_json(v, key) for v in value]

    return value


def dsl_decode(def_name: str, payload: bytes, silent: bool = False) -> Dict[str, Any]:
    """
    Safe DSL decoder; expect payload WITHOUT world header (size/opcode).
    Returns {} on failure.
    """
    try:
        rt = _get_dsl_runtime()
        return rt.decode(def_name, payload, silent=silent)
    except Exception as exc:
        if not silent:
            Logger.error(f"[DSL] decode {def_name} failed: {exc}")
        return {}


def _get_dsl_runtime() -> DslRuntime:
    """Lazy init of DSL runtime with cached ASTs and optional watchdog reload."""
    global _dsl_runtime
    if _dsl_runtime is None:
        cfg_local = ConfigLoader.load_config()
        program_local = cfg_local["program"]
        expansion_local = cfg_local.get("expansion")
        version_local = cfg_local["version"]
        try:
            rt = DslRuntime(program_local, version_local, watch=True, expansion=expansion_local)
            rt.load_runtime_all()
            _dsl_runtime = rt
            Logger.info(
                f"[DSL] Runtime ready (watching {program_local}/{expansion_local}/{version_local})"
            )
        except Exception as exc:
            Logger.error(f"[DSL] Failed to init runtime (watch disabled): {exc}")
            rt = DslRuntime(program_local, version_local, watch=False, expansion=expansion_local)
            rt.load_runtime_all()
            _dsl_runtime = rt
    return _dsl_runtime

def build_world_header(opcode: int, payload: bytes) -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    size = len(payload) + 2  # opcode size
    raw = ((size & 0x7FFFF) << 13) | (opcode & 0x1FFF)
    return raw.to_bytes(4, "little")

def build_world_header_plain(opcode: int, payload: bytes) -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    size = len(payload) + 2 # +2 for opcode size
    return size.to_bytes(2, "little") + opcode.to_bytes(2, "little")
