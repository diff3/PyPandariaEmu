#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import importlib
from typing import Any, Dict, Tuple

from shared.ConfigLoader import ConfigLoader


def _ctx() -> Tuple[str, str | None, str]:
    cfg = ConfigLoader.load_config()
    return cfg["program"], cfg.get("expansion"), cfg["version"]


def load_database():
    program, expansion, version = _ctx()
    mod = importlib.import_module(
        f"protocols.{program}.{expansion}.{version}.modules.database.DatabaseConnection"
    )
    return getattr(mod, "DatabaseConnection")


def load_auth_handlers() -> Dict[str, Any]:
    program, expansion, version = _ctx()
    mod = importlib.import_module(
        f"protocols.{program}.{expansion}.{version}.modules.handlers.AuthHandlers"
    )
    return getattr(mod, "opcode_handlers", {})


def load_world_handlers() -> Dict[str, Any]:
    program, expansion, version = _ctx()
    mod = importlib.import_module(
        f"protocols.{program}.{expansion}.{version}.modules.handlers.WorldHandlers"
    )
    print(f"protocols.{program}.{expansion}.{version}.modules.handlers.WorldHandlers")
    return {
        "opcode_handlers": getattr(mod, "opcode_handlers", {}),
        "get_auth_challenge": getattr(mod, "get_auth_challenge", None),
        "reset_state": getattr(mod, "reset_state", None),
        "preload_cache": getattr(mod, "preload_cache", None),
    }


def load_auth_opcodes() -> Tuple[dict, dict, Any]:
    program, expansion, version = _ctx()
    mod = importlib.import_module(
        f"protocols.{program}.{expansion}.{version}.modules.opcodes.AuthOpcodes"
    )
    return (
        getattr(mod, "AUTH_CLIENT_OPCODES", {}),
        getattr(mod, "AUTH_SERVER_OPCODES", {}),
        getattr(mod, "lookup", None),
    )


def load_world_opcodes() -> Tuple[dict, dict, Any]:
    program, expansion, version = _ctx()
    mod = importlib.import_module(
        f"protocols.{program}.{expansion}.{version}.modules.opcodes.WorldOpcodes"
    )
    return (
        getattr(mod, "WORLD_CLIENT_OPCODES", {}),
        getattr(mod, "WORLD_SERVER_OPCODES", {}),
        getattr(mod, "lookup", None),
    )


def get_world_crypto():
    from protocols.wow.shared.modules.crypto.ARC4Crypto import Arc4CryptoHandler

    return Arc4CryptoHandler


def get_world_handshake() -> Tuple[bytes, bytes]:
    return (
        b"0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00",
        b"0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00",
    )


def get_packet_dump():
    from protocols.wow.shared.utils.PacketDump import PacketDump

    return PacketDump
