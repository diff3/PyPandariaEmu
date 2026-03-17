#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Opcode resolution helper for world proxy/interpretation."""

from typing import Mapping, Any


class OpcodeResolver:
    """Resolves opcode integers to human-readable names for each direction."""

    def __init__(self, client_opcodes: Mapping[int, str] | None, server_opcodes: Mapping[int, str] | None, world_lookup: Any) -> None:
        """
        Initialize lookup sources.

        Args:
            client_opcodes: Mapping of client opcode ints to names.
            server_opcodes: Mapping of server opcode ints to names.
            world_lookup: Object with WorldOpcodes accessors for fallback resolution.
        """
        self.client_opcodes = client_opcodes
        self.server_opcodes = server_opcodes
        self.world_lookup = world_lookup

    def decode_opcode(self, opcode: int, direction: str) -> str:
        """
        Resolve an opcode to its name based on direction.

        Args:
            opcode: Opcode integer from packet header.
            direction: 'C' for client→server, 'S' for server→client.

        Returns:
            Resolved opcode name, or UNKNOWN_* string if not found.
        """
        if direction == "C":
            if self.client_opcodes and opcode in self.client_opcodes:
                return self.client_opcodes[opcode]
            try:
                return self.world_lookup.WorldOpcodes.getClientOpCodeName(opcode)
            except Exception:
                return f"UNKNOWN_CMSG_0x{opcode:04X}"

        if self.server_opcodes and opcode in self.server_opcodes:
            return self.server_opcodes[opcode]
        try:
            return self.world_lookup.WorldOpcodes.getServerOpCodeName(opcode)
        except Exception:
            return f"UNKNOWN_SMSG_0x{opcode:04X}"
