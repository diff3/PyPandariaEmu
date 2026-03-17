#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sanity test for encoding/packing CMSG_READY_FOR_ACCOUNT_DATA_TIMES.

Verifies:
  - Payload is empty when encoded via EncoderHandler.
  - Header packing (pack_data) produces the expected opcode/size pair.
  - Unpacking returns the original opcode and size.
"""

import unittest

from modules.dsl.EncoderHandler import EncoderHandler
from protocols.wow.shared.modules.crypto.ARC4Crypto import Arc4CryptoHandler
from utils.ConfigLoader import ConfigLoader
cfg = ConfigLoader.get_config()
cfg["program"] = "wow"
cfg["expansion"] = "mop"
cfg["version"] = "v18414"
world_opcode_module = (
    f"protocols.{cfg['program']}.{cfg.get('expansion')}.{cfg['version']}.modules.opcodes.WorldOpcodes"
)
WorldClientOpcodes = __import__(world_opcode_module, fromlist=["WorldClientOpcodes"]).WorldClientOpcodes


class ReadyForAccountDataTimesTest(unittest.TestCase):
    def test_encode_and_pack(self):
        # Encode the client message; spec has no fields so payload should be empty.
        payload = EncoderHandler.encode_packet("CMSG_READY_FOR_ACCOUNT_DATA_TIMES", {})
        self.assertEqual(payload, b"", "Payload must be empty for READY_FOR_ACCOUNT_DATA_TIMES")

        opcode = WorldClientOpcodes.CMSG_READY_FOR_ACCOUNT_DATA_TIMES

        # Pack header with size=0 (payload only, opcode is part of packed header).
        crypto = Arc4CryptoHandler()
        packed = crypto.pack_data(opcode, len(payload))

        # Unpack should round-trip the opcode and size.
        header = crypto.unpack_data(packed)
        self.assertEqual(header.cmd, opcode, "Opcode should round-trip in packed header")
        self.assertEqual(header.size, 0, "Size should be zero for empty payload")


if __name__ == "__main__":
    unittest.main()
