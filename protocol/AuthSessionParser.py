#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from protocol.BitReader import BitReader


class AuthSessionParser:
    """Parser for CMSG_AUTH_SESSION packets."""
    
    def __init__(self, raw_data: bytes):
        self.raw_data = raw_data
        self.parsed_data = {}

    def parse(self) -> dict:
        """Parses the raw binary data and extracts session information."""
        digest = ["00"] * 20  # Initialize digest array with placeholder values

        # Extract key values from packet
        digest[18] = f"{self.raw_data[10]:02X}"
        digest[14] = f"{self.raw_data[11]:02X}"
        digest[3] = f"{self.raw_data[12]:02X}"
        digest[4] = f"{self.raw_data[13]:02X}"
        digest[0] = f"{self.raw_data[14]:02X}"

        self.parsed_data["virtual_realm_id"] = int.from_bytes(self.raw_data[15:19], byteorder='little')
        digest[11] = f"{self.raw_data[19]:02X}"
        self.parsed_data["client_seed"] = int.from_bytes(self.raw_data[20:24], byteorder='little')
        digest[19] = f"{self.raw_data[24]:02X}"

        # Additional extracted values
        digest[2] = f"{self.raw_data[27]:02X}"
        digest[9] = f"{self.raw_data[28]:02X}"
        digest[12] = f"{self.raw_data[29]:02X}"

        digest[16] = f"{self.raw_data[42]:02X}"
        digest[5] = f"{self.raw_data[43]:02X}"
        digest[6] = f"{self.raw_data[44]:02X}"
        digest[8] = f"{self.raw_data[45]:02X}"
        self.parsed_data["client_build"] = int.from_bytes(self.raw_data[46:48], byteorder='little')
        digest[17] = f"{self.raw_data[48]:02X}"
        digest[7] = f"{self.raw_data[49]:02X}"
        digest[13] = f"{self.raw_data[50]:02X}"
        digest[15] = f"{self.raw_data[51]:02X}"
        digest[1] = f"{self.raw_data[52]:02X}"
        digest[10] = f"{self.raw_data[53]:02X}"

        # Extract addon data
        addon_size = int.from_bytes(self.raw_data[54:58], byteorder='little')
        addon_data_start = 58
        addon_data_end = addon_data_start + addon_size
        self.parsed_data["addon_size"] = addon_size
        self.parsed_data["addon_data"] = self.raw_data[addon_data_start:addon_data_end]

        # Extract account name
        remaining_data = self.raw_data[addon_data_end:]
        bit_reader = BitReader(remaining_data)
        bit_reader.read_bit()  # Skip first flag bit
        account_name_length = bit_reader.read_bits(11)
        self.parsed_data["username"] = remaining_data[2:2 + account_name_length].decode('utf-8')

        # Save digest as hex string
        self.parsed_data["digest"] = "".join(digest)

        return self.parsed_data