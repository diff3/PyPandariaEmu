#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class BitReader:
    """Class to read bits from a byte array."""
    def __init__(self, data: bytes):
        self.data = data
        self.byte_pos = 0
        self.bit_pos = 0
        self.cur_byte = self.data[self.byte_pos]

    def read_bit(self) -> int:
        """Reads a single bit from the byte array."""
        bit = (self.cur_byte >> (7 - self.bit_pos)) & 1
        self.bit_pos += 1

        if self.bit_pos > 7:  # Move to the next byte
            self.bit_pos = 0
            self.byte_pos += 1
            if self.byte_pos < len(self.data):
                self.cur_byte = self.data[self.byte_pos]

        return bit

    def read_bits(self, num_bits: int) -> int:
        """Reads multiple bits from the byte array."""
        value = 0
        for _ in range(num_bits):
            value = (value << 1) | self.read_bit()
        return value