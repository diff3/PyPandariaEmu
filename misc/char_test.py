from typing import Tuple


class BitReader:
    """Class to read bits from a byte array."""
    def __init__(self, data):
        self.data = data
        self.byte_pos = 0
        self.bit_pos = 0
        self.cur_byte = self.data[self.byte_pos]

    def read_bit(self):
        """Reads a single bit from the byte array."""
        bit = (self.cur_byte >> (7 - self.bit_pos)) & 1
        self.bit_pos += 1

        if self.bit_pos > 7:  # Move to the next byte
            self.bit_pos = 0
            self.byte_pos += 1
            if self.byte_pos < len(self.data):
                self.cur_byte = self.data[self.byte_pos]

        return bit

    def read_bits(self, num_bits):
        """Reads multiple bits from the byte array."""
        value = 0
        for _ in range(num_bits):
            bit = self.read_bit()
            # print(bit)
            value = (value << 1) | bit
        return value


def extract_guid_and_name(data: bytes) -> Tuple[int, str]:
    """
    Extract the GUID and name from raw data based on scrambling order and data layout.

    :param data: Raw packet data containing GUID and name information.
    :return: A tuple containing the GUID and name as (int, str).
    """
    # Scrambling order for GUID bytes based on bitBuffer logic

    guid = [0] * 8
    guild_guid = [0] * 8
    name = str()
    
    n = 0

    while n < 300:
        guid = [0] * 8

        # Parse
        guild_guid[4] = data[n]
        guid[0] = data[n+1]
        guild_guid[3] = data[n+2]
        guid[3] = data[n+3]
        guid[7] = data[n+4]
        boosted = data[n+5]
        at_login_flag = data[n+6]
        guid[6] = data[n+7]
        guild_guid[6] = data[n+8]
        bit_reader = BitReader(data[n+9:n+10])
        name_len = bit_reader.read_bits(6)
        guid[1] = data[n+10]
        guild_guid[1] = data[n+11]
        guild_guid[0] = data[n+12]
        guid[4] = data[13]
        guild_guid[7] = data[n+14]
        guid[2] = data[n+15]
        guid[5] = data[n+16]
        guild_guid[2] = data[n+17]
        guild_guid[5] = data[n+18]

       
        
        guild_guid_as_int = int.from_bytes(bytes(guild_guid), byteorder="little")

        if guild_guid_as_int == 0:
            print(f"Guild guid as integer: {guild_guid_as_int}")

        guid_as_int = int.from_bytes(bytes(guid), byteorder="little")

        if guid_as_int == 4:
            print(f"GUID as integer: {guid_as_int}")

        if guid_as_int == 4 and guild_guid_as_int == 0:
            print(f"GUID: {guid}")
            print(f"GUILD GUID: {guild_guid}")
            print(f"Name len: {name_len}")
            print(f"Name: {name}")
            print(f"Boost: {boosted}")
            print(f"at_login_flag: {at_login_flag}")
            

       

        n = n + 1
        print(n)

# Example Usage
raw_data = b'\x00\x00\x00\x00\n\x00@\x04\x00\x00\x00\x00\x00\x03Atty\x8b\xd2\xb6D\x00\x00\x00\x00\x11\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05}\x9b\x01\x00\x00\x00\x00\x00\x06\xc0\x9a\x01\x00\x00\x00\x00\x00\x07~\x9b\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\xc4\x9a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x03\x00\x00\x18\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x85\xd6XE\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00h\x16\x00\x00\xb0\x925C'
extract_guid_and_name(raw_data)
