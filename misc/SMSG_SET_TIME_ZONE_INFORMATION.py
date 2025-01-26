"""SMSG_SET_TIME_ZONE_INFORMATION parser"""

class ByteBuffer:
    def __init__(self):
        self._storage = bytearray()
        self._bitpos = 8
        self._curbitval = 0

    def write_bit(self, bit):
        self._bitpos -= 1
        if bit:
            self._curbitval |= (1 << self._bitpos)
        if self._bitpos == 0:
            self._storage.append(self._curbitval)
            self._curbitval = 0
            self._bitpos = 8

    def write_bits(self, value, bits):
        for i in range(bits - 1, -1, -1):
            self.write_bit((value >> i) & 1)

    def flush_bits(self):
        if self._bitpos < 8:
            self._storage.append(self._curbitval)
            self._curbitval = 0
            self._bitpos = 8

    def write_string(self, string):
        self._storage.extend(string.encode('utf-8'))

    def read_bit(self):
        if self._bitpos == 8:
            self._curbitval = self._storage.pop(0)
            self._bitpos = 0
        bit = (self._curbitval >> (7 - self._bitpos)) & 1
        self._bitpos += 1
        return bit

    def read_bits(self, bits):
        value = 0
        for i in range(bits):
            value = (value << 1) | self.read_bit()
        return value

    def read_string(self, length):
        result = self._storage[:length].decode('utf-8')
        del self._storage[:length]
        return result

    def get_data(self):
        return bytes(self._storage)


# Encoder
def encode_timezone_string(timezone):
    buffer = ByteBuffer()
    buffer.write_bits(len(timezone), 7)  # Write length (7 bits)
    buffer.write_bits(len(timezone), 7)  # Write length again (7 bits)
    buffer.flush_bits()  # Flush remaining bits to align to byte boundary
    buffer.write_string(timezone)  # Write the string
    buffer.write_string(timezone)  # Write the string again
    return buffer.get_data()


# Decoder
def decode_timezone_string(data):
    buffer = ByteBuffer()
    buffer._storage = bytearray(data)  # Load data into buffer
    length1 = buffer.read_bits(7)  # Read first length
    length2 = buffer.read_bits(7)  # Read second length
    buffer.flush_bits()  # Align to byte boundary
    string1 = buffer.read_string(length1)  # Read first string
    string2 = buffer.read_string(length2)  # Read second string
    return length1, length2, string1, string2


# Test the encoder and decoder
raw_data = encode_timezone_string("Etc/UTC")
print(f"Encoded: {raw_data}")

decoded_data = decode_timezone_string(raw_data)
print(f"Decoded: {decoded_data}")
