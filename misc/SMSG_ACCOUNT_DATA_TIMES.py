from dataclasses import dataclass
from typing import List
import struct

@dataclass
class AccountDataTimes:
    flag: int               # 1 bit (flushed to a byte)
    timestamps: List[int]   # List of 8 uint32 timestamps
    mask: int               # uint32 mask
    server_time: int        # uint32 server time


def decode_account_data_times(data: bytes) -> AccountDataTimes:
    """
    Decode the SMSG_ACCOUNT_DATA_TIMES packet.

    :param data: The raw bytes of the packet.
    :return: An AccountDataTimes object containing the decoded data.
    """
    offset = 0

    # Decode flag (1 bit, but stored as a full byte)
    flag = data[offset] & 0b1
    offset += 1  # Move past the byte used for the bit

    # Decode timestamps (8 x uint32)
    timestamps = []
    for _ in range(8):
        timestamp = struct.unpack_from('<I', data, offset)[0]
        timestamps.append(timestamp)
        offset += 4

    # Decode mask (uint32)
    mask = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    # Decode server time (uint32)
    server_time = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    return AccountDataTimes(flag=flag, timestamps=timestamps, mask=mask, server_time=server_time)


def encode_account_data_times(packet: AccountDataTimes) -> bytes:
    """
    Encode the SMSG_ACCOUNT_DATA_TIMES packet.

    :param packet: An AccountDataTimes object containing the data to encode.
    :return: The encoded bytes of the packet.
    """
    data = bytearray()

    # Encode flag (1 bit, flushed to a byte)
    data.append(packet.flag & 0b1)

    # Encode timestamps (8 x uint32)
    for timestamp in packet.timestamps:
        data.extend(struct.pack('<I', timestamp))

    # Encode mask (uint32)
    data.extend(struct.pack('<I', packet.mask))

    # Encode server time (uint32)
    data.extend(struct.pack('<I', packet.server_time))

    return bytes(data)

# Example usage:
# Decoding
raw_data = b'\x80?$|g\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00KSug\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00\x9b\xfa\x80g'
decoded = decode_account_data_times(raw_data)
print(decoded)

# Encoding
encoded = encode_account_data_times(decoded)
print(encoded)
