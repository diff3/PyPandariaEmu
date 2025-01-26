import struct
import random

def encode_smsg_auth_challenge(seed):
    """
    Encode an SMSG_AUTH_CHALLENGE packet.

    Args:
        seed (int): The seed value (uint32) to encode in the packet.

    Returns:
        bytes: Encoded packet.
    """
    packet = struct.pack('<H', 0)  # uint16(0)
    packet += struct.pack('<8I', *(0 for _ in range(8)))  # 8x uint32(0)
    packet += struct.pack('<B', 1)  # uint8(1)
    packet += struct.pack('<I', seed)  # uint32(seed)
    return packet

def decode_smsg_auth_challenge(data):
    """
    Decode an SMSG_AUTH_CHALLENGE packet.

    Args:
        data (bytes): Raw data of the packet.

    Returns:
        dict: Decoded data as a dictionary.
    """
    # if len(data) != 37:
        # raise ValueError("Invalid packet length, expected 37 bytes.")
    
    offset = 0
    uint16_0 = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    uint32_zeros = struct.unpack_from('<8I', data, offset)
    offset += 32
    uint8_value = struct.unpack_from('<B', data, offset)[0]
    offset += 1
    seed = struct.unpack_from('<I', data, offset)[0]

    return {
        "uint16_0": uint16_0,
        "uint32_zeros": uint32_zeros,
        "uint8_value": uint8_value,
        "seed": seed,
    }

def generate_seed():
    """
    Generate a random 32-bit unsigned integer seed value.

    Returns:
        int: A random seed value between 0 and 2**32 - 1.
    """
    return random.randint(0, 0xFFFFFFFF)

# Example raw data
raw_data = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff&F\xca'
print(raw_data.hex())
# Decoding
decoded = decode_smsg_auth_challenge(raw_data)
print("Decoded:", decoded)

# Encoding
seed = decoded["seed"]
encoded = encode_smsg_auth_challenge(seed)
print("Encoded matches raw data:", encoded == raw_data)

print(encoded.hex())


m_seed = generate_seed()
print(f"Generated seed: {m_seed}")

encoded_packet = encode_smsg_auth_challenge(m_seed)
print(f"Encoded packet: {encoded_packet.hex()}")
