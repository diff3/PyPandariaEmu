"""SMSG_CLIENTCACHE_VERSION parser"""


def encode_client_cache_version(version):
    # Convert the integer to 4 bytes in little-endian order
    return version.to_bytes(4, byteorder='little')

def decode_client_cache_version(raw_data):
    # Convert 4 bytes from little-endian format to an integer
    return int.from_bytes(raw_data, byteorder='little')



# Testdata
raw_data = b'\x05\x00\x00\x00'

# Decode raw data
decoded_version = decode_client_cache_version(raw_data)
print(f"Decoded version: {decoded_version}")  # Förväntat: 5

# Encode version back to bytes
encoded_data = encode_client_cache_version(decoded_version)
print(f"Encoded data: {encoded_data}")  # Förväntat: b'\x05\x00\x00\x00'

# Verifiera att det matchar
assert raw_data == encoded_data
print("Encoding and decoding match!")
