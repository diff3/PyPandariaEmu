"""CMSG_LOG_DISCONNECT perser"""


def decode_disconnect_reason(raw_data):
    # Konvertera 4 bytes från little-endian till ett heltal
    return int.from_bytes(raw_data, byteorder='little')


def encode_disconnect_reason(reason):
    # Konvertera ett heltal till 4 bytes i little-endian format
    return reason.to_bytes(4, byteorder='little')


# Testvärde
raw_data = b'\x0e\x00\x00\x00'

# Dekodning
decoded_reason = decode_disconnect_reason(raw_data)
print(f"Decoded reason: {decoded_reason}")

# Kodning
encoded_data = encode_disconnect_reason(decoded_reason)
print(f"Encoded data: {encoded_data}")

# Verifiera att original och kodad matchar
assert raw_data == encoded_data
print("Encoding and decoding match!")
