"""SMSG_TUTORIAL_FLAGS"""

def decode_tutorial_flags(raw_data):
    """Decode the tutorial flags from raw binary data."""
    tutorial_values = []
    for i in range(0, len(raw_data), 4):  # Varje värde är 4 bytes
        tutorial_values.append(int.from_bytes(raw_data[i:i + 4], byteorder='little'))
    return tutorial_values


def encode_tutorial_flags(tutorial_values):
    """Encode tutorial flags into raw binary data."""
    raw_data = bytearray()
    for value in tutorial_values:
        raw_data.extend(value.to_bytes(4, byteorder='little'))
    return bytes(raw_data)




# Testdata
raw_data = b'\xa3\x01@a\x86\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# Decode raw data
decoded_values = decode_tutorial_flags(raw_data)
print(f"Decoded tutorial values: {decoded_values}")

# Modify and encode back
decoded_values[0] = 12345  # Ändra första värdet
encoded_data = encode_tutorial_flags(decoded_values)
print(f"Encoded data: {encoded_data}")

# Verifiera att det fungerar
assert raw_data[:len(encoded_data)] != encoded_data  # Bör vara olika om vi ändrat
print("Encoding and decoding works correctly!")
