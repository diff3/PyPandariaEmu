import struct

# Rådata från paketet
raw_data = b' \x10\x00\x00\x80\x00`\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Boost your character to level 90!Level 90 Character Boost\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'

# Definiera ordning från koden
guid_mask_order = [4, 7, 0, 1, 2]  # Detta kommer från WriteGuidMask
guid_bytes_order = [1, 5, 0, 7]    # Detta kommer från WriteByteSeq

# Funktion för att dekoda data
def decode_guid(data, mask_order, byte_order):
    guid = [0] * 8
    offset = 0

    # Dekoda bitar i ordningen från mask_order
    for bit in mask_order:
        if data[offset] & (1 << bit):
            guid[bit] = data[offset + 1]
            offset += 1
    offset += 1  # Hoppa över skrivna bitar

    # Dekoda byte-sekvenser i ordningen från byte_order
    for byte in byte_order:
        guid[byte] = data[offset]
        offset += 1

    return bytes(guid), offset

# Använd funktionen för att dekoda
guid, offset = decode_guid(raw_data, guid_mask_order, guid_bytes_order)

# Dekoda andra fält (t.ex. bools, strängar etc.)
revoked_bit = raw_data[offset]
offset += 1

bonus_text_length = int.from_bytes(raw_data[offset:offset + 2], 'little')
offset += 2
bonus_text = raw_data[offset:offset + bonus_text_length].decode('utf-8')
offset += bonus_text_length

bonus_text2_length = int.from_bytes(raw_data[offset:offset + 2], 'little')
offset += 2
bonus_text2 = raw_data[offset:offset + bonus_text2_length].decode('utf-8')
offset += bonus_text2_length

# Resultat
decoded_packet = {
    "GUID": guid.hex(),
    "Revoked": revoked_bit,
    "Bonus Text": bonus_text,
    "Bonus Text 2": bonus_text2,
}

print(decoded_packet)
