"""
Decoding an SMSG_AUTH_RESPONSE packet structure.

Packet Structure:
1. Metadata (First Part):
   - AUTH_OK: 1 bit (indicates if authentication was successful).
   - Realm Count: 21 bits (number of realms in the data part).
   - For each realm:
       - Realm Name Length: 8 bits (length of realm name).
       - Normalized Name Length: 8 bits (length of normalized name).
       - Is Home Realm: 1 bit (flag indicating if it is the home realm).
   - Playable Classes Count: 23 bits (number of playable classes).
   - Reserved Bits: 21 bits (placeholders).
   - 4 Placeholder Bits: 1 bit each.
   - Playable Races Count: 23 bits (number of playable races).
   - Empty Bit: 1 bit (unused).
   - Queued Bit: 1 bit (flag indicating if the user is in a queue).
   - Total size depends on the number of realms.

2. Data (Second Part):
   - For each realm:
       - Realm ID: 4 bytes.
       - Realm Name: N bytes (based on Realm Name Length from metadata).
       - Normalized Realm Name: M bytes (based on Normalized Name Length from metadata).
   - Races:
       - For each race: 2 bytes (expansion and race ID).
   - Classes:
       - For each class: 2 bytes (expansion and class ID).
   - Placeholders and Expansions:
       - 3 Placeholder Blocks: Each 4 bytes (uint32).
       - Server Expansions: 1 byte each (uint8).
"""



def decode_auth_response_first_part(packet):
    """
    Decodes the metadata (first part) of the AUTH_RESPONSE packet.

    Args:
        packet (bytes): The raw AUTH_RESPONSE packet.

    Returns:
        dict: Metadata extracted from the first part of the packet, including:
            - auth_ok (bool): Whether authentication was successful.
            - realm_count (int): Number of realms.
            - realm_info (list): List of tuples with (realm_name_length, normalized_name_length, is_home_realm).
            - playable_classes_count (int): Number of playable classes.
            - playable_races_count (int): Number of playable races.
            - offset (int): Byte offset where the second part begins.
            - queued (bool): Whether the user is in a queue.
    """

    offset = 0 
    bit_offset = 0

    def read_bit():
        nonlocal offset, bit_offset
        value = (packet[offset] >> (7 - bit_offset)) & 0x01
        bit_offset += 1
        if bit_offset == 8:
            bit_offset = 0
            offset += 1
        return value

    def read_bits(num_bits):
        nonlocal offset, bit_offset
        value = 0
        for _ in range(num_bits):
            value = (value << 1) | read_bit()
        return value

    auth_ok = bool(read_bit())
    realm_count = read_bits(21)
    realm_info = []

    for _ in range(realm_count):
        realm_name_length = read_bits(8)
        normalized_name_length = read_bits(8)
        is_home_realm = bool(read_bit())
        realm_info.append((realm_name_length, normalized_name_length, is_home_realm))

    playable_classes_count = read_bits(23)
    reserved_bits = read_bits(21)
    
    for _ in range(4):
        placeholder_bit = read_bit()

    playable_races_count = read_bits(23) & 0x7FFFFF 
    
    empty_bit = read_bit()
    queued = bool(read_bit())
    
    return {
        "auth_ok": auth_ok,
        "realm_count": realm_count,
        "realm_info": realm_info,
        "playable_classes_count": playable_classes_count,
        "playable_races_count": playable_races_count,
        "offset": offset,
        "queued": queued,
    }


def decode_auth_response_second_part(packet, metadata):
    """
    Decodes the data (second part) of the AUTH_RESPONSE packet.

    Args:
        packet (bytes): The raw AUTH_RESPONSE packet.
        metadata (dict): Metadata extracted from the first part of the packet.

    Returns:
        dict: Data extracted from the second part of the packet, including:
            - realm_id (int): The ID of the realm.
            - realm_name (str): The name of the realm.
            - normalized_name (str): The normalized name of the realm.
            - races (list): List of tuples with (expansion, race_id).
            - classes (list): List of tuples with (expansion, class_id).
            - placeholders (list): Placeholder values extracted from the packet.
            - server_expansion1 (int): First server expansion value.
            - server_expansion2 (int): Second server expansion value.
    """

    offset = metadata['offset']

    for n in range(metadata['realm_count']):
        realm_id = int.from_bytes(packet[offset:offset + 4], "little")
        offset += 4

        realm_name_length = metadata['realm_info'][n][0]
        realm_name = packet[offset:offset + realm_name_length].decode('utf-8')
        offset += realm_name_length

        normalized_name_length = metadata['realm_info'][n][1]
        normalized_name = packet[offset:offset + normalized_name_length].decode('utf-8')
        offset += normalized_name_length

    races = []
    for _ in range(metadata['playable_classes_count']):
        expansion = packet[offset]
        offset += 1
        race_id = packet[offset]
        offset += 1
        races.append((expansion, race_id))
    
    classes = []
    for _ in range(metadata['playable_races_count']):
        expansion = packet[offset]
        offset += 1
        class_id = packet[offset]
        offset += 1
        classes.append((expansion, class_id))
    
    placeholders = []
    for _ in range(1):
        placeholder = int.from_bytes(packet[offset:offset + 4], "little")
        offset += 4
        placeholders.append(placeholder)

    server_expansion_1 = packet[offset]
    offset += 1

    for _ in range(2):
        placeholder = int.from_bytes(packet[offset:offset + 4], "little")
        offset += 4
        placeholders.append(placeholder)

    server_expansion_2 = packet[offset]
    offset += 1

    for _ in range(3):
        placeholder = int.from_bytes(packet[offset:offset + 4], "little")
        offset += 4
        placeholders.append(placeholder)

    return {
        "realm_id": realm_id,
        "realm_name": realm_name,
        "normalized_name": normalized_name,
        "races": races,
        "classes": classes,
        "placeholders": placeholders,
        "server_expansion1": server_expansion_1,
        "server_expansion2": server_expansion_2,
    }

raw_data = b'\x80\x00\x04\x18\x1a\x00\x00,\x00\x00\x00\x00\x00<\x01\x00\x00\x00AzarimAzarim\x00\x06\x00\x05\x00\x02\x00\x07\x03\t\x00\x01\x00\x08\x04\x18\x01\x0b\x03\x16\x01\n\x00\x04\x00\x03\x04\x19\x04\x1a\x04\n\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x07\x00\x08\x00\t\x00\x0b\x02\x06\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c'

metadata = decode_auth_response_first_part(raw_data)
print("Decoded First Part:", metadata)

decoded_data = decode_auth_response_second_part(raw_data, metadata)
print("Decoded Second Part:", decoded_data)