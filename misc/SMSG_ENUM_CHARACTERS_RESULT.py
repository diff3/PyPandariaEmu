import struct

"""SMSG_ENUM_CHARACTERS_RESULT"""

def parse_smsg_enum_characters_result(data):
    index = 0

    # Läs metadata
    faction_restrictions = int.from_bytes(data[index:index+3], 'little')
    index += 3

    character_count = int.from_bytes(data[index:index+2], 'little')
    index += 2

    success = data[index]
    index += 1

    print(f"Faction Restrictions: {faction_restrictions}, Character Count: {character_count}, Success: {success}")

    characters = []
    for _ in range(character_count):
        guid = struct.unpack('<Q', data[index:index+8])[0]
        index += 8
        name_length = data[index]
        index += 1
        name = data[index:index+name_length].decode('utf-8')
        index += name_length

        level, race, cclass = struct.unpack('<IHH', data[index:index+8])
        index += 8

        print(f"Character GUID: {guid}, Name: {name}, Level: {level}, Race: {race}, Class: {cclass}")
        characters.append((guid, name, level, race, cclass))

    return characters

# Exempelanrop
data = b'\x00\x00\x00\x00\n\x00@\x04\x00\x00\x00\x00\x00\x03Atty\x8b\xd2\xb6D\x00\x00\x00\x00\x11\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05}\x9b\x01\x00\x00\x00\x00\x00\x06\xc0\x9a\x01\x00\x00\x00\x00\x00\x07~\x9b\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\xc4\x9a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x03\x00\x00\x18\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x85\xd6XE\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00h\x16\x00\x00\xb0\x925C'
characters = parse_smsg_enum_characters_result(data)
