raw_data = b'\x00\x00\x00\x00\n\x00@\x04\x00\x00\x00\x00\x00\x03Atty\x8b\xd2\xb6D\x00\x00\x00\x00\x11\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05}\x9b\x01\x00\x00\x00\x00\x00\x06\xc0\x9a\x01\x00\x00\x00\x00\x00\x07~\x9b\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\xc4\x9a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x03\x00\x00\x18\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x85\xd6XE\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00h\x16\x00\x00\xb0\x925C'
sequence = b'\x50'

index = raw_data.find(sequence)
if index != -1:
    print(f"Sequence found at index {index}")
else:
    print("Sequence not found")
