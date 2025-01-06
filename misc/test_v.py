import hashlib

# Konstant
g = 7
N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
s = bytes.fromhex("885405935937C32A3292866F2AF1D784E3E8D5C3616F407F792B3AF60DE5998B")[::-1]
I = int("8301316D0D8448A34FA6D0C6BF1CBFA2B4A1A93A", 16)

# Steg 1: Förbered m_Digest från I, tolkad som big-endian
m_Digest = I.to_bytes((I.bit_length() + 7) // 8, byteorder='big')
m_Digest = m_Digest.rjust(20, b'\x00')

print(f'm_Digest: {m_Digest.hex()}')
print(f'm_Digest (expected): 8301316d0d8448a34fa6d0c6bf1cbfa2b4a1a93a')

# Steg 2: Hasha s (little-endian) och m_Digest (big-endian)
sha1 = hashlib.sha1()
sha1.update(s)  # s är little-endian här
sha1.update(m_Digest)  # m_Digest är big-endian
sha_digest = sha1.digest()

# Steg 3: Omvandla SHA-1 hash till ett stort tal x (little-endian)
x = int.from_bytes(sha_digest, byteorder='little')  # x ska vara little-endian

print(f'x: {hex(x)[2:].upper()}')
print(f'x (expected): 7B0D85E8BE4B89ED5866953F667E796B48850DBE')

# Steg 4: Beräkna v = g^x mod N
v = pow(g, x, N)

# Steg 5: Skriv ut resultatet för v
v_hex = format(v, 'x').upper()

# Skriv ut resultatet
print(f"v (verifier): {v_hex}")
print(f"v (expected): 8513F10B1D8A3D340145353D83623A555BEFE33133A534BFEACA84B7819A0A9D")
