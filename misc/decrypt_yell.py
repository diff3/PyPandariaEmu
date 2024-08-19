from Crypto.Cipher import ARC4
import hmac
import hashlib

# Define keys and K
ServerEncryptionKey = bytes([
    0x08, 0xF1, 0x95, 0x9F, 0x47, 0xE5, 0xD2, 0xDB,
    0xA1, 0x3D, 0x77, 0x8F, 0x3F, 0x3E, 0xE7, 0x00
])

ServerDecryptionKey = bytes([
    0x40, 0xAA, 0xD3, 0x92, 0x26, 0x71, 0x43, 0x47,
    0x3A, 0x31, 0x08, 0xA6, 0xE7, 0xDC, 0x98, 0x2A
])

K = bytes.fromhex('b4e1727d03d4a40afe51d6c609759bc900699c49dc94046e4ea332a9b74b4f2bbf96415cb365da29')

# Function to compute HMAC
def compute_hmac(key, data):
    return hmac.new(key, data, hashlib.sha1).digest()

# Function to create an ARC4 cipher
def create_arc4_cipher(key):
    return ARC4.new(key)

# Function to decrypt data
def decrypt_data(data, server_encryption_key, server_decryption_key, K):
    # Compute HMAC for encryption and decryption
    encrypt_hash = compute_hmac(server_encryption_key, K)
    decrypt_hash = compute_hmac(server_decryption_key, K)
    
    # Initialize ARC4 with HMAC
    server_encrypt = create_arc4_cipher(encrypt_hash)
    client_decrypt = create_arc4_cipher(decrypt_hash)
    
    # Drop first 1024 bytes
    if len(data) > 1024:
        data = data[1024:]
    
    # Decrypt data
    decrypted_data = client_decrypt.decrypt(data)
    
    return decrypted_data

# Example data
data1 = b'G3\xdfF\x01\x00\x00\x00\x0b'
# data1 = b'G3\xdfF\x01\x00\x00\x00\x0bHello World'
data2 = b'\x8c{\xf1\x9b\x97\x00\x04\x18\x08\x02\xf0\x00\x03\x06\x03\x01'
# data2 = b'\x8c{\xf1\x9b\x97\x00\x04\x18\x08\x02\xf0\x00\x03\x06\x03\x01Hello World'

# Decrypt data
decrypted_data1 = decrypt_data(data1, ServerEncryptionKey, ServerDecryptionKey, K)
decrypted_data2 = decrypt_data(data2, ServerEncryptionKey, ServerDecryptionKey, K)

print(f'Decrypted Data 1: {decrypted_data1}')
print(f'Decrypted Data 2: {decrypted_data2}')
