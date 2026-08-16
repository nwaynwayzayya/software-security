import os
from Crypto.Cipher import AES
from solution_skeleton import encrypt_gcm

key = os.urandom(32)
message = b"secret message"

# Encrypt
nonce, ciphertext, tag = encrypt_gcm(message, key)

print("=== AES-GCM TEST ===")
print("Original:   ", message)
print("Nonce:      ", nonce.hex())
print("Ciphertext: ", ciphertext.hex())
print("Tag:        ", tag.hex())

# Correct decryption
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
decrypted = cipher.decrypt_and_verify(ciphertext, tag)

print("Decrypted:  ", decrypted)
print("Round-trip: ", decrypted == message)

# Change one ciphertext byte
tampered = bytearray(ciphertext)
tampered[0] ^= 1

print()
print("=== TAMPERING TEST ===")

try:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.decrypt_and_verify(bytes(tampered), tag)
    print("Tampered:   ACCEPTED (unexpected)")
except ValueError:
    print("Tampered:   REJECTED — authentication failed")
