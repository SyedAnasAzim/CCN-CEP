from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)

cipher = AESGCM(key)

test_strings = [
    "Simple ASCII text",
    "Unicode: 你好世界",
    "Emoji: 🔐🚀💻",
    "Mixed: Hello مرحبا नमस्ते",
    "Special chars: @#$%^&*()"
]
for s in test_strings:  
    print(f"Original text: {s}")
    nonce = os.urandom(12)
    #encoding strings into utf-8 which supports all Unicode characters including emojis!
    encoded_str = s.encode("utf-8")
    #encryption
    ct = cipher.encrypt(nonce,encoded_str,None)
    print(f"Encrypted string: {ct}")
    #decryption
    decrypted = cipher.decrypt(nonce,ct,None)
    print(f"Decrypted string: {decrypted}")
    print(f"Decrypted and decoded string: {decrypted.decode("utf-8")}")
    if encoded_str == decrypted:
        print("Message encrypted and decrypted successfully\n")
    else:
        print("encryption and decryption failed\n")
    