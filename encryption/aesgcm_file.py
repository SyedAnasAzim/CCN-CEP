from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

#generating key
key = AESGCM.generate_key(bit_length=256)
print(f"Generated key: {key.hex()}")
print(f"Lenght: {len(key)}bytes\n")


#generating nonce
nonce = os.urandom(12)

cipher = AESGCM(key)

with open("Text.txt","rb") as f:
    plaintext = f.read()
# print(f"Data: {plaintext}")
print(f"Data(len): {len(plaintext)}\n")

#encryption
ct = cipher.encrypt(nonce=nonce,data=plaintext,associated_data=None)
print(f"Cipher Text + Tag: {ct}")
print(f"lenght: {len(ct)}")
print(f"lenght of data: {len(plaintext)}, lenght of tag: {len(ct) - len(plaintext)}\n")

#decryption
try:
    decrypted = cipher.decrypt(nonce=nonce,data=ct,associated_data=None)
    with open("Decrypted_T.txt","wb") as f:
        f.write(decrypted)
    # print(f"Decrypted Text: {decrypted}")
    print(f"Decrypted Text(len): {len(decrypted)}\n")
except Exception as e:
    print(f"Decryption Failed: {e}\n")

#Tampering Detection
tampered_ct = bytearray(ct)
tampered_ct[0] ^= 0x01
tampered_ct = bytes(tampered_ct)
try:
    tampered_data = cipher.decrypt(nonce,tampered_ct,None)
    print("✗ SECURITY FAILURE: Tampered data was accepted!")
except Exception as e:
    print(f"Tampering failed: {type(e).__name__}")
    print(f"Authentication failed")