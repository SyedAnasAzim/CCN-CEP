from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import os

key = AESGCM.generate_key(bit_length=256)

cipher = AESGCM(key)

user_data = {
    "username": "alice",
    "email": "alice@example.com",
    "age": 28,
    "premium": True,
    "files": ["doc1.txt", "doc2.pdf", "image.jpg"],
    "metadata": {
        "created": "2025-10-25",
        "last_login": "2025-10-25T10:30:00"
    }
}

#step 1: convert into json str
json_str = json.dumps(user_data)
print(f"Json String: {json_str}")
print(f"Len: {len(json_str)}\n")

#step 2: encoding into utf-8
encoded_json_str = json_str.encode("utf-8")
print(f"Encoded Json Str: {encoded_json_str}")
print(f"Len: {len(encoded_json_str)}\n")

#step 3: encryption
nonce = os.urandom(12)
ct = cipher.encrypt(nonce,encoded_json_str,None)
print(f"Encrypted Data: {ct}")
print(f"Len: {len(ct)}\n")

#step 4: decryption
plain_text = cipher.decrypt(nonce,ct,None)
print(f"Decrypted Data: {plain_text}")
print(f"Len: {len(plain_text)}\n")

#step 5: decode from utf-8
decoded_json_str = plain_text.decode("utf-8")
print(f"Decoded Json Str: {decoded_json_str}")
print(f"Len: {len(decoded_json_str)}\n")

#step 6: parse json
user_data_decrypted = json.loads(decoded_json_str)
print("Recovered Data:")
print(json.dumps(user_data_decrypted, indent=2))
print()

# Numbers need special handling
numbers = [42, 3.14159, -100, 999999999]

for num in numbers:
    # Convert number to bytes
    num_bytes = str(num).encode('utf-8')
    
    n = os.urandom(12)
    enc = cipher.encrypt(n, num_bytes, None)
    dec = cipher.decrypt(n, enc, None)
    
    # Convert back to number
    recovered = float(dec.decode('utf-8')) if '.' in dec.decode('utf-8') else int(dec.decode('utf-8'))
    
    status = "✓" if recovered == num else "✗"
    print(f"{status} {num:15} → encrypted → {recovered}")

print("\n💡 TIP: For complex data, use JSON. It handles all types!")