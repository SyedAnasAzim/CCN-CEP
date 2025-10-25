from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Setup
key = AESGCM.generate_key(bit_length=256)
cipher = AESGCM(key)

print("=" * 60)
print("ENCRYPTING FILES (In-Memory)")
print("=" * 60 + "\n")

# Simulate file content (in real scenario, read from actual file)
original_file_data = b"This is file content.\nIt can contain any binary data.\n\x00\x01\x02\xFF"
print(f"Original Data: {original_file_data[:50]}...")
print(f"Size: {len(original_file_data)} bytes\n")

# Encrypt file data
nonce = os.urandom(12)
encrypted_file_data = cipher.encrypt(nonce, original_file_data, None)
print(f"Encrypted Data (hex): {encrypted_file_data.hex()[:60]}...")
print(f"Encrypted Size: {len(encrypted_file_data)} bytes")
print(f"Overhead: +{len(encrypted_file_data) - len(original_file_data)} bytes (tag)\n")

# Decrypt file data
decrypted_file_data = cipher.decrypt(nonce, encrypted_file_data, None)
print(f"Decrypted Data: {decrypted_file_data[:50]}...")
print(f"Size: {len(decrypted_file_data)} bytes\n")

if original_file_data == decrypted_file_data:
    print("✓ SUCCESS! File data perfectly recovered\n")
else:
    print("✗ ERROR: File data corrupted\n")

print("=" * 60)
print("REAL FILE ENCRYPTION EXAMPLE")
print("=" * 60 + "\n")

# Example: How to encrypt/decrypt actual files
print("To encrypt a real file:\n")
print("""
def encrypt_file(input_path, output_path, key):
    # Read original file
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Encrypt
    cipher = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    
    # Save nonce + ciphertext
    with open(output_path, 'wb') as f:
        f.write(nonce)  # First 12 bytes
        f.write(ciphertext)  # Rest is encrypted data
    
    print(f"✓ Encrypted: {input_path} → {output_path}")
""")

print("\nTo decrypt a file:\n")
print("""
def decrypt_file(input_path, output_path, key):
    # Read encrypted file
    with open(input_path, 'rb') as f:
        nonce = f.read(12)  # First 12 bytes
        ciphertext = f.read()  # Rest of the file
    
    # Decrypt
    cipher = AESGCM(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    
    # Save decrypted file
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print(f"✓ Decrypted: {input_path} → {output_path}")
""")

print("=" * 60)
print("FILE FORMAT: [NONCE (12 bytes)][CIPHERTEXT + TAG]")
print("=" * 60 + "\n")

# Demonstrate format
demo_nonce = os.urandom(12)
demo_data = b"Small file content"
demo_encrypted = cipher.encrypt(demo_nonce, demo_data, None)

# Create encrypted file format
encrypted_file_format = demo_nonce + demo_encrypted

print(f"Nonce:      {demo_nonce.hex()} (12 bytes)")
print(f"Ciphertext: {demo_encrypted.hex()[:40]}... ({len(demo_encrypted)} bytes)")
print(f"Total File: {len(encrypted_file_format)} bytes\n")

# Parse it back
parsed_nonce = encrypted_file_format[:12]
parsed_ciphertext = encrypted_file_format[12:]

print("Parsing encrypted file:")
print(f"  Extract nonce (first 12 bytes): {parsed_nonce.hex()}")
print(f"  Extract ciphertext (rest): {len(parsed_ciphertext)} bytes")

recovered = cipher.decrypt(parsed_nonce, parsed_ciphertext, None)
print(f"  Decrypted: {recovered}")
print(f"\n✓ File format works correctly!")