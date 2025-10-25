"""
AES-GCM: Associated Authenticated Data (AAD)
Chapter 5: Advanced Features
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json

# Setup
key = AESGCM.generate_key(bit_length=256)
cipher = AESGCM(key)

print("=" * 60)
print("WHAT IS AAD?")
print("=" * 60 + "\n")

print("AAD (Associated Authenticated Data):")
print("  • Authenticated: Tampering detected ✓")
print("  • NOT Encrypted: Visible to anyone ✗")
print("  • Included in authentication tag calculation")
print("  • Must be same during encryption and decryption\n")

# Example data
plaintext = b"This is the SECRET content of the file"
metadata = {
    "filename": "report.pdf",
    "size": len(plaintext),
    "sender": "alice@example.com",
    "timestamp": "2025-10-25T10:30:00",
    "version": "1.0"
}

print("Plaintext (will be encrypted):")
print(f"  {plaintext}\n")

print("Metadata (will be authenticated but NOT encrypted):")
print(json.dumps(metadata, indent=2))
print()

print("=" * 60)
print("ENCRYPTION WITH AAD")
print("=" * 60 + "\n")

# Convert metadata to bytes
aad = json.dumps(metadata).encode('utf-8')
print(f"AAD as bytes: {aad}\n")

# Encrypt with AAD
nonce = os.urandom(12)
ciphertext = cipher.encrypt(nonce, plaintext, aad)

print(f"Nonce:      {nonce.hex()}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"AAD:        {aad} (NOT encrypted, readable!)\n")

print("=" * 60)
print("DECRYPTION WITH CORRECT AAD")
print("=" * 60 + "\n")

# Decrypt with SAME AAD
try:
    decrypted = cipher.decrypt(nonce, ciphertext, aad)
    print(f"✓ Decryption successful!")
    print(f"  Decrypted: {decrypted}")
    print(f"  Metadata verified: {json.loads(aad.decode())['filename']}")
except Exception as e:
    print(f"✗ Decryption failed: {e}")

print("\n" + "=" * 60)
print("TAMPERING TEST 1: Modified AAD")
print("=" * 60 + "\n")

# Try to decrypt with DIFFERENT AAD (tampering)
tampered_metadata = metadata.copy()
tampered_metadata['filename'] = "hacked.pdf"  # Changed!
tampered_aad = json.dumps(tampered_metadata).encode('utf-8')

print(f"Original AAD:  {aad}")
print(f"Tampered AAD:  {tampered_aad}")
print(f"\nAttempting decryption with tampered AAD...\n")

try:
    decrypted = cipher.decrypt(nonce, ciphertext, tampered_aad)
    print(f"✗ SECURITY FAILURE: Tampered AAD accepted!")
except Exception as e:
    print(f"✓ TAMPERING DETECTED!")
    print(f"  Error: {type(e).__name__}")
    print(f"  AAD modification was caught!")

print("\n" + "=" * 60)
print("TAMPERING TEST 2: Modified Ciphertext")
print("=" * 60 + "\n")

# Try to modify ciphertext
tampered_ciphertext = bytearray(ciphertext)
tampered_ciphertext[0] ^= 0x01  # Flip one bit

print(f"Original ciphertext:  {ciphertext.hex()[:40]}...")
print(f"Tampered ciphertext:  {bytes(tampered_ciphertext).hex()[:40]}...")
print(f"\nAttempting decryption with tampered ciphertext...\n")

try:
    decrypted = cipher.decrypt(nonce, bytes(tampered_ciphertext), aad)
    print(f"✗ SECURITY FAILURE: Tampered ciphertext accepted!")
except Exception as e:
    print(f"✓ TAMPERING DETECTED!")
    print(f"  Error: {type(e).__name__}")
    print(f"  Ciphertext modification was caught!")

print("\n" + "=" * 60)
print("AAD WITHOUT ENCRYPTION (Comparison)")
print("=" * 60 + "\n")

print("Scenario: Encrypt file WITHOUT AAD\n")

nonce2 = os.urandom(12)
ciphertext_no_aad = cipher.encrypt(nonce2, plaintext, None)

print(f"Ciphertext: {ciphertext_no_aad.hex()[:40]}...")
print(f"Metadata:   {metadata['filename']} (stored separately, unprotected!)\n")

# Attacker can modify metadata freely
print("Attacker modifies metadata:")
print(f"  Original:  report.pdf")
print(f"  Modified:  virus.exe ⚠️")
print(f"\nDecryption still succeeds:")

try:
    decrypted = cipher.decrypt(nonce2, ciphertext_no_aad, None)
    print(f"✓ Decrypted: {decrypted}")
    print(f"❌ BUT metadata was tampered and we can't detect it!")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "=" * 60)
print("💡 KEY TAKEAWAYS")
print("=" * 60)
print("""
1. AAD is authenticated but NOT encrypted
   - Anyone can READ it
   - Nobody can MODIFY it without detection

2. Use AAD for:
   ✓ File names, timestamps, sender info
   ✓ Chunk numbers, sequence IDs
   ✓ Protocol version, flags
   ✓ Any metadata that must be trusted

3. Don't use AAD for:
   ✗ Passwords, keys, sensitive data
   ✗ Data that needs confidentiality

4. AAD must be IDENTICAL during encryption and decryption
   - Even one byte difference → authentication fails

5. AAD protects metadata from tampering
   - Prevents file name swapping attacks
   - Ensures metadata integrity
""")
