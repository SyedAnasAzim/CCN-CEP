"""
AES-GCM: Using AAD in File Transfer
Chapter 5: Practical AAD Implementation
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import struct
import hashlib

class SecureFileTransfer:
    """
    File transfer with AAD for metadata protection
    """
    
    def __init__(self, key, chunk_size=64*1024):
        self.cipher = AESGCM(key)
        self.chunk_size = chunk_size
    
    def encrypt_chunk_with_metadata(self, chunk_data, chunk_number, total_chunks, filename):
        """
        Encrypt a chunk with authenticated metadata
        
        AAD contains:
        - Chunk number (prevents reordering)
        - Total chunks (prevents truncation)
        - Filename (prevents file swap)
        - Chunk hash (additional integrity)
        """
        # Create metadata
        chunk_hash = hashlib.sha256(chunk_data).hexdigest()
        metadata = {
            "chunk": chunk_number,
            "total": total_chunks,
            "filename": filename,
            "hash": chunk_hash,
            "size": len(chunk_data)
        }
        
        # Convert metadata to AAD bytes
        aad = json.dumps(metadata, sort_keys=True).encode('utf-8')
        
        # Encrypt with AAD
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, chunk_data, aad)
        
        return {
            'nonce': nonce,
            'ciphertext': ciphertext,
            'metadata': metadata,  # Store separately (readable)
            'aad': aad  # Needed for decryption
        }
    
    def decrypt_chunk_with_metadata(self, nonce, ciphertext, aad):
        """
        Decrypt and verify chunk with AAD
        """
        try:
            plaintext = self.cipher.decrypt(nonce, ciphertext, aad)
            
            # Parse and verify metadata
            metadata = json.loads(aad.decode('utf-8'))
            
            # Verify hash
            computed_hash = hashlib.sha256(plaintext).hexdigest()
            if computed_hash != metadata['hash']:
                raise ValueError("Hash mismatch! Data corrupted.")
            
            return plaintext, metadata
            
        except Exception as e:
            raise ValueError(f"Decryption/verification failed: {e}")


# ============================================================
# DEMONSTRATION
# ============================================================

print("=" * 60)
print("FILE TRANSFER WITH AAD")
print("=" * 60 + "\n")

# Setup
key = AESGCM.generate_key(bit_length=256)
transfer = SecureFileTransfer(key, chunk_size=32*1024)

# Simulate file
filename = "important_document.pdf"
file_data = b"This is chunk 1 data..." * 100
total_size = len(file_data)
total_chunks = 3

print(f"File: {filename}")
print(f"Size: {total_size:,} bytes")
print(f"Chunks: {total_chunks}\n")

print("=" * 60)
print("ENCRYPTING WITH METADATA PROTECTION")
print("=" * 60 + "\n")

# Encrypt chunks
encrypted_chunks = []
for i in range(total_chunks):
    chunk_data = file_data[i*1000:(i+1)*1000]  # Simulate chunks
    
    encrypted = transfer.encrypt_chunk_with_metadata(
        chunk_data, 
        chunk_number=i+1,
        total_chunks=total_chunks,
        filename=filename
    )
    
    encrypted_chunks.append(encrypted)
    
    print(f"Chunk {i+1}:")
    print(f"  Metadata: {encrypted['metadata']}")
    print(f"  Encrypted: {len(encrypted['ciphertext'])} bytes")
    print(f"  AAD protects: chunk#, total, filename, hash\n")

print("=" * 60)
print("DECRYPTING WITH VERIFICATION")
print("=" * 60 + "\n")

# Decrypt chunks
for i, enc in enumerate(encrypted_chunks, 1):
    try:
        plaintext, metadata = transfer.decrypt_chunk_with_metadata(
            enc['nonce'],
            enc['ciphertext'],
            enc['aad']
        )
        print(f"✓ Chunk {i}: Decrypted and verified")
        print(f"  File: {metadata['filename']}")
        print(f"  Chunk: {metadata['chunk']}/{metadata['total']}")
        print(f"  Size: {metadata['size']} bytes")
        print(f"  Hash: {metadata['hash'][:16]}...\n")
    except Exception as e:
        print(f"✗ Chunk {i}: Failed - {e}\n")

print("=" * 60)
print("ATTACK 1: Reordering Chunks")
print("=" * 60 + "\n")

print("Attacker swaps chunk 1 and chunk 2...\n")

# Try to decrypt chunk 2 with chunk 1's metadata
try:
    plaintext, metadata = transfer.decrypt_chunk_with_metadata(
        encrypted_chunks[1]['nonce'],  # Chunk 2's nonce
        encrypted_chunks[1]['ciphertext'],  # Chunk 2's ciphertext
        encrypted_chunks[0]['aad']  # Chunk 1's AAD (wrong!)
    )
    print("✗ SECURITY FAILURE: Reordering not detected!")
except Exception as e:
    print(f"✓ ATTACK BLOCKED!")
    print(f"  AAD mismatch detected")
    print(f"  Chunk numbers don't match\n")

print("=" * 60)
print("ATTACK 2: File Name Swap")
print("=" * 60 + "\n")

print("Attacker changes filename in metadata...\n")

# Modify metadata
fake_metadata = encrypted_chunks[0]['metadata'].copy()
fake_metadata['filename'] = "malware.exe"
fake_aad = json.dumps(fake_metadata, sort_keys=True).encode('utf-8')

print(f"Original: {encrypted_chunks[0]['metadata']['filename']}")
print(f"Fake:     {fake_metadata['filename']}\n")

try:
    plaintext, metadata = transfer.decrypt_chunk_with_metadata(
        encrypted_chunks[0]['nonce'],
        encrypted_chunks[0]['ciphertext'],
        fake_aad  # Modified AAD
    )
    print("✗ SECURITY FAILURE: Filename swap not detected!")
except Exception as e:
    print(f"✓ ATTACK BLOCKED!")
    print(f"  AAD authentication failed")
    print(f"  Filename tampering detected\n")

print("=" * 60)
print("ATTACK 3: Truncation Attack")
print("=" * 60 + "\n")

print("Attacker removes last chunk (2 of 3 chunks only)...\n")

# Try to present incomplete file
print("Received chunks: 1, 2")
print("Expected chunks: 1, 2, 3")
print()

# Receiver checks total_chunks in each chunk's metadata
received_chunks = 2
expected_total = encrypted_chunks[0]['metadata']['total']

if received_chunks < expected_total:
    print(f"✓ ATTACK BLOCKED!")
    print(f"  Expected {expected_total} chunks, got {received_chunks}")
    print(f"  AAD metadata reveals truncation\n")
else:
    print(f"✗ All chunks received\n")

print("=" * 60)
print("💡 AAD PROTECTION SUMMARY")
print("=" * 60)
print("""
AAD protects against:

1. ✓ Chunk reordering
   - Each chunk has authenticated chunk number
   
2. ✓ File name swapping
   - Filename in AAD, can't be changed
   
3. ✓ Truncation attacks
   - Total chunks in AAD, missing chunks detected
   
4. ✓ Data corruption
   - Hash in AAD ensures data integrity
   
5. ✓ Metadata tampering
   - All metadata authenticated, changes detected

WITHOUT AAD:
- Attacker could reorder chunks
- Could swap file names
- Could truncate files
- Metadata modifications undetected
""")

print("\n" + "=" * 60)
print("RECOMMENDED AAD STRUCTURE")
print("=" * 60)
print("""
{
    "chunk": 1,              # Chunk number (prevents reordering)
    "total": 10,             # Total chunks (prevents truncation)
    "filename": "doc.pdf",   # File name (prevents swapping)
    "hash": "a3c5...",       # SHA256 of chunk (integrity)
    "size": 65536,           # Chunk size (validation)
    "timestamp": "...",      # Optional: when sent
    "sender": "alice",       # Optional: who sent it
}
""")
