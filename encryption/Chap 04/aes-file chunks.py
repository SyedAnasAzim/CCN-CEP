"""
AES-GCM: Chunked File Encryption
Chapter 4: Large File Handling
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import struct

# Setup
key = AESGCM.generate_key(bit_length=256)
cipher = AESGCM(key)

# Configuration
CHUNK_SIZE = 64 * 1024  # 64 KB chunks (adjustable)

print("=" * 60)
print("CHUNKED ENCRYPTION CONCEPT")
print("=" * 60 + "\n")

print(f"Chunk Size: {CHUNK_SIZE:,} bytes ({CHUNK_SIZE // 1024} KB)\n")

# Simulate a large file
large_file_data = b"A" * (200 * 1024)  # 200 KB file
print(f"Simulated File Size: {len(large_file_data):,} bytes\n")

# Calculate chunks needed
num_chunks = (len(large_file_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
print(f"Number of Chunks: {num_chunks}")
print(f"  Chunk 1: {CHUNK_SIZE:,} bytes")
print(f"  Chunk 2: {CHUNK_SIZE:,} bytes")
print(f"  Chunk 3: {len(large_file_data) - (2 * CHUNK_SIZE):,} bytes (last chunk)\n")

print("=" * 60)
print("ENCRYPTION PROCESS")
print("=" * 60 + "\n")

encrypted_chunks = []
chunk_number = 0

# Process file in chunks
for i in range(0, len(large_file_data), CHUNK_SIZE):
    # Extract chunk
    chunk = large_file_data[i:i + CHUNK_SIZE]
    chunk_number += 1
    
    # Generate unique nonce for this chunk
    nonce = os.urandom(12)
    
    # Encrypt chunk
    encrypted_chunk = cipher.encrypt(nonce, chunk, None)
    
    # Store nonce + encrypted chunk
    encrypted_chunks.append((nonce, encrypted_chunk))
    
    print(f"Chunk {chunk_number}:")
    print(f"  Original:  {len(chunk):,} bytes")
    print(f"  Encrypted: {len(encrypted_chunk):,} bytes (+ 16 byte tag)")
    print(f"  Nonce:     {nonce.hex()[:24]}...")

print(f"\n✓ Encrypted {chunk_number} chunks successfully!\n")

print("=" * 60)
print("DECRYPTION PROCESS")
print("=" * 60 + "\n")

decrypted_chunks = []

for i, (nonce, encrypted_chunk) in enumerate(encrypted_chunks, 1):
    # Decrypt chunk
    decrypted_chunk = cipher.decrypt(nonce, encrypted_chunk, None)
    decrypted_chunks.append(decrypted_chunk)
    
    print(f"Chunk {i}: Decrypted {len(decrypted_chunk):,} bytes")

# Reassemble file
reconstructed_file = b''.join(decrypted_chunks)

print(f"\n✓ Decrypted {len(encrypted_chunks)} chunks")
print(f"✓ Reassembled: {len(reconstructed_file):,} bytes\n")

# Verify integrity
if reconstructed_file == large_file_data:
    print("✅ SUCCESS! File perfectly reconstructed")
else:
    print("❌ ERROR! File corrupted")

print("\n" + "=" * 60)
print("MEMORY USAGE COMPARISON")
print("=" * 60 + "\n")

file_size_mb = len(large_file_data) / (1024 * 1024)
chunk_size_kb = CHUNK_SIZE / 1024

print(f"File Size: {file_size_mb:.2f} MB\n")

print("Without Chunking:")
print(f"  RAM needed: ~{file_size_mb * 2:.2f} MB (read + encrypt)")
print("  Risk: Out of memory for large files\n")

print("With Chunking:")
print(f"  RAM needed: ~{chunk_size_kb * 2 / 1024:.2f} MB per chunk")
print(f"  Benefit: Can handle ANY file size!")

print("\n" + "=" * 60)
print("ENCRYPTED FILE FORMAT")
print("=" * 60 + "\n")

print("Each chunk stored as:")
print("  [4 bytes: chunk length][12 bytes: nonce][N bytes: encrypted data]")
print()

# Demonstrate format
demo_chunk = b"Sample chunk data"
demo_nonce = os.urandom(12)
demo_encrypted = cipher.encrypt(demo_nonce, demo_chunk, None)

# Create frame
chunk_length = 12 + len(demo_encrypted)
frame = struct.pack('>I', chunk_length) + demo_nonce + demo_encrypted

print(f"Example chunk frame: {len(frame)} bytes")
print(f"  Length:    {chunk_length} (4 bytes)")
print(f"  Nonce:     {demo_nonce.hex()} (12 bytes)")
print(f"  Encrypted: {len(demo_encrypted)} bytes")
print(f"\nFrame (hex): {frame.hex()[:60]}...")