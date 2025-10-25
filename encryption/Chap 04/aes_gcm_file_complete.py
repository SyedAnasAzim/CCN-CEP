"""
AES-GCM: Complete File Encryption/Decryption System
Chapter 4: Production-Ready Implementation
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import struct

class FileEncryptor:
    """
    Production-ready file encryptor using AES-GCM
    Handles files of any size using chunked encryption
    """
    
    def __init__(self, key, chunk_size=64*1024):
        """
        Initialize encryptor
        
        Args:
            key: 32-byte encryption key
            chunk_size: Size of chunks in bytes (default 64KB)
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits)")
        
        self.cipher = AESGCM(key)
        self.chunk_size = chunk_size
    
    def encrypt_file(self, input_path, output_path):
        """
        Encrypt a file in chunks
        
        Output format for each chunk:
        [4 bytes: length][12 bytes: nonce][N bytes: ciphertext+tag]
        """
        try:
            total_bytes = os.path.getsize(input_path)
            processed_bytes = 0
            
            print(f"Encrypting: {input_path}")
            print(f"Size: {total_bytes:,} bytes ({total_bytes/(1024*1024):.2f} MB)")
            print(f"Chunk size: {self.chunk_size:,} bytes\n")
            
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                chunk_num = 0
                
                while True:
                    # Read chunk
                    chunk = fin.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    chunk_num += 1
                    
                    # Generate unique nonce
                    nonce = os.urandom(12)
                    
                    # Encrypt chunk
                    ciphertext = self.cipher.encrypt(nonce, chunk, None)
                    
                    # Create frame: [length][nonce][ciphertext]
                    frame_length = 12 + len(ciphertext)
                    frame = struct.pack('>I', frame_length) + nonce + ciphertext
                    
                    # Write to output
                    fout.write(frame)
                    
                    # Progress
                    processed_bytes += len(chunk)
                    progress = (processed_bytes / total_bytes) * 100
                    print(f"Chunk {chunk_num}: {len(chunk):,} bytes encrypted ({progress:.1f}%)")
            
            encrypted_size = os.path.getsize(output_path)
            overhead = encrypted_size - total_bytes
            
            print(f"\n✓ Encryption complete!")
            print(f"  Original:  {total_bytes:,} bytes")
            print(f"  Encrypted: {encrypted_size:,} bytes")
            print(f"  Overhead:  {overhead:,} bytes ({(overhead/total_bytes)*100:.2f}%)")
            
            return True
            
        except Exception as e:
            print(f"✗ Encryption failed: {e}")
            return False
    
    def decrypt_file(self, input_path, output_path):
        """
        Decrypt a chunked encrypted file
        """
        try:
            total_bytes = os.path.getsize(input_path)
            processed_bytes = 0
            
            print(f"Decrypting: {input_path}")
            print(f"Size: {total_bytes:,} bytes ({total_bytes/(1024*1024):.2f} MB)\n")
            
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                chunk_num = 0
                
                while True:
                    # Read frame length (4 bytes)
                    length_data = fin.read(4)
                    if not length_data:
                        break
                    
                    chunk_num += 1
                    frame_length = struct.unpack('>I', length_data)[0]
                    
                    # Read nonce (12 bytes)
                    nonce = fin.read(12)
                    if len(nonce) != 12:
                        raise ValueError(f"Incomplete nonce in chunk {chunk_num}")
                    
                    # Read ciphertext (remaining bytes)
                    ciphertext_length = frame_length - 12
                    ciphertext = fin.read(ciphertext_length)
                    if len(ciphertext) != ciphertext_length:
                        raise ValueError(f"Incomplete ciphertext in chunk {chunk_num}")
                    
                    # Decrypt chunk
                    try:
                        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
                    except Exception:
                        raise ValueError(f"Authentication failed for chunk {chunk_num}. File may be corrupted or tampered!")
                    
                    # Write decrypted data
                    fout.write(plaintext)
                    
                    # Progress
                    processed_bytes += len(ciphertext) + 16  # approximate
                    progress = min((processed_bytes / total_bytes) * 100, 100)
                    print(f"Chunk {chunk_num}: {len(plaintext):,} bytes decrypted ({progress:.1f}%)")
            
            decrypted_size = os.path.getsize(output_path)
            
            print(f"\n✓ Decryption complete!")
            print(f"  Encrypted: {total_bytes:,} bytes")
            print(f"  Decrypted: {decrypted_size:,} bytes")
            
            return True
            
        except Exception as e:
            print(f"✗ Decryption failed: {e}")
            return False


# ============================================================
# DEMONSTRATION
# ============================================================

print("=" * 60)
print("FILE ENCRYPTOR - DEMONSTRATION")
print("=" * 60 + "\n")

# Generate key
key = AESGCM.generate_key(bit_length=256)
print(f"Generated key: {key.hex()[:32]}...\n")

# Create encryptor
encryptor = FileEncryptor(key, chunk_size=64*1024)

# Create a test file
test_file = "test_file.txt"
test_content = b"This is test content.\n" * 10000  # ~220 KB

print("Creating test file...")
with open(test_file, 'wb') as f:
    f.write(test_content)
print(f"✓ Created: {test_file} ({len(test_content):,} bytes)\n")

print("=" * 60)
print("ENCRYPTING")
print("=" * 60 + "\n")

# Encrypt
encrypted_file = test_file + ".enc"
encryptor.encrypt_file(test_file, encrypted_file)

print("\n" + "=" * 60)
print("DECRYPTING")
print("=" * 60 + "\n")

# Decrypt
decrypted_file = test_file + ".dec"
encryptor.decrypt_file(encrypted_file, decrypted_file)

print("\n" + "=" * 60)
print("VERIFICATION")
print("=" * 60 + "\n")

# Verify
with open(test_file, 'rb') as f:
    original = f.read()

with open(decrypted_file, 'rb') as f:
    decrypted = f.read()

if original == decrypted:
    print("✅ SUCCESS! Files match perfectly")
else:
    print("❌ ERROR! Files don't match")

# Cleanup
print("\nCleaning up test files...")
for f in [test_file, encrypted_file, decrypted_file]:
    if os.path.exists(f):
        os.remove(f)
print("✓ Cleanup complete")

print("\n" + "=" * 60)
print("💡 USAGE IN YOUR FILE TRANSFER APP")
print("=" * 60)
print("""
# On Sender Side:
key = AESGCM.generate_key(bit_length=256)
encryptor = FileEncryptor(key)

# Encrypt file
encryptor.encrypt_file('document.pdf', 'document.pdf.enc')

# Send encrypted file over socket
# Also send key securely (we'll cover this in next chapter)

# On Receiver Side:
# Receive encrypted file and key
decryptor = FileEncryptor(key)
decryptor.decrypt_file('document.pdf.enc', 'document.pdf')
""")
