from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

key = os.urandom(32)
iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key),modes.CFB(iv))

plaintext = b"This is a secret"

encryptor = cipher.encryptor()

"""🔹 update(data)

Processes a chunk of your data.
Returns as many encrypted bytes as it can right now.
You can call update() multiple times — it’s useful for streaming or large files."""

encrypted = encryptor.update(plaintext) + encryptor.finalize()

"""🔹 finalize()

Tells the cipher: “I’m done sending data — finish up.”
It flushes any remaining buffered data and finalizes the encryption process.
In some modes (like CBC or GCM), it also adds authentication tags or padding.

.finalize() acts like pressing “Send” after typing your message —
it tells AES “I’m done, now give me whatever’s left.”
Without it, AES still thinks you might send more data, so it keeps part of the last block inside."""

print(f"encrypted text: {encrypted}")
print(len(encrypted))
decryptor = cipher.decryptor()
decrypted = decryptor.update(encrypted) + decryptor.finalize()
print(len(decrypted))
print(f"decrypted text: {decrypted.decode()}")