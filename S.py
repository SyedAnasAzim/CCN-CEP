import socket 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
from base64 import b64encode

def encrypt(data):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    cipher_text = aesgcm.encrypt(nonce,data,None)
    return nonce,key,cipher_text

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(("localhost",9000))
server.listen(1)

print("Waiting for connection\n")

conn, add = server.accept()

print(f"connected to {add}")

data = b"Hello, This is a secret"
nonce, key, cipher_text = encrypt(data)

print("data has been encrypted")
print(f"key:{key}")
print(f"nonce:{nonce}")
print(f"cipher_text:{cipher_text}")

dic_str = {
    "command":"Secret Request",
    "nonce":b64encode(nonce).decode("ascii"),
    "key":b64encode(key).decode("ascii"),
    "cipher_text":b64encode(cipher_text).decode("ascii")
}

json_str = json.dumps(dic_str).encode("utf-8")
print(json_str)
conn.sendall(json_str)

print("data has been sent, closing the server")

conn.close()
server.close()