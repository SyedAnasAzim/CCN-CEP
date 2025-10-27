import socket 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
from base64 import b64decode

def decrypt(nonce,key,cipher_text):
    aesgcm = AESGCM(key)
    plain_text = aesgcm.decrypt(nonce,cipher_text,None)
    return plain_text

client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect((("localhost",9000)))

print("connected to server\n\n")

msg = client.recv(1024)
print("Msg has been received")
print(f"msg:{msg}\n")

msg = msg.decode("utf-8")
print(f"Decoded msg: {msg}\n")

json_msg = json.loads(msg)
print(f"Decoded Json msg: {json_msg}\n")

print("Decrypting the msg\n")
plain_text = decrypt(b64decode(json_msg["nonce"]),b64decode(json_msg["key"]),b64decode(json_msg["cipher_text"]))
print("msg has been decrypted")
print(f"Decrypted msg: {plain_text}\n")

print("Connected has been ended")

client.close()