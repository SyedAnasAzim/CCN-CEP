import socket
import os

client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect(("localhost",9000))
client.sendall(f"Hi {os.path.getsize("ghost.jpg")}\n".encode())


print("msg sent")
with open("ghost.jpg","rb") as f:
    while True:
        data = f.read(4096)
        if not data:
            break
        client.sendall(data)
        

client.close()