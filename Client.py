import socket
import os

client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect(("localhost",9000))

images = ["ghost.jpg","gta.jpg","R9.jpg"]
for img in images: 
    client.sendall(f"Hi {img} {os.path.getsize(img)}\n".encode())


    print("msg sent")
    with open(img,"rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            client.sendall(data)
        

client.close()