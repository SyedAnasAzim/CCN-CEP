import socket
import os
import hashlib
# import time

def file_hash(file):
    h = hashlib.sha256()
    with open(file,"rb") as f:
        while chunk:=f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def bar(current,total):
    percent = current * 100 / total
    b = int(percent)
    print(f"\rProgress: {percent:.2f}% [{'=' * b}{' ' * (100 - b)}]", end="")


def recv_until(sock,delimiter):
    buf = bytearray()
    data = sock.recv(1)
    buf.extend(data)
    while data:
        data = sock.recv(1)
        if data == delimiter:
            break
        buf.extend(data)
    return bytes(buf)

def recv_full(sock,filesize):
    chunk_size = 4096
    got_data = 0
    buf = bytearray()
    # print(filesize)
    while filesize > got_data:
        # time.sleep(0.01)
        data = sock.recv(min(chunk_size,filesize-got_data))
        if not data:
            break
        buf.extend(data)
        got_data += min(chunk_size,filesize-got_data)
        bar(got_data,filesize)
        # print(got_data)
    print()
    return bytes(buf)

client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect(("localhost",9000))

# images = ["ghost.jpg","gta.jpg","R9.jpg"]
while True:
    command = input("$:").strip()
    if command == "":
        continue
    comm_list = command.split()
    if comm_list[0].lower() == "send":
        file_h = file_hash(comm_list[1])
        filesize = os.path.getsize(comm_list[1])
        client.sendall(f"{command} {filesize} {file_h}\n".encode())
    
        print("msg sent")
        try:
            with open(comm_list[1],"rb") as f:
                while True:
                    data = f.read(4096)
                    if not data:
                        break
                    # time.sleep(0.01)
                    client.sendall(data)
        except FileNotFoundError:
            print("File doesn't exist!!!")

    elif comm_list[0].lower() == "exit":
        client.sendall(command.encode())
        break
    else:
        print(8)
        client.sendall(f"{command}\n".encode())
        

client.close()