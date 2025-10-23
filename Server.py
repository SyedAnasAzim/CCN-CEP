import socket
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

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(("localhost",9000))
server.listen(1)

print("Waiting for connection !!!")
conn, add = server.accept()
print(f"Connedted to [{add}]")

while True:
    msg = recv_until(conn,b"\n").decode()
    # msg = conn.recv(1024).decode()
    print(msg)
    msg = msg.split()

    if msg[0].lower() == "send":
        data = recv_full(conn,int(msg[2]))
        with open(f"received_{msg[1]}","wb") as f:
            f.write(data)
        if msg[3] == file_hash(f"received_{msg[1]}"):
            print("File received successfully!!!")
        else:
            print("File is corrupted durng transfer!!!")
    elif msg[0].lower() == "exit":
        break
    else:
        print("Wrong Command")

conn.close()
server.close()
