import socket

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
    print(filesize)
    while filesize > got_data:
        data = sock.recv(min(chunk_size,filesize-got_data))
        if not data:
            break
        buf.extend(data)
        got_data += min(chunk_size,filesize-got_data)
        print(got_data)
    return bytes(buf)




server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(("localhost",9000))
server.listen(1)

print("Waiting for connection !!!")
conn, add = server.accept()
print(f"Connedted to [{add}]")

msg = recv_until(conn,b"\n").decode()
# msg = conn.recv(1024).decode()
print(msg)

data = recv_full(conn,int(msg.split()[1]))
with open("received.jpg","wb") as f:
    f.write(data)

conn.close()
server.close()
