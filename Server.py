import socket
import time
import json
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidTag
import hashlib

IP = "localhost"
PORT = 5000
CHUNK_SIZE = 65536
PATH = "CUBE Downloads"

def format_time(sec):
    """Format seconds into hours:minutes:seconds"""
    try:
        m, s = divmod(int(sec), 60)
        h, m = divmod(m, 60)
        return f"{h:02d}h:{m:02d}m:{s:02d}s"
    except:
        return "N/A"

def create_hash(data):
    """Create SHA256 hash of data"""
    try:
        h = hashlib.sha256()
        if not isinstance(data, bytes):
            data = data.encode("utf-8")
        h.update(data)
        return h.hexdigest()
    except Exception as e:
        print(f"[Hash Error] {e}")
        return None


class BufferedSocket:
    """Wrapper for socket with buffered reading capability"""
    
    def __init__(self, sock, chunk_size=CHUNK_SIZE):
        self.sock = sock
        self.chunk_size = chunk_size
        self.buffer = bytearray()
    
    def recv_until(self, delimiter):
        """
        Receive data until delimiter is found.
        
        Raises:
            socket.timeout: If no data received within timeout period
            ConnectionResetError: If connection forcefully closed by peer
            BrokenPipeError: If connection broken mid-transfer
            ConnectionError: For other connection issues
        """
        try:
            while True:
                index = self.buffer.find(delimiter)
                if index != -1:
                    data = bytes(self.buffer[:index])
                    self.buffer = self.buffer[index + len(delimiter):]
                    return data
                
                try:
                    chunk = self.sock.recv(self.chunk_size)
                except socket.timeout:
                    print("[Timeout] No data received within timeout period")
                    raise 
                except ConnectionResetError:
                    print("[Connection Error] Peer disconnected abruptly")
                    raise
                except BrokenPipeError:
                    print("[Connection Error] Connection broken mid-transfer")
                    raise
                except OSError as e:
                    print(f"[Socket Error] {e}")
                    raise ConnectionError(f"Socket error during receive: {e}")
                
                if not chunk:
                    break
                self.buffer.extend(chunk)
            
            # Return remaining buffer if connection closed
            data = bytes(self.buffer)
            self.buffer.clear()
            return data
        
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            raise
        except Exception as e:
            print(f"[BufferedSocket Error] {e}")
            self.buffer.clear()
            raise


class Server:
    """Server class for encrypted file transfer"""
    
    def __init__(self, ip=IP, port=PORT):
        """Initialize server - create socket, bind, listen, accept, handshake"""
        self.ip = ip
        self.port = port
        self.server = None
        self.conn = None
        self.buf_conn = None
        self.is_connected = False
        
        try:
            # 1. Create and configure socket
            self._create_socket()
            
            # 2. Wait for connection
            self._wait_for_connection()
            
            # 3. Perform handshake
            self._handshake()
            
            self.is_connected = True
            
        except Exception as e:
            # Cleanup and re-raise
            self.cleanup()
            raise
    
    def _create_socket(self):
        """Create, configure, bind, and listen on socket"""
        try:
            print("\n[Server] Creating socket...")
            # Create socket
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Allow port reuse
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Set timeout
            self.server.settimeout(30)
            
            # Bind to port
            try:
                self.server.bind((self.ip, self.port))
                print(f"[Server] ✓ Bound to {self.ip}:{self.port}")
            except OSError as e:
                if e.errno in [48, 98, 10048]:  # Port in use
                    print(f"\n❌ [Error] Port {self.port} is already in use!")
                    print("\n💡 Solutions:")
                    print("   • Wait 30 seconds and try again")
                    print("   • Close other programs using this port")
                    print(f"   • Change PORT in Server.py (currently {self.port})")
                    raise
                else:
                    print(f"[Bind Error] {e}")
                    raise
            
            # Listen
            self.server.listen(1)
            print(f"[Server] Listening for connections...")
            
        except socket.error as e:
            print(f"[Socket Error] Failed to create socket: {e}")
            raise
    
    def _wait_for_connection(self):
        """Wait for client to connect"""
        try:
            print("[Server] ⏳ Waiting for client (30 second timeout)...")
            self.conn, addr = self.server.accept()
            
            # Set timeout on connection socket too
            self.conn.settimeout(30)
            
            self.buf_conn = BufferedSocket(self.conn)
            print(f"[Server] ✓ Client connected from {addr[0]}:{addr[1]}")
            
        except socket.timeout:
            print("\n[Timeout] No client connected within 30 seconds")
            print("💡 Make sure client is trying to connect to this IP")
            raise
    
    def _handshake(self):
        """Perform three-way handshake"""
        try:
            print("[Handshake] Starting handshake protocol...")
            
            # Step 1: Receive SYN
            req = self.buf_conn.recv_until(b"\n").decode().strip()
            if not req:
                raise ConnectionError("Client disconnected before handshake")
            if req != "SYN":
                raise ValueError(f"Expected SYN, got '{req}'")
            print("[Handshake] ← Received: SYN")
            
            # Step 2: Send SYN-ACK
            self.conn.sendall("SYN-ACK\n".encode())
            print("[Handshake] → Sent: SYN-ACK")
            
            # Step 3: Receive ACK
            req = self.buf_conn.recv_until(b"\n").decode().strip()
            if not req:
                raise ConnectionError("Client disconnected during handshake")
            if req != "ACK":
                raise ValueError(f"Expected ACK, got '{req}'")
            print("[Handshake] ← Received: ACK")
            
            print("[Handshake] ✓ Handshake successful!\n")
            
        except socket.timeout:
            print("[Handshake Error] Timeout - client not responding")
            raise
        except ConnectionResetError:
            print("[Handshake Error] Client forcefully disconnected")
            raise
        except BrokenPipeError:
            print("[Handshake Error] Connection broken")
            raise
    
    def cleanup(self):
        """Clean up resources"""
        if self.conn:
            try:
                self.conn.close()
            except:
                pass
        if self.server:
            try:
                self.server.close()
            except:
                pass

    def sending(self):
        """Send file to client"""
        if not self.is_connected:
            print("[Error] Not connected to any client")
            return False
        
        try:
            print("\n" + "="*60)
            print("📤 SENDING FILE TO CLIENT")
            print("="*60 + "\n")
            
            command = input("Enter command (send <filename>): ").strip()
            comm_list = command.split()

            # Validate command
            if len(comm_list) != 2 or comm_list[0].lower() != "send":
                print("[Error] Invalid command format")
                print("Usage: send <filename>")
                return False
            
            filename = comm_list[1]
            
            # Step 1: Get file size with exception handling
            print("[1/5] Validating file...")
            try:
                filesize = os.path.getsize(filename)
                print(f"[Info] File: {filename}")
                print(f"[Info] Size: {filesize / (1024**2):.2f} MB ({filesize} bytes)")
            except FileNotFoundError:
                print(f"\n[Error] File not found: {filename}")
                print("💡 Check the filename and try again")
                return False
            except PermissionError:
                print(f"\n[Error] Permission denied: Cannot read {filename}")
                print("💡 Check file permissions")
                return False
            except IsADirectoryError:
                print(f"\n[Error] '{filename}' is a directory, not a file")
                print("💡 Specify a file, not a folder")
                return False
            except OSError as e:
                print(f"\n[Error] Cannot access file: {e}")
                return False

            # Send command with filesize
            print("\n[2/5] Sending file information...")
            self.conn.sendall((command + " " + str(filesize) + "\n").encode())

            request_action = self.buf_conn.recv_until(b"\n")

            if request_action == "2":
                print("Receiver has declined the transfer")
                print("Shutting the sending procedure")
                return False
            # Step 2: Receive RSA public key
            print("[3/5] Exchanging encryption keys...")
            try:
                public_key_dict = self.buf_conn.recv_until(b"\n")
                public_key_json = json.loads(public_key_dict)
            except socket.timeout:
                print("[Error] Timeout waiting for client's public key")
                return False
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[Error] Connection lost: {e}")
                return False
            except json.JSONDecodeError as e:
                print(f"[Error] Invalid response from client: {e}")
                return False
            
            if public_key_json.get("Exchange type") != "public key":
                print("[Error] Invalid key exchange response from client")
                return False
            
            public_pem = b64decode(public_key_json["Key"])
            
            # Deserialize public key
            public_key = serialization.load_pem_public_key(public_pem)

            # Generate AES-GCM Key 
            key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(key)

            # Encrypt AES-GCM session key
            encrypted_key = public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Send encrypted AES-GCM session key
            key_dict = {
                "Exchange type": "key",
                "Key": b64encode(encrypted_key).decode("ascii")
            }
            key_dict_json = json.dumps(key_dict)
            self.conn.sendall((key_dict_json + "\n").encode("utf-8"))
            print("[3/5] ✓ Encryption keys exchanged")

            # Step 3: Send file in chunks
            print("[4/5] Encrypting and sending file...")
            chunk_number = 0
            send_chunk_size = 0
            
            try:
                with open(filename, "rb") as f:
                    start = time.time()
                    while send_chunk_size < filesize:
                        data = f.read(min(CHUNK_SIZE, filesize - send_chunk_size))
                        
                        # Create hash of data
                        hash_data = create_hash(data)
                        
                        # Generate nonce(12-bytes)
                        nonce = os.urandom(12)
                        
                        # Encrypt the chunk 
                        encrypted_data = aesgcm.encrypt(nonce=nonce, data=data, associated_data=None)
                        
                        if not data:
                            break
                        
                        send_chunk_size += len(data)
                        chunk_number += 1
                        
                        # Prepare chunk with hash
                        chunk_dict = {
                            "Chunk": chunk_number,
                            "Size": len(data),
                            "Nonce": b64encode(nonce).decode("ascii"),
                            "Data": b64encode(encrypted_data).decode("ascii"),
                            "Hash": hash_data
                        }
                        chunk_dict_json = json.dumps(chunk_dict)
                        
                        # Send chunk
                        try:
                            self.conn.sendall((chunk_dict_json + "\n").encode("utf-8"))
                        except (ConnectionResetError, BrokenPipeError) as e:
                            print(f"\n[Error] Connection lost during transfer: {e}")
                            return False
                        except socket.timeout:
                            print(f"\n[Error] Timeout during transfer")
                            return False
                        
                        # Progress indicator
                        elapsed = time.time()-start
                        rate = send_chunk_size / elapsed
                        progress = (send_chunk_size / filesize) * 100
                        print(f"[4/5] Progress: {progress:.1f}% | Chunk {chunk_number} | "
                              f"{send_chunk_size}/{filesize} bytes | Speed {rate/1024**2:.2f}MB/s |"
                              f"Time Remaiing {format_time((filesize-send_chunk_size)/rate)}", end="\r", flush=True)
                
                print()  # New line after progress
                
                # Step 4: Receive status from client
                print("[5/5] Waiting for client confirmation...")
                try:
                    status = self.buf_conn.recv_until(b"\n")
                    
                    if status == b"Corrupted":
                        print("\n❌ [Transfer Failed] Client received corrupted file")
                        print("💡 Try sending the file again")
                        return False
                    elif status == b"Ok":
                        print("[5/5] ✓ File sent successfully!")
                        print(f"      Total chunks: {chunk_number}")
                        print(f"      Total size: {filesize / (1024**2):.2f} MB")
                        print(f"      Client confirmed: File received intact")
                        return True
                    else:
                        print(f"\n[Warning] Unexpected status: {status}")
                        return False
                        
                except socket.timeout:
                    print("\n[Error] Timeout waiting for client confirmation")
                    return False
                except (ConnectionResetError, BrokenPipeError) as e:
                    print(f"\n[Error] Connection lost: {e}")
                    return False
                
            except FileNotFoundError:
                print(f"\n[Error] File disappeared during transfer: {filename}")
                return False
            except PermissionError:
                print(f"\n[Error] Permission denied while reading file")
                return False
            except IsADirectoryError:
                print(f"\n[Error] Target is a directory, not a file")
                return False
            except OSError as e:
                print(f"\n[Error] I/O error during transfer: {e}")
                return False
        
        except Exception as e:
            print(f"\n[Unexpected Error] {e}")
            return False
    
    def close_connection(self):
        """Close connection gracefully"""
        print("\n[Server] Closing connection...")
        self.cleanup()
        self.is_connected = False
        print("[Server] ✓ Connection closed")