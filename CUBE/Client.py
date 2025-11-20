import socket
import json
import os
import time
from base64 import b64encode, b64decode
from shutil import disk_usage
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidTag
from Server import BufferedSocket, create_hash

IP = "localhost"
PORT = 5000
CHUNK_SIZE = 65536
PATH = "CUBE Downloads"

def format_bytes(b):
    if b >= 1024**3:  # GB
        return f"{b / 1024**3:.2f} GB"
    elif b >= 1024**2:  # MB
        return f"{b / 1024**2:.2f} MB"
    elif b >= 1024:  # KB
        return f"{b / 1024:.2f} KB"
    else:  # Bytes
        return f"{b} B"

def is_there_space(filesize):
    """Check if there is enough disk space to store the file"""
    try:
        total, used, free = disk_usage("/")
        filesize_overhead = filesize * 1.1
        
        if free < filesize_overhead:
            print("\n❌ [Error] Insufficient disk space to store the file!")
            print("\nDisk Status:")
            print(f"   Total space:     {format_bytes(total)}")
            print(f"   Used space:      {format_bytes(used)}")
            print(f"   Free space:      {format_bytes(free)}")
            print(f"   Required space:  {format_bytes(filesize_overhead)}")
            return False
        return True
    except Exception as e:
        print(f"[Warning] Cannot check disk space: {e}")
        return True

def format_time(sec):
    """Format seconds into hours:minutes:seconds"""
    try:
        m, s = divmod(int(sec), 60)
        h, m = divmod(m, 60)
        return f"{h:02d}h:{m:02d}m:{s:02d}s"
    except:
        return "N/A"


def progress_bar(got, filesize, start_time, bar_len=50):
    """Display progress bar with remaining time"""
    try:
        elapsed = time.time() - start_time
        rate = got / elapsed if elapsed > 0 else 0.0
        remaining_time = (filesize - got) / rate if rate > 0 else 0.0
        percent = (got / filesize) * 100 if filesize > 0 else 0.0

        filled = int((percent / 100) * bar_len)
        bar = "=" * filled + " " * (bar_len - filled)
        
        print(f"Progress: {percent:6.2f}% [{bar}] Remaining: {format_time(remaining_time)} "
              f"Speed: {rate / 1024**2:.2f} MB/s", end="\r", flush=True)
    except:
        pass

def recv_full(sock, filesize, aesgcm):
    """
    Receive and decrypt full file.
    Returns: bytes on success, or None on failure.
    """
    start_time = time.time()
    buf = bytearray()
    got = 0 #it keeps track of how much bytes we get
    chunk_count = 0

    try:
        while got < filesize:
            try:
                raw = sock.recv_until(b"\n")
            except socket.timeout:
                print(f"\n[Timeout] Transfer stalled after {got}/{filesize} bytes")
                return None
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"\n[Connection Lost] After {got}/{filesize} bytes: {e}")
                return None
            except Exception as e:
                print(f"\n[Receive Error] recv_until failed: {e}")
                return None

            if not raw:
                print("[Receive Error] Peer disconnected: No data received")
                return None

            try:
                data = raw.decode("utf-8")
            except Exception as e:
                print(f"[Receive Error] Decode error: {e}")
                return None

            try:
                data_json = json.loads(data)
            except json.JSONDecodeError as e:
                print(f"[Receive Error] Invalid JSON received: {e}")
                return None

            # Validate chunk data
            required = {"Nonce", "Data", "Size", "Hash", "Chunk"}
            if not required.issubset(data_json.keys()):
                print(f"[Receive Error] Incomplete chunk data. Keys present: {list(data_json.keys())}")
                return None

            try:
                nonce = b64decode(data_json["Nonce"])
                encrypted_data = b64decode(data_json["Data"])
            except Exception as e:
                print(f"[Receive Error] Base64 decode error: {e}")
                return None

            # Decrypt chunk
            try:
                decrypted_chunk = aesgcm.decrypt(
                    data=encrypted_data,
                    nonce=nonce,
                    associated_data=None
                )
            except InvalidTag:
                print(f"[Receive Error] Decryption failed (InvalidTag) for chunk {data_json.get('Chunk')}")
                return None
            except Exception as e:
                print(f"[Receive Error] Decryption error for chunk {data_json.get('Chunk')}: {e}")
                return None

            # Verify hash
            hash_data = create_hash(decrypted_chunk)
            if data_json["Hash"] != hash_data:
                print(f"\n❌ [Corruption] Chunk {data_json.get('Chunk')} failed hash verification")
                return None

            buf.extend(decrypted_chunk)
            try:
                got += int(data_json["Size"])
            except Exception:
                got += len(decrypted_chunk)
            chunk_count += 1
            progress_bar(got, filesize, start_time)

        print()
        return bytes(buf)

    except Exception as e:
        print(f"\n[Receive Error] Unexpected exception: {e}")
        return None

class Client:
    """Client class for encrypted file transfer"""
    
    def __init__(self, ip=IP, port=PORT):
        """Initialize client and connect to server"""
        self.ip = ip
        self.port = port
        self.client = None
        self.buf_conn = None
        self.is_connected = False
        self.not_connected_to_ser = False

        try:
            # 1. Create and connect socket
            if self._create_and_connect():
                # 2. Perform handshake
                if self._handshake():
                    self.is_connected = True
            else:
                print("[Client] ❌ Failed to create or connect socket")
                return
            
        except Exception as e:
            # Cleanup and re-raise
            self.cleanup()
            return
    
    def _create_and_connect(self):
        """Create socket and connect to server"""
        try:
            print(f"\n[Client] Connecting to server at {self.ip}:{self.port}...")
            
            # Create socket
            try:
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error as e:
                print(f"[Socket Error] Failed to create socket: {e}")
                return False
            
            # Set timeout
            self.client.settimeout(60)
            
            # Connect to server
            try:
                self.client.connect((self.ip, self.port))
                print(f"[Client] ✓ Connected to {self.ip}:{self.port}")
            except ConnectionRefusedError:
                print(f"\n[Connection Refused] Cannot connect to {self.ip}:{self.port}")
                print("\n💡 Make sure:")
                print("   • Server is running")
                print("   • IP address is correct")
                print("   • Port is not blocked by firewall")
                return False
            except socket.gaierror:
                print(f"\n[Error] Invalid IP address: {self.ip}")
                return False
            except OSError as e:
                print(f"\n[Connection Error] {e}")
                return False
            
            self.buf_conn = BufferedSocket(self.client)
            return True
        
        except socket.error as e:
            print(f"[Socket Error] {e}")
            return False
    
    def _handshake(self):
        """Perform three-way handshake with server"""
        try:
            print("[Handshake] Starting handshake protocol...")
            
            # Step 1: Send SYN
            self.client.sendall("SYN\n".encode())
            print("[Handshake] → Sent: SYN")
            
            # Step 2: Receive SYN-ACK
            try:
                reply = self.buf_conn.recv_until(b"\n")
                if reply:
                    reply = reply.decode().strip()
            except socket.timeout:
                print("[Handshake Error] Timeout - server not responding")
                return False
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[Handshake Error] Connection lost: {e}")
                return False
            
            if not reply:
                print("Server disconnected during handshake")
                print("Shutting off the connection process")
                return False
            if reply != "SYN-ACK":
                print(f"Expected SYN-ACK, got '{reply}'")
                print("Shutting off the connection process")
                return False
            print("[Handshake] ← Received: SYN-ACK")
            
            # Step 3: Send ACK
            self.client.sendall("ACK\n".encode())
            print("[Handshake] → Sent: ACK")
            print("[Handshake] ✓ Handshake successful!\n")
            return True
            
        except socket.timeout:
            print("[Handshake Error] Server not responding")
            return False
        except ConnectionResetError:
            print("[Handshake Error] Server disconnected")
            return False
        except BrokenPipeError:
            print("[Handshake Error] Connection broken")
            return False
    
    def cleanup(self):
        """Clean up resources"""
        if self.client:
            try:
                self.client.close()
            except:
                pass
    
    def receiving(self):
        """Receive file from server"""
        if not self.is_connected:
            print("[Error] Not connected to server")
            return False
        
        try:
            print("\n" + "="*60)
            print("📥 RECEIVING FILE FROM SERVER")
            print("="*60 + "\n")
            
            # Step 1: Wait for command
            print("[1/5] Waiting for file information...")
            try:
                command = self.buf_conn.recv_until(b"\n")
                if not command:
                    print("[Error] No data (timeout/disconnect)")
                    self.not_connected_to_ser = True
                    return False
                command = command.decode().strip()
            except socket.timeout:
                print("[Error] Timeout waiting for server")
                return False
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[Error] Connection lost: {e}")
                return False
            
            comm_list = command.split('|')
            
            # Validate command
            if len(comm_list) != 3 or comm_list[0].lower() != "send":
                print(f"[Error] Invalid command from server: {command}")
                return False
            
            filename = comm_list[1].split('/')[-1]
            filesize = int(comm_list[2])

            while True:
                print(f"[Info] File: {filename}    " f"Extension: {filename.split('.')[-1]}")
                print(f"[Info] Size: {filesize / (1024**2):.2f} MB ({filesize} bytes)")
                print(f"[Info] Free Space: {format_bytes(disk_usage('/')[-1]/1024**3)}")
                print("[Decision]:")
                print("\t1. Accept")
                print("\t2. Ignore")
                request_action = input("Action: ").encode() + b"\n"
                # checking desk space
                if not is_there_space(filesize):
                    print("\nYou have low disk space (Rejecting the transfer)")
                    self.client.sendall(b"2\n")
                    return False
                if request_action == b"1\n":
                    self.client.sendall(request_action)
                    break
                elif request_action == b"2\n":
                    print("You have rejected the transfer")
                    self.client.sendall(request_action)
                    return False
                else:
                    print("Wrong command")
            
            print("[Check] ✓ Sufficient disk space available")
            
            # Step 2: Generate RSA keys
            print("\n[2/5] Generating encryption keys...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Send RSA public key
            rsa_key = {
                "Exchange type": "public key",
                "Key": b64encode(public_pem).decode("ascii")
            }
            rsa_key_json = json.dumps(rsa_key)
            self.client.sendall((rsa_key_json + "\n").encode("utf-8"))
            
            # Step 3: Receive encrypted Key
            print("[3/5] Exchanging encryption keys...")
            try:
                key_dict = self.buf_conn.recv_until(b"\n")
                if not key_dict:
                    print("[Error] No data (timeout/disconnect)")
                    return False
                key_dict_json = json.loads(key_dict.decode("utf-8"))
            except socket.timeout:
                print("[Error] Timeout waiting for encryption key")
                return False
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[Error] Connection lost: {e}")
                return False
            except json.JSONDecodeError as e:
                print(f"[Error] Invalid key response: {e}")
                return False
            
            if key_dict_json.get("Exchange type") != "key":
                print("[Error] Invalid key exchange response")
                return False
            
            encrypted_key = b64decode(key_dict_json["Key"])
            
            # Decrypt AES-GCM using RSA private key
            try:
                key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                print(f"[Error] Failed to decrypt session key: {e}")
                try:
                    self.client.sendall(b"Corrupted\n")
                except:
                    pass
                return False
            self.client.sendall(b"Ok\n")
            print("[3/5] ✓ Encryption keys exchanged")
            
            # Create AES-GCM object
            aesgcm = AESGCM(key)
            
            # Step 4: Receive file
            print("[4/5] Receiving and decrypting file...")
            try:
                data = recv_full(self.buf_conn, filesize, aesgcm)
            except socket.timeout:
                print("\n[Error] Transfer timeout")
                self.client.sendall(b"Corrupted\n")
                return False
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"\n[Error] Connection lost during transfer: {e}")
                self.client.sendall(b"Corrupted\n")
                return False
            except InvalidTag:
                print("\n[Error] Decryption failed - data corrupted")
                self.client.sendall(b"Corrupted\n")
                return False
            except Exception as e:
                print(f"\n[Error] Transfer failed: {e}")
                self.client.sendall(b"Corrupted\n")
                return False
            
            # Check if data is valid
            if data is None:
                print("\n[Error] Received corrupted data")
                self.client.sendall(b"Corrupted\n")
                return False
            
            # Send OK status
            self.client.sendall(b"Ok\n")
            
            # Step 5: Save file
            print(f"\n[5/5] Saving file...")
            output_filename = f"{PATH}/{filename}"
            
            try:
                os.makedirs(PATH, exist_ok=True)
                with open(output_filename, "wb") as f:
                    f.write(data)
                
                print(f"[5/5] ✓ File saved successfully!")
                print(f"      Location: {output_filename}")
                print(f"      Size: {format_bytes(len(data))}")
                return True
                
            except PermissionError:
                print(f"\n[Error] Permission denied: Cannot write to {PATH}")
                print("💡 Check folder permissions or run with appropriate rights")
                return False
            except OSError as e:
                if e.errno == 28:
                    print(f"\n[Error] Not enough disk space!")
                else:
                    print(f"\n[Error] Cannot save file: {e}")
                return False
        
        except Exception as e:
            print(f"\n[Unexpected Error] {e}")
            return False
    
    def close_connection(self):
        """Close connection gracefully"""
        print("\n[Client] Closing connection...")
        self.cleanup()
        self.is_connected = False
        print("[Client] ✓ Connection closed")