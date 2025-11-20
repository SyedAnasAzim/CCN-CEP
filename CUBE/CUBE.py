from Server import Server
from Client import Client
import socket
import os
import sys
import time
from re import match

IP_PATTERN = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

def get_my_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        private_ip = s.getsockname()[0]
        s.close()
        return private_ip
    except Exception as e:
        return "Unable to determine"


while True:
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║     ██████╗██╗   ██╗██████╗ ███████╗                  ║
    ║    ██╔════╝██║   ██║██╔══██╗██╔════╝                  ║
    ║    ██║     ██║   ██║██████╔╝█████╗                    ║
    ║    ██║     ██║   ██║██╔══██╗██╔══╝                    ║
    ║    ╚██████╗╚██████╔╝██████╔╝███████╗                  ║
    ║     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝                  ║
    ║                                                       ║
    ║         🔐 Encrypted File Transfer System 🔐          ║
    ║              Secure • Fast • Reliable                 ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    current_ip = get_my_ip()
    print(f"    Your Local IP: {current_ip}")
    print(f"    Port: 5000\n")
    
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║                      MAIN MENU                         ║
    ╠════════════════════════════════════════════════════════╣
    ║                                                        ║
    ║         1. 📤  Send Files        Send to client        ║
    ║                                                        ║
    ║         2. 📥  Receive Files     Receive from server   ║
    ║                                                        ║
    ║         3. 📖  Help              Usage guide           ║
    ║                                                        ║
    ║         4. 📋  Instructions      Getting started       ║
    ║                                                        ║
    ║         5. 🚪  Exit              Close application     ║
    ║                                                        ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    choice = input("    Enter your choice [1-5]: ").strip()
    
    # Option 1: Send Files
    if choice == "1":
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n" + "="*60)
        print("📤 SEND FILES MODE")
        print("="*60 + "\n")
        
        while True:
            print("Select IP Configuration:")
            print("  1. Your Local IP  (for network transfer)")
            print("  2. Localhost      (for testing on same machine)\n")
            
            select = input("Enter your choice [1-2]: ").strip()
            
            if select == "1":
                ip = get_my_ip()
                print(f"\n✓ Using your IP: {ip}\n")
                server = Server(ip=ip)
                break
            elif select == "2":
                ip = "localhost"
                print(f"\n✓ Using: {ip}\n")
                server = Server()
                break
            else:
                print("❌ Invalid choice. Please select 1 or 2.\n")
        
        while True:  
            ret = server.sending()
            
            print("\n" + "="*60)
            if ret:
                print("✅ FILE TRANSFER COMPLETED SUCCESSFULLY!")
            else:
                print("❌ FILE TRANSFER FAILED OR CANCELLED")
            print("="*60 + "\n")
            if server.not_connected_to_cli:
                print("\nConnection between Server and Client has been lost\n")
                for i in range(5,0,-1):
                    print(f"\rReturing to main menu in {i} seconds....",end="",flush=True)
                    time.sleep(1)
                server.close_connection()
                break
            select = input("Send another file? [y for yes or any other key to stop]: ").strip()
            if select.lower() != "y":
                server.close_connection()
                break
        
        
        # input("\n📌 Press Enter to return to main menu...")
    
    # Option 2: Receive Files
    elif choice == "2":
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n" + "="*60)
        print("📥 RECEIVE FILES MODE")
        print("="*60 + "\n")
        
        while True:
            print("Select Server Connection:")
            print("  1. Enter Server IP  (network transfer)")
            print("  2. Localhost        (testing on same machine)\n")
            
            select = input("Enter your choice [1-2]: ").strip()
            
            if select == "1":
                ip = input("\nEnter server IP address: ").strip()
                match_ip = match(IP_PATTERN,ip)
                if not match_ip:
                    print("❌ No IP provided. Please try again.\n")
                    continue
                print(f"\n✓ Connecting to: {ip}\n")
                client = Client(ip=ip)
                break
            elif select == "2":
                ip = "localhost"
                print(f"\n✓ Connecting to: {ip}\n")
                client = Client()
                break
            else:
                print("❌ Invalid choice. Please select 1 or 2.\n")
        while True:
            ret = client.receiving()
            
            print("\n" + "="*60)
            if ret:
                print("✅ FILE TRANSFER COMPLETED SUCCESSFULLY!")
                print("   Check 'CUBE Downloads' folder for your file")
            else:
                print("❌ FILE TRANSFER FAILED OR CANCELLED")
            print("="*60 + "\n")
            if client.not_connected_to_ser:
                print("\nConnection between Server and Client has been lost\n")
                for i in range(5,0,-1):
                    print(f"\rReturing to main menu in {i} seconds....",end="",flush=True)
                    time.sleep(1)
                client.close_connection()
                break
            select = input("Receive another file? [y for yes or any other key to stop]: ").strip()
            if select.lower() != "y":
                client.close_connection()
                break
            
        # input("\n📌 Press Enter to return to main menu...")
    
    # Option 3: Help
    elif choice == "3":
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    📖 HELP & USAGE GUIDE
    ════════════════════════════════════════════════════════
    
    OVERVIEW:
    ─────────
    CUBE is an encrypted file transfer application that allows
    secure file sharing between two devices using encryption 
    (RSA-2048 + AES-256-GCM).
    
    FEATURES:
    ─────────
    ✓ End-to-end encryption
    ✓ File integrity verification (SHA-256 hashing)
    ✓ Progress tracking with transfer speed
    ✓ Automatic disk space checking
    ✓ Connection handshake protocol
    ✓ Support for files of any size
    
    HOW TO USE:
    ───────────
    
    🔹 SENDING FILES (Option 1):
       • Choose "Send Files" from main menu
       • Select IP configuration (your IP or localhost)
       • Wait for client to connect
       • Enter: send <filename>
       • File will be encrypted and transferred
    
    🔹 RECEIVING FILES (Option 2):
       • Choose "Receive Files" from main menu
       • Enter server's IP address
       • Server will send file automatically
       • File saves to "CUBE Downloads" folder
    
    NETWORK SETUP:
    ──────────────
    • Same Computer: Use "localhost" on both sides
    • Local Network: Use "Your IP" option
    • Make sure port 5000 is not blocked
    • Server must be started before client connects
    
    TROUBLESHOOTING:
    ────────────────
    ❌ "Port already in use"
       → Wait 30 seconds or close other programs
    
    ❌ "Connection refused"
       → Ensure server is running first
       → Check firewall settings
    
    ❌ "Permission denied"
       → Check file/folder permissions
       → Run with appropriate rights
    
    ❌ "Disk space error"
       → Free up disk space
       → Check available storage
    
    SECURITY:
    ─────────
    🔒 Your files are encrypted during transfer
    🔒 Each transfer uses unique session keys
    🔒 Data integrity verified with hashes
    🔒 No data stored by application
    
    ════════════════════════════════════════════════════════
        """)
        input("\n    📌 Press Enter to return to main menu...")
    
    # Option 4: Instructions
    elif choice == "4":
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    📋 STEP-BY-STEP INSTRUCTIONS
    ════════════════════════════════════════════════════════
    
    🎯 QUICK START GUIDE
    
    ┌────────────────────────────────────────────────────────┐
    │  SCENARIO 1: Testing on Same Computer                 │
    └────────────────────────────────────────────────────────┘
    
    Terminal 1 (Server):
    ────────────────────
    1. Run: python main.py
    2. Select: 1 (Send Files)
    3. Select: 2 (Localhost)
    4. Wait for connection...
    5. When prompted, type: send filename.txt
    6. File will be transferred!
    
    Terminal 2 (Client):
    ────────────────────
    1. Run: python main.py
    2. Select: 2 (Receive Files)
    3. Select: 2 (Localhost)
    4. File received automatically!
    5. Check "CUBE Downloads" folder
    
    
    ┌────────────────────────────────────────────────────────┐
    │  SCENARIO 2: Transfer Between Two Computers           │
    └────────────────────────────────────────────────────────┘
    
    Computer A (Server - Has the file):
    ────────────────────────────────────
    1. Run: python main.py
    2. Select: 1 (Send Files)
    3. Select: 1 (Your IP)
    4. Note the IP address shown (e.g., 192.168.1.100)
    5. Wait for Computer B to connect...
    6. Type: send yourfile.pdf
    7. Transfer begins!
    
    Computer B (Client - Wants the file):
    ──────────────────────────────────────
    1. Run: python main.py
    2. Select: 2 (Receive Files)
    3. Select: 1 (Enter IP)
    4. Enter Computer A's IP (192.168.1.100)
    5. File received automatically!
    6. Saved to "CUBE Downloads" folder
    
    
    ⚠️  IMPORTANT NOTES:
    ────────────────────
    • Server must be running BEFORE client connects
    • Both computers must be on same network (for LAN)
    • Make sure port 5000 is not blocked by firewall
    • File integrity is automatically verified
    • You can send/receive multiple files in one session
    
    
    💡 TIPS:
    ────────
    • Use descriptive filenames
    • Check file size before sending large files
    • Ensure sufficient disk space on receiving end
    • Close application properly using Exit option
    • For best speed, use wired connection
    
    
    🔐 SECURITY NOTES:
    ──────────────────
    • All files encrypted during transfer
    • Keys generated fresh for each session
    • No keys stored permanently
    • Hash verification ensures data integrity
    
    ════════════════════════════════════════════════════════
        """)
        input("\n    📌 Press Enter to return to main menu...")
    
    # Option 5: Exit
    elif choice == "5":
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║     ██████╗██╗   ██╗██████╗ ███████╗                  ║
    ║    ██╔════╝██║   ██║██╔══██╗██╔════╝                  ║
    ║    ██║     ██║   ██║██████╔╝█████╗                    ║
    ║    ██║     ██║   ██║██╔══██╗██╔══╝                    ║
    ║    ╚██████╗╚██████╔╝██████╔╝███████╗                  ║
    ║     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝                  ║
    ║                                                       ║
    ║         🔐 Encrypted File Transfer System 🔐          ║
    ║              Secure • Fast • Reliable                 ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝

    ╔════════════════════════════════════════════╗
    ║                                            ║
    ║     👋 Thank you for using CUBE! 👋        ║
    ║                                            ║
    ║         Stay Secure, Transfer Safe         ║
    ║                                            ║
    ╚════════════════════════════════════════════╝

        """)
        sys.exit(0)
    
    # Invalid choice
    else:
        print("\n    ❌ Invalid option. Please select 1-5.")
        input("    Press Enter to continue...")