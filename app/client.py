"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import secrets
import sys
import threading
from typing import Optional
from dotenv import load_dotenv

from app.crypto.pki import validate_certificate_from_pem
from app.crypto.dh import generate_dh_parameters, generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key
from app.crypto.aes import encrypt_aes_128_ecb, decrypt_aes_128_ecb
from app.crypto.sign import load_private_key, load_public_key_from_pem, sign_data_base64, verify_signature_base64
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.common.protocol import HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage, DHClientMessage, DHServerMessage, ChatMessage, SessionReceipt
from app.storage.db import hash_password, get_user_salt
from app.storage.transcript import append_to_transcript, compute_transcript_hash, get_certificate_fingerprint as get_cert_fp, get_transcript_filename

load_dotenv()


class SecureChatClient:
    def __init__(self, host: str = "localhost", port: int = 8888):
        self.host = host
        self.port = port
        self.ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
        self.client_cert_path = os.getenv("CLIENT_CERT_PATH", "certs/client_cert.pem")
        self.client_key_path = os.getenv("CLIENT_KEY_PATH", "certs/client_key.pem")
        
        # Load client certificate and key
        with open(self.client_cert_path, "r") as f:
            self.client_cert_pem = f.read()
        self.client_key = load_private_key(self.client_key_path)
        
        # Session state
        self.server_cert_pem: Optional[str] = None
        self.temp_dh_key: Optional[int] = None
        self.temp_dh_p: Optional[int] = None
        self.temp_dh_g: Optional[int] = None
        self.temp_aes_key: Optional[bytes] = None
        self.session_dh_key: Optional[int] = None
        self.session_aes_key: Optional[bytes] = None
        self.seqno: int = 0
        self.transcript_path: Optional[str] = None
        self.sock: Optional[socket.socket] = None
    
    def send_json(self, data: dict):
        """Send JSON message over socket."""
        message = json.dumps(data) + "\n"
        self.sock.sendall(message.encode('utf-8'))
    
    def recv_json(self) -> dict:
        """Receive JSON message from socket."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            buffer += chunk
        line = buffer.split(b"\n", 1)[0]
        return json.loads(line.decode('utf-8'))
    
    def connect(self):
        """Connect to server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[+] Connected to server at {self.host}:{self.port}")
    
    def certificate_exchange(self) -> bool:
        """Handle certificate exchange."""
        # Send client hello
        client_nonce = b64e(secrets.token_bytes(16))
        hello = HelloMessage(
            client_cert=self.client_cert_pem,
            nonce=client_nonce
        )
        self.send_json(hello.model_dump())
        
        # Receive server hello
        msg_data = self.recv_json()
        
        # Check for error message
        if msg_data.get("type") == "error":
            print(f"[!] Server error: {msg_data.get('message')}")
            return False
        
        # Parse server hello
        try:
            server_hello = ServerHelloMessage(**msg_data)
            self.server_cert_pem = server_hello.server_cert
        except Exception as e:
            print(f"[!] Failed to parse server hello: {e}")
            print(f"[!] Received: {msg_data}")
            return False
        
        # Validate server certificate
        is_valid, error_msg = validate_certificate_from_pem(
            self.server_cert_pem,
            self.ca_cert_path,
            expected_hostname="server.local",
            strict_hostname=True
        )
        
        if not is_valid:
            print(f"[!] Server certificate validation failed: {error_msg}")
            return False
        
        print("[+] Server certificate validated")
        return True
    
    def temp_dh_exchange(self) -> bool:
        """Handle temporary DH exchange for credential encryption."""
        # Generate DH parameters
        self.temp_dh_p, self.temp_dh_g = generate_dh_parameters()
        
        # Generate client private key and public value
        self.temp_dh_key = generate_private_key(self.temp_dh_p)
        client_A = compute_public_value(self.temp_dh_key, self.temp_dh_g, self.temp_dh_p)
        
        # Send client DH parameters
        dh_client = DHClientMessage(g=self.temp_dh_g, p=self.temp_dh_p, A=client_A)
        self.send_json(dh_client.model_dump())
        
        # Receive server DH response
        msg_data = self.recv_json()
        dh_server = DHServerMessage(**msg_data)
        server_B = dh_server.B
        
        # Compute shared secret and derive AES key
        shared_secret = compute_shared_secret(self.temp_dh_key, server_B, self.temp_dh_p)
        self.temp_aes_key = derive_aes_key(shared_secret)
        
        print("[+] Temporary DH key exchange completed")
        return True
    
    def register(self, email: str, username: str, password: str) -> bool:
        """Register a new user."""
        # Generate salt and hash password
        salt = secrets.token_bytes(16)
        pwd_hash = hash_password(password, salt)
        
        # Create registration message
        reg_msg = RegisterMessage(
            email=email,
            username=username,
            pwd=b64e(pwd_hash.encode('utf-8')),  # Already hex string
            salt=b64e(salt)
        )
        
        # Encrypt and send
        reg_json = json.dumps(reg_msg.model_dump()).encode('utf-8')
        encrypted = encrypt_aes_128_ecb(reg_json, self.temp_aes_key)
        
        self.send_json({"type": "encrypted_auth", "data": b64e(encrypted)})
        
        # Receive response
        response = self.recv_json()
        if response.get("type") == "register_success":
            print(f"[+] Registration successful: {response.get('message')}")
            return True
        else:
            print(f"[!] Registration failed: {response.get('message')}")
            return False
    
    def login(self, email: str, password: str) -> bool:
        """Login user."""
        # Request salt from server first (encrypted)
        salt_request = {"type": "get_salt", "email": email}
        salt_json = json.dumps(salt_request).encode('utf-8')
        encrypted_salt_req = encrypt_aes_128_ecb(salt_json, self.temp_aes_key)
        self.send_json({"type": "encrypted_auth", "data": b64e(encrypted_salt_req)})
        
        # Receive encrypted salt response
        salt_response = self.recv_json()
        if salt_response.get("type") != "encrypted_salt":
            print("[!] Failed to get salt from server")
            return False
        
        # Decrypt salt
        try:
            encrypted_salt_bytes = b64d(salt_response.get("data", ""))
            decrypted_salt_bytes = decrypt_aes_128_ecb(encrypted_salt_bytes, self.temp_aes_key)
            salt_data = json.loads(decrypted_salt_bytes.decode('utf-8'))
            
            # Check if server sent an error
            if salt_data.get("type") == "error":
                print(f"[!] {salt_data.get('message', 'User not found')}")
                return False
            
            # Extract salt
            salt_b64 = salt_data.get("salt", "")
            if not salt_b64:
                print("[!] No salt in server response")
                return False
            
            salt = b64d(salt_b64)
        except Exception as e:
            print(f"[!] Failed to decrypt salt: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Compute password hash
        pwd_hash = hash_password(password, salt)
        
        # Generate nonce
        nonce = b64e(secrets.token_bytes(16))
        
        # Create login message
        login_msg = LoginMessage(
            email=email,
            pwd=b64e(pwd_hash.encode('utf-8')),
            nonce=nonce
        )
        
        # Encrypt and send
        login_json = json.dumps(login_msg.model_dump()).encode('utf-8')
        encrypted = encrypt_aes_128_ecb(login_json, self.temp_aes_key)
        
        self.send_json({"type": "encrypted_auth", "data": b64e(encrypted)})
        
        # Receive response
        response = self.recv_json()
        if response.get("type") == "login_success":
            print(f"[+] Login successful: {response.get('username')}")
            return True
        else:
            print(f"[!] Login failed: {response.get('message')}")
            return False
    
    def session_key_exchange(self) -> bool:
        """Establish session key after login."""
        # Generate new DH parameters for session
        session_p, session_g = generate_dh_parameters()
        
        # Generate client session private key
        self.session_dh_key = generate_private_key(session_p)
        client_A = compute_public_value(self.session_dh_key, session_g, session_p)
        
        # Send client DH parameters
        dh_client = DHClientMessage(g=session_g, p=session_p, A=client_A)
        self.send_json(dh_client.model_dump())
        
        # Receive server DH response
        msg_data = self.recv_json()
        dh_server = DHServerMessage(**msg_data)
        server_B = dh_server.B
        
        # Compute session shared secret and derive AES key
        session_shared_secret = compute_shared_secret(self.session_dh_key, server_B, session_p)
        self.session_aes_key = derive_aes_key(session_shared_secret)
        
        # Initialize transcript
        self.transcript_path = f"transcripts/{get_transcript_filename('client')}"
        self.seqno = 0
        
        print("[+] Session key established")
        return True
    
    def send_message(self, message: str):
        """Send an encrypted chat message."""
        # Increment sequence number
        self.seqno += 1
        
        # Encrypt message
        plaintext_bytes = message.encode('utf-8')
        ciphertext_bytes = encrypt_aes_128_ecb(plaintext_bytes, self.session_aes_key)
        ciphertext_b64 = b64e(ciphertext_bytes)
        
        # Compute hash and sign
        timestamp = now_ms()
        hash_input = f"{self.seqno}{timestamp}{ciphertext_b64}".encode('utf-8')
        hash_bytes = sha256_hex(hash_input).encode('utf-8')
        signature = sign_data_base64(hash_bytes, self.client_key)
        
        # Create chat message
        chat_msg = ChatMessage(
            seqno=self.seqno,
            ts=timestamp,
            ct=ciphertext_b64,
            sig=signature
        )
        
        # Send message
        self.send_json(chat_msg.model_dump())
        
        # Append to transcript
        server_fp = get_cert_fp(self.server_cert_pem)
        append_to_transcript(
            self.transcript_path,
            self.seqno,
            timestamp,
            ciphertext_b64,
            signature,
            server_fp
        )
    
    def receive_messages(self):
        """Receive and display messages from server."""
        while True:
            try:
                # Receive message
                msg_data = self.recv_json()
                
                # Check for error messages
                if msg_data.get("type") == "error":
                    error_msg = msg_data.get("message", "Unknown error")
                    if error_msg in ["REPLAY", "SIG_FAIL", "DECRYPT_FAIL"]:
                        print(f"[!] Server error: {error_msg}")
                    continue
                
                # Parse chat message
                try:
                    chat_msg = parse_message(msg_data)
                    if not isinstance(chat_msg, ChatMessage):
                        continue
                    
                    # Verify signature
                    server_pub_key = load_public_key_from_pem(self.server_cert_pem)
                    hash_input = f"{chat_msg.seqno}{chat_msg.ts}{chat_msg.ct}".encode('utf-8')
                    hash_bytes = sha256_hex(hash_input).encode('utf-8')
                    
                    if not verify_signature_base64(hash_bytes, chat_msg.sig, server_pub_key):
                        print("[!] Signature verification failed for server message")
                        continue
                    
                    # Decrypt message
                    ciphertext_bytes = b64d(chat_msg.ct)
                    plaintext_bytes = decrypt_aes_128_ecb(ciphertext_bytes, self.session_aes_key)
                    plaintext = plaintext_bytes.decode('utf-8')
                    
                    # Append to transcript
                    server_fp = get_cert_fp(self.server_cert_pem)
                    append_to_transcript(
                        self.transcript_path,
                        chat_msg.seqno,
                        chat_msg.ts,
                        chat_msg.ct,
                        chat_msg.sig,
                        server_fp
                    )
                    
                    # Display message
                    print(f"\n[Server] {plaintext}")
                    print("You: ", end="", flush=True)
                    
                except Exception as e:
                    print(f"[!] Error processing message: {e}")
                    continue
                    
            except ConnectionError:
                print("\n[*] Server disconnected")
                break
            except Exception as e:
                print(f"\n[!] Receive error: {e}")
                break
    
    def chat_loop(self):
        """Main chat loop with bidirectional communication."""
        print("[+] Chat session started. Type messages (or 'quit' to end)")
        
        # Start receiver thread
        receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receiver_thread.start()
        
        while True:
            try:
                # Get user input
                message = input("You: ").strip()
                
                if message.lower() == 'quit':
                    break
                
                if not message:
                    continue
                
                # Send message
                self.send_message(message)
                
            except KeyboardInterrupt:
                print("\n[*] Ending chat session...")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                break
        
        # Generate and receive session receipt
        self.handle_session_receipt()
    
    def handle_session_receipt(self):
        """Generate and exchange session receipt."""
        if not self.transcript_path or not os.path.exists(self.transcript_path):
            return
        
        try:
            # Compute transcript hash
            transcript_hash = compute_transcript_hash(self.transcript_path)
            
            # Read transcript to get first and last seqno
            from app.storage.transcript import read_transcript
            entries = read_transcript(self.transcript_path)
            
            if not entries:
                return
            
            first_seq = entries[0]["seqno"]
            last_seq = entries[-1]["seqno"]
            
            # Sign transcript hash
            hash_bytes = transcript_hash.encode('utf-8')
            receipt_sig = sign_data_base64(hash_bytes, self.client_key)
            
            # Create session receipt
            receipt = SessionReceipt(
                peer="client",
                first_seq=first_seq,
                last_seq=last_seq,
                transcript_sha256=transcript_hash,
                sig=receipt_sig
            )
            
            # Send receipt to server
            self.send_json(receipt.model_dump())
            
            # Save receipt to file
            receipt_path = self.transcript_path.replace(".txt", "_receipt.json")
            with open(receipt_path, "w") as f:
                f.write(json.dumps(receipt.model_dump(), indent=2))
            
            print(f"[+] Session receipt generated: {receipt_path}")
            
            # Try to receive server receipt
            try:
                server_receipt_data = self.recv_json()
                if server_receipt_data.get("type") == "receipt":
                    server_receipt_path = receipt_path.replace("client", "server_received")
                    with open(server_receipt_path, "w") as f:
                        f.write(json.dumps(server_receipt_data, indent=2))
                    print(f"[+] Server receipt received: {server_receipt_path}")
            except:
                pass  # Server might have disconnected
                
        except Exception as e:
            print(f"[!] Error generating receipt: {e}")
            import traceback
            traceback.print_exc()
    
    def run(self):
        """Run the client."""
        try:
            # Connect
            self.connect()
            
            # Certificate exchange
            if not self.certificate_exchange():
                return
            
            # Temporary DH exchange
            if not self.temp_dh_exchange():
                return
            
            # Registration or Login
            print("\n1. Register")
            print("2. Login")
            choice = input("Choose (1/2): ").strip()
            
            if choice == "1":
                email = input("Email: ").strip()
                username = input("Username: ").strip()
                password = input("Password: ").strip()
                if not self.register(email, username, password):
                    return
            elif choice == "2":
                email = input("Email: ").strip()
                password = input("Password: ").strip()
                if not self.login(email, password):
                    return
            else:
                print("[!] Invalid choice")
                return
            
            # Session key exchange
            if not self.session_key_exchange():
                return
            
            # Start chat
            self.chat_loop()
            
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            if self.sock:
                self.sock.close()


def main():
    host = os.getenv("SERVER_HOST", "localhost")
    port = int(os.getenv("SERVER_PORT", 8888))
    
    client = SecureChatClient(host, port)
    client.run()


if __name__ == "__main__":
    main()
