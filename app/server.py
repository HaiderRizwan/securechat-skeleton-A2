"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import secrets
import threading
from typing import Optional
from dotenv import load_dotenv

from app.crypto.pki import validate_certificate_from_pem, load_ca_certificate
from app.crypto.dh import generate_dh_parameters, generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key
from app.crypto.aes import encrypt_aes_128_ecb, decrypt_aes_128_ecb
from app.crypto.sign import load_private_key, load_public_key_from_pem, sign_data_base64, verify_signature_base64
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.common.protocol import parse_message, HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage, DHClientMessage, DHServerMessage, ChatMessage
from app.storage.db import register_user, authenticate_user, get_user_salt
from app.storage.transcript import append_to_transcript, compute_transcript_hash, get_certificate_fingerprint as get_cert_fp, get_transcript_filename

load_dotenv()


class SecureChatServer:
    def __init__(self, host: str = "localhost", port: int = 8888):
        self.host = host
        self.port = port
        self.ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
        self.server_cert_path = os.getenv("SERVER_CERT_PATH", "certs/server_cert.pem")
        self.server_key_path = os.getenv("SERVER_KEY_PATH", "certs/server_key.pem")
        
        # Load server certificate and key
        with open(self.server_cert_path, "r") as f:
            self.server_cert_pem = f.read()
        self.server_key = load_private_key(self.server_key_path)
        
        # Session state
        self.client_cert_pem: Optional[str] = None
        self.temp_dh_key: Optional[int] = None
        self.temp_dh_p: Optional[int] = None
        self.temp_dh_g: Optional[int] = None
        self.temp_aes_key: Optional[bytes] = None
        self.session_dh_key: Optional[int] = None
        self.session_aes_key: Optional[bytes] = None
        self.last_seqno: int = 0
        self.transcript_path: Optional[str] = None
        self.authenticated_username: Optional[str] = None
    
    def send_json(self, sock: socket.socket, data: dict):
        """Send JSON message over socket."""
        message = json.dumps(data) + "\n"
        sock.sendall(message.encode('utf-8'))
    
    def recv_json(self, sock: socket.socket) -> dict:
        """Receive JSON message from socket."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            buffer += chunk
        line = buffer.split(b"\n", 1)[0]
        return json.loads(line.decode('utf-8'))
    
    def handle_client(self, client_sock: socket.socket, addr):
        """Handle a single client connection."""
        try:
            print(f"[*] Client connected from {addr}")
            
            # Phase 1: Control Plane - Certificate Exchange
            if not self.handle_certificate_exchange(client_sock):
                return
            
            # Phase 2: Temporary DH for credential encryption
            if not self.handle_temp_dh_exchange(client_sock):
                return
            
            # Phase 3: Registration or Login
            action = self.handle_auth(client_sock)
            if not action:
                return
            
            # Phase 4: Session Key Establishment
            if not self.handle_session_key_exchange(client_sock):
                return
            
            # Phase 5: Chat Messages
            self.handle_chat(client_sock)
            
        except Exception as e:
            print(f"[!] Error handling client: {e}")
        finally:
            client_sock.close()
            print(f"[*] Client {addr} disconnected")
    
    def handle_certificate_exchange(self, sock: socket.socket) -> bool:
        """Handle certificate exchange (hello/server_hello)."""
        # Receive client hello
        msg_data = self.recv_json(sock)
        hello_msg = parse_message(msg_data)
        
        if not isinstance(hello_msg, HelloMessage):
            print("[!] Expected hello message")
            return False
        
        self.client_cert_pem = hello_msg.client_cert
        
        # Validate client certificate
        is_valid, error_msg = validate_certificate_from_pem(
            self.client_cert_pem,
            self.ca_cert_path,
            expected_hostname="client.local",
            strict_hostname=True
        )
        
        if not is_valid:
            print(f"[!] Client certificate validation failed: {error_msg}")
            self.send_json(sock, {"type": "error", "message": error_msg})
            return False
        
        print("[+] Client certificate validated")
        
        # Send server hello
        server_nonce = b64e(secrets.token_bytes(16))
        server_hello = ServerHelloMessage(
            server_cert=self.server_cert_pem,
            nonce=server_nonce
        )
        self.send_json(sock, server_hello.model_dump())
        
        return True
    
    def handle_temp_dh_exchange(self, sock: socket.socket) -> bool:
        """Handle temporary DH exchange for credential encryption."""
        # Receive client DH parameters
        msg_data = self.recv_json(sock)
        dh_msg = parse_message(msg_data)
        
        if not isinstance(dh_msg, DHClientMessage):
            print("[!] Expected dh_client message")
            return False
        
        self.temp_dh_p = dh_msg.p
        self.temp_dh_g = dh_msg.g
        client_A = dh_msg.A
        
        # Generate server private key and public value
        self.temp_dh_key = generate_private_key(self.temp_dh_p)
        server_B = compute_public_value(self.temp_dh_key, self.temp_dh_g, self.temp_dh_p)
        
        # Compute shared secret and derive AES key
        shared_secret = compute_shared_secret(self.temp_dh_key, client_A, self.temp_dh_p)
        self.temp_aes_key = derive_aes_key(shared_secret)
        
        # Send server DH response
        dh_response = DHServerMessage(B=server_B)
        self.send_json(sock, dh_response.model_dump())
        
        print("[+] Temporary DH key exchange completed")
        return True
    
    def handle_auth(self, sock: socket.socket) -> Optional[str]:
        """Handle registration or login."""
        # Receive encrypted auth message
        encrypted_data = self.recv_json(sock)
        
        # Decrypt
        try:
            encrypted_bytes = b64d(encrypted_data.get("data", ""))
            decrypted_bytes = decrypt_aes_128_ecb(encrypted_bytes, self.temp_aes_key)
            auth_data = json.loads(decrypted_bytes.decode('utf-8'))
        except Exception as e:
            print(f"[!] Failed to decrypt auth message: {e}")
            self.send_json(sock, {"type": "error", "message": "Decryption failed"})
            return None
        
        auth_type = auth_data.get("type")
        
        if auth_type == "get_salt":
            return self.handle_get_salt(sock, auth_data)
        elif auth_type == "register":
            return self.handle_register(sock, auth_data)
        elif auth_type == "login":
            return self.handle_login(sock, auth_data)
        else:
            self.send_json(sock, {"type": "error", "message": "Unknown auth type"})
            return None
    
    def handle_get_salt(self, sock: socket.socket, salt_data: dict) -> Optional[str]:
        """Handle salt request for login."""
        email = salt_data.get("email")
        salt = get_user_salt(email)
        
        if not salt:
            # User doesn't exist - send error
            error_msg = {"type": "error", "message": "User not found"}
            error_json = json.dumps(error_msg).encode('utf-8')
            encrypted = encrypt_aes_128_ecb(error_json, self.temp_aes_key)
            self.send_json(sock, {"type": "encrypted_salt", "data": b64e(encrypted)})
            return None
        
        # Send salt (encrypted)
        salt_response = {"type": "salt_response", "salt": b64e(salt)}
        salt_json = json.dumps(salt_response).encode('utf-8')
        encrypted = encrypt_aes_128_ecb(salt_json, self.temp_aes_key)
        self.send_json(sock, {"type": "encrypted_salt", "data": b64e(encrypted)})
        
        # Wait for login message
        encrypted_login = self.recv_json(sock)
        try:
            encrypted_bytes = b64d(encrypted_login.get("data", ""))
            decrypted_bytes = decrypt_aes_128_ecb(encrypted_bytes, self.temp_aes_key)
            login_data = json.loads(decrypted_bytes.decode('utf-8'))
            return self.handle_login(sock, login_data)
        except Exception as e:
            print(f"[!] Failed to decrypt login: {e}")
            return None
    
    def handle_register(self, sock: socket.socket, reg_data: dict) -> Optional[str]:
        """Handle user registration."""
        try:
            reg_msg = RegisterMessage(**reg_data)
            
            # Client sends: pwd (base64-encoded hex hash) and salt (base64-encoded)
            # Decode them
            pwd_hash_b64 = reg_msg.pwd
            salt_b64 = reg_msg.salt
            
            # Decode from base64
            pwd_hash_hex = b64d(pwd_hash_b64).decode('utf-8')  # Hex string
            salt = b64d(salt_b64)  # Bytes
            
            # Check if username already exists
            from app.storage.db import user_exists_by_username, user_exists_by_email, get_db_connection
            if user_exists_by_username(reg_msg.username):
                self.send_json(sock, {"type": "register_fail", "message": "Username already exists"})
                return None
            
            if user_exists_by_email(reg_msg.email):
                self.send_json(sock, {"type": "register_fail", "message": "Email already registered"})
                return None
            
            # Store in database
            connection = get_db_connection()
            try:
                with connection.cursor() as cursor:
                    sql = """
                    INSERT INTO users (email, username, salt, pwd_hash)
                    VALUES (%s, %s, %s, %s)
                    """
                    cursor.execute(sql, (reg_msg.email, reg_msg.username, salt, pwd_hash_hex))
                    connection.commit()
                    
                    # Set authenticated username for registration
                    self.authenticated_username = reg_msg.username
                    self.send_json(sock, {"type": "register_success", "message": "User registered successfully"})
                    print(f"[+] User registered: {reg_msg.username}")
                    return "registered"
            except Exception as db_error:
                connection.rollback()
                self.send_json(sock, {"type": "register_fail", "message": f"Database error: {str(db_error)}"})
                return None
            finally:
                connection.close()
        except Exception as e:
            print(f"[!] Registration error: {e}")
            import traceback
            traceback.print_exc()
            self.send_json(sock, {"type": "error", "message": str(e)})
            return None
    
    def handle_login(self, sock: socket.socket, login_data: dict) -> Optional[str]:
        """Handle user login."""
        try:
            login_msg = LoginMessage(**login_data)
            
            # Get user salt and stored hash from database
            from app.storage.db import get_db_connection
            connection = get_db_connection()
            try:
                with connection.cursor() as cursor:
                    sql = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
                    cursor.execute(sql, (login_msg.email,))
                    result = cursor.fetchone()
                    
                    if not result:
                        self.send_json(sock, {"type": "login_fail", "message": "Invalid email or password"})
                        return None
                    
                    username = result['username']
                    salt = result['salt']
                    stored_hash = result['pwd_hash']
                    
                    # Decode the client's password hash (base64 -> hex string)
                    client_hash_b64 = login_msg.pwd
                    client_hash_hex = b64d(client_hash_b64).decode('utf-8')
                    
                    # Compare hashes (constant-time)
                    from app.storage.db import verify_password
                    # We need to reconstruct the password hash to verify
                    # Actually, we can't verify without the password. The client sent the hash.
                    # We need to compare the hash directly
                    import secrets
                    if secrets.compare_digest(client_hash_hex, stored_hash):
                        # Dual gate: certificate already validated, password verified
                        self.authenticated_username = username
                        self.send_json(sock, {"type": "login_success", "message": "Login successful", "username": username})
                        print(f"[+] User logged in: {username}")
                        return "logged_in"
                    else:
                        self.send_json(sock, {"type": "login_fail", "message": "Invalid email or password"})
                        print(f"[!] Login failed: Password hash mismatch")
                        return None
            finally:
                connection.close()
        except Exception as e:
            print(f"[!] Login error: {e}")
            import traceback
            traceback.print_exc()
            self.send_json(sock, {"type": "error", "message": str(e)})
            return None
    
    def handle_session_key_exchange(self, sock: socket.socket) -> bool:
        """Handle session key establishment after login."""
        # Receive client DH parameters for session
        msg_data = self.recv_json(sock)
        dh_msg = parse_message(msg_data)
        
        if not isinstance(dh_msg, DHClientMessage):
            print("[!] Expected dh_client message for session")
            return False
        
        session_p = dh_msg.p
        session_g = dh_msg.g
        client_A = dh_msg.A
        
        # Generate server session private key
        self.session_dh_key = generate_private_key(session_p)
        server_B = compute_public_value(self.session_dh_key, session_g, session_p)
        
        # Compute session shared secret and derive AES key
        session_shared_secret = compute_shared_secret(self.session_dh_key, client_A, session_p)
        self.session_aes_key = derive_aes_key(session_shared_secret)
        
        # Send server DH response
        dh_response = DHServerMessage(B=server_B)
        self.send_json(sock, dh_response.model_dump())
        
        # Initialize transcript
        self.transcript_path = f"transcripts/{get_transcript_filename('server')}"
        self.last_seqno = 0
        
        print("[+] Session key established")
        return True
    
    def handle_chat(self, sock: socket.socket):
        """Handle encrypted chat messages."""
        print("[+] Chat session started. Type messages (or 'quit' to end)")
        
        while True:
            try:
                # Receive message
                msg_data = self.recv_json(sock)
                chat_msg = parse_message(msg_data)
                
                if not isinstance(chat_msg, ChatMessage):
                    print("[!] Expected chat message")
                    break
                
                # Check sequence number (replay protection)
                if chat_msg.seqno <= self.last_seqno:
                    print(f"[!] Replay detected: seqno {chat_msg.seqno} <= {self.last_seqno}")
                    self.send_json(sock, {"type": "error", "message": "REPLAY"})
                    continue
                
                # Verify signature
                client_pub_key = load_public_key_from_pem(self.client_cert_pem)
                hash_input = f"{chat_msg.seqno}{chat_msg.ts}{chat_msg.ct}".encode('utf-8')
                hash_bytes = sha256_hex(hash_input).encode('utf-8')
                
                if not verify_signature_base64(hash_bytes, chat_msg.sig, client_pub_key):
                    print("[!] Signature verification failed")
                    self.send_json(sock, {"type": "error", "message": "SIG_FAIL"})
                    continue
                
                # Decrypt message
                try:
                    ciphertext_bytes = b64d(chat_msg.ct)
                    plaintext_bytes = decrypt_aes_128_ecb(ciphertext_bytes, self.session_aes_key)
                    plaintext = plaintext_bytes.decode('utf-8')
                except Exception as e:
                    print(f"[!] Decryption failed: {e}")
                    self.send_json(sock, {"type": "error", "message": "DECRYPT_FAIL"})
                    continue
                
                # Update sequence number
                self.last_seqno = chat_msg.seqno
                
                # Append to transcript
                client_fp = get_cert_fp(self.client_cert_pem)
                append_to_transcript(
                    self.transcript_path,
                    chat_msg.seqno,
                    chat_msg.ts,
                    chat_msg.ct,
                    chat_msg.sig,
                    client_fp
                )
                
                # Display message
                username = self.authenticated_username or "Unknown"
                print(f"[{username}] {plaintext}")
                
            except json.JSONDecodeError:
                print("[!] Invalid JSON received")
                break
            except ConnectionError:
                print("[*] Client disconnected")
                self.generate_session_receipt(sock)
                break
            except KeyboardInterrupt:
                print("\n[*] Chat session ending...")
                self.generate_session_receipt(sock)
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                break
        
        # Generate receipt when chat ends
        self.generate_session_receipt(sock)
    
    def generate_session_receipt(self, sock: socket.socket):
        """Generate and send session receipt for non-repudiation."""
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
            receipt_sig = sign_data_base64(hash_bytes, self.server_key)
            
            # Create session receipt
            from app.common.protocol import SessionReceipt
            receipt = SessionReceipt(
                peer="server",
                first_seq=first_seq,
                last_seq=last_seq,
                transcript_sha256=transcript_hash,
                sig=receipt_sig
            )
            
            # Send receipt to client
            self.send_json(sock, receipt.model_dump())
            
            # Save receipt to file
            receipt_path = self.transcript_path.replace(".txt", "_receipt.json")
            with open(receipt_path, "w") as f:
                f.write(json.dumps(receipt.model_dump(), indent=2))
            
            print(f"[+] Session receipt generated: {receipt_path}")
            
        except Exception as e:
            print(f"[!] Error generating receipt: {e}")
            import traceback
            traceback.print_exc()
    
    def start(self):
        """Start the server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        
        print(f"[*] Secure Chat Server listening on {self.host}:{self.port}")
        print(f"[*] Waiting for clients...")
        
        while True:
            client_sock, addr = server_sock.accept()
            # Handle each client in a separate thread
            client_thread = threading.Thread(target=self.handle_client, args=(client_sock, addr))
            client_thread.daemon = True
            client_thread.start()


def main():
    host = os.getenv("SERVER_HOST", "localhost")
    port = int(os.getenv("SERVER_PORT", 8888))
    
    server = SecureChatServer(host, port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down...")


if __name__ == "__main__":
    main()
