"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from typing import Optional
from pydantic import BaseModel, Field


class HelloMessage(BaseModel):
    """Client hello message with certificate and nonce."""
    type: str = Field(default="hello", description="Message type")
    client_cert: str = Field(..., description="Client certificate in PEM format")
    nonce: str = Field(..., description="Random nonce (base64-encoded)")


class ServerHelloMessage(BaseModel):
    """Server hello message with certificate and nonce."""
    type: str = Field(default="server_hello", description="Message type")
    server_cert: str = Field(..., description="Server certificate in PEM format")
    nonce: str = Field(..., description="Random nonce (base64-encoded)")


class RegisterMessage(BaseModel):
    """User registration message (encrypted)."""
    type: str = Field(default="register", description="Message type")
    email: str = Field(..., description="User email")
    username: str = Field(..., description="Username")
    pwd: str = Field(..., description="Base64-encoded SHA256(salt || password)")
    salt: str = Field(..., description="Base64-encoded salt")


class LoginMessage(BaseModel):
    """User login message (encrypted)."""
    type: str = Field(default="login", description="Message type")
    email: str = Field(..., description="User email")
    pwd: str = Field(..., description="Base64-encoded SHA256(salt || password)")
    nonce: str = Field(..., description="Random nonce (base64-encoded)")


class DHClientMessage(BaseModel):
    """Client Diffie-Hellman parameters."""
    type: str = Field(default="dh_client", description="Message type")
    g: int = Field(..., description="Generator")
    p: int = Field(..., description="Prime modulus")
    A: int = Field(..., description="Client public value (g^a mod p)")


class DHServerMessage(BaseModel):
    """Server Diffie-Hellman response."""
    type: str = Field(default="dh_server", description="Message type")
    B: int = Field(..., description="Server public value (g^b mod p)")


class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: str = Field(default="msg", description="Message type")
    seqno: int = Field(..., description="Sequence number")
    ts: int = Field(..., description="Unix timestamp in milliseconds")
    ct: str = Field(..., description="Base64-encoded ciphertext")
    sig: str = Field(..., description="Base64-encoded RSA signature over SHA256(seqno || ts || ct)")


class SessionReceipt(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = Field(default="receipt", description="Message type")
    peer: str = Field(..., description="Peer identifier (client or server)")
    first_seq: int = Field(..., description="First sequence number in transcript")
    last_seq: int = Field(..., description="Last sequence number in transcript")
    transcript_sha256: str = Field(..., description="SHA-256 hash of transcript (hex)")
    sig: str = Field(..., description="Base64-encoded RSA signature over transcript hash")


# Helper function to parse message type
def parse_message(json_data: dict) -> BaseModel:
    """
    Parse JSON message and return appropriate Pydantic model.
    
    Args:
        json_data: Dictionary containing message data
        
    Returns:
        Appropriate message model instance
        
    Raises:
        ValueError: If message type is unknown
    """
    msg_type = json_data.get("type", "")
    
    if msg_type == "hello":
        return HelloMessage(**json_data)
    elif msg_type == "server_hello":
        return ServerHelloMessage(**json_data)
    elif msg_type == "register":
        return RegisterMessage(**json_data)
    elif msg_type == "login":
        return LoginMessage(**json_data)
    elif msg_type == "dh_client":
        return DHClientMessage(**json_data)
    elif msg_type == "dh_server":
        return DHServerMessage(**json_data)
    elif msg_type == "msg":
        return ChatMessage(**json_data)
    elif msg_type == "receipt":
        return SessionReceipt(**json_data)
    else:
        raise ValueError(f"Unknown message type: {msg_type}")
