"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import base64
import hashlib
import time


def now_ms() -> int:
    """
    Get current Unix timestamp in milliseconds.
    
    Returns:
        Unix timestamp in milliseconds
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Encode bytes to base64 string.
    
    Args:
        b: Bytes to encode
        
    Returns:
        Base64-encoded string
    """
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str) -> bytes:
    """
    Decode base64 string to bytes.
    
    Args:
        s: Base64-encoded string
        
    Returns:
        Decoded bytes
    """
    return base64.b64decode(s)


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hexadecimal string.
    
    Args:
        data: Data to hash
        
    Returns:
        Hexadecimal string of SHA-256 hash (64 characters)
    """
    return hashlib.sha256(data).hexdigest()
