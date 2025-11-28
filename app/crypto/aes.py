"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Add PKCS#7 padding to data.
    
    Args:
        data: Data to pad
        block_size: Block size (16 for AES)
        
    Returns:
        Padded data
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data.
    
    Args:
        data: Padded data
        
    Returns:
        Unpadded data
        
    Raises:
        ValueError: If padding is invalid
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    
    padding_length = data[-1]
    
    # Validate padding length
    if padding_length == 0 or padding_length > len(data):
        raise ValueError("Invalid padding length")
    
    # Validate all padding bytes are the same
    padding = data[-padding_length:]
    if not all(b == padding_length for b in padding):
        raise ValueError("Invalid padding bytes")
    
    return data[:-padding_length]


def encrypt_aes_128_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: Plaintext to encrypt
        key: 16-byte AES key
        
    Returns:
        Encrypted ciphertext
        
    Raises:
        ValueError: If key length is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Add PKCS#7 padding
    padded_plaintext = pkcs7_pad(plaintext, block_size=16)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext


def decrypt_aes_128_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in ECB mode and remove PKCS#7 padding.
    
    Args:
        ciphertext: Ciphertext to decrypt
        key: 16-byte AES key
        
    Returns:
        Decrypted plaintext (with padding removed)
        
    Raises:
        ValueError: If key length is not 16 bytes or if padding is invalid
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext
