"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import secrets
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh


# Standard DH parameters (RFC 3526 - 2048-bit MODP Group)
# These are well-known safe prime and generator values
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16
)
DEFAULT_G = 2


def generate_dh_parameters(p: int = None, g: int = None) -> tuple[int, int]:
    """
    Generate or return DH parameters (prime p and generator g).
    
    Args:
        p: Prime modulus (optional, uses default if None)
        g: Generator (optional, uses default if None)
        
    Returns:
        Tuple of (p, g)
    """
    if p is None:
        p = DEFAULT_P
    if g is None:
        g = DEFAULT_G
    return p, g


def generate_private_key(p: int) -> int:
    """
    Generate a random private key for DH.
    
    Args:
        p: Prime modulus
        
    Returns:
        Random private key (a or b) in range [1, p-1]
    """
    # Generate a random private key
    # In practice, we want it to be large enough for security
    # Generate a random number between 2 and p-2 (avoiding 1 and p-1)
    return secrets.randbelow(p - 2) + 2


def compute_public_value(private_key: int, g: int, p: int) -> int:
    """
    Compute public value: A = g^a mod p or B = g^b mod p.
    
    Args:
        private_key: Private key (a or b)
        g: Generator
        p: Prime modulus
        
    Returns:
        Public value (A or B)
    """
    return pow(g, private_key, p)


def compute_shared_secret(private_key: int, peer_public_value: int, p: int) -> int:
    """
    Compute shared secret: Ks = peer_public^private mod p.
    
    Args:
        private_key: Our private key (a or b)
        peer_public_value: Peer's public value (B or A)
        p: Prime modulus
        
    Returns:
        Shared secret Ks
    """
    return pow(peer_public_value, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from shared secret: K = Trunc16(SHA256(big-endian(Ks))).
    
    Args:
        shared_secret: Shared secret Ks (integer)
        
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    # Calculate number of bytes needed
    num_bytes = (shared_secret.bit_length() + 7) // 8
    if num_bytes == 0:
        num_bytes = 1
    
    # Convert to big-endian bytes
    ks_bytes = shared_secret.to_bytes(num_bytes, byteorder='big')
    
    # Compute SHA-256 hash
    hash_bytes = hashlib.sha256(ks_bytes).digest()
    
    # Truncate to 16 bytes (AES-128 key length)
    aes_key = hash_bytes[:16]
    
    return aes_key


def perform_dh_key_exchange(p: int, g: int) -> tuple[int, int, int]:
    """
    Perform a complete DH key exchange (generate private key and compute public value).
    
    Args:
        p: Prime modulus
        g: Generator
        
    Returns:
        Tuple of (private_key, public_value, shared_secret_placeholder)
        Note: shared_secret_placeholder is 0, actual shared secret computed after receiving peer's public value
    """
    private_key = generate_private_key(p)
    public_value = compute_public_value(private_key, g, p)
    return private_key, public_value, 0


def complete_dh_key_exchange(private_key: int, peer_public_value: int, p: int) -> bytes:
    """
    Complete DH key exchange by computing shared secret and deriving AES key.
    
    Args:
        private_key: Our private key
        peer_public_value: Peer's public value
        p: Prime modulus
        
    Returns:
        16-byte AES key
    """
    shared_secret = compute_shared_secret(private_key, peer_public_value, p)
    aes_key = derive_aes_key(shared_secret)
    return aes_key
