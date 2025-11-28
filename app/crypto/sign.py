"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def load_private_key(key_path: str) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from PEM file.
    
    Args:
        key_path: Path to private key file
        
    Returns:
        RSA private key object
    """
    with open(key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Key is not an RSA private key")
    
    return private_key


def load_public_key_from_cert(cert_path: str) -> rsa.RSAPublicKey:
    """
    Load RSA public key from certificate file.
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        RSA public key object
    """
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Certificate does not contain an RSA public key")
    
    return public_key


def load_public_key_from_pem(cert_pem: str) -> rsa.RSAPublicKey:
    """
    Load RSA public key from PEM certificate string.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        RSA public key object
    """
    cert = x509.load_pem_x509_certificate(
        cert_pem.encode() if isinstance(cert_pem, str) else cert_pem,
        default_backend()
    )
    
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Certificate does not contain an RSA public key")
    
    return public_key


def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign data using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        data: Data to sign
        private_key: RSA private key
        
    Returns:
        Signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def sign_data_base64(data: bytes, private_key: rsa.RSAPrivateKey) -> str:
    """
    Sign data and return base64-encoded signature.
    
    Args:
        data: Data to sign
        private_key: RSA private key
        
    Returns:
        Base64-encoded signature string
    """
    signature = sign_data(data, private_key)
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verify RSA signature using PKCS#1 v1.5 with SHA-256.
    
    Args:
        data: Original data
        signature: Signature bytes
        public_key: RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def verify_signature_base64(data: bytes, signature_b64: str, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verify base64-encoded RSA signature.
    
    Args:
        data: Original data
        signature_b64: Base64-encoded signature string
        public_key: RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        signature = base64.b64decode(signature_b64)
        return verify_signature(data, signature, public_key)
    except Exception:
        return False
