"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

import os
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import oid
from cryptography.x509.oid import NameOID


class CertificateValidationError(Exception):
    """Custom exception for certificate validation errors."""
    pass


def load_ca_certificate(ca_cert_path: str = "certs/ca_cert.pem") -> x509.Certificate:
    """
    Load the Root CA certificate.
    
    Args:
        ca_cert_path: Path to CA certificate file
        
    Returns:
        CA certificate object
        
    Raises:
        FileNotFoundError: If CA certificate file doesn't exist
    """
    if not os.path.exists(ca_cert_path):
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
    
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_cert


def load_certificate_from_pem(cert_pem: str) -> x509.Certificate:
    """
    Load certificate from PEM string.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        Certificate object
    """
    return x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)


def load_certificate_from_file(cert_path: str) -> x509.Certificate:
    """
    Load certificate from file.
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Certificate object
    """
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_certificate_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify that the certificate is signed by the CA.
    
    Args:
        cert: Certificate to verify
        ca_cert: CA certificate (trust anchor)
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Check if issuer matches CA subject
        if cert.issuer != ca_cert.subject:
            return False
        
        # Get the CA's public key
        ca_public_key = ca_cert.public_key()
        
        # Determine the hash algorithm from the signature algorithm OID
        # Extract hash algorithm from signature algorithm OID
        sig_oid = cert.signature_algorithm_oid
        if sig_oid == oid.SignatureAlgorithmOID.RSA_WITH_SHA256:
            hash_algorithm = hashes.SHA256()
        elif sig_oid == oid.SignatureAlgorithmOID.RSA_WITH_SHA384:
            hash_algorithm = hashes.SHA384()
        elif sig_oid == oid.SignatureAlgorithmOID.RSA_WITH_SHA512:
            hash_algorithm = hashes.SHA512()
        else:
            # Default to SHA256
            hash_algorithm = hashes.SHA256()
        
        # Verify the certificate signature using PKCS1v15 padding
        # The signature is over the TBS (To Be Signed) certificate bytes
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_algorithm
        )
        return True
    except Exception:
        # Signature verification failed
        return False


def check_certificate_validity(cert: x509.Certificate) -> bool:
    """
    Check if certificate is within its validity period.
    
    Args:
        cert: Certificate to check
        
    Returns:
        True if certificate is valid (not expired, not before valid date), False otherwise
    """
    from datetime import timezone
    now = datetime.now(timezone.utc)
    
    # Convert certificate dates to timezone-aware if needed
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    
    # If certificate dates are naive, make them timezone-aware (UTC)
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    
    # Check if certificate is not yet valid
    if now < not_before:
        return False
    
    # Check if certificate has expired
    if now > not_after:
        return False
    
    return True


def get_certificate_cn(cert: x509.Certificate) -> str:
    """
    Extract Common Name (CN) from certificate.
    
    Args:
        cert: Certificate object
        
    Returns:
        Common Name string, or empty string if not found
    """
    try:
        cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attributes:
            return cn_attributes[0].value
    except Exception:
        pass
    return ""


def get_certificate_san_dns_names(cert: x509.Certificate) -> list[str]:
    """
    Extract DNS names from Subject Alternative Name (SAN) extension.
    
    Args:
        cert: Certificate object
        
    Returns:
        List of DNS names
    """
    dns_names = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                dns_names.append(name.value)
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    return dns_names


def check_hostname_match(cert: x509.Certificate, expected_hostname: str) -> bool:
    """
    Check if certificate's CN or SAN matches the expected hostname.
    
    Args:
        cert: Certificate to check
        expected_hostname: Expected hostname (e.g., "server.local" or "client.local")
        
    Returns:
        True if hostname matches, False otherwise
    """
    # Check CN
    cn = get_certificate_cn(cert)
    if cn == expected_hostname:
        return True
    
    # Check SAN DNS names
    san_dns_names = get_certificate_san_dns_names(cert)
    if expected_hostname in san_dns_names:
        return True
    
    return False


def is_self_signed(cert: x509.Certificate) -> bool:
    """
    Check if certificate is self-signed.
    
    Args:
        cert: Certificate to check
        
    Returns:
        True if self-signed, False otherwise
    """
    return cert.subject == cert.issuer


def validate_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_hostname: str = None,
    strict_hostname: bool = True
) -> tuple[bool, str]:
    """
    Comprehensive certificate validation.
    
    Args:
        cert: Certificate to validate
        ca_cert: Root CA certificate (trust anchor)
        expected_hostname: Expected hostname (CN or SAN) - optional
        strict_hostname: If True, hostname must match; if False, hostname check is skipped
        
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if certificate is valid, False otherwise
        - error_message: Empty string if valid, error description if invalid
    """
    # Check 1: Is it self-signed? (should be rejected)
    if is_self_signed(cert):
        return False, "BAD_CERT: Certificate is self-signed"
    
    # Check 2: Verify signature chain (signed by trusted CA)
    if not verify_certificate_signature(cert, ca_cert):
        return False, "BAD_CERT: Certificate signature verification failed (not signed by trusted CA)"
    
    # Check 3: Validity period (not expired, not before valid date)
    if not check_certificate_validity(cert):
        from datetime import timezone
        now = datetime.now(timezone.utc)
        
        # Convert certificate dates to timezone-aware if needed
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        
        if now < not_before:
            return False, f"BAD_CERT: Certificate not yet valid (valid from {not_before})"
        if now > not_after:
            return False, f"BAD_CERT: Certificate expired (expired on {not_after})"
        return False, "BAD_CERT: Certificate validity check failed"
    
    # Check 4: Hostname match (if expected_hostname is provided and strict_hostname is True)
    if expected_hostname and strict_hostname:
        if not check_hostname_match(cert, expected_hostname):
            cn = get_certificate_cn(cert)
            san_dns = get_certificate_san_dns_names(cert)
            return False, f"BAD_CERT: Hostname mismatch (expected: {expected_hostname}, CN: {cn}, SAN: {san_dns})"
    
    # All checks passed
    return True, ""


def validate_certificate_from_pem(
    cert_pem: str,
    ca_cert_path: str = "certs/ca_cert.pem",
    expected_hostname: str = None,
    strict_hostname: bool = True
) -> tuple[bool, str]:
    """
    Validate certificate from PEM string.
    
    Args:
        cert_pem: PEM-encoded certificate string
        ca_cert_path: Path to CA certificate
        expected_hostname: Expected hostname (optional)
        strict_hostname: If True, hostname must match
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        cert = load_certificate_from_pem(cert_pem)
        ca_cert = load_ca_certificate(ca_cert_path)
        return validate_certificate(cert, ca_cert, expected_hostname, strict_hostname)
    except Exception as e:
        return False, f"BAD_CERT: {str(e)}"


def validate_certificate_from_file(
    cert_path: str,
    ca_cert_path: str = "certs/ca_cert.pem",
    expected_hostname: str = None,
    strict_hostname: bool = True
) -> tuple[bool, str]:
    """
    Validate certificate from file.
    
    Args:
        cert_path: Path to certificate file
        ca_cert_path: Path to CA certificate
        expected_hostname: Expected hostname (optional)
        strict_hostname: If True, hostname must match
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        cert = load_certificate_from_file(cert_path)
        ca_cert = load_ca_certificate(ca_cert_path)
        return validate_certificate(cert, ca_cert, expected_hostname, strict_hostname)
    except Exception as e:
        return False, f"BAD_CERT: {str(e)}"
