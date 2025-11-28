"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def load_ca(cert_path: str, key_path: str):
    """Load CA certificate and private key."""
    # Load CA certificate
    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    # Load CA private key
    with open(key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    return ca_cert, ca_key


def generate_certificate(
    cn: str,
    output_prefix: str,
    ca_cert_path: str = "certs/ca_cert.pem",
    ca_key_path: str = "certs/ca_key.pem",
    output_dir: str = "certs"
):
    """
    Generate a certificate signed by the Root CA.
    
    Args:
        cn: Common Name (e.g., "server.local" or "client.local")
        output_prefix: Prefix for output files (e.g., "server" or "client")
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
        output_dir: Directory to save the certificate and key
    """
    # Create output directory if it doesn't exist
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Check if CA files exist
    if not os.path.exists(ca_cert_path):
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
    if not os.path.exists(ca_key_path):
        raise FileNotFoundError(f"CA private key not found: {ca_key_path}")
    
    # Load CA
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path)
    
    # Generate RSA private key for the entity
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Certificate validity: 1 year from now
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=365)
    
    # Build the certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # Issued by CA
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn)  # SAN with DNS name
        ]),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False
    )
    
    # Sign the certificate with CA private key
    cert = cert_builder.sign(ca_key, hashes.SHA256())
    
    # Save private key
    key_path = os.path.join(output_dir, f"{output_prefix}_key.pem")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✓ Private key saved to: {key_path}")
    
    # Save certificate
    cert_path = os.path.join(output_dir, f"{output_prefix}_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"✓ Certificate saved to: {cert_path}")
    
    print(f"\n✓ Certificate for '{cn}' generated successfully!")
    print(f"  Valid from: {valid_from.strftime('%Y-%m-%d')}")
    print(f"  Valid to: {valid_to.strftime('%Y-%m-%d')}")
    print(f"  Signed by: {ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")


def main():
    parser = argparse.ArgumentParser(description="Generate certificate signed by Root CA")
    parser.add_argument(
        "--cn",
        type=str,
        required=True,
        help="Common Name (e.g., 'server.local' or 'client.local')"
    )
    parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output prefix for files (e.g., 'server' or 'client')"
    )
    parser.add_argument(
        "--ca-cert",
        type=str,
        default="certs/ca_cert.pem",
        help="Path to CA certificate (default: 'certs/ca_cert.pem')"
    )
    parser.add_argument(
        "--ca-key",
        type=str,
        default="certs/ca_key.pem",
        help="Path to CA private key (default: 'certs/ca_key.pem')"
    )
    parser.add_argument(
        "--cert-dir",
        type=str,
        default="certs",
        help="Output directory (default: 'certs')"
    )
    
    args = parser.parse_args()
    
    try:
        generate_certificate(
            args.cn,
            args.out,
            args.ca_cert,
            args.ca_key,
            args.cert_dir
        )
    except Exception as e:
        print(f"✗ Error generating certificate: {e}")
        raise


if __name__ == "__main__":
    main()
