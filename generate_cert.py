"""
TLS Certificate Generator
-------------------------
Creates a self-signed X.509 certificate for FTPS (TLS encryption).
Self-signed = for lab/testing only. Production would use a CA-signed cert.

This demonstrates the concept of "Encryption in Transit" (Transport Layer Security).
Uses the `cryptography` library (pure Python) - no OpenSSL CLI needed.
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import config


def generate_self_signed_cert():
    """
    Generate a self-signed X.509 certificate + RSA private key using
    the `cryptography` library.
    """
    cert_path = config.TLS_CERT_FILE
    key_path = config.TLS_KEY_FILE

    # Skip if already exists
    if cert_path.exists() and key_path.exists():
        print(f"[+] Certificates already exist:\n    {cert_path}\n    {key_path}")
        return True

    print("[*] Generating self-signed TLS certificate (RSA-2048)...")

    # ---- 1. Generate RSA private key (2048-bit) ----
    # RSA-2048 = industry standard. 1024-bit is broken, 4096 is overkill for lab.
    key = rsa.generate_private_key(
        public_exponent=65537,   # Standard public exponent
        key_size=2048            # 2048-bit key
    )

    # ---- 2. Build the certificate metadata (X.509 Distinguished Name) ----
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OSProject"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BD"),
    ])

    # Certificate valid for 365 days
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )

    # ---- 3. Write the private key ----
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # No passphrase for lab
        )
    )

    # ---- 4. Write the certificate ----
    cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )

    print("[+] Certificate generated successfully!")
    print(f"    Cert : {cert_path}")
    print(f"    Key  : {key_path}")
    print(f"    RSA-2048 / SHA-256 / Valid 365 days")
    return True


if __name__ == "__main__":
    generate_self_signed_cert()
