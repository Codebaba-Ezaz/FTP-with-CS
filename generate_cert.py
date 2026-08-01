import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import config


def generate_self_signed_cert():
    cert_path = config.TLS_CERT_FILE
    key_path = config.TLS_KEY_FILE

    if cert_path.exists() and key_path.exists():
        print(f"[+] Certificates already exist:\n    {cert_path}\n    {key_path}")
        return True

    print("[*] Generating self-signed TLS certificate (RSA-2048)...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OSProject"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BD"),
    ])

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

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

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