from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID
from cryptography import x509
import datetime
import pathlib
import argparse

def generate_root_ca(name: str, out_dir: str = "certs"):
    out_path = pathlib.Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Serialize private key
    with open(out_path / "root_ca.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Build self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name)
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(key, hashes.SHA256())

    # Serialize certificate
    with open(out_path / "root_ca.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Root CA generated in '{out_dir}'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", required=True, help="Root CA CN (e.g., 'FAST-NU Root CA')")
    parser.add_argument("--out", default="certs", help="Output directory")
    args = parser.parse_args()

    generate_root_ca(args.name, args.out)
