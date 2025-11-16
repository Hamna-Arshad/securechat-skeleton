from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID, DNSName
from cryptography import x509
import datetime
import pathlib
import argparse

def generate_cert(cn: str, out_path: str = "certs", ca_cert_path="certs/root_ca.crt", ca_key_path="certs/root_ca.key"):
    out_path = pathlib.Path(out_path)
    out_path.mkdir(parents=True, exist_ok=True)

    # Load CA
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(out_path / f"{cn}.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Build CSR (Certificate Signing Request)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn)
    ])).add_extension(
        x509.SubjectAlternativeName([DNSName(cn)]),
        critical=False
    ).sign(key, hashes.SHA256())

    # Sign CSR with CA
    cert = x509.CertificateBuilder()\
        .subject_name(csr.subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(csr.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .add_extension(x509.SubjectAlternativeName([DNSName(cn)]), critical=False)\
        .sign(ca_key, hashes.SHA256())

    # Save certificate
    with open(out_path / f"{cn}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Certificate for '{cn}' generated in '{out_path}'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate server/client cert signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name for cert (e.g., 'server.local')")
    parser.add_argument("--out", default="certs", help="Output directory")
    args = parser.parse_args()

    generate_cert(args.cn, args.out)
