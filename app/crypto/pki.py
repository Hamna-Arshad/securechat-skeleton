from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
from cryptography.x509 import Certificate

def load_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_cert_from_pem(pem_str: str):
    return x509.load_pem_x509_certificate(pem_str.encode() if isinstance(pem_str, str) else pem_str)

def verify_cert(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str) -> bool:
    try:
        ca_cert.public_key().verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )
    except Exception as e:
        print("Certificate signature invalid:", str(e))
        return False

    now = datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc:
        print("Certificate not valid yet")
        return False

    if now > cert.not_valid_after_utc:
        print("Certificate expired")
        return False

    # 3. Verify CN
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if cn != expected_cn:
        print("CN mismatch")
        return False

    print("Certificate signature OK")
    return True
