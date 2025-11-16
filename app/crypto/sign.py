from cryptography.hazmat.primitives.asymmetric import padding as asympadding, rsa
from cryptography.hazmat.primitives import hashes, serialization

def sign(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        asympadding.PKCS1v15(),
        hashes.SHA256()
    )

def verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            asympadding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False

def load_private_key(pem_path: str):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(pem_path: str):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
