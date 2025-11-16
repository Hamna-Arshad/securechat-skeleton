# app/crypto/dh.py
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import secrets
import hashlib

# --- Phase 1: Legacy integer DH (optional) ---
def generate_private_key_simple() -> int:
    """Random 256-bit private key (legacy)"""
    return secrets.randbits(256)

def compute_public_key_simple(g: int, priv: int, p: int) -> int:
    return pow(g, priv, p)

def compute_shared_secret_simple(peer_pub: int, priv: int, p: int) -> int:
    return pow(peer_pub, priv, p)

def derive_aes_key(Ks: int) -> bytes:
    Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, 'big')
    digest = hashlib.sha256(Ks_bytes).digest()
    return digest[:16]  # AES-128 key

def generate_parameters(key_size: int = 2048):
    return dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())

def generate_private_key(parameters):
    return parameters.generate_private_key()

def DHParameterNumbers(p: int, g: int):
    class ParamsWrapper:
        def __init__(self, p, g):
            self._numbers = dh.DHParameterNumbers(p, g)

        def parameters(self):
            return self._numbers.parameters(default_backend())

        def parameter_numbers(self):
            return self._numbers

    return ParamsWrapper(p, g)

def DHPublicNumbers(y: int, params_numbers):

    class PublicWrapper:
        def __init__(self, y, params_numbers):
            self._numbers = dh.DHPublicNumbers(y, params_numbers)
        def public_key(self):
            return self._numbers.public_key(default_backend())
    return PublicWrapper(y, params_numbers)

def get_public_number(priv_key):
    return priv_key.public_key().public_numbers().y

def load_peer_public_number(y: int, parameters):

    pub_numbers = dh.DHPublicNumbers(y, parameters.parameter_numbers())
    return pub_numbers.public_key(default_backend())

def compute_shared_secret(priv_key, peer_pub_key):
    """Compute shared secret (bytes)"""
    return priv_key.exchange(peer_pub_key)

