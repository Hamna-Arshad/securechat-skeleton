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

# --- Phase 2: Proper ephemeral DH using cryptography ---
def generate_parameters(key_size: int = 2048):
    """Return DH parameters object"""
    return dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())

def generate_private_key(parameters):
    """Generate DH private key object"""
    return parameters.generate_private_key()

def DHParameterNumbers(p: int, g: int):
    """
    Return a lightweight wrapper that mimics cryptography's DHParameterNumbers
    interface but allows `.parameters()` to be called without the caller needing
    to pass a backend. This preserves compatibility with your client/server.
    """
    class ParamsWrapper:
        def __init__(self, p, g):
            # store a real DHParameterNumbers object
            self._numbers = dh.DHParameterNumbers(p, g)

        def parameters(self):
            # return a real Parameters object (requires backend)
            return self._numbers.parameters(default_backend())

        def parameter_numbers(self):
            # return the underlying DHParameterNumbers instance
            return self._numbers

    return ParamsWrapper(p, g)

def DHPublicNumbers(y: int, params_numbers):
    """
    Lightweight wrapper for DHPublicNumbers that exposes `.public_key()`.
    """
    class PublicWrapper:
        def __init__(self, y, params_numbers):
            self._numbers = dh.DHPublicNumbers(y, params_numbers)
        def public_key(self):
            return self._numbers.public_key(default_backend())
    return PublicWrapper(y, params_numbers)

def get_public_number(priv_key):
    """Return public number of a private key (int)"""
    return priv_key.public_key().public_numbers().y

def load_peer_public_number(y: int, parameters):
    """
    Construct a public key object from peer's integer 'y' and a parameters object.
    `parameters` is expected to be a real Parameters object from cryptography
    (i.e., result of dh.generate_parameters() or wrapper.parameters()).
    """
    # cryptography expects a DHParameterNumbers instance as second arg of DHPublicNumbers
    pub_numbers = dh.DHPublicNumbers(y, parameters.parameter_numbers())
    return pub_numbers.public_key(default_backend())

def compute_shared_secret(priv_key, peer_pub_key):
    """Compute shared secret (bytes)"""
    return priv_key.exchange(peer_pub_key)


#dont know
# # app/crypto/dh.py
# from cryptography.hazmat.primitives.asymmetric import dh
# from cryptography.hazmat.backends import default_backend
# import secrets
# import hashlib

# # --- Phase 1: Legacy integer DH (optional) ---
# def generate_private_key_simple() -> int:
#     """Random 256-bit private key (legacy)"""
#     return secrets.randbits(256)

# def compute_public_key_simple(g: int, priv: int, p: int) -> int:
#     return pow(g, priv, p)

# def compute_shared_secret_simple(peer_pub: int, priv: int, p: int) -> int:
#     return pow(peer_pub, priv, p)

# def derive_aes_key(Ks: int) -> bytes:
#     Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, 'big')
#     digest = hashlib.sha256(Ks_bytes).digest()
#     return digest[:16]  # AES-128 key

# # --- Phase 2: Proper ephemeral DH using cryptography ---
# def generate_parameters(key_size: int = 2048):
#     """Return DH parameters object"""
#     return dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())

# def generate_private_key(parameters):
#     """Generate DH private key object"""
#     return parameters.generate_private_key()

# def DHParameterNumbers(p: int, g: int):
#     """
#     Return a lightweight object that mimics cryptography's DHParameterNumbers interface,
#     so client/server code calling `DHParameterNumbers(p, g).parameters()` works.
#     """
#     class ParamsWrapper:
#         def __init__(self, p, g):
#             self._numbers = dh.DHParameterNumbers(p, g)

#         def parameters(self):
#             return self._numbers.parameters(default_backend())

#         def parameter_numbers(self):
#             return self._numbers

#     return ParamsWrapper(p, g)

# def DHPublicNumbers(y: int, params_numbers):
#     """
#     Return a lightweight object that mimics cryptography's DHPublicNumbers interface
#     so client/server code calling `DHPublicNumbers(y, params.parameter_numbers()).public_key()` works.
#     """
#     class PublicWrapper:
#         def __init__(self, y, params_numbers):
#             self._numbers = dh.DHPublicNumbers(y, params_numbers)
#         def public_key(self):
#             return self._numbers.public_key(default_backend())
#     return PublicWrapper(y, params_numbers)

# def get_public_number(priv_key):
#     """Return public number of a private key"""
#     return priv_key.public_key().public_numbers().y

# def load_peer_public_number(y: int, parameters):
#     """Construct a public key object from peer's number"""
#     pub_numbers = dh.DHPublicNumbers(y, parameters.parameter_numbers())
#     return pub_numbers.public_key(default_backend())

# def compute_shared_secret(priv_key, peer_pub_key):
#     """Compute shared secret (bytes)"""
#     return priv_key.exchange(peer_pub_key)


#phase 1

# from cryptography.hazmat.primitives.asymmetric import dh
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

# def generate_parameters():
#     return dh.generate_parameters(generator=2, key_size=2048)

# def generate_private_key(params):
#     return params.generate_private_key()

# def compute_shared_secret(private_key, peer_public_key):
#     shared_key = private_key.exchange(peer_public_key)
#     # Truncate SHA-256 to 16 bytes
#     digest = hashes.Hash(hashes.SHA256())
#     digest.update(shared_key)
#     full_hash = digest.finalize()
#     return full_hash[:16]  # 16 bytes = AES-128 key
