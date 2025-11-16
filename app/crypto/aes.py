from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
from typing import Union

BLOCK_SIZE = 128  # AES block size in bits

def pad(msg: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(msg) + padder.finalize()

def unpad(padded: bytes) -> bytes:
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext bytes with AES-128-ECB and return raw ciphertext bytes.

    Note: ECB is used here to preserve original behavior but is NOT recommended
    for production. Use AES-GCM or AES-CBC+HMAC in real systems.
    """
    plaintext = pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext  # raw bytes

def decrypt(key: bytes, ciphertext_or_b64: Union[bytes, str]) -> bytes:
    """
    Decrypt ciphertext. Accepts either raw bytes or a base64-encoded string.
    Returns plaintext bytes (unpadded).
    """
    if isinstance(ciphertext_or_b64, str):
        ciphertext = base64.b64decode(ciphertext_or_b64.encode('utf-8'))
    else:
        ciphertext = ciphertext_or_b64

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded)


# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding
# import base64

# BLOCK_SIZE = 128  # AES block size in bits

# def pad(msg: bytes) -> bytes:
#     padder = padding.PKCS7(BLOCK_SIZE).padder()
#     return padder.update(msg) + padder.finalize()

# def unpad(padded: bytes) -> bytes:
#     unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
#     return unpadder.update(padded) + unpadder.finalize()

# def encrypt(key: bytes, plaintext: bytes) -> bytes:
#     plaintext = pad(plaintext)
#     cipher = Cipher(algorithms.AES(key), modes.ECB())
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(plaintext) + encryptor.finalize()
#     return ciphertext  # <- bytes


# def decrypt(key: bytes, ciphertext_b64: str) -> bytes:
#     ciphertext = base64.b64decode(ciphertext_b64)
#     cipher = Cipher(algorithms.AES(key), modes.ECB())
#     decryptor = cipher.decryptor()
#     padded = decryptor.update(ciphertext) + decryptor.finalize()
#     return unpad(padded)
