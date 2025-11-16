import base64
import hashlib
import time

def now_ms() -> int:
    """Return current time in milliseconds."""
    return int(time.time() * 1000)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def sha256_bytes(data: bytes) -> bytes:
    """Return SHA-256 digest of bytes."""
    return hashlib.sha256(data).digest()

def sha256_hex(data: bytes) -> str:
    """Return SHA-256 digest of bytes as hex string."""
    return hashlib.sha256(data).hexdigest()
