from pydantic import BaseModel
from typing import Optional

# -----------------------------
# Message Models
# -----------------------------

class Hello(BaseModel):
    client_name: str          # <--- required
    client_cert: str
    nonce: str

class ServerHello(BaseModel):
    server_name: str          # the server's CN
    server_cert: str          # <--- add this, required for client verification
    nonce: str

class Register(BaseModel):
    username: str
    password_hash: str  # SHA-256 hash
    pubkey_pem: str     # Client public key in PEM

class Login(BaseModel):
    username: str
    password_hash: str

class DHClient(BaseModel):
    username: str
    dh_pubkey: str  # client's DH public key (PEM/base64)
    nonce: str

class DHServer(BaseModel):
    dh_pubkey: str  # server's DH public key
    session_id: str
    signature: str  # sign(server_dh || session_id)

class Msg(BaseModel):
    session_id: str
    seq_no: int
    ciphertext: str  # AES encrypted message (base64)
    mac: str         # HMAC or signature

class Receipt(BaseModel):
    session_id: str
    seq_no: int
    signature: str   # server/client signs the transcript hash
