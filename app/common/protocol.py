from pydantic import BaseModel
from typing import Optional

class Hello(BaseModel):
    client_name: str          
    client_cert: str
    nonce: str

class ServerHello(BaseModel):
    server_name: str          
    server_cert: str         
    nonce: str

class Register(BaseModel):
    username: str
    password_hash: str 
    pubkey_pem: str     

class Login(BaseModel):
    username: str
    password_hash: str

class DHClient(BaseModel):
    username: str
    dh_pubkey: str  
    nonce: str

class DHServer(BaseModel):
    dh_pubkey: str  
    session_id: str
    signature: str  

class Msg(BaseModel):
    session_id: str
    seq_no: int
    ciphertext: str 
    mac: str        
class Receipt(BaseModel):
    session_id: str
    seq_no: int
    signature: str   
