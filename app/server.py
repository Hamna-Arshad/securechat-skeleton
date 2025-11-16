import socket, json, os, base64, time
from .common.protocol import Hello, ServerHello
from .crypto import pki, dh, aes
from .storage import db
from .common.utils import sha256_bytes
from .storage.transcript import generate_receipt, verify_receipt
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

HOST = "127.0.0.1"
PORT = 9000

SERVER_CERT = "certs/server.local.crt"
SERVER_KEY  = "certs/server.local.key"
CA_CERT     = "certs/root_ca.crt"
FAKE_KEY = "certs/fake_server_key.pem"
FAKE_CERT = "certs/fake_server_cert.pem"
EXPIRED_CERT = "certs/expired_server_cert.pem"
EXPIRED_KEY = "certs/expired_server_key.pem"

with open(SERVER_KEY,"rb") as f:
    SERVER_PRIV = serialization.load_pem_private_key(f.read(), password=None)
with open(SERVER_CERT,"rb") as f:
    SERVER_CERT_OBJ = pki.load_cert_from_pem(f.read())
    

# with open(FAKE_KEY, "rb") as f:
#     SERVER_PRIV = serialization.load_pem_private_key(f.read(), password=None)

# with open(FAKE_CERT, "rb") as f:
#     SERVER_CERT_OBJ = pki.load_cert_from_pem(f.read())   

# with open(EXPIRED_KEY, "rb") as f:
#     SERVER_PRIV = serialization.load_pem_private_key(f.read(), password=None)

# with open(EXPIRED_CERT, "rb") as f:
#     SERVER_CERT_OBJ = pki.load_cert_from_pem(f.read()) 

SERVER_FP = SERVER_CERT_OBJ.fingerprint(hashes.SHA256()).hex()

def load_server_cert():
    with open(SERVER_CERT,"r") as f:    # changing here to SERVER_CERT from FAKE_CERT
        return f.read()

def server_hello():
    cert_pem = load_server_cert()
    nonce = base64.b64encode(os.urandom(16)).decode()
    return ServerHello(server_cert=cert_pem, nonce=nonce, server_name="server.local")

# def recv_json(conn):
#     data = b""
#     while True:
#         part = conn.recv(4096)
#         if not part: break
#         data += part
#         try: return Hello.model_validate_json(data.decode())
#         except json.JSONDecodeError: continue
#     return None

def recv_json(sock):
    data = b""
    while True:
        part = sock.recv(4096)
        if not part:
            break
        data += part
        try:
            # decode after all data is collected
            return json.loads(data.decode())
        except json.JSONDecodeError:
            continue
    return None



def perform_phase2_dh(conn, params):
    print("Key exchange (Confidentiality)")
    dh_client_raw = conn.recv(4096)
    dh_client = json.loads(dh_client_raw.decode())
    A = dh_client["A"]
    server_priv_ephemeral = dh.generate_private_key(params)
    server_pub  = server_priv_ephemeral.public_key()
    B = server_pub.public_numbers().y
    client_pub = dh.load_peer_public_number(A, params)
    Ks_session = dh.compute_shared_secret(server_priv_ephemeral, client_pub)
    session_key = sha256_bytes(Ks_session)[:16]
    conn.sendall(json.dumps({"type":"dh_server","B":B}).encode())
    print(f"Session key established: {session_key.hex()} (Confidentiality)")
    return session_key

def data_plane_chat(conn, session_key, client_cert, server_priv):
    print("Secure messaging (Integrity & Confidentiality)")
    seqno_recv = 1
    seqno_send = 1
    transcript = []
    CLIENT_FP = client_cert.fingerprint(hashes.SHA256()).hex()

    while True:
        raw = conn.recv(4096)
        if not raw: break
        payload = json.loads(raw.decode())
        ct_b64 = payload["ct"]
        sig_b64 = payload["sig"]
        ts = payload["ts"]
        seqno = payload["seqno"]

        # #test 5
        # if seqno <= seqno_recv:
        #     print(f" Replay detected for seqno {seqno}")
        #     continue  # ignore the message
        # seqno_recv = seqno  # update latest received seqno
        # # ending test 5

        digest = sha256_bytes(f"{seqno}{ts}{ct_b64}".encode())
        try:
            client_cert.public_key().verify(base64.b64decode(sig_b64), digest, padding.PKCS1v15(), hashes.SHA256())
            print(f"Verified client signature for seqno {seqno} (Integrity & Authenticity)")
        except Exception:
            print(" Signature invalid"); continue

        ct_bytes = base64.b64decode(ct_b64)
        msg = aes.decrypt(session_key, ct_bytes).decode()
        print(f"[Client]: {msg} (Decrypted: Confidentiality)")
        seqno_recv += 1
        transcript.append({"seqno":seqno,"ts":ts,"ct":ct_b64,"sig":sig_b64,"peer_fp":CLIENT_FP})

        if msg.lower() in ("exit","quit"): break

        reply_text = input("[Server] Enter reply: ")
        ts_send = int(time.time()*1000)
        ct_bytes = aes.encrypt(session_key, reply_text.encode())
        ct_b64 = base64.b64encode(ct_bytes).decode()
        digest_send = sha256_bytes(f"{seqno_send}{ts_send}{ct_b64}".encode())
        sig_bytes_send = server_priv.sign(digest_send, padding.PKCS1v15(), hashes.SHA256())
        sig_b64_send = base64.b64encode(sig_bytes_send).decode()
        payload_send = {"type":"msg","seqno":seqno_send,"ts":ts_send,"ct":ct_b64,"sig":sig_b64_send}
        conn.sendall(json.dumps(payload_send).encode())
        transcript.append({"seqno":seqno_send,"ts":ts_send,"ct":ct_b64,"sig":sig_b64_send,"peer_fp":SERVER_FP})
        print(f"Sent reply seqno {seqno_send} (Integrity & Confidentiality)")
        seqno_send += 1
        if reply_text.lower() in ("exit","quit"): break

    print("Generating server receipt (Non-repudiation)")
    server_receipt = generate_receipt(transcript, server_priv, "server")

    print("Verifying client receipt (Authenticity & Integrity)")
    client_receipt_raw = conn.recv(4096)
    client_receipt_json = json.loads(client_receipt_raw.decode())
    client_receipt = client_receipt_json.get("receipt")

    conn.sendall(json.dumps({"type":"receipt","receipt":server_receipt}).encode())

    valid = verify_receipt(transcript, client_receipt, client_cert.public_key())
    print("Client receipt verification:", "PASS" if valid else "FAIL")
    print("Server transcript receipt:", json.dumps(server_receipt, indent=2))

    #test 6
    # Export server transcript and receipt for offline verification
    with open("server_transcript.json", "w") as f:
        json.dump(transcript, f, indent=2)

    with open("server_receipt.json", "w") as f:
        json.dump(server_receipt, f, indent=2)

    print("Server transcript and receipt exported for offline verification")

    valid = verify_receipt(transcript, server_receipt, SERVER_PRIV.public_key())
    print("Offline verification (original transcript):", "PASS" if valid else "FAIL")

    # --- Tamper test for offline verification ---
    if transcript:
        ct_b64 = transcript[0]["ct"]
        b = bytearray(base64.b64decode(ct_b64))
        b[0] ^= 0x01
        transcript[0]["ct"] = base64.b64encode(b).decode()

        valid = verify_receipt(transcript, server_receipt, SERVER_PRIV.public_key())
        print("Offline verification (tampered transcript):", "PASS" if valid else "FAIL")

def main():
    db.init_db()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"Listening on {HOST}:{PORT}")
    conn, addr = s.accept()
    print(f"Connection from {addr}")

    with conn:
        # Use updated recv_json that returns raw JSON string
        hello_raw = recv_json(conn)
        if not hello_raw:
            print("Failed to receive client hello")
            return

        try:
            hello = Hello.model_validate(hello_raw)
        except Exception as e:
            print("Invalid Hello JSON:", e)
            return

        # Load client certificate and CA certificate
        client_cert = pki.load_cert_from_pem(hello.client_cert)
        ca_cert = pki.load_cert(CA_CERT)

        # Proper certificate verification
        if not pki.verify_cert(client_cert, ca_cert, expected_cn="client.local"):
            print(" Invalid client certificate, rejecting connection")
            return
        print("Client certificate verified")

        # Send server hello
        conn.sendall(server_hello().model_dump_json().encode())

        # Diffie-Hellman setup
        params = dh.generate_parameters()
        server_priv_ephemeral = dh.generate_private_key(params)
        server_pub = server_priv_ephemeral.public_key()
        dh_msg = {"p": params.parameter_numbers().p, 
                  "g": params.parameter_numbers().g, 
                  "B": server_pub.public_numbers().y}
        conn.sendall(json.dumps(dh_msg).encode())

        # Receive credentials
        payload_raw = conn.recv(4096)
        payload = json.loads(payload_raw.decode())
        A = payload["A"]
        enc_creds = base64.b64decode(payload["enc_credentials"])
        client_pub = dh.load_peer_public_number(A, params)
        Ks = dh.compute_shared_secret(server_priv_ephemeral, client_pub)
        auth_key = sha256_bytes(Ks)[:16]
        creds = json.loads(aes.decrypt(auth_key, enc_creds).decode())
        username, password, action = creds["username"], creds["password"], creds.get("action")

        if action == "register":
            ok = db.add_user(username, password) or db.verify_user(username, password)
        elif action == "login":
            ok = db.verify_user(username, password)
        else:
            ok = False

        conn.sendall(json.dumps({"status": "ok" if ok else "error"}).encode())
        if not ok:
            print(" Authentication failed")
            return

        # Continue with Phase 2 DH and data plane
        session_key = perform_phase2_dh(conn, params)
        data_plane_chat(conn, session_key, client_cert, SERVER_PRIV)

if __name__=="__main__":
    main()



#1+2+3+4

# import socket, json, os, base64, time
# from .common.protocol import Hello, ServerHello
# from .crypto import pki, dh, aes
# from .storage import db
# from .common.utils import sha256_bytes
# from .storage.transcript import compute_transcript_hash, verify_receipt
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes, serialization

# HOST = "127.0.0.1"
# PORT = 9000

# SERVER_CERT = "certs/server.local.crt"
# SERVER_KEY  = "certs/server.local.key"
# CA_CERT     = "certs/root_ca.crt"

# with open(SERVER_KEY, "rb") as f:
#     SERVER_PRIV = serialization.load_pem_private_key(f.read(), password=None)

# with open(SERVER_CERT, "rb") as f:
#     SERVER_CERT_OBJ = pki.load_cert_from_pem(f.read())
# SERVER_FP = SERVER_CERT_OBJ.fingerprint(hashes.SHA256()).hex()

# def load_server_cert():
#     with open(SERVER_CERT, "r") as f:
#         return f.read()

# def server_hello():
#     cert_pem = load_server_cert()
#     nonce = base64.b64encode(os.urandom(16)).decode()
#     return ServerHello(server_cert=cert_pem, nonce=nonce, server_name="server.local")

# def recv_json(conn):
#     data = b""
#     while True:
#         part = conn.recv(4096)
#         if not part:
#             break
#         data += part
#         try:
#             return Hello.model_validate_json(data.decode())
#         except json.JSONDecodeError:
#             continue
#     return None

# def perform_phase2_dh(conn, params):
#     dh_client_raw = conn.recv(4096)
#     dh_client = json.loads(dh_client_raw.decode())
#     A = dh_client["A"]
#     server_priv_ephemeral = dh.generate_private_key(params)
#     server_pub  = server_priv_ephemeral.public_key()
#     B = server_pub.public_numbers().y
#     client_pub = dh.load_peer_public_number(A, params)
#     Ks_session = dh.compute_shared_secret(server_priv_ephemeral, client_pub)
#     session_key = sha256_bytes(Ks_session)[:16]
#     conn.sendall(json.dumps({"type": "dh_server", "B": B}).encode())
#     print("Session key established:", session_key.hex())
#     return session_key

# def generate_session_receipt(transcript, priv_key, peer_label):
#     lines = []
#     for entry in transcript:
#         line = f"{entry['seqno']}|{entry['ts']}|{entry['ct']}|{entry['sig']}|{entry['peer_fp']}"
#         lines.append(line)
#     concat = "\n".join(lines).encode()
#     digest = hashes.Hash(hashes.SHA256())
#     digest.update(concat)
#     transcript_hash = digest.finalize().hex()

#     sig = priv_key.sign(bytes.fromhex(transcript_hash), padding.PKCS1v15(), hashes.SHA256())
#     receipt = {
#         "type": "receipt",
#         "peer": peer_label,
#         "first_seq": transcript[0]["seqno"] if transcript else 0,
#         "last_seq": transcript[-1]["seqno"] if transcript else 0,
#         "transcript_sha256": transcript_hash,
#         "sig": base64.b64encode(sig).decode()
#     }
#     return receipt

# def data_plane_chat(conn, session_key, client_cert, server_priv):
#     seqno_recv = 1
#     seqno_send = 1
#     transcript = []
#     CLIENT_FP = client_cert.fingerprint(hashes.SHA256()).hex()

#     while True:
#         # --- Wait for client message ---
#         raw = conn.recv(4096)
#         if not raw:
#             print("Client disconnected")
#             break

#         payload = json.loads(raw.decode())
#         ct_b64 = payload["ct"]
#         sig_b64 = payload["sig"]
#         ts = payload["ts"]
#         seqno = payload["seqno"]

#         # Verify order and freshness
#         if seqno != seqno_recv:
#             print("Replay or out-of-order message"); continue
#         if abs(int(time.time()*1000) - ts) > 5*60*1000:
#             print("Stale message"); continue

#         digest_input = f"{seqno}{ts}{ct_b64}".encode()
#         digest = sha256_bytes(digest_input)
#         sig_bytes = base64.b64decode(sig_b64)
#         try:
#             client_cert.public_key().verify(sig_bytes, digest, padding.PKCS1v15(), hashes.SHA256())
#         except Exception:
#             print("Signature invalid"); continue

#         ct_bytes = base64.b64decode(ct_b64)
#         msg = aes.decrypt(session_key, ct_bytes).decode()
#         print(f"[Client]: {msg}")
#         seqno_recv += 1

#         transcript.append({"seqno": seqno, "ts": ts, "ct": ct_b64, "sig": sig_b64, "peer_fp": CLIENT_FP})

#         if msg.lower() in ("exit", "quit"):
#             print("Client requested exit")
#             break

#         # --- Server replies ---
#         reply_text = input("[Server] Enter reply: ")
#         ts_send = int(time.time() * 1000)
#         ct_bytes = aes.encrypt(session_key, reply_text.encode())
#         ct_b64 = base64.b64encode(ct_bytes).decode()

#         digest_input_send = f"{seqno_send}{ts_send}{ct_b64}".encode()
#         digest_send = sha256_bytes(digest_input_send)
#         sig_bytes_send = server_priv.sign(digest_send, padding.PKCS1v15(), hashes.SHA256())
#         sig_b64_send = base64.b64encode(sig_bytes_send).decode()

#         payload_send = {"type": "msg", "seqno": seqno_send, "ts": ts_send, "ct": ct_b64, "sig": sig_b64_send}
#         conn.sendall(json.dumps(payload_send).encode())
#         transcript.append({"seqno": seqno_send, "ts": ts_send, "ct": ct_b64, "sig": sig_b64_send, "peer_fp": CLIENT_FP})
#         seqno_send += 1

#         if reply_text.lower() in ("exit", "quit"):
#             print("Exiting chat")
#             break

#     receipt = generate_session_receipt(transcript, server_priv, "server")
#     print("SessionReceipt generated:\n", json.dumps(receipt, indent=2))

# def main():
#     db.init_db()
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind((HOST, PORT))
#     s.listen(1)
#     print(f"Listening on {HOST}:{PORT}")
#     conn, addr = s.accept()
#     print(f"Connection from {addr}")
#     with conn:
#         hello = recv_json(conn)
#         client_cert = pki.load_cert_from_pem(hello.client_cert)
#         ca_cert = pki.load_cert(CA_CERT)
#         if not pki.verify_cert(client_cert, ca_cert, expected_cn="client.local"): return
#         conn.sendall(server_hello().model_dump_json().encode())

#         params = dh.generate_parameters()
#         server_priv_ephemeral = dh.generate_private_key(params)
#         server_pub  = server_priv_ephemeral.public_key()
#         dh_msg = {"p": params.parameter_numbers().p, "g": params.parameter_numbers().g, "B": server_pub.public_numbers().y}
#         conn.sendall(json.dumps(dh_msg).encode())

#         payload_raw = conn.recv(4096)
#         payload = json.loads(payload_raw.decode())
#         A = payload["A"]
#         enc_creds = base64.b64decode(payload["enc_credentials"])
#         client_pub = dh.load_peer_public_number(A, params)
#         Ks = dh.compute_shared_secret(server_priv_ephemeral, client_pub)
#         auth_key = sha256_bytes(Ks)[:16]
#         creds = json.loads(aes.decrypt(auth_key, enc_creds).decode())
#         username, password, action = creds["username"], creds["password"], creds.get("action")

#         if action == "register":
#             ok = db.add_user(username, password)
#             if not ok: ok = db.verify_user(username, password)
#         elif action == "login":
#             ok = db.verify_user(username, password)
#         else:
#             ok = False
#         conn.sendall(json.dumps({"status": "ok" if ok else "error"}).encode())
#         if not ok: return

#         session_key = perform_phase2_dh(conn, params)
#         data_plane_chat(conn, session_key, client_cert, SERVER_PRIV)


# if __name__ == "__main__":
#     main()


# phase 1+2+3
# import socket, json, os, base64, time
# from .common.protocol import Hello, ServerHello
# from .crypto import pki, dh, aes
# from .storage import db
# from .common.utils import sha256_bytes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes, serialization

# HOST = "127.0.0.1"
# PORT = 9000

# SERVER_CERT = "certs/server.local.crt"
# SERVER_KEY  = "certs/server.local.key"
# CA_CERT     = "certs/root_ca.crt"

# # Load server private key
# with open(SERVER_KEY, "rb") as f:
#     SERVER_PRIV = serialization.load_pem_private_key(f.read(), password=None)

# def load_server_cert():
#     with open(SERVER_CERT, "r") as f:
#         return f.read()

# def server_hello():
#     cert_pem = load_server_cert()
#     nonce = base64.b64encode(os.urandom(16)).decode()
#     return ServerHello(server_cert=cert_pem, nonce=nonce, server_name="server.local")

# def recv_json(conn):
#     data = b""
#     while True:
#         part = conn.recv(4096)
#         if not part:
#             break
#         data += part
#         try:
#             return Hello.model_validate_json(data.decode())
#         except json.JSONDecodeError:
#             continue
#     return None

# def perform_phase2_dh(conn, params):
#     dh_client_raw = conn.recv(4096)
#     dh_client = json.loads(dh_client_raw.decode())
#     A = dh_client["A"]
#     server_priv = dh.generate_private_key(params)
#     server_pub  = server_priv.public_key()
#     B = server_pub.public_numbers().y
#     client_pub = dh.load_peer_public_number(A, params)
#     Ks_session = dh.compute_shared_secret(server_priv, client_pub)
#     session_key = sha256_bytes(Ks_session)[:16]
#     conn.sendall(json.dumps({"type": "dh_server", "B": B}).encode())
#     print("Session key established:", session_key.hex())
#     return session_key

# def data_plane_chat(conn, session_key, client_cert, server_priv):

#     seqno_recv = 1
#     seqno_send = 1

#     while True:
#         # --- Wait for client message ---
#         raw = conn.recv(4096)
#         if not raw:
#             print(" Client disconnected")
#             break

#         payload = json.loads(raw.decode())
#         ct_b64 = payload["ct"]
#         sig_b64 = payload["sig"]
#         ts = payload["ts"]
#         seqno = payload["seqno"]

#         # Check freshness and order
#         if seqno != seqno_recv:
#             print(" Replay or out-of-order message")
#             continue
#         if abs(int(time.time()*1000) - ts) > 5*60*1000:
#             print(" Stale message")
#             continue

#         # Verify signature
#         digest_input = f"{seqno}{ts}{ct_b64}".encode()
#         digest = sha256_bytes(digest_input)
#         sig_bytes = base64.b64decode(sig_b64)
#         try:
#             client_cert.public_key().verify(sig_bytes, digest, padding.PKCS1v15(), hashes.SHA256())
#         except Exception:
#             print(" Signature invalid")
#             continue

#         # Decrypt message
#         ct_bytes = base64.b64decode(ct_b64)
#         msg = aes.decrypt(session_key, ct_bytes).decode()
#         print(f"[Client]: {msg}")
#         seqno_recv += 1

#         if msg.lower() in ("exit", "quit"):
#             print(" Client requested exit")
#             break

#         # --- Server replies ---
#         reply_text = input("[Server] Enter reply: ")
#         ts_send = int(time.time() * 1000)
#         ct_bytes = aes.encrypt(session_key, reply_text.encode())
#         ct_b64 = base64.b64encode(ct_bytes).decode()

#         digest_input_send = f"{seqno_send}{ts_send}{ct_b64}".encode()
#         digest_send = sha256_bytes(digest_input_send)
#         sig_bytes_send = server_priv.sign(digest_send, padding.PKCS1v15(), hashes.SHA256())
#         sig_b64_send = base64.b64encode(sig_bytes_send).decode()

#         payload_send = {
#             "type": "msg",
#             "seqno": seqno_send,
#             "ts": ts_send,
#             "ct": ct_b64,
#             "sig": sig_b64_send
#         }
#         conn.sendall(json.dumps(payload_send).encode())
#         seqno_send += 1

#         if reply_text.lower() in ("exit", "quit"):
#             print(" Exiting chat")
#             break

# def main():
#     db.init_db()
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind((HOST, PORT))
#     s.listen(1)
#     print(f" Listening on {HOST}:{PORT}")
#     conn, addr = s.accept()
#     print(f" Connection from {addr}")
#     with conn:
#         hello = recv_json(conn)
#         client_cert = pki.load_cert_from_pem(hello.client_cert)
#         ca_cert     = pki.load_cert(CA_CERT)
#         if not pki.verify_cert(client_cert, ca_cert, expected_cn="client.local"):
#             return
#         conn.sendall(server_hello().model_dump_json().encode())

#         # DH ephemeral key for credentials
#         params = dh.generate_parameters()
#         server_priv = dh.generate_private_key(params)
#         server_pub  = server_priv.public_key()
#         dh_msg = {"p": params.parameter_numbers().p,
#                   "g": params.parameter_numbers().g,
#                   "B": server_pub.public_numbers().y}
#         conn.sendall(json.dumps(dh_msg).encode())

#         payload_raw = conn.recv(4096)
#         payload = json.loads(payload_raw.decode())
#         A = payload["A"]
#         enc_creds = base64.b64decode(payload["enc_credentials"])
#         client_pub = dh.load_peer_public_number(A, params)
#         Ks = dh.compute_shared_secret(server_priv, client_pub)
#         auth_key = sha256_bytes(Ks)[:16]
#         creds = json.loads(aes.decrypt(auth_key, enc_creds).decode())
#         username, password, action = creds["username"], creds["password"], creds.get("action")

#         # Register/login
#         if action == "register":
#             ok = db.add_user(username, password)
#             if not ok: ok = db.verify_user(username, password)
#         elif action == "login":
#             ok = db.verify_user(username, password)
#         else:
#             ok = False
#         conn.sendall(json.dumps({"status": "ok" if ok else "error"}).encode())
#         if not ok: return

#         # --- Phase 2 DH ---
#         session_key = perform_phase2_dh(conn, params)

#         # --- Data Plane: Chat ---
#         data_plane_chat(conn, session_key, client_cert, SERVER_PRIV)


# if __name__ == "__main__":
#     main()
#phase 1+2
# import socket, json, os, base64
# from .common.protocol import Hello, ServerHello
# from .crypto import pki, dh, aes
# from .storage import db
# from .common.utils import sha256_bytes

# HOST = "127.0.0.1"
# PORT = 9000

# SERVER_CERT = "certs/server.local.crt"
# SERVER_KEY  = "certs/server.local.key"
# CA_CERT     = "certs/root_ca.crt"

# def load_server_cert():
#     with open(SERVER_CERT, "r") as f:
#         return f.read()

# def server_hello():
#     cert_pem = load_server_cert()
#     nonce = base64.b64encode(os.urandom(16)).decode()
#     return ServerHello(server_cert=cert_pem, nonce=nonce, server_name="server.local")

# def recv_json(conn):
#     data = b""
#     while True:
#         part = conn.recv(4096)
#         if not part:
#             break
#         data += part
#         try:
#             return Hello.model_validate_json(data.decode())
#         except json.JSONDecodeError:
#             continue
#     return None

# def perform_phase2_dh(conn, params):
#     dh_client_raw = conn.recv(4096)
#     if not dh_client_raw:
#         raise ConnectionError("Client disconnected during DH handshake")

#     dh_client = json.loads(dh_client_raw.decode())
#     if dh_client.get("type") != "dh_client":
#         raise ValueError("Expected dh_client message")

#     A = dh_client["A"]
#     server_priv = dh.generate_private_key(params)
#     server_pub  = server_priv.public_key()
#     B = server_pub.public_numbers().y

#     client_pub = dh.load_peer_public_number(A, params)
#     Ks_session = dh.compute_shared_secret(server_priv, client_pub)
#     session_key = sha256_bytes(Ks_session)[:16]

#     conn.sendall(json.dumps({"type": "dh_server", "B": B}).encode())
#     print(" Phase 2: Session key established:", session_key.hex())
#     return session_key

# def main():
#     db.init_db()
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind((HOST, PORT))
#     s.listen(1)
#     print(f" Listening on {HOST}:{PORT}")

#     conn, addr = s.accept()
#     print(f" Connection from {addr}")
#     with conn:
#         hello = recv_json(conn)
#         if not hello:
#             print(" Invalid client hello")
#             return

#         client_cert = pki.load_cert_from_pem(hello.client_cert)
#         ca_cert     = pki.load_cert(CA_CERT)
#         if not pki.verify_cert(client_cert, ca_cert, expected_cn="client.local"):
#             print(" Invalid client cert")
#             return

#         conn.sendall(server_hello().model_dump_json().encode())

#         params = dh.generate_parameters()
#         server_priv = dh.generate_private_key(params)
#         server_pub  = server_priv.public_key()

#         dh_msg = {"p": params.parameter_numbers().p,
#                   "g": params.parameter_numbers().g,
#                   "B": server_pub.public_numbers().y}
#         conn.sendall(json.dumps(dh_msg).encode())

#         # Receive A + encrypted credentials
#         payload_raw = conn.recv(4096)
#         if not payload_raw:
#             print(" Client disconnected before sending payload")
#             return

#         payload = json.loads(payload_raw.decode())
#         A = payload["A"]
#         enc_creds = base64.b64decode(payload["enc_credentials"])

#         client_pub = dh.load_peer_public_number(A, params)
#         Ks = dh.compute_shared_secret(server_priv, client_pub)
#         auth_key = sha256_bytes(Ks)[:16]

#         creds = json.loads(aes.decrypt(auth_key, enc_creds).decode())
#         username, password, action = creds["username"], creds["password"], creds.get("action")

#         # Register or login
#         if action == "register":
#             ok = db.add_user(username, password)
#             if not ok:
#                 print(f" User {username} already exists, switching to login")
#                 ok = db.verify_user(username, password)
#         elif action == "login":
#             ok = db.verify_user(username, password)
#         else:
#             ok = False

#         conn.sendall(json.dumps({"status": "ok" if ok else "error"}).encode())
#         if not ok:
#             return

#         # --- Phase 2 DH ---
#         session_key = perform_phase2_dh(conn, params)

#         # Receive encrypted message
#         enc_msg_raw = conn.recv(4096)
#         if not enc_msg_raw:
#             print(" Client disconnected before sending message")
#             return
#         enc_msg_json = json.loads(enc_msg_raw.decode())
#         enc_msg = base64.b64decode(enc_msg_json["enc_msg"])
#         msg = aes.decrypt(session_key, enc_msg)
#         print("[Server] Received:", msg.decode())

#         # Reply
#         reply = "Hello, client!"
#         enc_reply = base64.b64encode(aes.encrypt(session_key, reply.encode())).decode()
#         conn.sendall(json.dumps({"enc_msg": enc_reply}).encode())

# if __name__ == "__main__":
#     main()

#phase 1 working
# import socket, json, os, base64
# from .common.protocol import Hello, ServerHello
# from .crypto import pki, dh, aes
# from .storage import db
# from .common.utils import sha256_bytes

# HOST = "127.0.0.1"
# PORT = 9000

# SERVER_CERT = "certs/server.local.crt"
# SERVER_KEY = "certs/server.local.key"
# CA_CERT = "certs/root_ca.crt"

# def load_server_cert():
#     with open(SERVER_CERT, "r") as f:
#         return f.read()


# def server_hello():
#     cert_pem = load_server_cert()
#     nonce = base64.b64encode(os.urandom(16)).decode()
#     return ServerHello(
#         server_cert=cert_pem,
#         nonce=nonce,
#         server_name="server.local"   # <-- required field
#     )

# def ephemeral_dh():
#     params = dh.generate_parameters()
#     priv_key = dh.generate_private_key(params)
#     pub_key = priv_key.public_key()
#     return params, priv_key, pub_key

# def recv_json(conn):
#     data = b""
#     while True:
#         part = conn.recv(4096)
#         if not part:
#             break
#         data += part
#         try:
#             return Hello.model_validate_json(data.decode())
#         except json.JSONDecodeError:
#             continue  # keep receiving until valid

# def main():
#     db.init_db()  # Ensure MySQL table exists

#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind((HOST, PORT))
#     s.listen(1)
#     print(f" Listening on {HOST}:{PORT}")
#     conn, addr = s.accept()
#     print(f" Connection from {addr}")

#     with conn:
#         # --- Receive client hello ---
#         hello = recv_json(conn)

#         # --- Verify client certificate ---
#         client_cert = client_cert = pki.load_cert_from_pem(hello.client_cert)  # use load_cert for PEM string
#         ca_cert = pki.load_cert(CA_CERT)
#         if not pki.verify_cert(client_cert, ca_cert, expected_cn="client.local"):
#             print(" Invalid client cert")
#             conn.close()
#             return

#         # --- Send server hello ---
#         sh = server_hello()
#         conn.sendall(sh.model_dump_json().encode())  # Pydantic v2

#         # --- Ephemeral DH for credentials ---
#         params, priv_key, pub_key = ephemeral_dh()
#         dh_msg = {
#             "p": params.parameter_numbers().p,
#             "g": params.parameter_numbers().g,
#             "B": pub_key.public_numbers().y
#         }
#         conn.sendall(json.dumps(dh_msg).encode())

#         # --- Receive client DH public & encrypted credentials ---
#         data = conn.recv(4096)
#         payload = json.loads(data.decode())
#         A = payload["A"]
#         enc_creds = base64.b64decode(payload["enc_credentials"])

#         # Compute shared secret
#         client_pub = dh.DHPublicNumbers(A, params.parameter_numbers()).public_key()
#         Ks = priv_key.exchange(client_pub)
#         session_aes = sha256_bytes(Ks)[:16]

#         # Decrypt credentials
#         creds_json = aes.decrypt(session_aes, enc_creds)
#         creds = json.loads(creds_json)

#         username = creds["username"]
#         password = creds["password"]

#         # --- Authenticate user ---
#         if creds.get("action") == "register":
#             if db.add_user(username, password):
#                 conn.sendall(json.dumps({"status": "registered"}).encode())
#                 print(f" User {username} registered")
#             else:
#                 conn.sendall(json.dumps({"status": "error"}).encode())
#         elif creds.get("action") == "login":
#             if db.verify_user(username, password):
#                 conn.sendall(json.dumps({"status": "authenticated"}).encode())
#                 print(f" User {username} authenticated")
#             else:
#                 conn.sendall(json.dumps({"status": "failed"}).encode())

#         # --- Main session DH key agreement ---
#         client_dh_msg = conn.recv(4096)
#         dh_client = json.loads(client_dh_msg.decode())
#         g, p, A = dh_client["g"], dh_client["p"], dh_client["A"]
#         params_numbers = dh.DHParameterNumbers(p, g)
#         params = params_numbers.parameters()
#         server_priv = dh.generate_private_key(params)
#         server_pub = server_priv.public_key()
#         Ks_session = server_priv.exchange(dh.DHPublicNumbers(A, params.parameter_numbers()).public_key())
#         session_key = sha256_bytes(Ks_session)[:16]  # AES-128 session key
#         dh_server_msg = {"B": server_pub.public_numbers().y}
#         conn.sendall(json.dumps(dh_server_msg).encode())
#         print(" Session key established for data plane")

# if __name__ == "__main__":
#     main()


