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
    with open("server_transcript.json", "w") as f:
        json.dump(transcript, f, indent=2)

    with open("server_receipt.json", "w") as f:
        json.dump(server_receipt, f, indent=2)

    print("Server transcript and receipt exported for offline verification")

    valid = verify_receipt(transcript, server_receipt, SERVER_PRIV.public_key())
    print("Offline verification (original transcript):", "PASS" if valid else "FAIL")

    #  Tamper test for offline verification 
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
        hello_raw = recv_json(conn)
        if not hello_raw:
            print("Failed to receive client hello")
            return

        try:
            hello = Hello.model_validate(hello_raw)
        except Exception as e:
            print("Invalid Hello JSON:", e)
            return

        client_cert = pki.load_cert_from_pem(hello.client_cert)
        ca_cert = pki.load_cert(CA_CERT)

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

        session_key = perform_phase2_dh(conn, params)
        data_plane_chat(conn, session_key, client_cert, SERVER_PRIV)

if __name__=="__main__":
    main()
