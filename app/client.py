import socket, json, base64, os, time
from .common.protocol import ServerHello, Hello
from .crypto import pki, dh, aes
from .common.utils import sha256_bytes, b64e, b64d
from .storage.transcript import generate_receipt, verify_receipt
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

HOST = "127.0.0.1"
PORT = 9000

CLIENT_CERT = "certs/client.local.crt"
CLIENT_KEY  = "certs/client.local.key"
CA_CERT     = "certs/root_ca.crt"

USERNAME = "Bob"
PASSWORD = "mypassword"
ACTION   = "register"

with open(CLIENT_KEY, "rb") as f:
    CLIENT_PRIV = serialization.load_pem_private_key(f.read(), password=None)

with open(CLIENT_CERT, "rb") as f:
    CLIENT_CERT_OBJ = pki.load_cert_from_pem(f.read())
CLIENT_FP = CLIENT_CERT_OBJ.fingerprint(hashes.SHA256()).hex()


def send_json(sock, data):
    sock.sendall(json.dumps(data).encode())
    
def client_hello():
    print("Authenticating server (Authenticity)")
    nonce = base64.b64encode(os.urandom(16)).decode()
    with open(CLIENT_CERT, "r") as f:
        cert_pem = f.read()
    hello_msg = Hello(
        client_name="client.local",
        client_cert=cert_pem,
        nonce=nonce
    )
    return hello_msg.model_dump_json()

def perform_phase2_dh(sock, params):
    print("Key exchange (Confidentiality)")
    client_priv_ephemeral = dh.generate_private_key(params)
    client_pub_ephemeral = client_priv_ephemeral.public_key()
    A = client_pub_ephemeral.public_numbers().y

    dh_client_msg = {"type":"dh_client","g":params.parameter_numbers().g,
                     "p":params.parameter_numbers().p,"A":A}
    send_json(sock, dh_client_msg)

    dh_server_msg_raw = sock.recv(4096)
    dh_server_msg = json.loads(dh_server_msg_raw.decode())
    B = dh_server_msg["B"]
    server_pub = dh.load_peer_public_number(B, params)
    Ks_session = dh.compute_shared_secret(client_priv_ephemeral, server_pub)
    session_key = sha256_bytes(Ks_session)[:16]
    print(f"Session key established: {session_key.hex()} (Confidentiality)")
    return session_key

def data_plane_chat(sock, session_key, client_priv, server_cert):
    print("Secure messaging (Integrity & Confidentiality)")
    seqno_send = 1
    transcript = []
    SERVER_FP = server_cert.fingerprint(hashes.SHA256()).hex()

    while True:
        msg = input("[Client] Enter message: ")
        ts_send = int(time.time() * 1000)
        ct_bytes = aes.encrypt(session_key, msg.encode())
        ct_b64 = base64.b64encode(ct_bytes).decode()
        digest = sha256_bytes(f"{seqno_send}{ts_send}{ct_b64}".encode())
        sig_b64 = base64.b64encode(client_priv.sign(digest, padding.PKCS1v15(), hashes.SHA256())).decode()

        payload_send = {"type":"msg","seqno":seqno_send,"ts":ts_send,"ct":ct_b64,"sig":sig_b64}
        send_json(sock, payload_send)

        transcript.append({"seqno":seqno_send,"ts":ts_send,"ct":ct_b64,"sig":sig_b64,"peer_fp":CLIENT_FP})
        seqno_send += 1

        if msg.lower() in ("exit","quit"):
            print("Exiting chat")
            break

        reply_raw = sock.recv(4096)
        if not reply_raw:
            print("Server disconnected"); break
        reply_json = json.loads(reply_raw.decode())
        ct_b64 = reply_json["ct"]
        ts = reply_json.get("ts", int(time.time()*1000))
        seqno = reply_json["seqno"]
        ct_bytes = base64.b64decode(ct_b64)
        reply_msg = aes.decrypt(session_key, ct_bytes).decode()
        print(f"[Server]: {reply_msg} (Decrypted: Confidentiality)")

        transcript.append({"seqno":seqno,"ts":ts,"ct":ct_b64,"sig":reply_json.get("sig",""),"peer_fp":SERVER_FP})
        if reply_msg.lower() in ("exit","quit"):
            print("Server requested to end chat"); break


    # #test 5
    # print("Running replay test...")
    # if transcript:
    #     # Take the first message sent by the client
    #     old_msg = transcript[0].copy()

    #     # Re-send it with the same seqno
    #     print(f"Replaying seqno {old_msg['seqno']} ...")
    #     send_json(sock, {
    #         "type": "msg",
    #         "seqno": old_msg["seqno"],
    #         "ts": old_msg["ts"],
    #         "ct": old_msg["ct"],
    #         "sig": old_msg["sig"]
    #     })

    #     print("Replay sent, server should detect it")
    # else:
    #     print("No messages to replay")

    # --- Generate client receipt ---
    print("Generating receipt (Non-repudiation)")
    client_receipt = generate_receipt(transcript, client_priv, "client")
    send_json(sock, {"type":"receipt","receipt":client_receipt})

    # --- Receive server receipt and verify ---
    print("Verifying server receipt (Authenticity & Integrity)")
    srv_receipt_raw = sock.recv(4096)
    srv_receipt_json = json.loads(srv_receipt_raw.decode())
    srv_receipt = srv_receipt_json.get("receipt")

    #  TAMPER TEST 
    # print("Running tamper test...")
    # import base64

    # ct_b64 = transcript[0]["ct"]
    # b = bytearray(base64.b64decode(ct_b64))
    # b[0] ^= 0x01
    # transcript[0]["ct"] = base64.b64encode(b).decode()
    #  END TAMPER TEST 

    valid = verify_receipt(transcript, srv_receipt, server_cert.public_key())
    print("Server receipt verification:", "PASS" if valid else "FAIL")
    print("Client transcript receipt:", json.dumps(client_receipt, indent=2))

    #test 6
    with open("client_transcript.json", "w") as f:
        json.dump(transcript, f, indent=2)

    with open("client_receipt.json", "w") as f:
        json.dump(client_receipt, f, indent=2)

    print("Client transcript and receipt exported for offline verification")
   
    valid = verify_receipt(transcript, client_receipt, CLIENT_PRIV.public_key())
    print("Offline verification (original transcript):", "PASS" if valid else "FAIL")

    if transcript:
        ct_b64 = transcript[0]["ct"]
        b = bytearray(base64.b64decode(ct_b64))
        b[0] ^= 0x01  # flip a bit
        transcript[0]["ct"] = base64.b64encode(b).decode()

        valid = verify_receipt(transcript, client_receipt, CLIENT_PRIV.public_key())
        print("Offline verification (tampered transcript):", "PASS" if valid else "FAIL")


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    send_json(s, json.loads(client_hello()))

    sh_raw = s.recv(4096)
    if not sh_raw:
        print("Failed to receive server hello")
        return

    try:
        sh_data = json.loads(sh_raw.decode())
        sh = ServerHello.model_validate(sh_data)  
    except Exception as e:
        print("Invalid ServerHello JSON:", e)
        return

    server_cert = pki.load_cert_from_pem(sh.server_cert)
    print("Client received server cert issuer:", server_cert.issuer)
    print("Client received server cert subject:", server_cert.subject)

    ca_cert = pki.load_cert(CA_CERT)
    if not pki.verify_cert(server_cert, ca_cert, expected_cn="server.local"):
        print("Invalid server cert")
        return
    print("Server certificate verified")

    dh_msg_raw = s.recv(4096)
    if not dh_msg_raw:
        print("Failed to receive DH parameters")
        return
    dh_msg = json.loads(dh_msg_raw.decode())
    p, g, B = dh_msg["p"], dh_msg["g"], dh_msg["B"]
    params = dh.DHParameterNumbers(p, g).parameters()

    client_priv_ephemeral = dh.generate_private_key(params)
    client_pub_ephemeral = client_priv_ephemeral.public_key()
    server_pub = dh.load_peer_public_number(B, params)
    Ks = dh.compute_shared_secret(client_priv_ephemeral, server_pub)
    auth_key = sha256_bytes(Ks)[:16]

    creds = {"username": USERNAME, "password": PASSWORD, "action": ACTION}
    enc_creds = aes.encrypt(auth_key, json.dumps(creds).encode())
    payload = {
        "A": client_pub_ephemeral.public_numbers().y,
        "enc_credentials": base64.b64encode(enc_creds).decode()
    }
    send_json(s, payload)

    status_raw = s.recv(4096)
    if not status_raw:
        print("Failed to receive auth status")
        return
    status = json.loads(status_raw.decode())
    print("Auth status:", status["status"])
    if status["status"] != "ok":
        return

    session_key = perform_phase2_dh(s, params)

    data_plane_chat(s, session_key, CLIENT_PRIV, server_cert)

if __name__ == "__main__":
    main()
