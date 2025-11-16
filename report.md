
# Secure Chat Skeleton

This project implements a **secure client-server chat application** in Python, demonstrating key security properties:  

- **Confidentiality** via AES encryption  
- **Integrity** via SHA-256 and RSA signatures  
- **Authenticity** via X.509 certificates  
- **Non-repudiation** via transcript & receipt generation  

It supports:  

- Server authentication using valid, fake, and expired certificates  
- Client authentication (register/login)  
- Diffie-Hellman key exchange for session keys  
- Secure message exchange with encryption and signatures  
- Transcript & receipt export for offline verification  
- Tamper detection and replay attack prevention  

---

## Project Structure

```

securechat-skeleton/
│
├─ app/
│  ├─ client.py
│  ├─ server.py
│  ├─ crypto/          # PKI, AES, DH helpers
│  ├─ common/          # Protocol & utility functions
│  └─ storage/         # Database & transcript helpers
│
├─ certs/              # Certificates and keys
├─ .venv/              # Python virtual environment
└─ README.md

````

---

## Prerequisites

1. **Python 3.10+**  
2. **Docker** (for MySQL database)  
3. Install Python dependencies:

```bash
python -m venv .venv
# Windows
.\.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
````

---

## Configuration

1. Start the MySQL database in Docker:

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

2. Update certificate paths in `client.py` and `server.py` if needed:

```python
# client.py
CLIENT_CERT = "certs/client.local.crt"
CLIENT_KEY  = "certs/client.local.key"
CA_CERT     = "certs/root_ca.crt"

# server.py
SERVER_CERT = "certs/server.local.crt"
SERVER_KEY  = "certs/server.local.key"
```

3. Default server host/port:

```python
HOST = "127.0.0.1"
PORT = 9000
```

---

## Execution Steps

### Run Server

```bash
python -m app.server
```

* Initializes DB and listens on `127.0.0.1:9000`
* Waits for client connections

### Run Client

```bash
python -m app.client
```

* Performs **server authentication**
* Registers/logs in a user
* Performs **Diffie-Hellman key exchange**
* Starts secure chat with message encryption & signature

---
## Execution Steps & Security Workflow

This section explains how the secure chat application works, step by step, and how the security properties are ensured.

---

### 1. Client-Server Connection & Server Authentication

1. **Client starts and connects** to the server at `127.0.0.1:9000`.
2. **Client sends a Hello message** containing:
   - Client name
   - Client certificate
   - Random nonce
3. **Server responds with a ServerHello** containing:
   - Server certificate
   - Random nonce
   - Server name
4. **Server certificate verification by client**:
   - Checks certificate signature against the root CA.
   - Ensures the certificate CN matches `server.local`.
   
**Security assurance:**
-**Authenticity**: Client ensures server is genuine using CA signature.
-**Integrity**: Certificate content cannot be tampered without invalid signature.

---

### 2. User Authentication (Optional)

1. Client sends encrypted credentials (username, password, action) using a temporary key derived from ephemeral DH exchange.
2. Server decrypts credentials, validates against database.
3. Server responds with authentication status (`ok` or `error`).

**Security assurance:**
-**Confidentiality**: Credentials are encrypted over the network.
-**Integrity**: Tampered credentials will fail decryption.

---

### 3. Diffie-Hellman Key Exchange (Phase 2)

1. Both client and server generate ephemeral DH key pairs.
2. Public keys are exchanged.
3. Both sides compute **shared secret** `Ks`.
4. Session key is derived from SHA-256 of `Ks` (16 bytes).

**Security assurance:**
-**Confidentiality**: Only client and server can derive the session key.
-**Forward secrecy**: Compromise of long-term keys does not reveal past session keys.

---

### 4. Secure Messaging (Data Plane)

1. **Message sending**:
   - Client encrypts plaintext using AES with session key.
   - Computes SHA-256 digest over `seqno | timestamp | ciphertext`.
   - Signs digest with RSA private key.
   - Sends JSON: `{type, seqno, ts, ct, sig}`.
2. **Message receiving**:
   - Receiver verifies RSA signature against sender’s public key.
   - Decrypts AES ciphertext to recover message.

**Security assurance:**
-**Confidentiality**: AES encrypts message contents.
-**Integrity**: RSA signature ensures ciphertext is untampered.
-**Authenticity**: RSA signature proves message origin.

---

### 5. Non-repudiation & Receipts

1. Both client and server maintain a **transcript** of messages: `seqno, ts, ct, sig, peer_fp`.
2. At the end of the chat:
   - Each generates a **receipt**: SHA-256 of transcript signed with their RSA private key.
   - Receipts are exchanged.
3. Each side **verifies the receipt** from the other side offline:
   - Recomputes transcript hash.
   - Verifies RSA signature.

**Security assurance:**
-**Non-repudiation**: Sender cannot deny having sent a message.
-**Offline verification**: Transcript & receipt can be verified later.
-**Tamper detection**: Any edit to transcript invalidates the receipt.

---

### 6. Special Security Tests

1. **Fake certificate test**:
   - Replace server certificate with fake certificate.
   - Client verification fails → ensures authenticity check works.

2. **Expired certificate test**:
   - Replace server certificate with expired certificate.
   - Client verification fails → ensures expiration check works.

3. **Replay attack test**:
   - Resend old messages with same `seqno`.
   - Server detects and ignores replayed messages → ensures sequence protection.

4. **Tampering test**:
   - Modify ciphertext in transcript.
   - Offline receipt verification fails → ensures integrity and non-repudiation.

---

### 7. Termination

1. Chat ends when either side sends `exit` or `quit`.
2. Final transcript and receipts are exported for offline verification.
3. Both client and server can independently verify the full session.

**Summary of security properties achieved:**

| Property            | Mechanism                                           |
|---------------------|----------------------------------------------------|
| Confidentiality      | AES encryption + DH key exchange                   |
| Integrity            | SHA-256 digests + RSA signatures                  |
| Authenticity         | RSA signatures + CA-signed certificates          |
| Non-repudiation      | Signed transcripts & session receipts            |
| Replay protection    | Sequence numbers (seqno)                          |
| Tamper detection     | Offline receipt verification                       |

---

## Sample Input/Output

**Client Terminal:**

```
[Client] Enter message: hey there
[Server]: hi (Decrypted: Confidentiality)
[Client] Enter message: ok
[Server]: exit (Decrypted: Confidentiality)
Server requested to end chat
Generating receipt (Non-repudiation)
Server receipt verification: PASS
Client transcript receipt: {...}
Offline verification (original transcript): PASS
Offline verification (tampered transcript): FAIL
```

**Server Terminal:**

```
Verified client signature for seqno 1 (Integrity & Authenticity)
[Client]: hey there (Decrypted: Confidentiality)
[Server] Enter reply: hi
Sent reply seqno 1 (Integrity & Confidentiality)
Verified client signature for seqno 2 (Integrity & Authenticity)
[Client]: ok (Decrypted: Confidentiality)
[Server] Enter reply: exit
Sent reply seqno 2 (Integrity & Confidentiality)
Generating server receipt (Non-repudiation)
Client receipt verification: PASS
Server transcript receipt: {...}
Offline verification (original transcript): PASS
Offline verification (tampered transcript): FAIL
```

---

## Tests Performed

1. **Server Certificate Tests**

   * Verified valid server certificate
   * Tested with **fake certificate** (verification failed)
   * Tested with **expired certificate** (verification failed)

2. **Client Authentication**

   * Register new users
   * Login existing users
   * Verified credentials securely

3. **Secure Messaging**

   * AES encryption/decryption of messages
   * RSA signatures verified for message integrity

4. **Non-Repudiation**

   * Transcript & receipt generation for all messages
   * Offline verification of transcript and receipt
   * Detection of any tampering

5. **Replay Attack Test**

   * Attempted to resend old messages
   * Server detects and ignores replayed messages

---

## GitHub Repository

Full project repository:
[https://github.com/Hamna-Arshad/securechat-skeleton.git](https://github.com/Hamna-Arshad/securechat-skeleton.git)

