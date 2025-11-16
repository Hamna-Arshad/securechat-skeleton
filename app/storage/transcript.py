import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def compute_transcript_hash(transcript):

    lines = []
    for entry in transcript:
        line = f"{entry['seqno']}|{entry['ts']}|{entry['ct']}|{entry['sig']}|{entry['peer_fp']}"
        lines.append(line)
    concat = "\n".join(lines).encode()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(concat)
    return digest.finalize().hex()

def generate_receipt(transcript, priv_key, peer):

    transcript_hash = compute_transcript_hash(transcript)
    sig = priv_key.sign(bytes.fromhex(transcript_hash),
                        padding.PKCS1v15(),
                        hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode()
    receipt = {
        "type": "receipt",
        "peer": peer,
        "first_seq": transcript[0]["seqno"] if transcript else 0,
        "last_seq": transcript[-1]["seqno"] if transcript else 0,
        "transcript_sha256": transcript_hash,
        "sig": sig_b64
    }
    return receipt

def verify_receipt(transcript, receipt, pub_key):
    
    computed_hash = compute_transcript_hash(transcript)
    if computed_hash != receipt["transcript_sha256"]:
        print("[!] Transcript hash mismatch")
        return False
    sig_bytes = base64.b64decode(receipt["sig"])
    try:
        pub_key.verify(sig_bytes,
                       bytes.fromhex(receipt["transcript_sha256"]),
                       padding.PKCS1v15(),
                       hashes.SHA256())
        return True
    except Exception:
        print("[!] Receipt signature invalid")
        return False
