"""
simulate_ransomware.py — # MOCK ransomware attack simulator for Canary demo.

What this does:
  1. Connects to the running Canary node's TCP sync port (localhost:9000 by default).
  2. Sends a signed manifest containing 20 "encrypted" entries that look like ransomware:
       - High-entropy payloads (random bytes → base64) that trigger the ENTROPY signal
       - One entry named "AAA_canary_tripwire.txt" to fire CANARY_FILE
       - One entry named "passwords.kdbx" to fire TRIPWIRE
  3. Prints the peer's response (ok vs blocked).

On FREE tier  → sync goes through silently (no canary, no detection).
On PRO  tier  → SYNC BLOCKED with signals listed and batch quarantined.

Usage:
  # target the running Canary node (default localhost:9000):
  python simulate_ransomware.py

  # target a different host/port:
  python simulate_ransomware.py --host 192.168.1.5 --port 9000
"""
import argparse
import base64
import json
import os
import socket
import time

# ---------------------------------------------------------------------------
# Inline crypto helpers (avoids importing the full Canary stack)
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import config  # for PEER_PORT


# ---------------------------------------------------------------------------
# Frame helpers (mirrors sync/peer.py wire format)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer disconnected mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def _send_frame(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, "big") + data)


def _recv_frame(sock) -> bytes:
    length = int.from_bytes(_recv_exact(sock, 4), "big")
    return _recv_exact(sock, length)


# ---------------------------------------------------------------------------
# AES-256-GCM (mirrors core/crypto.py)
# ---------------------------------------------------------------------------

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _aes_gcm_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], None)


# ---------------------------------------------------------------------------
# Session key (HKDF — same as peer.py)
# ---------------------------------------------------------------------------

def _derive_session_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"canary-session",
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# X25519 client handshake
# ---------------------------------------------------------------------------

def _handshake_client(sock) -> bytes:
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    _send_frame(sock, pub_bytes)
    server_pub_bytes = _recv_frame(sock)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared = priv.exchange(server_pub)
    return _derive_session_key(shared)


# ---------------------------------------------------------------------------
# Encrypted message helpers
# ---------------------------------------------------------------------------

def _send_msg(sock, session_key: bytes, payload: dict):
    _send_frame(sock, _aes_gcm_encrypt(session_key, json.dumps(payload, sort_keys=True).encode()))


def _recv_msg(sock, session_key: bytes) -> dict:
    return json.loads(_aes_gcm_decrypt(session_key, _recv_frame(sock)))


# ---------------------------------------------------------------------------
# Ed25519 signed manifest
# ---------------------------------------------------------------------------

def _build_manifest(entries: list[dict], node_id: str) -> dict:
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    body = {
        "entries": entries,
        "node_id": node_id,
        "ed_pub": pub_raw.hex(),
        "timestamp": time.time(),
    }
    sig = priv.sign(json.dumps(body, sort_keys=True).encode())
    return {**body, "sig": sig.hex()}


# ---------------------------------------------------------------------------
# Build the attack payload
# ---------------------------------------------------------------------------

def _make_attack_entries(count: int = 20) -> list[dict]:
    """
    Craft entries that trigger all three per-item signals:
      ENTROPY     — high-entropy base64 payload
      CANARY_FILE — name starts with AAA_canary
      TRIPWIRE    — name ends with .kdbx
    """
    entries = []

    # Entry 0 — literal canary tripwire (CANARY_FILE signal)
    entries.append({
        "name": "AAA_canary_tripwire.txt",
        "data_b64": base64.b64encode(os.urandom(512)).decode(),
    })

    # Entry 1 — vault file (TRIPWIRE signal)
    entries.append({
        "name": "passwords.kdbx",
        "data_b64": base64.b64encode(os.urandom(512)).decode(),
    })

    # Remaining — high-entropy "encrypted" files (ENTROPY signal)
    for i in range(count - 2):
        entries.append({
            "name": f"document_{i:04d}.enc",
            "data_b64": base64.b64encode(os.urandom(512)).decode(),  # random = high entropy
        })

    return entries


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_attack(host: str, port: int):
    node_id = f"attacker_{os.urandom(4).hex()}"
    entries = _make_attack_entries(20)

    print(f"\n🦠  Canary Ransomware Simulator  (# MOCK)")
    print(f"   Target  : {host}:{port}")
    print(f"   Attacker: {node_id}")
    print(f"   Payload : {len(entries)} entries")
    print(f"   Signals present: CANARY_FILE, TRIPWIRE, ENTROPY")
    print()

    try:
        sock = socket.create_connection((host, port), timeout=10)
    except ConnectionRefusedError:
        print(f"[!] Connection refused — is Canary running on {host}:{port}?")
        return

    try:
        session_key = _handshake_client(sock)
        manifest = _build_manifest(entries, node_id)
        _send_msg(sock, session_key, manifest)
        response = _recv_msg(sock, session_key)
    finally:
        sock.close()

    status = response.get("status", "?")

    if status == "blocked":
        signals = response.get("signals", [])
        flagged = response.get("flagged", [])
        detail = response.get("detail", "")
        print("🚨  SYNC BLOCKED — Canary Pro caught the attack!")
        print(f"   Signals  : {', '.join(signals)}")
        print(f"   Flagged  : {', '.join(flagged[:5])}{'…' if len(flagged) > 5 else ''}")
        if detail:
            print(f"   {detail}")
    elif status == "ok":
        count = response.get("count", "?")
        print("😬  SYNC ACCEPTED — Free tier, no canary protection.")
        print(f"   {count} poisoned entries ingested without detection.")
        print("   Flip to Canary Pro and rerun to see the canary scream.")
    else:
        print(f"?   Unexpected response: {response}")

    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Canary ransomware attack simulator (MOCK)")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=config.PEER_PORT, help=f"Target port (default: {config.PEER_PORT})")
    args = parser.parse_args()
    run_attack(args.host, args.port)
