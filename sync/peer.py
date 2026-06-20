"""
sync/peer.py — P2P sync layer (Free tier).

Wire protocol over TCP (big-endian length-prefixed frames):
  HANDSHAKE
    client → server : [4B][X25519-pub 32 B]
    server → client : [4B][X25519-pub 32 B]
    both derive     : session_key = HKDF-SHA256(shared_secret, info=b"canary-session")
  DATA (post-handshake, both directions)
    either side     : [4B][AES-256-GCM(session_key, json_bytes)]

Every outgoing manifest is Ed25519-signed by the sender's identity key.
Phase 6 wires guard/detector.py into _ingest_hook().
"""
import io
import json
import os
import socket
import threading
import time

import qrcode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

import config
from guard.detector import SyncBlockedError, inspect_batch
from core.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ed25519_priv_bytes,
    ed25519_priv_from_bytes,
    ed25519_pub_bytes,
    ed25519_pub_from_bytes,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    x25519_exchange,
    x25519_pub_bytes,
    x25519_pub_from_bytes,
)

_SERVICE_TYPE = "_canary._tcp.local."
_FRAME_MAX = 4 * 1024 * 1024  # 4 MB per frame


# ---------------------------------------------------------------------------
# Identity — persisted Ed25519 keys + 128-bit pairing secret
# ---------------------------------------------------------------------------

def _load_or_create_identity(config_dir: str) -> tuple[bytes, bytes, bytes]:
    """Return (ed_priv_raw, ed_pub_raw, secret_key). Generated once, then reloaded."""
    os.makedirs(config_dir, exist_ok=True)
    id_path = os.path.join(config_dir, "peer_identity.json")
    if os.path.exists(id_path):
        with open(id_path) as f:
            d = json.load(f)
        return bytes.fromhex(d["ed_priv"]), bytes.fromhex(d["ed_pub"]), bytes.fromhex(d["secret_key"])

    priv, pub = generate_ed25519_keypair()
    priv_raw, pub_raw = ed25519_priv_bytes(priv), ed25519_pub_bytes(pub)
    secret_key = os.urandom(16)  # 128-bit pairing secret (shown as QR, never sent)

    with open(id_path, "w") as f:
        json.dump({"ed_priv": priv_raw.hex(), "ed_pub": pub_raw.hex(), "secret_key": secret_key.hex()}, f)

    return priv_raw, pub_raw, secret_key


# ---------------------------------------------------------------------------
# Frame I/O
# ---------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer disconnected mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def _send_frame(sock: socket.socket, data: bytes) -> None:
    if len(data) > _FRAME_MAX:
        raise ValueError(f"frame too large: {len(data)} B")
    sock.sendall(len(data).to_bytes(4, "big") + data)


def _recv_frame(sock: socket.socket) -> bytes:
    length = int.from_bytes(_recv_exact(sock, 4), "big")
    if length > _FRAME_MAX:
        raise ValueError(f"frame too large: {length} B")
    return _recv_exact(sock, length)


# ---------------------------------------------------------------------------
# Session key (HKDF over X25519 shared secret)
# ---------------------------------------------------------------------------

def _derive_session_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"canary-session",
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# X25519 handshake
# ---------------------------------------------------------------------------

def _handshake_server(conn: socket.socket) -> bytes:
    client_pub = x25519_pub_from_bytes(_recv_frame(conn))
    priv, pub = generate_x25519_keypair()
    _send_frame(conn, x25519_pub_bytes(pub))
    return _derive_session_key(x25519_exchange(priv, client_pub))


def _handshake_client(conn: socket.socket) -> bytes:
    priv, pub = generate_x25519_keypair()
    _send_frame(conn, x25519_pub_bytes(pub))
    server_pub = x25519_pub_from_bytes(_recv_frame(conn))
    return _derive_session_key(x25519_exchange(priv, server_pub))


# ---------------------------------------------------------------------------
# Encrypted message framing
# ---------------------------------------------------------------------------

def _send_msg(sock: socket.socket, session_key: bytes, payload: dict) -> None:
    _send_frame(sock, aes_gcm_encrypt(session_key, json.dumps(payload, sort_keys=True).encode()))


def _recv_msg(sock: socket.socket, session_key: bytes) -> dict:
    return json.loads(aes_gcm_decrypt(session_key, _recv_frame(sock)))


# ---------------------------------------------------------------------------
# Manifest signing & verification
# ---------------------------------------------------------------------------

def _build_manifest(ed_priv_raw: bytes, ed_pub_raw: bytes, entries: list[dict], node_id: str) -> dict:
    body = {
        "entries": entries,
        "node_id": node_id,
        "ed_pub": ed_pub_raw.hex(),
        "timestamp": time.time(),
    }
    sig = ed25519_sign(ed25519_priv_from_bytes(ed_priv_raw), json.dumps(body, sort_keys=True).encode())
    return {**body, "sig": sig.hex()}


def _verify_manifest(manifest: dict) -> bool:
    sig_hex = manifest.get("sig", "")
    if not sig_hex:
        return False
    body = {k: v for k, v in manifest.items() if k != "sig"}
    pub = ed25519_pub_from_bytes(bytes.fromhex(manifest["ed_pub"]))
    return ed25519_verify(pub, bytes.fromhex(sig_hex), json.dumps(body, sort_keys=True).encode())


# ---------------------------------------------------------------------------
# Detection hook — wired to guard/detector.py (Pro-gated)
# ---------------------------------------------------------------------------

def _ingest_hook(entries: list[dict], node_id: str, vault_entry_count: int = 0) -> None:
    if not config.CANARY_PRO:
        return  # Free tier — coal mine has no canary
    result = inspect_batch(
        entries,
        total_vault_entries=vault_entry_count,
        quarantine_dir=config.QUARANTINE_DIR,
        node_id=node_id,
    )
    if result.should_block:
        raise SyncBlockedError(result)
    if result.signals:
        print(f"[canary] ⚠️  WARNING signals={result.signals} flagged={result.flagged}")


# ---------------------------------------------------------------------------
# QR pairing
# ---------------------------------------------------------------------------

def generate_pairing_qr(host: str, port: int, ed_pub_raw: bytes, secret_key: bytes) -> str:
    """Return an ASCII QR string encoding the info a peer needs to pair with this node."""
    payload = json.dumps({"host": host, "port": port, "pubkey": ed_pub_raw.hex(), "secret": secret_key.hex()})
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# mDNS listener
# ---------------------------------------------------------------------------

class _CanaryListener:
    def __init__(self, node: "PeerNode"):
        self._node = node

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info is None or not info.addresses:
            return
        host = socket.inet_ntoa(info.addresses[0])
        port = info.port
        raw = info.properties.get(b"node_id", b"")
        node_id = raw.decode() if isinstance(raw, bytes) else raw
        if node_id and node_id != self._node.node_id:
            self._node.peers[node_id] = (host, port)
            print(f"[canary] discovered peer {node_id[:8]}… @ {host}:{port}")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)


# ---------------------------------------------------------------------------
# PeerNode — main public interface
# ---------------------------------------------------------------------------

class PeerNode:
    """
    Canary P2P node. Call start() to bring up the TCP server + mDNS.
    Use send_to_peer() or broadcast() to push vault entries to peers.
    """

    def __init__(self, config_dir: str = ".canary", vault_entry_count: int = 100):
        self.config_dir = config_dir
        self.ed_priv_raw, self.ed_pub_raw, self.secret_key = _load_or_create_identity(config_dir)
        # Short display ID derived from Ed25519 public key
        self.node_id = self.ed_pub_raw.hex()[:16]
        self.peers: dict[str, tuple[str, int]] = {}  # node_id → (host, port)
        self.vault_entry_count = vault_entry_count  # used for mass-change % calculation
        self._zeroconf: Zeroconf | None = None
        self._server_sock: socket.socket | None = None
        self._running = False

    # ------------------------------------------------------------------
    # TCP server
    # ------------------------------------------------------------------

    def start_server(self, port: int | None = None) -> None:
        port = port or config.PEER_PORT
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", port))
        self._server_sock.listen(8)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        print(f"[canary] TCP server listening on :{port}  node={self.node_id}")

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
            except OSError:
                break

    def _handle_conn(self, conn: socket.socket, addr: tuple) -> None:
        try:
            session_key = _handshake_server(conn)
            manifest = _recv_msg(conn, session_key)
            if not _verify_manifest(manifest):
                print(f"[canary] REJECTED manifest from {addr} — bad Ed25519 signature")
                _send_msg(conn, session_key, {"status": "rejected", "reason": "invalid signature"})
                return
            entries = manifest.get("entries", [])
            node_id = manifest.get("node_id", "unknown")
            _ingest_hook(entries, node_id, vault_entry_count=self.vault_entry_count)
            _send_msg(conn, session_key, {"status": "ok", "count": len(entries)})
            print(f"[canary] ingested {len(entries)} entries from {node_id[:8]}…")
        except SyncBlockedError as blocked:
            print(f"[canary] 🚨 SYNC BLOCKED from {node_id[:8] if 'node_id' in dir() else '?'}… signals={blocked.result.signals}")
            try:
                _send_msg(conn, session_key, {
                    "status": "blocked",
                    "signals": blocked.result.signals,
                    "flagged": blocked.result.flagged,
                    "detail": blocked.result.detail,
                })
            except Exception:
                pass
        except Exception as exc:
            print(f"[canary] error handling connection from {addr}: {exc}")
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # mDNS
    # ------------------------------------------------------------------

    def start_mdns(self, port: int | None = None) -> None:
        port = port or config.PEER_PORT
        host_ip = _local_ip()
        self._zeroconf = Zeroconf()
        info = ServiceInfo(
            _SERVICE_TYPE,
            f"canary-{self.node_id}.{_SERVICE_TYPE}",
            addresses=[socket.inet_aton(host_ip)],
            port=port,
            properties={b"node_id": self.node_id.encode()},
        )
        self._zeroconf.register_service(info)
        ServiceBrowser(self._zeroconf, _SERVICE_TYPE, _CanaryListener(self))
        print(f"[canary] mDNS registered @ {host_ip}:{port}")

    # ------------------------------------------------------------------
    # Client — push entries to a peer
    # ------------------------------------------------------------------

    def send_to_peer(self, host: str, port: int, entries: list[dict]) -> dict:
        """Open a connection, handshake, send signed manifest, return peer's ack."""
        conn = socket.create_connection((host, port), timeout=10)
        try:
            session_key = _handshake_client(conn)
            manifest = _build_manifest(self.ed_priv_raw, self.ed_pub_raw, entries, self.node_id)
            _send_msg(conn, session_key, manifest)
            return _recv_msg(conn, session_key)
        finally:
            conn.close()

    def broadcast(self, entries: list[dict]) -> dict[str, dict]:
        """Send entries to all known peers. Returns {node_id: ack_or_error}."""
        results = {}
        for nid, (host, port) in list(self.peers.items()):
            try:
                results[nid] = self.send_to_peer(host, port, entries)
            except Exception as exc:
                results[nid] = {"status": "error", "reason": str(exc)}
        return results

    # ------------------------------------------------------------------
    # QR pairing
    # ------------------------------------------------------------------

    def pairing_qr(self, port: int | None = None) -> str:
        """Return ASCII QR string to show on screen for pairing."""
        return generate_pairing_qr(_local_ip(), port or config.PEER_PORT, self.ed_pub_raw, self.secret_key)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, port: int | None = None) -> None:
        port = port or config.PEER_PORT
        self.start_server(port)
        self.start_mdns(port)

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            self._server_sock.close()
        if self._zeroconf:
            self._zeroconf.close()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()
