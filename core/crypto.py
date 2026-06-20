import math
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Argon2id parameters (CLAUDE.md: m=65536, t=3, p=4)
ARGON2_M = 65536
ARGON2_T = 3
ARGON2_P = 4
ARGON2_HASH_LEN = 32  # 256-bit output

NONCE_SIZE = 12  # 96-bit nonce for AES-256-GCM


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------

def derive_key(password: str | bytes, salt: bytes, m: int = ARGON2_M) -> bytes:
    """Argon2id KDF → 32-byte (256-bit) key. Pass m=256 in tests for speed."""
    if isinstance(password, str):
        password = password.encode()
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_T,
        memory_cost=m,
        parallelism=ARGON2_P,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def random_salt(size: int = 16) -> bytes:
    return os.urandom(size)


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce || ciphertext+tag."""
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad if aad else None)
    return nonce + ct


def aes_gcm_decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM blob (nonce || ciphertext+tag)."""
    nonce, ct = data[:NONCE_SIZE], data[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, aad if aad else None)


# ---------------------------------------------------------------------------
# X25519 ECDH (transport key exchange)
# ---------------------------------------------------------------------------

def generate_x25519_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def x25519_exchange(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey) -> bytes:
    """DH exchange → 32-byte shared secret."""
    return private_key.exchange(peer_public_key)


def x25519_pub_bytes(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519_pub_from_bytes(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Ed25519 signing (sync manifests)
# ---------------------------------------------------------------------------

def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def ed25519_sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def ed25519_verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def ed25519_pub_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed25519_pub_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def ed25519_priv_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def ed25519_priv_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


# ---------------------------------------------------------------------------
# Shannon entropy (used by canary detector)
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Normalized Shannon entropy in [0.0, 1.0]. 1.0 = maximally random."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h / 8.0  # 8 bits per byte is the theoretical max
