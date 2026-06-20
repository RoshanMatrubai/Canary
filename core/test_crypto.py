"""pytest core/test_crypto.py -x"""
import os

import pytest
from cryptography.exceptions import InvalidTag

from config import ENTROPY_THRESHOLD
from core.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    derive_key,
    ed25519_priv_bytes,
    ed25519_priv_from_bytes,
    ed25519_pub_bytes,
    ed25519_pub_from_bytes,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    random_salt,
    shannon_entropy,
    x25519_exchange,
    x25519_pub_bytes,
    x25519_pub_from_bytes,
)

FAST_M = 256  # MOCK: reduced Argon2id memory for test speed


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------

def test_derive_key_deterministic():
    salt = random_salt()
    assert derive_key("password", salt, m=FAST_M) == derive_key("password", salt, m=FAST_M)


def test_derive_key_length():
    assert len(derive_key("pw", random_salt(), m=FAST_M)) == 32


def test_derive_key_different_passwords():
    salt = random_salt()
    assert derive_key("a", salt, m=FAST_M) != derive_key("b", salt, m=FAST_M)


def test_derive_key_different_salts():
    assert derive_key("pw", random_salt(), m=FAST_M) != derive_key("pw", random_salt(), m=FAST_M)


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------

def test_aes_gcm_roundtrip():
    key = derive_key("k", random_salt(), m=FAST_M)
    pt = b"hello canary"
    assert aes_gcm_decrypt(key, aes_gcm_encrypt(key, pt)) == pt


def test_aes_gcm_with_aad():
    key = derive_key("k", random_salt(), m=FAST_M)
    pt = b"protected"
    aad = b"metadata"
    assert aes_gcm_decrypt(key, aes_gcm_encrypt(key, pt, aad), aad) == pt


def test_aes_gcm_wrong_aad_rejected():
    key = derive_key("k", random_salt(), m=FAST_M)
    ct = aes_gcm_encrypt(key, b"data", b"good-aad")
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(key, ct, b"bad-aad")


def test_aes_gcm_wrong_key_rejected():
    key = derive_key("right", random_salt(), m=FAST_M)
    bad = derive_key("wrong", random_salt(), m=FAST_M)
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(bad, aes_gcm_encrypt(key, b"data"))


def test_aes_gcm_tamper_detected():
    key = derive_key("k", random_salt(), m=FAST_M)
    ct = bytearray(aes_gcm_encrypt(key, b"data"))
    ct[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(key, bytes(ct))


def test_aes_gcm_unique_nonces():
    key = derive_key("k", random_salt(), m=FAST_M)
    ct1 = aes_gcm_encrypt(key, b"same")
    ct2 = aes_gcm_encrypt(key, b"same")
    assert ct1[:12] != ct2[:12]  # nonces differ


# ---------------------------------------------------------------------------
# X25519
# ---------------------------------------------------------------------------

def test_x25519_shared_secret_matches():
    priv_a, pub_a = generate_x25519_keypair()
    priv_b, pub_b = generate_x25519_keypair()
    assert x25519_exchange(priv_a, pub_b) == x25519_exchange(priv_b, pub_a)


def test_x25519_shared_secret_length():
    priv_a, pub_a = generate_x25519_keypair()
    _, pub_b = generate_x25519_keypair()
    assert len(x25519_exchange(priv_a, pub_b)) == 32


def test_x25519_pub_serialization_roundtrip():
    _, pub = generate_x25519_keypair()
    assert x25519_pub_bytes(x25519_pub_from_bytes(x25519_pub_bytes(pub))) == x25519_pub_bytes(pub)


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------

def test_ed25519_sign_verify():
    priv, pub = generate_ed25519_keypair()
    msg = b"sync manifest"
    assert ed25519_verify(pub, ed25519_sign(priv, msg), msg)


def test_ed25519_bad_signature_rejected():
    priv, pub = generate_ed25519_keypair()
    msg = b"manifest"
    sig = bytes(b ^ 0xFF for b in ed25519_sign(priv, msg))
    assert not ed25519_verify(pub, sig, msg)


def test_ed25519_wrong_key_rejected():
    priv, _ = generate_ed25519_keypair()
    _, pub2 = generate_ed25519_keypair()
    assert not ed25519_verify(pub2, ed25519_sign(priv, b"msg"), b"msg")


def test_ed25519_tampered_message_rejected():
    priv, pub = generate_ed25519_keypair()
    sig = ed25519_sign(priv, b"original")
    assert not ed25519_verify(pub, sig, b"tampered")


def test_ed25519_pub_serialization_roundtrip():
    _, pub = generate_ed25519_keypair()
    assert ed25519_pub_bytes(ed25519_pub_from_bytes(ed25519_pub_bytes(pub))) == ed25519_pub_bytes(pub)


def test_ed25519_priv_serialization_roundtrip():
    priv, pub = generate_ed25519_keypair()
    priv2 = ed25519_priv_from_bytes(ed25519_priv_bytes(priv))
    msg = b"roundtrip"
    assert ed25519_verify(pub, ed25519_sign(priv2, msg), msg)


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

def test_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_entropy_uniform_bytes_is_low():
    assert shannon_entropy(bytes([0xAA] * 1000)) < 0.01


def test_entropy_random_bytes_is_high():
    assert shannon_entropy(os.urandom(1000)) > 0.90


def test_entropy_random_exceeds_threshold():
    # Random data must trip the canary detector's threshold
    assert shannon_entropy(os.urandom(512)) > ENTROPY_THRESHOLD


def test_entropy_text_is_mid_range():
    data = b"hello world " * 100
    e = shannon_entropy(data)
    assert 0.2 < e < 0.8
