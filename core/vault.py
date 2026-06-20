"""
Append-only versioned vault.

Layout on disk:
  <vault_dir>/
    vault.meta              — JSON: {salt, created_at}
    v001_<timestamp>/
      manifest.json         — {version, timestamp, entries: [id, ...], entry_count}
      <entry_id>.enc        — two-layer encrypted entry blob
    v002_<timestamp>/
      ...

Two-layer encryption per entry:
  1. Random 256-bit CipherKey encrypts the entry JSON.
  2. VSK (Vault Storage Key) encrypts the CipherKey.
  Blob format: [4-byte big-endian key_blob_len][key_blob][entry_blob]
"""
import json
import os
import uuid
from datetime import datetime, timezone

from core.crypto import (
    ARGON2_M,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    derive_key,
    random_salt,
)
from core.license import check_vault_limit

VAULT_META = "vault.meta"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _version_dirs(vault_dir: str) -> list[str]:
    names = [
        n for n in os.listdir(vault_dir)
        if os.path.isdir(os.path.join(vault_dir, n)) and n.startswith("v")
    ]
    return sorted(names)


def _version_name(index: int) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"v{index:03d}_{ts}"


def _read_manifest(version_path: str) -> dict:
    with open(os.path.join(version_path, "manifest.json")) as f:
        return json.load(f)


def _entry_count(vault_dir: str) -> int:
    versions = _version_dirs(vault_dir)
    if not versions:
        return 0
    manifest = _read_manifest(os.path.join(vault_dir, versions[-1]))
    return len(manifest.get("entries", []))


def _encrypt_entry(vsk: bytes, entry: dict) -> bytes:
    cipher_key = os.urandom(32)
    encrypted_entry = aes_gcm_encrypt(cipher_key, json.dumps(entry).encode())
    encrypted_key = aes_gcm_encrypt(vsk, cipher_key)
    key_len = len(encrypted_key).to_bytes(4, "big")
    return key_len + encrypted_key + encrypted_entry


def _decrypt_entry(vsk: bytes, data: bytes) -> dict:
    key_len = int.from_bytes(data[:4], "big")
    encrypted_key = data[4: 4 + key_len]
    encrypted_entry = data[4 + key_len:]
    cipher_key = aes_gcm_decrypt(vsk, encrypted_key)
    return json.loads(aes_gcm_decrypt(cipher_key, encrypted_entry))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_vault(vault_dir: str, master_password: str, *, argon2_m: int = ARGON2_M) -> bytes:
    """
    Initialise a new vault directory and return the VSK.
    Raises FileExistsError if vault.meta already exists.
    """
    os.makedirs(vault_dir, exist_ok=True)
    meta_path = os.path.join(vault_dir, VAULT_META)
    if os.path.exists(meta_path):
        raise FileExistsError(f"Vault already exists at {vault_dir}")

    salt = random_salt(16)
    vsk = derive_key(master_password, salt, m=argon2_m)

    with open(meta_path, "w") as f:
        json.dump({
            "salt": salt.hex(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }, f)

    return vsk


def unlock_vault(vault_dir: str, master_password: str, *, argon2_m: int = ARGON2_M) -> bytes:
    """Derive and return the VSK from the stored salt. Raises FileNotFoundError if no vault."""
    meta_path = os.path.join(vault_dir, VAULT_META)
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"No vault found at {vault_dir}")

    with open(meta_path) as f:
        meta = json.load(f)

    return derive_key(master_password, bytes.fromhex(meta["salt"]), m=argon2_m)


def add_entry(vault_dir: str, vsk: bytes, entry: dict) -> str:
    """
    Encrypt and append a new entry, creating a new version snapshot.
    Raises CanaryLockedError if the free-tier 50-entry cap is reached.
    Returns the entry ID.
    """
    check_vault_limit(_entry_count(vault_dir))

    versions = _version_dirs(vault_dir)
    new_index = len(versions) + 1

    # Carry forward all encrypted blobs from the previous version unchanged.
    prev_files: dict[str, bytes] = {}
    prev_entry_ids: list[str] = []
    if versions:
        prev_path = os.path.join(vault_dir, versions[-1])
        prev_manifest = _read_manifest(prev_path)
        for eid in prev_manifest.get("entries", []):
            with open(os.path.join(prev_path, f"{eid}.enc"), "rb") as fh:
                prev_files[eid] = fh.read()
            prev_entry_ids.append(eid)

    entry_id = entry.get("id") or str(uuid.uuid4())
    entry = {
        **entry,
        "id": entry_id,
        "created_at": entry.get("created_at") or datetime.now(timezone.utc).isoformat(),
    }
    entry_blob = _encrypt_entry(vsk, entry)

    new_ver_path = os.path.join(vault_dir, _version_name(new_index))
    os.makedirs(new_ver_path)

    for eid, blob in prev_files.items():
        with open(os.path.join(new_ver_path, f"{eid}.enc"), "wb") as fh:
            fh.write(blob)

    with open(os.path.join(new_ver_path, f"{entry_id}.enc"), "wb") as fh:
        fh.write(entry_blob)

    all_ids = prev_entry_ids + [entry_id]
    with open(os.path.join(new_ver_path, "manifest.json"), "w") as f:
        json.dump({
            "version": new_index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "entries": all_ids,
            "entry_count": len(all_ids),
        }, f, indent=2)

    return entry_id


def list_entries(vault_dir: str, vsk: bytes, version: str = None) -> list[dict]:
    """Return decrypted entries from the latest (or a named) version."""
    versions = _version_dirs(vault_dir)
    if not versions:
        return []

    ver_name = version or versions[-1]
    ver_path = os.path.join(vault_dir, ver_name)
    manifest = _read_manifest(ver_path)

    result = []
    for eid in manifest.get("entries", []):
        with open(os.path.join(ver_path, f"{eid}.enc"), "rb") as fh:
            result.append(_decrypt_entry(vsk, fh.read()))
    return result


def list_versions(vault_dir: str) -> list[str]:
    """Return sorted list of version directory names."""
    return _version_dirs(vault_dir)


def restore_version(vault_dir: str, vsk: bytes, version: str) -> list[dict]:
    """Return entries from a named past version (read-only). Pro-gated at dashboard layer."""
    return list_entries(vault_dir, vsk, version=version)
