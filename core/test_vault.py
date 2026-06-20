"""pytest core/test_vault.py -x"""
import pytest

import config
from core.license import CanaryLockedError
from core.vault import (
    add_entry,
    create_vault,
    list_entries,
    list_versions,
    restore_version,
    unlock_vault,
)

FAST_M = 256  # MOCK: reduced Argon2id memory for test speed


@pytest.fixture
def vault(tmp_path):
    vdir = str(tmp_path / "vault")
    vsk = create_vault(vdir, "hunter2", argon2_m=FAST_M)
    return vdir, vsk


# ---------------------------------------------------------------------------
# Create / unlock
# ---------------------------------------------------------------------------

def test_create_returns_vsk(vault):
    _, vsk = vault
    assert len(vsk) == 32


def test_unlock_matches_create(vault, tmp_path):
    vdir, vsk = vault
    vsk2 = unlock_vault(vdir, "hunter2", argon2_m=FAST_M)
    assert vsk == vsk2


def test_wrong_password_different_vsk(vault):
    vdir, vsk = vault
    bad_vsk = unlock_vault(vdir, "wrongpassword", argon2_m=FAST_M)
    assert bad_vsk != vsk


def test_create_raises_if_already_exists(vault):
    vdir, _ = vault
    with pytest.raises(FileExistsError):
        create_vault(vdir, "other", argon2_m=FAST_M)


def test_unlock_raises_if_no_vault(tmp_path):
    with pytest.raises(FileNotFoundError):
        unlock_vault(str(tmp_path / "missing"), "pw", argon2_m=FAST_M)


# ---------------------------------------------------------------------------
# Add / list entries
# ---------------------------------------------------------------------------

def test_add_and_list_single_entry(vault):
    vdir, vsk = vault
    eid = add_entry(vdir, vsk, {"site": "gmail.com", "username": "u", "password": "p"})
    entries = list_entries(vdir, vsk)
    assert len(entries) == 1
    assert entries[0]["site"] == "gmail.com"
    assert entries[0]["id"] == eid


def test_add_multiple_entries_all_present(vault):
    vdir, vsk = vault
    add_entry(vdir, vsk, {"site": "a.com", "username": "a", "password": "1"})
    add_entry(vdir, vsk, {"site": "b.com", "username": "b", "password": "2"})
    add_entry(vdir, vsk, {"site": "c.com", "username": "c", "password": "3"})
    entries = list_entries(vdir, vsk)
    assert len(entries) == 3
    sites = {e["site"] for e in entries}
    assert sites == {"a.com", "b.com", "c.com"}


def test_entry_id_is_preserved(vault):
    vdir, vsk = vault
    custom_id = "my-custom-id-123"
    eid = add_entry(vdir, vsk, {"id": custom_id, "site": "x.com", "username": "u", "password": "p"})
    assert eid == custom_id
    entries = list_entries(vdir, vsk)
    assert entries[0]["id"] == custom_id


def test_empty_vault_returns_empty_list(vault):
    vdir, vsk = vault
    assert list_entries(vdir, vsk) == []


# ---------------------------------------------------------------------------
# Append-only versioning
# ---------------------------------------------------------------------------

def test_each_add_creates_new_version(vault):
    vdir, vsk = vault
    add_entry(vdir, vsk, {"site": "a.com", "username": "u", "password": "p"})
    add_entry(vdir, vsk, {"site": "b.com", "username": "u", "password": "p"})
    assert len(list_versions(vdir)) == 2


def test_latest_version_has_all_entries(vault):
    vdir, vsk = vault
    add_entry(vdir, vsk, {"site": "a.com", "username": "u", "password": "p"})
    add_entry(vdir, vsk, {"site": "b.com", "username": "u", "password": "p"})
    assert len(list_entries(vdir, vsk)) == 2


def test_first_version_has_one_entry(vault):
    vdir, vsk = vault
    add_entry(vdir, vsk, {"site": "a.com", "username": "u", "password": "p"})
    add_entry(vdir, vsk, {"site": "b.com", "username": "u", "password": "p"})
    v1 = list_versions(vdir)[0]
    assert len(list_entries(vdir, vsk, version=v1)) == 1


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

def test_restore_version_returns_past_entries(vault):
    vdir, vsk = vault
    add_entry(vdir, vsk, {"site": "first.com", "username": "a", "password": "x"})
    add_entry(vdir, vsk, {"site": "second.com", "username": "b", "password": "y"})
    v1 = list_versions(vdir)[0]
    restored = restore_version(vdir, vsk, v1)
    assert len(restored) == 1
    assert restored[0]["site"] == "first.com"


def test_restore_does_not_modify_vault(vault):
    vdir, vsk = vault
    add_entry(vdir, vsk, {"site": "a.com", "username": "u", "password": "p"})
    add_entry(vdir, vsk, {"site": "b.com", "username": "u", "password": "p"})
    v1 = list_versions(vdir)[0]
    restore_version(vdir, vsk, v1)
    # Still 2 versions — restore is read-only
    assert len(list_versions(vdir)) == 2


# ---------------------------------------------------------------------------
# Free-tier limit (the big gate)
# ---------------------------------------------------------------------------

def test_free_tier_blocks_51st_entry(vault, monkeypatch):
    vdir, vsk = vault
    monkeypatch.setattr(config, "CANARY_PRO", False)
    for i in range(config.FREE_PASSWORD_LIMIT):
        add_entry(vdir, vsk, {"site": f"site{i}.com", "username": "u", "password": "p"})
    with pytest.raises(CanaryLockedError, match="Free tier"):
        add_entry(vdir, vsk, {"site": "blocked.com", "username": "u", "password": "p"})


def test_pro_tier_allows_beyond_50(vault, monkeypatch):
    vdir, vsk = vault
    monkeypatch.setattr(config, "CANARY_PRO", True)
    for i in range(config.FREE_PASSWORD_LIMIT + 1):
        add_entry(vdir, vsk, {"site": f"site{i}.com", "username": "u", "password": "p"})
    assert len(list_entries(vdir, vsk)) == config.FREE_PASSWORD_LIMIT + 1


def test_error_message_mentions_upgrade(vault, monkeypatch):
    vdir, vsk = vault
    monkeypatch.setattr(config, "CANARY_PRO", False)
    for i in range(config.FREE_PASSWORD_LIMIT):
        add_entry(vdir, vsk, {"site": f"s{i}.com", "username": "u", "password": "p"})
    with pytest.raises(CanaryLockedError, match="Upgrade to Canary Pro"):
        add_entry(vdir, vsk, {"site": "x.com", "username": "u", "password": "p"})
