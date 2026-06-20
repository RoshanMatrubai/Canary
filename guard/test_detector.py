"""Phase 6 — canary detection engine tests.
Run: pytest guard/test_detector.py -x
"""
import base64
import os
import tempfile

import pytest

import config
from core.license import CanaryLockedError
from guard.detector import (
    SIGNAL_CANARY,
    SIGNAL_ENTROPY,
    SIGNAL_MASS,
    SIGNAL_TRIPWIRE,
    SyncBlockedError,
    inspect_batch,
    reset_state,
)


@pytest.fixture(autouse=True)
def pro_mode_and_clean_state():
    """Run every test in Pro mode with a fresh sliding window."""
    original = config.CANARY_PRO
    config.CANARY_PRO = True
    reset_state()
    yield
    config.CANARY_PRO = original
    reset_state()


# ---------------------------------------------------------------------------
# License gate
# ---------------------------------------------------------------------------

def test_inspect_raises_on_free():
    config.CANARY_PRO = False
    with pytest.raises(CanaryLockedError, match="🔒"):
        inspect_batch([{"name": "file.txt", "data_b64": base64.b64encode(b"hello").decode()}])


def test_inspect_passes_on_pro():
    result = inspect_batch([{"name": "readme.txt", "data_b64": base64.b64encode(b"hello world").decode()}])
    assert result.severity == "OK"


# ---------------------------------------------------------------------------
# Entropy signal
# ---------------------------------------------------------------------------

def test_high_entropy_fires():
    random_bytes = os.urandom(512)
    item = {"name": "blob.bin", "data_b64": base64.b64encode(random_bytes).decode()}
    result = inspect_batch([item])
    assert SIGNAL_ENTROPY in result.signals
    assert "blob.bin" in result.flagged


def test_low_entropy_clean():
    plain = b"this is a normal readable password entry with human text"
    item = {"name": "entry.txt", "data_b64": base64.b64encode(plain).decode()}
    result = inspect_batch([item])
    assert SIGNAL_ENTROPY not in result.signals


def test_entropy_fallback_to_text_fields():
    # Without data_b64, detector falls back to string field values
    item = {"name": "login", "title": "Gmail", "username": "user@example.com", "password": "secret123"}
    result = inspect_batch([item])
    assert SIGNAL_ENTROPY not in result.signals  # human text is low entropy


# ---------------------------------------------------------------------------
# Canary file signal
# ---------------------------------------------------------------------------

def test_canary_file_fires_on_prefix():
    item = {"name": "AAA_canary_tripwire.txt", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert SIGNAL_CANARY in result.signals


def test_canary_file_fires_on_exact_prefix():
    item = {"name": "AAA_canaryXYZ", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert SIGNAL_CANARY in result.signals


def test_canary_file_no_false_positive():
    item = {"name": "normal_file.txt", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert SIGNAL_CANARY not in result.signals


# ---------------------------------------------------------------------------
# Tripwire signal
# ---------------------------------------------------------------------------

def test_tripwire_kdbx():
    item = {"name": "vault.kdbx", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert SIGNAL_TRIPWIRE in result.signals


def test_tripwire_1pux():
    item = {"name": "export.1pux", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert SIGNAL_TRIPWIRE in result.signals


def test_tripwire_enpass():
    item = {"name": "backup.enpass", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert SIGNAL_TRIPWIRE in result.signals


def test_no_tripwire_false_positive():
    item = {"name": "document.pdf", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert SIGNAL_TRIPWIRE not in result.signals


# ---------------------------------------------------------------------------
# Mass change signal
# ---------------------------------------------------------------------------

def test_mass_change_fires_over_threshold():
    # total=10, batch=5 → 50% > 10%
    result = inspect_batch(
        [{"name": f"f{i}.bin", "data_b64": base64.b64encode(b"x").decode()} for i in range(5)],
        total_vault_entries=10,
    )
    assert SIGNAL_MASS in result.signals


def test_mass_change_does_not_fire_below_threshold():
    # total=1000, batch=5 → 0.5% < 10%
    result = inspect_batch(
        [{"name": f"f{i}.bin", "data_b64": base64.b64encode(b"x").decode()} for i in range(5)],
        total_vault_entries=1000,
    )
    assert SIGNAL_MASS not in result.signals


def test_mass_change_zero_total_never_fires():
    result = inspect_batch(
        [{"name": "f.bin", "data_b64": base64.b64encode(b"x").decode()}],
        total_vault_entries=0,
    )
    assert SIGNAL_MASS not in result.signals


# ---------------------------------------------------------------------------
# Severity & block logic
# ---------------------------------------------------------------------------

def test_canary_alone_is_critical_and_blocks():
    item = {"name": "AAA_canary.txt", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert result.severity == "CRITICAL"
    assert result.should_block is True


def test_tripwire_alone_is_critical_and_blocks():
    item = {"name": "vault.kdbx", "data_b64": base64.b64encode(b"x").decode()}
    result = inspect_batch([item])
    assert result.severity == "CRITICAL"
    assert result.should_block is True


def test_entropy_alone_is_warning_no_block():
    item = {"name": "blob.bin", "data_b64": base64.b64encode(os.urandom(512)).decode()}
    result = inspect_batch([item])
    assert SIGNAL_CANARY not in result.signals
    assert SIGNAL_TRIPWIRE not in result.signals
    assert result.severity == "WARNING"
    assert result.should_block is False


def test_two_signals_is_critical():
    # entropy (random bytes) + mass change (50% of vault)
    item = {"name": "blob.bin", "data_b64": base64.b64encode(os.urandom(512)).decode()}
    result = inspect_batch([item] * 5, total_vault_entries=10)
    assert len(result.signals) >= 2
    assert result.severity == "CRITICAL"
    assert result.should_block is True


def test_clean_batch_is_ok():
    item = {"name": "readme.txt", "data_b64": base64.b64encode(b"hello world readme text").decode()}
    result = inspect_batch([item])
    assert result.severity == "OK"
    assert result.should_block is False
    assert result.signals == []


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def test_quarantine_creates_batch_file():
    with tempfile.TemporaryDirectory() as qdir:
        item = {"name": "vault.kdbx", "data_b64": base64.b64encode(b"x").decode()}
        result = inspect_batch([item], quarantine_dir=qdir, node_id="testnode123")
        assert result.should_block is True
        assert result.detail.startswith("quarantined →")
        batch_dir = result.detail.split("→ ")[1].strip()
        assert os.path.isfile(os.path.join(batch_dir, "batch.json"))


# ---------------------------------------------------------------------------
# SyncBlockedError
# ---------------------------------------------------------------------------

def test_sync_blocked_error_carries_result():
    item = {"name": "AAA_canary.txt", "data_b64": base64.b64encode(os.urandom(256)).decode()}
    result = inspect_batch([item])
    err = SyncBlockedError(result)
    assert err.result is result
    assert "SYNC BLOCKED" in str(err)
