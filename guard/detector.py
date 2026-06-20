"""
guard/detector.py — 🐤 Canary detection engine (Pro-gated).

Signals checked on every incoming sync batch:
  ENTROPY     — Shannon entropy > 0.85 on any item's data
  CANARY_FILE — item named AAA_canary* (literal tripwire)
  TRIPWIRE    — item is a .kdbx / .1pux / .enpass file
  MASS_CHANGE — > 10% of vault entries changed in the last 5 min

Block conditions (CRITICAL):
  - CANARY_FILE or TRIPWIRE present (alone is enough)
  - 3+ signals firing simultaneously

When CANARY_PRO = False: inspect_batch() raises CanaryLockedError — coal mine has no canary.
"""
import base64
import collections
import json
import os
import time
from dataclasses import dataclass, field

import config
from core.crypto import shannon_entropy
from core.license import CanaryLockedError, require_pro

SIGNAL_ENTROPY = "ENTROPY"
SIGNAL_CANARY = "CANARY_FILE"
SIGNAL_TRIPWIRE = "TRIPWIRE"
SIGNAL_MASS = "MASS_CHANGE"

# Sliding-window log: deque of (timestamp, batch_size) for mass-change tracking
_change_log: collections.deque = collections.deque()


# ---------------------------------------------------------------------------
# Public result types
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    signals: list[str]
    flagged: list[str]
    severity: str        # "OK" | "WARNING" | "CRITICAL"
    should_block: bool
    detail: str = ""


class SyncBlockedError(Exception):
    """Raised by _ingest_hook when the canary fires and sync must be refused."""
    def __init__(self, result: DetectionResult):
        self.result = result
        super().__init__(f"SYNC BLOCKED signals={result.signals} flagged={result.flagged}")


# ---------------------------------------------------------------------------
# Per-item signal checks
# ---------------------------------------------------------------------------

def _item_bytes(item: dict) -> bytes:
    """Extract bytes to entropy-check. Prefer explicit data_b64 field, fall back to text."""
    if "data_b64" in item:
        try:
            return base64.b64decode(item["data_b64"])
        except Exception:
            pass
    return " ".join(str(v) for v in item.values() if isinstance(v, str)).encode()


def _item_name(item: dict) -> str:
    return str(item.get("name", item.get("title", item.get("id", ""))))


def _is_high_entropy(item: dict) -> bool:
    return shannon_entropy(_item_bytes(item)) > config.ENTROPY_THRESHOLD


def _is_canary_file(item: dict) -> bool:
    return os.path.basename(_item_name(item)).startswith(config.CANARY_PREFIX)


def _is_tripwire(item: dict) -> bool:
    name = _item_name(item).lower()
    return any(name.endswith(ext) for ext in config.VAULT_EXTENSIONS)


def _is_mass_change(batch_size: int, total_vault_entries: int) -> bool:
    now = time.time()
    _change_log.append((now, batch_size))
    cutoff = now - config.MASS_CHANGE_WINDOW_SECS
    while _change_log and _change_log[0][0] < cutoff:
        _change_log.popleft()
    if total_vault_entries == 0:
        return False
    recent = sum(c for _, c in _change_log)
    return (recent / total_vault_entries) > config.MASS_CHANGE_RATIO


# ---------------------------------------------------------------------------
# Severity computation
# ---------------------------------------------------------------------------

def _compute_severity(signals: list[str]) -> tuple[str, bool]:
    if not signals:
        return "OK", False
    if SIGNAL_CANARY in signals or SIGNAL_TRIPWIRE in signals:
        return "CRITICAL", True
    if len(signals) >= 3:
        return "CRITICAL", True
    if len(signals) >= 2:
        return "CRITICAL", True  # any two signals = CRITICAL per demo spec
    return "WARNING", False


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def quarantine_batch(items: list[dict], quarantine_dir: str, node_id: str) -> str:
    """Write flagged batch to quarantine dir. Returns the batch path."""
    batch_id = f"{int(time.time())}_{node_id[:8]}"
    batch_dir = os.path.join(quarantine_dir, batch_id)
    os.makedirs(batch_dir, exist_ok=True)
    with open(os.path.join(batch_dir, "batch.json"), "w") as f:
        json.dump({"node_id": node_id, "quarantined_at": time.time(), "items": items}, f, indent=2)
    return batch_dir


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def inspect_batch(
    items: list[dict],
    total_vault_entries: int = 0,
    quarantine_dir: str = "",
    node_id: str = "unknown",
) -> DetectionResult:
    """
    Inspect an incoming sync batch for ransomware signals.
    Raises CanaryLockedError when CANARY_PRO = False — the coal mine has no canary.
    """
    require_pro("Canary Detection")

    signals: list[str] = []
    flagged: list[str] = []

    for item in items:
        name = _item_name(item)
        fired = []

        if _is_high_entropy(item):
            fired.append(SIGNAL_ENTROPY)
        if _is_canary_file(item):
            fired.append(SIGNAL_CANARY)
        if _is_tripwire(item):
            fired.append(SIGNAL_TRIPWIRE)

        if fired:
            flagged.append(name)
            for s in fired:
                if s not in signals:
                    signals.append(s)

    if _is_mass_change(len(items), total_vault_entries):
        if SIGNAL_MASS not in signals:
            signals.append(SIGNAL_MASS)

    severity, should_block = _compute_severity(signals)
    detail = ""

    if should_block and quarantine_dir:
        batch_path = quarantine_batch(items, quarantine_dir, node_id)
        detail = f"quarantined → {batch_path}"

    return DetectionResult(
        signals=signals,
        flagged=flagged,
        severity=severity,
        should_block=should_block,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Test helper
# ---------------------------------------------------------------------------

def reset_state() -> None:
    """Clear the mass-change sliding window. For tests only."""
    _change_log.clear()
