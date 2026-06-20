"""Phase 4 — license gate tests."""
import pytest
import config
from core.license import (
    CanaryLockedError,
    activate,
    deactivate,
    check_vault_limit,
    is_pro,
    require_pro,
)


@pytest.fixture(autouse=True)
def reset_license():
    """Restore config state after every test."""
    original = config.CANARY_PRO
    yield
    config.CANARY_PRO = original


# ---------------------------------------------------------------------------
# require_pro
# ---------------------------------------------------------------------------

def test_require_pro_raises_on_free():
    config.CANARY_PRO = False
    with pytest.raises(CanaryLockedError, match="🔒"):
        require_pro("Test Feature")


def test_require_pro_passes_on_pro():
    config.CANARY_PRO = True
    require_pro("Test Feature")  # must not raise


# ---------------------------------------------------------------------------
# check_vault_limit
# ---------------------------------------------------------------------------

def test_limit_not_hit_below_cap():
    config.CANARY_PRO = False
    check_vault_limit(config.FREE_PASSWORD_LIMIT - 1)  # must not raise


def test_limit_hit_at_cap_free():
    config.CANARY_PRO = False
    with pytest.raises(CanaryLockedError, match="50 passwords"):
        check_vault_limit(config.FREE_PASSWORD_LIMIT)


def test_limit_not_enforced_on_pro():
    config.CANARY_PRO = True
    check_vault_limit(config.FREE_PASSWORD_LIMIT)      # must not raise
    check_vault_limit(config.FREE_PASSWORD_LIMIT + 99) # way over cap — still fine


# ---------------------------------------------------------------------------
# activate / deactivate
# ---------------------------------------------------------------------------

def test_activate_enables_pro():
    config.CANARY_PRO = False
    activate()
    assert is_pro() is True


def test_deactivate_disables_pro():
    config.CANARY_PRO = True
    deactivate()
    assert is_pro() is False


def test_activate_then_require_pro_passes():
    config.CANARY_PRO = False
    activate()
    require_pro("Canary Detection")  # must not raise after activation


def test_deactivate_then_require_pro_raises():
    config.CANARY_PRO = True
    deactivate()
    with pytest.raises(CanaryLockedError):
        require_pro("Canary Detection")


def test_toggle_lifts_vault_cap():
    config.CANARY_PRO = False
    with pytest.raises(CanaryLockedError):
        check_vault_limit(config.FREE_PASSWORD_LIMIT)
    activate()
    check_vault_limit(config.FREE_PASSWORD_LIMIT)  # now allowed
