"""
License gate — Phase 3 stub (activation/deactivation wired in Phase 4).
All Pro feature gates live here so vault.py can import check_vault_limit
without a circular dep.
"""
import config


class CanaryLockedError(Exception):
    pass


def require_pro(feature: str) -> None:
    if not config.CANARY_PRO:
        raise CanaryLockedError(
            f"🔒 {feature} is a Canary Pro feature. Upgrade to unlock."
        )


def check_vault_limit(current_count: int) -> None:
    if not config.CANARY_PRO and current_count >= config.FREE_PASSWORD_LIMIT:
        raise CanaryLockedError(
            f"🔒 Free tier is limited to {config.FREE_PASSWORD_LIMIT} passwords. "
            f"Upgrade to Canary Pro for unlimited storage."
        )
