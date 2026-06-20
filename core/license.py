"""
License gate — gates all Pro features and the free-tier password cap.
activate()/deactivate() mutate config at runtime so the dashboard toggle
takes effect immediately without a restart.
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


def activate() -> None:
    """Flip Pro on at runtime. Called by POST /license/activate. # MOCK — no payment."""
    config.CANARY_PRO = True


def deactivate() -> None:
    """Flip Pro off at runtime. Useful for demo reset."""
    config.CANARY_PRO = False


def is_pro() -> bool:
    return config.CANARY_PRO
