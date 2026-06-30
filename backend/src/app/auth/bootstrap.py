"""Bootstrap-admin lifecycle, driven by ``DASH_ADMIN_DISABLED`` (US-1.1 + 2FA).

The seed ``admin`` account (created from ``DASH_ADMIN_PASSWORD``) is the operator's
way in and the break-glass for a 2FA lockout. Its state is reconciled on every
startup against ``DASH_ADMIN_DISABLED``:

- **first start** (no users) → create it, enabled, forced to enroll 2FA on login.
- **=1, currently enabled** → retire it (the operator now has their own admin).
- **=0, currently disabled** → break-glass: re-enable, reset the password from the
  env, wipe its 2FA so the operator can log back in and re-enroll.
- **=0, currently enabled** → no-op (a normal restart never wipes enrolled 2FA).
- **row missing + no enabled admin left** → recreate it (so there is always a way
  back in), unless retired via ``=1``.
"""

from __future__ import annotations

import structlog
from sqlalchemy import delete, func, select

from app.auth.roles import ROLE_ADMIN
from app.auth.security import hash_password
from app.config import get_settings
from app.db.base import get_sessionmaker
from app.db.models import User, WebauthnCredential

log = structlog.get_logger("app.auth.bootstrap")


async def _clear_factors(session, user: User) -> None:
    user.totp_enabled = False
    user.totp_secret_enc = None
    await session.execute(delete(WebauthnCredential).where(WebauthnCredential.user_id == user.id))


async def ensure_admin() -> None:
    settings = get_settings()
    want_disabled = settings.admin_disabled
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        boot = (
            await session.execute(select(User).where(User.is_bootstrap.is_(True)))
        ).scalar_one_or_none()

        if boot is None:
            await _maybe_create(session, settings, want_disabled)
            return

        if want_disabled and not boot.disabled:
            boot.disabled = True
            await session.commit()
            log.info("admin_bootstrap.retired", username=boot.username)
            return

        if not want_disabled and boot.disabled:
            boot.disabled = False
            if settings.admin_password:
                boot.password_hash = hash_password(settings.admin_password)
                boot.password_version += 1
            await _clear_factors(session, boot)
            await session.commit()
            log.warning("admin_bootstrap.breakglass", username=boot.username)
            return

        log.info("admin_bootstrap.unchanged", username=boot.username, disabled=boot.disabled)


async def _maybe_create(session, settings, want_disabled: bool) -> None:
    """Create the bootstrap admin on first start, or as Löschschutz when no
    enabled admin remains and it has not been retired via ``DASH_ADMIN_DISABLED=1``."""
    if not settings.admin_password:
        log.warning("admin_bootstrap.skip", reason="DASH_ADMIN_PASSWORD not set")
        return

    total_users = await session.scalar(select(func.count()).select_from(User))
    enabled_admins = await session.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == ROLE_ADMIN, User.disabled.is_(False))
    )
    first_start = total_users == 0
    lockout = enabled_admins == 0 and not want_disabled
    if not (first_start or lockout):
        log.info("admin_bootstrap.skip", reason="admin already present")
        return

    admin = User(
        username="admin",
        password_hash=hash_password(settings.admin_password),
        password_version=1,
        role=ROLE_ADMIN,
        is_bootstrap=True,
        disabled=want_disabled,
    )
    session.add(admin)
    await session.commit()
    log.info("admin_bootstrap.created", username="admin", disabled=want_disabled)
