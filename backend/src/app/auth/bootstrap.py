"""Bootstrap-admin lifecycle.

The seed ``admin`` account (created from ``DASH_ADMIN_PASSWORD``) is a temporary
break-glass: it logs in with a password only (**no 2FA**) and is meant to be
retired once a real admin exists. Its enabled/disabled state is *derived* on every
startup, never forced into 2FA:

- **first start** (no users) → create it, enabled, password-only.
- **another (non-bootstrap) admin exists** → auto-disable it. This is the normal
  end state: as soon as you have your own 2FA-protected admin, the seed is off.
- **no other enabled admin left** → re-enable it and reset its password from the
  env (break-glass back in), unless explicitly retired with ``DASH_ADMIN_DISABLED=1``.

``DASH_ADMIN_DISABLED=1`` forces the seed off regardless. The seed is also disabled
the moment a non-bootstrap admin is created/promoted (see app.users.routes), so a
restart isn't required.
"""

from __future__ import annotations

import structlog
from sqlalchemy import func, select

from app.auth.roles import ROLE_ADMIN
from app.auth.security import hash_password
from app.config import get_settings
from app.db.base import get_sessionmaker
from app.db.models import User

log = structlog.get_logger("app.auth.bootstrap")


async def _other_enabled_admins(session, exclude_id: int | None = None) -> int:
    """Count enabled, non-bootstrap admins (optionally excluding one id)."""
    stmt = (
        select(func.count())
        .select_from(User)
        .where(
            User.role == ROLE_ADMIN,
            User.disabled.is_(False),
            User.is_bootstrap.is_(False),
        )
    )
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return await session.scalar(stmt)


async def ensure_admin() -> None:
    settings = get_settings()
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        boot = (
            await session.execute(select(User).where(User.is_bootstrap.is_(True)))
        ).scalar_one_or_none()

        if boot is None:
            await _maybe_create(session, settings)
            return

        # Derive the target state: disabled when retired by env or supplanted by a
        # real admin; enabled (break-glass) when it's the only way back in.
        others = await _other_enabled_admins(session)
        want_disabled = settings.admin_disabled or others > 0

        if want_disabled and not boot.disabled:
            boot.disabled = True
            await session.commit()
            log.info("admin_bootstrap.disabled", username=boot.username, others=others)
            return

        if not want_disabled and boot.disabled:
            boot.disabled = False
            if settings.admin_password:
                boot.password_hash = hash_password(settings.admin_password)
                boot.password_version += 1
            await session.commit()
            log.warning("admin_bootstrap.breakglass", username=boot.username)
            return

        log.info("admin_bootstrap.unchanged", username=boot.username, disabled=boot.disabled)


async def _maybe_create(session, settings) -> None:
    """Create the seed admin on first start, or as Löschschutz when no enabled
    admin remains at all (and it has not been retired via ``DASH_ADMIN_DISABLED=1``)."""
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
    lockout = enabled_admins == 0 and not settings.admin_disabled
    if not (first_start or lockout):
        log.info("admin_bootstrap.skip", reason="admin already present")
        return

    admin = User(
        username="admin",
        password_hash=hash_password(settings.admin_password),
        password_version=1,
        role=ROLE_ADMIN,
        is_bootstrap=True,
        disabled=settings.admin_disabled,
    )
    session.add(admin)
    await session.commit()
    log.info("admin_bootstrap.created", username="admin", disabled=settings.admin_disabled)
