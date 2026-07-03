"""Bootstrap-seed lifecycle (admin + superadmin).

Two seed accounts exist, each a temporary break-glass that logs in with a
password only (**no 2FA**) and is retired once a real counterpart exists:

- ``admin`` (from ``DASH_ADMIN_PASSWORD``) — role ``admin``, full dashboard.
- ``superadmin`` (from ``DASH_SUPERADMIN_PASSWORD``) — rights management only
  (``is_superadmin=True``, role ``view_only``, no group memberships → sees no
  instances at all).

Their enabled/disabled state is *derived* on every startup:

- **first start** (no users) → create them, enabled, password-only.
- **another (non-bootstrap) admin/superadmin exists** → auto-disable the seed.
  This is the normal end state: as soon as you have your own 2FA-protected
  account, the seed is off.
- **no other enabled admin/superadmin left** → re-enable the seed and reset its
  password from the env (break-glass back in), unless explicitly retired with
  ``DASH_ADMIN_DISABLED=1`` / ``DASH_SUPERADMIN_DISABLED=1``.

``…_DISABLED=1`` forces a seed off regardless. Seeds are also disabled the
moment a non-bootstrap counterpart is created/promoted (see app.users.routes),
so a restart isn't required. The two seed rows are told apart by their
``is_superadmin`` flag — every bootstrap lookup MUST filter on it.
"""

from __future__ import annotations

import structlog
from sqlalchemy import func, select

from app.auth.roles import ROLE_ADMIN, ROLE_VIEW_ONLY
from app.auth.security import hash_password
from app.config import get_settings
from app.db.base import get_sessionmaker
from app.db.models import User

log = structlog.get_logger("app.auth.bootstrap")


def _resolve_mode(raw: str) -> str:
    """Resolve a *_DISABLED env value to "auto" | "enabled" | "disabled"."""
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return "disabled"
    if v in ("0", "false", "no", "off"):
        return "enabled"
    return "auto"


def admin_mode() -> str:
    return _resolve_mode(get_settings().admin_disabled)


def superadmin_mode() -> str:
    return _resolve_mode(get_settings().superadmin_disabled)


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


async def _other_enabled_superadmins(session, exclude_id: int | None = None) -> int:
    """Count enabled, non-bootstrap superadmins (optionally excluding one id)."""
    stmt = (
        select(func.count())
        .select_from(User)
        .where(
            User.is_superadmin.is_(True),
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
            await session.execute(
                select(User).where(User.is_bootstrap.is_(True), User.is_superadmin.is_(False))
            )
        ).scalar_one_or_none()

        if boot is None:
            await _maybe_create_admin(session, settings)
            return
        await _apply_seed_state(
            session,
            boot,
            mode=admin_mode(),
            supplanted=await _other_enabled_admins(session) > 0,
            env_password=settings.admin_password,
            event="admin_bootstrap",
        )


async def ensure_superadmin() -> None:
    settings = get_settings()
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        boot = (
            await session.execute(
                select(User).where(User.is_bootstrap.is_(True), User.is_superadmin.is_(True))
            )
        ).scalar_one_or_none()

        if boot is None:
            await _maybe_create_superadmin(session, settings)
            return
        await _apply_seed_state(
            session,
            boot,
            mode=superadmin_mode(),
            supplanted=await _other_enabled_superadmins(session) > 0,
            env_password=settings.superadmin_password,
            event="superadmin_bootstrap",
        )


async def _apply_seed_state(
    session, boot: User, *, mode: str, supplanted: bool, env_password: str, event: str
) -> None:
    """Derive and apply the seed's enabled/disabled state from the mode."""
    if mode == "disabled":
        want_disabled = True
    elif mode == "enabled":
        want_disabled = False
    else:  # auto: off once a real counterpart exists, on when none remains
        want_disabled = supplanted

    if want_disabled and not boot.disabled:
        boot.disabled = True
        await session.commit()
        log.info(f"{event}.disabled", username=boot.username, mode=mode)
        return

    if not want_disabled and boot.disabled:
        boot.disabled = False
        if env_password:
            boot.password_hash = hash_password(env_password)
            boot.password_version += 1
        await session.commit()
        log.warning(f"{event}.breakglass", username=boot.username, mode=mode)
        return

    log.info(f"{event}.unchanged", username=boot.username, disabled=boot.disabled)


async def _maybe_create_admin(session, settings) -> None:
    """Create the seed admin on first start, or as Löschschutz when no enabled
    admin remains at all (and it has not been retired via ``DASH_ADMIN_DISABLED=1``)."""
    if not settings.admin_password:
        log.warning("admin_bootstrap.skip", reason="DASH_ADMIN_PASSWORD not set")
        return

    mode = admin_mode()
    total_users = await session.scalar(select(func.count()).select_from(User))
    enabled_admins = await session.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == ROLE_ADMIN, User.disabled.is_(False))
    )
    first_start = total_users == 0
    lockout = enabled_admins == 0 and mode != "disabled"
    if not (first_start or lockout):
        log.info("admin_bootstrap.skip", reason="admin already present")
        return

    disabled = mode == "disabled"
    admin = User(
        username="admin",
        password_hash=hash_password(settings.admin_password),
        password_version=1,
        role=ROLE_ADMIN,
        is_bootstrap=True,
        disabled=disabled,
    )
    session.add(admin)
    await session.commit()
    log.info("admin_bootstrap.created", username="admin", disabled=disabled)


async def _maybe_create_superadmin(session, settings) -> None:
    """Create the seed superadmin when no enabled superadmin exists at all (and
    it has not been retired via ``DASH_SUPERADMIN_DISABLED=1``)."""
    if not settings.superadmin_password:
        log.warning("superadmin_bootstrap.skip", reason="DASH_SUPERADMIN_PASSWORD not set")
        return

    mode = superadmin_mode()
    total_users = await session.scalar(select(func.count()).select_from(User))
    enabled_superadmins = await session.scalar(
        select(func.count())
        .select_from(User)
        .where(User.is_superadmin.is_(True), User.disabled.is_(False))
    )
    first_start = total_users == 0
    lockout = enabled_superadmins == 0 and mode != "disabled"
    if not (first_start or lockout):
        log.info("superadmin_bootstrap.skip", reason="superadmin already present")
        return

    disabled = mode == "disabled"
    superadmin = User(
        username="superadmin",
        password_hash=hash_password(settings.superadmin_password),
        password_version=1,
        role=ROLE_VIEW_ONLY,
        is_bootstrap=True,
        is_superadmin=True,
        disabled=disabled,
    )
    session.add(superadmin)
    await session.commit()
    log.info("superadmin_bootstrap.created", username="superadmin", disabled=disabled)
