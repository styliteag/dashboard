"""First-start admin bootstrap (US-1.1).

If no user exists in the database and ``DASH_ADMIN_PASSWORD`` is set, create
the initial admin. Once an admin exists, the env var is ignored on subsequent
starts — passwords can only be rotated through the API.
"""
from __future__ import annotations

import structlog
from sqlalchemy import select

from app.auth.security import hash_password
from app.config import get_settings
from app.db.base import get_sessionmaker
from app.db.models import User

log = structlog.get_logger("app.auth.bootstrap")


async def ensure_admin() -> None:
    settings = get_settings()
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        existing = (await session.execute(select(User).limit(1))).scalar_one_or_none()
        if existing is not None:
            log.info("admin_bootstrap.skip", reason="user_exists")
            return
        if not settings.admin_password:
            log.warning(
                "admin_bootstrap.skip",
                reason="DASH_ADMIN_PASSWORD not set; no admin will be created",
            )
            return
        admin = User(
            username="admin",
            password_hash=hash_password(settings.admin_password),
            password_version=1,
            is_admin=True,
        )
        session.add(admin)
        await session.commit()
        log.info("admin_bootstrap.created", username="admin")
