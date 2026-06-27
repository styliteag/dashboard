"""FastAPI dependencies: current user from session cookie / API key."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.apikey import API_KEY_PREFIX, hash_key
from app.auth.dev_token import read_dev_token
from app.config import get_settings
from app.db.base import get_session
from app.db.models import ApiKey, User


async def current_user(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> User:
    sess = request.session
    user_id = sess.get("user_id")
    pwv = sess.get("password_version")
    if (not user_id or pwv is None) and get_settings().env == "dev":
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token_data = read_dev_token(auth[7:].strip())
            if token_data is not None:
                user_id, pwv = token_data

    if not user_id or pwv is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")

    user = await session.get(User, user_id)
    if user is None or user.password_version != pwv:
        # Either deleted, or password was changed elsewhere -> all sessions invalidated.
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session invalidated")
    return user


async def require_admin(
    user: Annotated[User, Depends(current_user)],
) -> User:
    """Like ``current_user`` but also requires the ``is_admin`` flag.

    Guards admin-only surfaces (Settings: API keys, Checkmk export config). Today
    the only seeded user is admin; this keeps the door shut for future non-admin
    accounts.
    """
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    return user


async def read_principal(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> User | ApiKey:
    """Auth for read-only endpoints: a logged-in user OR a valid API key.

    API keys (``orbit_…`` bearer) are read-only — rejected on non-GET methods —
    so service accounts (e.g. the Checkmk special agent) read without a session
    and can't mutate anything.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token.startswith(API_KEY_PREFIX):
            key = (
                await session.execute(
                    select(ApiKey).where(
                        ApiKey.key_hash == hash_key(token),
                        ApiKey.revoked_at.is_(None),
                    )
                )
            ).scalar_one_or_none()
            if key is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key"
                )
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="API key is read-only"
                )
            key.last_used_at = datetime.now(UTC)
            await session.commit()
            return key
    return await current_user(request, session)
