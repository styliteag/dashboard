"""FastAPI dependencies: current user from session cookie."""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dev_token import read_dev_token
from app.config import get_settings
from app.db.base import get_session
from app.db.models import User


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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="session invalidated"
        )
    return user
