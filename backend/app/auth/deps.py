"""FastAPI dependencies: current user from session cookie."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_session
from app.db.models import User


async def current_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User:
    sess = request.session
    user_id = sess.get("user_id")
    pwv = sess.get("password_version")
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
