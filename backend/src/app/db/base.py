"""Async SQLAlchemy engine and session factory."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    """Base for all ORM models."""


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _pin_session_utc(dbapi_connection: object, _record: object) -> None:
    """Force every pooled connection's session time zone to UTC.

    ``UtcDateTime`` assumes the DB holds a UTC wall-clock and re-tags naive
    values as UTC on read. But columns defaulted with ``func.now()`` /
    ``CURRENT_TIMESTAMP`` take the *session* time zone, which is the DB server's
    ``SYSTEM`` zone — i.e. the container's ``TZ``. If ``TZ`` is set to anything
    but UTC, those defaults write local wall-clock that then gets mislabelled as
    UTC, so timestamps render offset (a "last seen: in 1h" future on /log).
    Pinning the session to UTC makes ``NOW()`` == ``UTC_TIMESTAMP()`` regardless
    of ``TZ``, keeping every server-default timestamp honest. Do not remove.
    """
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute("SET time_zone = '+00:00'")
    finally:
        cursor.close()


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
        )
        event.listen(_engine.sync_engine, "connect", _pin_session_utc)
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        get_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None
