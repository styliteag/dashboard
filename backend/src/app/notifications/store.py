"""Process-local cache of notification routes (which channel gets which category).

Mirrors ``app.settings.store``: a single-worker in-memory set, loaded at startup
and re-synced after every change. The hot path (notification dispatch) reads the
cache with no DB round-trip. A write updates the DB; the caller then commits and
calls ``load_routes`` to resync — so a rolled-back commit never desyncs the cache.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import NotificationRoute
from app.notifications.routing import Route, is_subscribed

_routes: set[Route] = set()


async def load_routes(session: AsyncSession) -> int:
    """(Re)load all routes from the DB into the process cache. Returns count."""
    rows = (await session.execute(select(NotificationRoute))).scalars().all()
    fresh = {(r.channel, r.category) for r in rows}
    _routes.clear()
    _routes.update(fresh)
    return len(_routes)


def current_routes() -> set[Route]:
    """A copy of the cached routes (for the routing matrix endpoint)."""
    return set(_routes)


def is_subscribed_live(channel: str, category: str) -> bool:
    """Whether ``channel`` currently receives ``category`` (reads the cache)."""
    return is_subscribed(channel, category, _routes)


async def add_route(session: AsyncSession, channel: str, category: str) -> None:
    """Subscribe a channel to a category (idempotent). Does NOT touch the cache."""
    stmt = select(NotificationRoute).where(
        NotificationRoute.channel == channel, NotificationRoute.category == category
    )
    if (await session.execute(stmt)).scalar_one_or_none() is None:
        session.add(NotificationRoute(channel=channel, category=category))
        await session.flush()


async def remove_route(session: AsyncSession, channel: str, category: str) -> bool:
    """Unsubscribe a channel from a category. Returns True if a row existed."""
    stmt = select(NotificationRoute).where(
        NotificationRoute.channel == channel, NotificationRoute.category == category
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is not None:
        await session.delete(row)
        await session.flush()
    return row is not None
