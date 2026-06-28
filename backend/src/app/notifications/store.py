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
    fresh = {(r.instance_id, r.channel, r.category, r.enabled) for r in rows}
    _routes.clear()
    _routes.update(fresh)
    return len(_routes)


def current_routes() -> set[Route]:
    """A copy of the cached routes (for the routing matrix endpoint)."""
    return set(_routes)


def is_subscribed_live(channel: str, category: str, instance_id: int) -> bool:
    """Whether ``channel`` currently receives ``category`` for ``instance_id`` (cache)."""
    return is_subscribed(channel, category, instance_id, _routes)


def _route_query(channel: str, category: str, instance_id: int | None):  # noqa: ANN202
    """Identity filter for one route. ``instance_id`` NULL needs ``IS NULL`` — a
    ``== None`` predicate never matches in SQL (mirrors ``checkmk`` add_exclusion)."""
    stmt = select(NotificationRoute).where(
        NotificationRoute.channel == channel, NotificationRoute.category == category
    )
    return stmt.where(
        NotificationRoute.instance_id.is_(None)
        if instance_id is None
        else NotificationRoute.instance_id == instance_id
    )


async def set_route(
    session: AsyncSession,
    channel: str,
    category: str,
    instance_id: int | None = None,
    enabled: bool = True,
) -> None:
    """Upsert a route's ``enabled`` state (idempotent). Does NOT touch the cache.

    ``instance_id`` NULL = a global route (all instances); a value scopes it to one.
    ``enabled=False`` is an explicit per-instance off-override (a global route is
    pure presence and should never be written disabled — the API rejects that).
    """
    row = (await session.execute(_route_query(channel, category, instance_id))).scalar_one_or_none()
    if row is None:
        session.add(
            NotificationRoute(
                instance_id=instance_id, channel=channel, category=category, enabled=enabled
            )
        )
        await session.flush()
    elif row.enabled != enabled:
        row.enabled = enabled
        await session.flush()


async def remove_route(
    session: AsyncSession, channel: str, category: str, instance_id: int | None = None
) -> bool:
    """Unsubscribe a channel from a category. Returns True if a row existed."""
    row = (await session.execute(_route_query(channel, category, instance_id))).scalar_one_or_none()
    if row is not None:
        await session.delete(row)
        await session.flush()
    return row is not None
