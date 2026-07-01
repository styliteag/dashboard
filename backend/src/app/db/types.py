"""Custom SQLAlchemy column types."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator):
    """A DateTime that is always timezone-aware UTC in Python.

    MariaDB ``DATETIME`` carries no timezone: aiomysql stores and returns naive
    datetimes, so a plain ``DateTime(timezone=True)`` silently yields naive values
    on read. Those then serialize to JSON without a ``Z`` (e.g.
    ``"2026-07-01T20:15:42"``) and browsers parse them as *local* time — the
    dashboard showed 'Last poll' two hours behind actual in CEST.

    This decorator re-attaches UTC on the way out and normalizes aware inputs to
    UTC on the way in. It does not change what is stored (the DB already holds a
    UTC wall-clock, since the app writes ``datetime.now(UTC)`` and the DB runs in
    UTC), so it is a serialization-only fix — no migration required.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is not None:
            value = value.astimezone(UTC)
        # Persist the same naive UTC wall-clock MariaDB has always held.
        return value.replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
