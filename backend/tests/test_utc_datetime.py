"""UtcDateTime column type: MariaDB DATETIME is naive, so reads must be re-tagged UTC.

Without this, ``DateTime(timezone=True)`` yields naive datetimes on read and API
responses serialize without a ``Z``; clients parse them as local time and show the
wrong hour (observed: pfSense/OPNsense 'Last poll' 2h behind in CEST).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from app.db.types import UtcDateTime


def test_result_value_tags_naive_as_utc() -> None:
    got = UtcDateTime().process_result_value(datetime(2026, 7, 1, 20, 15, 42), None)
    assert got is not None
    assert got.tzinfo is not None
    assert got == datetime(2026, 7, 1, 20, 15, 42, tzinfo=UTC)


def test_result_value_keeps_existing_tz() -> None:
    aware = datetime(2026, 7, 1, 20, 15, 42, tzinfo=UTC)
    assert UtcDateTime().process_result_value(aware, None) == aware


def test_result_value_none_passthrough() -> None:
    assert UtcDateTime().process_result_value(None, None) is None


def test_bind_param_normalizes_aware_to_utc_wall_clock() -> None:
    berlin = timezone(timedelta(hours=2))  # CEST
    aware = datetime(2026, 7, 1, 22, 15, 42, tzinfo=berlin)  # == 20:15:42 UTC
    got = UtcDateTime().process_bind_param(aware, None)
    assert got == datetime(2026, 7, 1, 20, 15, 42)  # stored as naive UTC wall-clock
    assert got is not None and got.tzinfo is None


def test_bind_param_naive_passthrough() -> None:
    naive = datetime(2026, 7, 1, 20, 15, 42)
    assert UtcDateTime().process_bind_param(naive, None) == naive


def test_bind_param_none_passthrough() -> None:
    assert UtcDateTime().process_bind_param(None, None) is None
