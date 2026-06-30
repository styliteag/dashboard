"""Availability event mapping + key-prefix filtering for the check-event store.

DB-free, fake-AsyncSession style (see test_ipsec_history.py): availability is
recorded directly at the scheduler/hub flip sites into the shared check_events
table, and the history reader can narrow to one surface by key prefix.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.checks.event_store import (
    AVAILABILITY_KEY,
    read_check_events,
    record_availability_event,
)
from app.checks.models import CheckState

_TS = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)


class _CaptureInsert:
    """Captures (statement, params) for an INSERT — no DB."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def execute(self, stmt, params=None):  # noqa: ANN001
        self.calls.append((stmt, params))


@pytest.mark.asyncio
async def test_availability_online_maps_to_ok() -> None:
    session = _CaptureInsert()
    n = await record_availability_event(
        session, 7, _TS, online=True, summary="agent resumed pushing metrics"
    )
    assert n == 1
    _, rows = session.calls[0]
    row = rows[0]
    assert row["check_key"] == AVAILABILITY_KEY
    assert row["old_state"] == int(CheckState.CRIT)  # was offline
    assert row["new_state"] == int(CheckState.OK)  # now online
    assert row["summary"] == "agent resumed pushing metrics"


@pytest.mark.asyncio
async def test_availability_offline_maps_to_crit() -> None:
    session = _CaptureInsert()
    await record_availability_event(session, 7, _TS, online=False, summary="agent silent for >120s")
    _, rows = session.calls[0]
    assert rows[0]["old_state"] == int(CheckState.OK)  # was online
    assert rows[0]["new_state"] == int(CheckState.CRIT)  # now offline


class _CaptureSelect:
    """Captures the SELECT statement and returns no rows."""

    def __init__(self) -> None:
        self.stmt = None

    async def execute(self, stmt):  # noqa: ANN001
        self.stmt = stmt
        return _EmptyResult()


class _EmptyResult:
    def scalars(self):
        return self

    def all(self):
        return []


@pytest.mark.asyncio
async def test_read_check_events_applies_key_prefix_filter() -> None:
    session = _CaptureSelect()
    await read_check_events(session, 7, limit=50, key_prefix="connectivity:")
    sql = str(session.stmt.compile())
    assert "LIKE" in sql.upper()  # prefix → a LIKE 'connectivity:%' clause


@pytest.mark.asyncio
async def test_read_check_events_without_prefix_has_no_like() -> None:
    session = _CaptureSelect()
    await read_check_events(session, 7, limit=50)
    sql = str(session.stmt.compile())
    assert "LIKE" not in sql.upper()  # unfiltered → all surfaces
