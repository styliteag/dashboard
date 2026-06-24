"""Tests for the metrics maintenance jobs (rollup + retention).

DB-free: the AsyncSession factory is stubbed, so we assert the SQL issued and
the retention cutoffs without a real MariaDB."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import app.maintenance.jobs as jobs


class _Result:
    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount


class _Session:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []
        self.committed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt, params=None):
        self.calls.append((str(stmt), params))
        return _Result(7)

    async def commit(self):
        self.committed = True


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> _Session:
    s = _Session()
    monkeypatch.setattr(jobs, "get_sessionmaker", lambda: lambda: s)
    return s


@pytest.mark.asyncio
async def test_rollup_upserts_into_metrics_5m(session: _Session) -> None:
    rows = await jobs.rollup_5m()
    assert rows == 7
    assert session.committed
    sql = session.calls[0][0]
    assert "INSERT INTO metrics_5m" in sql
    assert "ON DUPLICATE KEY UPDATE" in sql
    assert "AVG(value)" in sql


@pytest.mark.asyncio
async def test_prune_deletes_both_tables_with_cutoffs(session: _Session) -> None:
    raw, agg = await jobs.prune_metrics()
    assert (raw, agg) == (7, 7)
    assert session.committed
    assert len(session.calls) == 2

    (sql_raw, p_raw), (sql_agg, p_agg) = session.calls
    assert "DELETE FROM metrics WHERE ts <" in sql_raw
    assert "DELETE FROM metrics_5m WHERE bucket <" in sql_agg

    now = datetime.now(timezone.utc)
    # raw kept 30 days, agg 365 — cutoffs in the past, raw newer than agg
    assert p_raw["c"] < now and p_agg["c"] < now
    assert p_raw["c"] > p_agg["c"]
    assert abs((now - p_raw["c"]) - timedelta(days=30)) < timedelta(hours=1)
    assert abs((now - p_agg["c"]) - timedelta(days=365)) < timedelta(hours=1)
