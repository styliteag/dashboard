"""Tests for the metrics maintenance job (raw-metrics retention prune).

DB-free: the AsyncSession factory is stubbed, so we assert the SQL issued and
the retention cutoff without a real MariaDB."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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
async def test_prune_deletes_raw_metrics_with_cutoff(session: _Session) -> None:
    deleted = await jobs.prune_metrics()
    assert deleted == 7
    assert session.committed
    assert len(session.calls) == 1

    (sql_raw, p_raw) = session.calls[0]
    assert "DELETE FROM metrics WHERE ts <" in sql_raw

    now = datetime.now(UTC)
    # raw metrics kept 30 days — cutoff sits in the past, ~30 days back
    assert p_raw["c"] < now
    assert abs((now - p_raw["c"]) - timedelta(days=30)) < timedelta(hours=1)
