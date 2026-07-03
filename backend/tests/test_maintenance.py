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
    def __init__(self, rowcounts: list[int]) -> None:
        self.rowcounts = list(rowcounts)
        self.calls: list[tuple[str, dict | None]] = []
        self.commits = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt, params=None):
        self.calls.append((str(stmt), params))
        return _Result(self.rowcounts.pop(0))

    async def commit(self):
        self.commits += 1


def _install(monkeypatch: pytest.MonkeyPatch, rowcounts: list[int]) -> _Session:
    s = _Session(rowcounts)
    monkeypatch.setattr(jobs, "get_sessionmaker", lambda: lambda: s)
    monkeypatch.setattr(jobs, "_DELETE_BATCH_SIZE", 3)
    monkeypatch.setattr(jobs, "_BATCH_PAUSE_SECONDS", 0)
    return s


@pytest.mark.asyncio
async def test_prune_deletes_raw_metrics_with_cutoff(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _install(monkeypatch, rowcounts=[2])
    deleted = await jobs.prune_metrics()
    assert deleted == 2
    assert session.commits == 1
    assert len(session.calls) == 1

    (sql_raw, p_raw) = session.calls[0]
    assert "DELETE FROM metrics WHERE ts <" in sql_raw
    assert "LIMIT" in sql_raw
    assert p_raw["n"] == 3

    now = datetime.now(UTC)
    # raw metrics kept 30 days — cutoff sits in the past, ~30 days back
    assert p_raw["c"] < now
    assert abs((now - p_raw["c"]) - timedelta(days=30)) < timedelta(hours=1)


@pytest.mark.asyncio
async def test_prune_metrics_batches_until_below_batch_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Two full batches (3 rows each) then a short one — loop must stop after it.
    session = _install(monkeypatch, rowcounts=[3, 3, 1])
    deleted = await jobs.prune_metrics()
    assert deleted == 7
    assert len(session.calls) == 3
    # One commit per batch, so row locks are released between batches and
    # concurrent metric INSERTs get a window (pool-exhaustion incident).
    assert session.commits == 3


@pytest.mark.asyncio
async def test_prune_metrics_full_last_batch_needs_final_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Row count divides evenly by batch size: a final zero-row probe ends the loop.
    session = _install(monkeypatch, rowcounts=[3, 3, 0])
    deleted = await jobs.prune_metrics()
    assert deleted == 6
    assert len(session.calls) == 3


@pytest.mark.asyncio
async def test_prune_event_tables_are_batched_too(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _install(monkeypatch, rowcounts=[1])
    deleted = await jobs.prune_ipsec_events()
    assert deleted == 1
    (sql, params) = session.calls[0]
    assert "DELETE FROM ipsec_tunnel_events WHERE ts <" in sql
    assert "LIMIT" in sql

    session2 = _install(monkeypatch, rowcounts=[1])
    deleted = await jobs.prune_check_events()
    assert deleted == 1
    (sql, params) = session2.calls[0]
    assert "DELETE FROM check_events WHERE ts <" in sql
    assert "LIMIT" in sql
    assert params["n"] == 3
