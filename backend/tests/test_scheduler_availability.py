"""The scheduler's push-mode stale flip records an availability CRIT event.

Guards the reordered control flow in ``_check_stale_agents``: the availability
event is recorded (same session) only when the guarded UPDATE actually wins
(``rowcount``), before the single commit. Pure-logic with a fake sessionmaker.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import app.poller.scheduler as sched


class _Result:
    def __init__(self, rows=None, rowcount=0):  # noqa: ANN001
        self._rows = rows or []
        self.rowcount = rowcount

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _FakeSession:
    """execute #1 → the instance SELECT; execute #2 → the guarded UPDATE (won)."""

    def __init__(self, rows):  # noqa: ANN001
        self._rows = rows
        self.calls = 0
        self.events: list = []  # order log: ("update"|"record"|"commit")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt):  # noqa: ANN001
        self.calls += 1
        if self.calls == 1:
            return _Result(rows=self._rows)
        self.events.append("update")
        return _Result(rowcount=1)

    async def commit(self):
        self.events.append("commit")


@pytest.mark.asyncio
async def test_stale_flip_records_availability_crit_before_commit(monkeypatch) -> None:
    now = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
    inst = SimpleNamespace(
        id=42,
        name="fw42",
        push_interval_seconds=None,
        agent_last_seen=now - timedelta(hours=1),
        last_success_at=now - timedelta(minutes=5),
        last_error_at=None,
    )
    session = _FakeSession([inst])
    monkeypatch.setattr(sched, "get_sessionmaker", lambda: lambda: session)
    monkeypatch.setattr(
        sched,
        "effective_settings",
        lambda: SimpleNamespace(push_interval_seconds=60, agent_stale_seconds=120),
    )
    monkeypatch.setattr(sched, "stale_threshold", lambda *a: 120)
    monkeypatch.setattr(sched, "is_stale", lambda *a: True)
    monkeypatch.setattr(sched, "is_online", lambda *a: True)
    monkeypatch.setattr(sched, "dispatch_async", lambda *a, **k: None)

    recorded: list = []

    async def _rec(sess, instance_id, ts, *, online, summary):  # noqa: ANN001
        sess.events.append("record")
        recorded.append((instance_id, online, summary))
        return 1

    monkeypatch.setattr(sched, "record_availability_event", _rec)

    await sched._check_stale_agents()

    assert recorded == [(42, False, "agent silent for >120s")]  # CRIT edge persisted
    assert session.events == ["update", "record", "commit"]  # record before commit


@pytest.mark.asyncio
async def test_stale_flip_does_not_record_when_update_loses(monkeypatch) -> None:
    """A fresher push landed (guarded UPDATE rowcount=0) → no availability event."""
    now = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
    inst = SimpleNamespace(
        id=7,
        name="fw7",
        push_interval_seconds=None,
        agent_last_seen=now - timedelta(hours=1),
        last_success_at=now - timedelta(minutes=5),
        last_error_at=None,
    )

    class _LoseSession(_FakeSession):
        async def execute(self, stmt):  # noqa: ANN001
            self.calls += 1
            if self.calls == 1:
                return _Result(rows=self._rows)
            return _Result(rowcount=0)  # someone else won the race

    session = _LoseSession([inst])
    monkeypatch.setattr(sched, "get_sessionmaker", lambda: lambda: session)
    monkeypatch.setattr(
        sched,
        "effective_settings",
        lambda: SimpleNamespace(push_interval_seconds=60, agent_stale_seconds=120),
    )
    monkeypatch.setattr(sched, "stale_threshold", lambda *a: 120)
    monkeypatch.setattr(sched, "is_stale", lambda *a: True)
    monkeypatch.setattr(sched, "is_online", lambda *a: True)
    monkeypatch.setattr(sched, "dispatch_async", lambda *a, **k: None)

    recorded: list = []
    monkeypatch.setattr(
        sched,
        "record_availability_event",
        lambda *a, **k: recorded.append(1),
    )

    await sched._check_stale_agents()
    assert recorded == []  # no flip → no event


@pytest.mark.asyncio
async def test_stale_check_skips_silence_from_backend_downtime(monkeypatch) -> None:
    """Regression 2026-07-12: a 5-min container outage flagged every push
    instance offline on the first tick after restart (agents had no chance to
    reconnect yet) — 140 offline/recovered messages in Mattermost for 70 boxes.
    With ``_started_at`` flooring the silence clock, an agent last seen before
    the restart is NOT stale right after boot: no flip, no event, no dispatch.
    """
    now = datetime.now(UTC)
    inst = SimpleNamespace(
        id=42,
        name="fw42",
        push_interval_seconds=None,
        agent_last_seen=now - timedelta(hours=1),  # silent since before the outage
        last_success_at=now - timedelta(minutes=5),
        last_error_at=None,
    )
    session = _FakeSession([inst])
    monkeypatch.setattr(sched, "get_sessionmaker", lambda: lambda: session)
    monkeypatch.setattr(
        sched,
        "effective_settings",
        lambda: SimpleNamespace(push_interval_seconds=60, agent_stale_seconds=120),
    )
    # Real is_stale + real threshold: the backend "booted" 5 seconds ago.
    monkeypatch.setattr(sched, "_started_at", now - timedelta(seconds=5))
    monkeypatch.setattr(sched, "is_online", lambda *a: True)

    dispatched: list = []
    monkeypatch.setattr(sched, "dispatch_async", lambda *a, **k: dispatched.append(a))
    recorded: list = []
    monkeypatch.setattr(sched, "record_availability_event", lambda *a, **k: recorded.append(1))

    await sched._check_stale_agents()

    assert session.events == []  # no guarded UPDATE, no commit-side effects
    assert recorded == []
    assert dispatched == []
