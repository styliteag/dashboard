"""Background logfile-ingest queue (hub) — the prod slow_push fix.

Hourly MEDIUMTEXT ingests moved off the push path into a bounded queue with
one serial writer; these pin the enqueue/consume/drop semantics. DB-free.
"""

from __future__ import annotations

import asyncio

import pytest

import app.agent_hub.hub as hub_mod
from app.agent_hub.hub import AgentHub

_RAW = [{"name": "system", "content": "x"}]


@pytest.mark.asyncio
async def test_enqueued_logfiles_are_written_with_own_session(monkeypatch) -> None:
    written: list = []
    commits: list = []

    async def fake_record(session, instance_id, raw):
        written.append((instance_id, raw))
        return len(raw)

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def commit(self):
            commits.append(1)

    monkeypatch.setattr(hub_mod, "record_logfiles", fake_record)
    monkeypatch.setattr(hub_mod, "get_sessionmaker", lambda: lambda: _FakeSession())
    h = AgentHub()
    h._enqueue_logfiles(7, _RAW)
    for _ in range(20):
        await asyncio.sleep(0)
        if written:
            break
    assert written == [(7, _RAW)]
    assert commits  # own transaction — no longer rides the push commit
    h._log_worker.cancel()


@pytest.mark.asyncio
async def test_full_queue_drops_instead_of_buffering(monkeypatch) -> None:
    """Bounded on purpose: a synchronized fleet must not buffer ~1 MB per box
    in memory; a dropped snapshot is replaced on the next hourly push."""
    h = AgentHub()
    h._log_queue = asyncio.Queue(maxsize=1)
    # Pin a fake never-done worker so enqueue doesn't start a consumer.
    h._log_worker = asyncio.get_event_loop().create_task(asyncio.sleep(3600))
    h._enqueue_logfiles(1, _RAW)
    h._enqueue_logfiles(2, _RAW)  # queue full — must warn + drop, not raise
    assert h._log_queue.qsize() == 1
    h._log_worker.cancel()


@pytest.mark.asyncio
async def test_worker_survives_a_failing_ingest(monkeypatch) -> None:
    calls: list = []

    async def flaky_record(session, instance_id, raw):
        calls.append(instance_id)
        if instance_id == 1:
            raise RuntimeError("db hiccup")

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def commit(self):
            pass

    monkeypatch.setattr(hub_mod, "record_logfiles", flaky_record)
    monkeypatch.setattr(hub_mod, "get_sessionmaker", lambda: lambda: _FakeSession())
    h = AgentHub()
    h._enqueue_logfiles(1, _RAW)
    h._enqueue_logfiles(2, _RAW)
    for _ in range(30):
        await asyncio.sleep(0)
        if len(calls) == 2:
            break
    assert calls == [1, 2]  # the failed item didn't kill the worker
    h._log_worker.cancel()
