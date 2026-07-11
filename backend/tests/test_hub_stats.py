"""Tests for hub self-monitoring: counters, push-rate window, /api/hub/stats.

Pure tests drive the HubStats class directly (injected clock); the endpoint
tests call the route function with fake sessions/users, mirroring the other
route tests; the WS tests reuse the in-process TestClient from test_agent_ws.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import app.agent_hub.hub as hub_mod
import app.agent_hub.routes.stats as stats_routes
import app.agent_hub.routes.ws as routes_mod
import app.main as main_mod
from app.agent_hub.hub import hub
from app.agent_hub.stats import KNOWN_COUNTERS, RATE_WINDOW_MINUTES, HubStats, stats
from app.auth.deps import require_admin

NOW = datetime(2026, 7, 5, 12, 30, 45, tzinfo=UTC)


# --- HubStats: counters -------------------------------------------------------


def test_snapshot_has_all_known_counters_at_zero() -> None:
    s = HubStats()
    snap = s.counters_snapshot()
    assert set(snap) == set(KNOWN_COUNTERS)
    assert all(v == 0 for v in snap.values())


def test_record_increments_counter() -> None:
    s = HubStats()
    s.record("auth_failures")
    s.record("auth_failures")
    s.record("json_errors")
    snap = s.counters_snapshot()
    assert snap["auth_failures"] == 2
    assert snap["json_errors"] == 1


def test_record_unknown_counter_rejected() -> None:
    s = HubStats()
    with pytest.raises(KeyError):
        s.record("no_such_counter")


def test_reset_clears_counters_and_rate() -> None:
    s = HubStats()
    s.record_push(now=NOW)
    s.reset(now=NOW)
    assert all(v == 0 for v in s.counters_snapshot().values())
    assert all(p["count"] == 0 for p in s.push_rate(now=NOW))
    assert s.started_at == NOW


# --- HubStats: push-rate window -------------------------------------------------


def test_record_push_counts_in_minute_bucket() -> None:
    s = HubStats()
    s.record_push(now=NOW)
    s.record_push(now=NOW + timedelta(seconds=10))
    s.record_push(now=NOW - timedelta(minutes=1))
    series = s.push_rate(now=NOW)
    assert len(series) == RATE_WINDOW_MINUTES
    assert series[-1]["count"] == 2  # current minute, newest last
    assert series[-2]["count"] == 1
    assert s.counters_snapshot()["pushes"] == 3


def test_push_rate_zero_fills_empty_minutes() -> None:
    s = HubStats()
    s.record_push(now=NOW - timedelta(minutes=5))
    series = s.push_rate(now=NOW)
    assert sum(p["count"] for p in series) == 1
    assert series[-6]["count"] == 1


def test_push_rate_drops_buckets_older_than_window() -> None:
    s = HubStats()
    s.record_push(now=NOW - timedelta(minutes=RATE_WINDOW_MINUTES + 1))
    series = s.push_rate(now=NOW)
    assert sum(p["count"] for p in series) == 0
    # The total counter is monotonic and unaffected by window pruning.
    assert s.counters_snapshot()["pushes"] == 1


def test_push_rate_timestamps_are_utc_minutes() -> None:
    s = HubStats()
    series = s.push_rate(now=NOW)
    assert series[-1]["ts"] == "2026-07-05T12:30:00+00:00"


# --- Endpoint: /api/hub/stats ---------------------------------------------------


class _FakeScalars:
    def __init__(self, values: list[int]) -> None:
        self._values = values

    def scalars(self):
        return iter(self._values)


class _FakeSession:
    """Returns the given instance ids for the visible-instances scope query."""

    def __init__(self, instance_ids: list[int]) -> None:
        self._ids = instance_ids

    async def execute(self, *a, **k):
        return _FakeScalars(self._ids)


class _FakeHub:
    def __init__(self, agents: list[dict]) -> None:
        self._agents = agents

    def list_connected(self) -> list[dict]:
        return self._agents


def _agent_dict(instance_id: int) -> dict:
    return {
        "instance_id": instance_id,
        "instance_name": f"fw{instance_id}",
        "connected_at": "2026-07-05T12:00:00+00:00",
        "agent_version": "2.7.0",
        "platform": "opnsense",
        "last_update_error": None,
        "last_update_version": None,
        "pushes": 12,
        "last_push_at": "2026-07-05T12:30:00+00:00",
    }


def _user(group_ids: set[int]) -> SimpleNamespace:
    return SimpleNamespace(is_admin=True, group_id_set=group_ids)


def test_hub_stats_requires_admin_dependency() -> None:
    dep = inspect.signature(stats_routes.hub_stats).parameters["user"].default
    assert dep.dependency is require_admin


@pytest.mark.asyncio
async def test_hub_stats_filters_agents_by_scope(monkeypatch) -> None:
    monkeypatch.setattr(stats_routes, "hub", _FakeHub([_agent_dict(1), _agent_dict(2)]))
    resp = await stats_routes.hub_stats(session=_FakeSession([1]), user=_user({10}))
    assert [a.instance_id for a in resp.agents] == [1]
    assert resp.connected_agents == 1


@pytest.mark.asyncio
async def test_hub_stats_zero_group_user_sees_no_agents(monkeypatch) -> None:
    monkeypatch.setattr(stats_routes, "hub", _FakeHub([_agent_dict(1)]))
    resp = await stats_routes.hub_stats(session=_FakeSession([]), user=_user(set()))
    assert resp.agents == []
    assert resp.connected_agents == 0


@pytest.mark.asyncio
async def test_hub_stats_response_shape(monkeypatch) -> None:
    monkeypatch.setattr(stats_routes, "hub", _FakeHub([_agent_dict(1)]))
    resp = await stats_routes.hub_stats(session=_FakeSession([1]), user=_user({10}))
    assert set(resp.counters) == set(KNOWN_COUNTERS)
    assert len(resp.push_rate) == RATE_WINDOW_MINUTES
    assert resp.uptime_seconds >= 0
    agent = resp.agents[0]
    assert agent.instance_name == "fw1"
    assert agent.pushes == 12
    assert agent.last_push_at == "2026-07-05T12:30:00+00:00"


# --- WS integration: counters wired into the endpoint ---------------------------
# Mirrors test_agent_ws (stubbed sessionmaker/scheduler, real WS endpoint).


class _FakeResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _FakeWsSession:
    def __init__(self, instance: object) -> None:
        self._instance = instance

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *a, **k):
        return _FakeResult(self._instance)

    async def get(self, model, pk):
        return self._instance

    def add(self, obj):
        pass

    async def commit(self):
        pass


async def _noop(*a, **k):
    return None


def _instance():
    return SimpleNamespace(
        id=7,
        name="fw7",
        device_type="opnsense",
        last_success_at=None,
        last_error_at=None,
        last_error_message=None,
        agent_last_seen=None,
    )


def _patch(monkeypatch, instance) -> None:
    def maker():
        return _FakeWsSession(instance)

    monkeypatch.setattr(routes_mod, "get_sessionmaker", lambda: maker)
    monkeypatch.setattr(hub_mod, "get_sessionmaker", lambda: maker)
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)
    stats.reset()


def test_ws_invalid_token_counts_auth_failure(monkeypatch) -> None:
    from fastapi.testclient import TestClient

    _patch(monkeypatch, None)  # token lookup finds no instance
    with (
        TestClient(main_mod.create_app()) as client,
        client.websocket_connect("/api/ws/agent", headers={"Authorization": "Bearer nope"}) as ws,
    ):
        assert ws.receive_json()["message"] == "invalid token"
    assert stats.counters_snapshot()["auth_failures"] == 1


def test_ws_metrics_push_counts_and_stamps_agent(monkeypatch) -> None:
    from fastapi.testclient import TestClient

    _patch(monkeypatch, _instance())
    with (
        TestClient(main_mod.create_app()) as client,
        client.websocket_connect("/api/ws/agent", headers={"Authorization": "Bearer good"}) as ws,
    ):
        ws.send_json({"type": "hello", "agent_version": "9.9", "platform": "opnsense"})
        assert ws.receive_json()["type"] == "welcome"
        ws.send_json({"type": "metrics", "data": {"system": {}}})
        ws.send_json({"type": "pong"})  # ordering barrier: processed after metrics
        ws.send_json({"type": "pong"})
        agent = hub.get(7)
        assert agent is not None
    snap = stats.counters_snapshot()
    assert snap["pushes"] == 1
    assert snap["connects"] == 1
    assert snap["disconnects"] == 1  # context exit closed the WS
    listed = [a for a in hub.list_connected() if a["instance_id"] == 7]
    assert listed == []  # unregistered after disconnect


def test_ws_non_object_json_keeps_connection(monkeypatch) -> None:
    # Valid JSON that is not an object must count as unknown and NOT tear the
    # connection down (regression: AttributeError on msg.get escaped the loop).
    from fastapi.testclient import TestClient

    _patch(monkeypatch, _instance())
    with (
        TestClient(main_mod.create_app()) as client,
        client.websocket_connect("/api/ws/agent", headers={"Authorization": "Bearer good"}) as ws,
    ):
        ws.send_json({"type": "hello"})
        assert ws.receive_json()["type"] == "welcome"
        ws.send_text("[1, 2]")
        ws.send_json({"type": "pong"})  # would raise if the connection had closed
        assert hub.is_connected(7)
    snap = stats.counters_snapshot()
    assert snap["unknown_messages"] == 1
    assert snap["ws_errors"] == 0


def test_ws_bad_json_counts_json_error(monkeypatch) -> None:
    from fastapi.testclient import TestClient

    _patch(monkeypatch, _instance())
    with (
        TestClient(main_mod.create_app()) as client,
        client.websocket_connect("/api/ws/agent", headers={"Authorization": "Bearer good"}) as ws,
    ):
        ws.send_json({"type": "hello"})
        assert ws.receive_json()["type"] == "welcome"
        ws.send_text("{not json")
        ws.send_json({"type": "pong"})  # keeps the loop alive past the bad frame
    assert stats.counters_snapshot()["json_errors"] == 1


# --- push-handler timing (scaling observability) -------------------------------


def test_push_ms_snapshot_percentiles() -> None:
    s = HubStats()
    assert s.push_ms_snapshot() == {"p50": 0.0, "p95": 0.0, "max": 0.0, "samples": 0}
    for ms in range(1, 101):  # 1..100 ms
        s.record_push_ms(float(ms))
    snap = s.push_ms_snapshot()
    assert snap["samples"] == 100
    assert snap["p50"] == 51.0  # index int(100*0.5) on the sorted list
    assert snap["p95"] == 96.0
    assert snap["max"] == 100.0


def test_push_ms_window_is_bounded_and_reset_clears_it() -> None:
    from app.agent_hub.stats import PUSH_MS_SAMPLES

    s = HubStats()
    for _ in range(PUSH_MS_SAMPLES + 50):
        s.record_push_ms(1.0)
    assert s.push_ms_snapshot()["samples"] == PUSH_MS_SAMPLES
    s.reset()
    assert s.push_ms_snapshot()["samples"] == 0


@pytest.mark.asyncio
async def test_handle_metrics_records_timing_and_flags_slow(monkeypatch) -> None:
    """The wrapper must sample every push and count/log the slow ones —
    this is the 'is the loop stalling right now' signal for scaling."""
    from app.agent_hub.hub import AgentHub

    stats.reset()
    h = AgentHub()

    async def instant(instance_id: int, data: dict) -> None:
        return None

    monkeypatch.setattr(h, "_handle_metrics", instant)
    await h.handle_metrics(1, {})
    assert stats.push_ms_snapshot()["samples"] == 1
    assert stats.counters_snapshot()["slow_pushes"] == 0

    monkeypatch.setattr(hub_mod, "SLOW_PUSH_MS", 0.0)
    await h.handle_metrics(1, {})
    assert stats.counters_snapshot()["slow_pushes"] == 1
    # Timing is recorded even when the handler raises (finally path).
    async def boom(instance_id: int, data: dict) -> None:
        raise RuntimeError("nope")

    monkeypatch.setattr(h, "_handle_metrics", boom)
    with pytest.raises(RuntimeError):
        await h.handle_metrics(1, {})
    assert stats.push_ms_snapshot()["samples"] == 3
    stats.reset()
