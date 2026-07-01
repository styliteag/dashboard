"""Tests for the served-agent-version parser used by the self-update endpoint."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.agent_hub import routes
from app.auth.deps import require_write


def test_iso_utc_tags_naive_as_utc() -> None:
    # MariaDB returns naive datetimes (still UTC) → must gain a +00:00 offset so
    # the browser doesn't render them as local time.
    naive = datetime(2026, 6, 24, 6, 22, 54)
    assert routes._iso_utc(naive) == "2026-06-24T06:22:54+00:00"


def test_iso_utc_preserves_aware() -> None:
    aware = datetime(2026, 6, 24, 6, 22, 54, tzinfo=UTC)
    assert routes._iso_utc(aware) == "2026-06-24T06:22:54+00:00"


def test_iso_utc_none() -> None:
    assert routes._iso_utc(None) is None


def test_served_agent_version_parses(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "orbit_agent.py").write_text(
        '#!/usr/bin/env python3\n__version__ = "1.2.3"\n\nx = 1\n'
    )
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)
    assert routes._served_agent_version() == "1.2.3"


def test_served_agent_version_single_quotes(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "orbit_agent.py").write_text("__version__ = '0.3.0'\n")
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)
    assert routes._served_agent_version() == "0.3.0"


def test_served_agent_version_missing_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)
    assert routes._served_agent_version() is None


def test_agent_update_params(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import base64
    import hashlib

    src = tmp_path / "orbit_agent.py"
    src.write_text('__version__ = "1.2.3"\nx = 1\n')
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)

    params = routes._agent_update_params()
    assert params is not None
    assert params["version"] == "1.2.3"
    assert params["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    assert base64.b64decode(params["code"]) == src.read_bytes()


def test_agent_update_params_missing_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)
    assert routes._agent_update_params() is None


# --- Same-version push guard (update endpoints) -------------------------------
#
# Overlapping "Update all" runs raced: run B's stale target snapshot pushed the
# served code to an agent that run A had already updated — the agent's
# anti-rollback then refused ("pushed X not newer than X") and the rejection
# stuck as a persistent "update rejected" marker. Both endpoints must re-check
# the LIVE connection's version right before sending.


class FakeAgent:
    def __init__(self, version: str):
        self.agent_version = version
        self.last_update_error: str | None = None
        self.last_update_version: str | None = None
        self.sent: list[tuple[str, dict]] = []

    async def send_command(self, action: str, params: dict | None = None, timeout: float = 30):
        self.sent.append((action, params or {}))
        return {"success": True, "output": f"update staged to {params['version']}, restarting"}


class FakeHub:
    def __init__(self, snapshot: list[dict], agents: dict[int, FakeAgent]):
        self._snapshot = snapshot
        self._agents = agents

    def list_connected(self) -> list[dict]:
        return self._snapshot

    def get(self, instance_id: int) -> FakeAgent | None:
        return self._agents.get(instance_id)


class FakeSession:
    def __init__(self, instance: object | None = None):
        self._instance = instance

    async def get(self, model, pk):
        return self._instance

    async def commit(self) -> None:
        pass


@pytest.fixture
def update_env(monkeypatch: pytest.MonkeyPatch):
    """Patch the module-level collaborators of the update endpoints."""
    params = {"version": "2.4.0", "sha256": "x", "code": "eA==", "signature": ""}
    monkeypatch.setattr(routes, "_agent_update_params", lambda: dict(params))

    async def noop_audit(*args, **kwargs):
        pass

    monkeypatch.setattr(routes, "write_audit", noop_audit)
    monkeypatch.setattr(routes, "client_ip", lambda request: "127.0.0.1")
    return params


def _patch_hub(monkeypatch: pytest.MonkeyPatch, hub: FakeHub) -> None:
    monkeypatch.setattr(routes, "hub", hub)


async def test_update_all_recheck_skips_agent_reconnected_at_served(
    update_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stale snapshot says 2.3.6, but the live connection (post-update reconnect)
    # is already at the served version → must NOT push, must NOT set a marker.
    live = FakeAgent("2.4.0")
    snapshot = [{"instance_id": 1, "instance_name": "opn1", "agent_version": "2.3.6"}]
    _patch_hub(monkeypatch, FakeHub(snapshot, {1: live}))

    result = await routes.update_all_agents(
        request=SimpleNamespace(), session=FakeSession(), user=SimpleNamespace(id=1)
    )

    assert live.sent == []
    assert live.last_update_error is None
    assert result["updated"] == []


async def test_update_all_pushes_outdated_agent(
    update_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = FakeAgent("2.3.6")
    snapshot = [{"instance_id": 1, "instance_name": "opn1", "agent_version": "2.3.6"}]
    _patch_hub(monkeypatch, FakeHub(snapshot, {1: live}))

    result = await routes.update_all_agents(
        request=SimpleNamespace(), session=FakeSession(), user=SimpleNamespace(id=1)
    )

    assert [a for a, _ in live.sent] == ["agent.update"]
    assert live.last_update_error is None
    assert len(result["updated"]) == 1 and result["updated"][0]["result"]["success"]


async def test_update_single_skips_when_agent_current(
    update_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = FakeAgent("2.4.0")
    _patch_hub(monkeypatch, FakeHub([], {1: live}))
    inst = SimpleNamespace(id=1, deleted_at=None)

    result = await routes.update_agent(
        instance_id=1,
        request=SimpleNamespace(),
        session=FakeSession(instance=inst),
        user=SimpleNamespace(id=1),
    )

    assert live.sent == []
    assert live.last_update_error is None
    assert result["sent"] is False
    assert result["result"]["success"] is True
    assert "already" in result["result"]["output"]


async def test_update_single_pushes_when_outdated(
    update_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = FakeAgent("2.3.6")
    _patch_hub(monkeypatch, FakeHub([], {1: live}))
    inst = SimpleNamespace(id=1, deleted_at=None)

    result = await routes.update_agent(
        instance_id=1,
        request=SimpleNamespace(),
        session=FakeSession(instance=inst),
        user=SimpleNamespace(id=1),
    )

    assert [a for a, _ in live.sent] == ["agent.update"]
    assert result["sent"] is True
    assert result["result"]["success"] is True


# --- Trust-boundary gates ------------------------------------------------------
#
# Privileged actions must not be reachable through the generic command passthrough
# (they carry firewall-admin authority or curated params that bind agent.update to
# the container's signed .sig), and the agent token — a bearer credential to the
# agent WebSocket — must not be readable by a read-only session.


@pytest.mark.parametrize(
    "action", ["agent.update", "relay.enable", "http.relay", "agent.uninstall", "gui.login"]
)
async def test_send_command_rejects_internal_actions(action: str) -> None:
    # The denylist is checked before the hub lookup, so no agent needs to be wired.
    with pytest.raises(HTTPException) as exc:
        await routes.send_agent_command(
            instance_id=1,
            body={"action": action, "params": {}},
            request=SimpleNamespace(),
            session=FakeSession(),
            user=SimpleNamespace(id=1),
        )
    assert exc.value.status_code == 400
    assert "internal" in exc.value.detail


def test_get_agent_token_is_write_gated() -> None:
    # Regression guard: the token endpoint must stay require_write, not the looser
    # current_user (which would let a view_only session read the agent bearer token).
    dep = inspect.signature(routes.get_agent_token).parameters["_user"].default
    assert dep.dependency is require_write
