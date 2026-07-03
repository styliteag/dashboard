"""Tests for lifecycle routes: agent uninstall + enrollment (§16 chunk C).

Drives the real routes in-process via TestClient with current_user and get_session
overridden and the hub/limiter stubbed, so no MariaDB and no real agent are needed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.agent_hub.routes.enroll as enroll_mod
import app.agent_hub.routes.gui as gui_mod
import app.agent_hub.routes.management as mgmt_mod
import app.agent_hub.routes.relay as relay_mod
import app.main as main_mod
from app.auth.deps import current_user
from app.db.base import get_session


class _Result:
    def __init__(self, val):
        self._val = val

    def scalar_one_or_none(self):
        return self._val


class _FakeSession:
    def __init__(self, instance=None, enroll_row=None):
        self.instance = instance
        self.enroll_row = enroll_row
        self.added: list = []
        self.committed = False

    async def get(self, model, pk):
        return self.instance

    async def execute(self, *a, **k):
        return _Result(self.enroll_row)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True


class _FakeAgent:
    def __init__(self, result):
        self.result = result
        self.calls: list = []

    async def send_command(self, action, params=None, timeout=30):
        self.calls.append((action, params))
        return self.result


class _FakeLimiter:
    def __init__(self, locked=False):
        self.locked = locked
        self.failures = 0
        self.successes = 0

    def is_locked(self, ip):
        return self.locked

    def record_failure(self, ip):
        self.failures += 1

    def record_success(self, ip):
        self.successes += 1


async def _noop(*a, **k):
    return None


def _app(monkeypatch, session, *, agent=None, limiter=None):
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)
    # write_audit is imported per route module — patch every module under test.
    for mod in (enroll_mod, gui_mod, mgmt_mod, relay_mod):
        monkeypatch.setattr(mod, "write_audit", _noop)
    monkeypatch.setattr(enroll_mod.hub, "get", lambda iid: agent)
    monkeypatch.setattr(enroll_mod.hub, "unregister", lambda iid: None)
    monkeypatch.setattr(enroll_mod.hub, "hydrate_from_db", _noop)
    if limiter is not None:
        monkeypatch.setattr(enroll_mod, "limiter", limiter)
    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id=1, role="admin", is_admin=True
    )
    app.dependency_overrides[get_session] = lambda: session
    return app


# --- uninstall ---------------------------------------------------------------


def test_uninstall_503_when_not_connected(monkeypatch):
    inst = SimpleNamespace(id=7, deleted_at=None, transport="push", agent_token="t")
    app = _app(monkeypatch, _FakeSession(instance=inst), agent=None)
    with TestClient(app) as c:
        r = c.post("/api/instances/7/agent/uninstall")
    assert r.status_code == 503


def test_uninstall_success_clears_agent_mode(monkeypatch):
    inst = SimpleNamespace(id=7, deleted_at=None, transport="push", agent_token="t")
    fa = _FakeAgent({"success": True, "output": "uninstall started"})
    app = _app(monkeypatch, _FakeSession(instance=inst), agent=fa)
    with TestClient(app) as c:
        r = c.post("/api/instances/7/agent/uninstall")
    assert r.status_code == 200
    assert fa.calls[0][0] == "agent.uninstall"
    assert inst.agent_token is None
    assert inst.transport == "direct"


# --- gui proxy disabled by default -------------------------------------------


def test_gui_open_404_when_proxy_disabled(monkeypatch):
    # gui_proxy_enabled defaults False -> /gui/open is gated off.
    inst = SimpleNamespace(id=7, deleted_at=None)
    app = _app(monkeypatch, _FakeSession(instance=inst), agent=None)
    with TestClient(app) as c:
        r = c.post("/api/instances/7/gui/open")
    assert r.status_code == 404


# --- gui auto-login (opt-in, §18) --------------------------------------------


def _gui_proxy_on():
    # dev convention (no prod template) → _gui_base_url falls back to the per-port URL
    return SimpleNamespace(gui_proxy_enabled=True, gui_base_template="")


def _gui_open(monkeypatch, inst, agent):
    app = _app(monkeypatch, _FakeSession(instance=inst), agent=agent)
    monkeypatch.setattr(gui_mod, "get_settings", _gui_proxy_on)
    monkeypatch.setattr(gui_mod.gui_tunnels, "ensure", _noop)
    with TestClient(app) as c:
        return c.post("/api/instances/7/gui/open")


def _token_of(resp):
    from urllib.parse import parse_qs, urlsplit

    return parse_qs(urlsplit(resp.json()["url"]).query)["t"][0]


def test_gui_open_replays_login_when_enabled(monkeypatch):
    from app.agent_hub.gui_session import gui_sessions

    inst = SimpleNamespace(id=7, deleted_at=None, gui_login_enabled=True)
    fa = _FakeAgent({"success": True, "cookies": [{"name": "PHPSESSID", "value": "sess-xyz"}]})
    r = _gui_open(monkeypatch, inst, fa)
    assert r.status_code == 200
    assert ("gui.login", {}) in fa.calls
    # the replayed session cookie is stashed under the one-time handoff token
    assert gui_sessions.pop(_token_of(r)) == [("PHPSESSID", "sess-xyz")]


def test_gui_open_skips_login_when_disabled(monkeypatch):
    inst = SimpleNamespace(id=7, deleted_at=None, gui_login_enabled=False)
    fa = _FakeAgent({"success": True, "cookies": []})
    r = _gui_open(monkeypatch, inst, fa)
    assert r.status_code == 200
    assert fa.calls == []  # no gui.login when opt-in is off


def test_gui_open_degrades_when_login_fails(monkeypatch):
    from app.agent_hub.gui_session import gui_sessions

    inst = SimpleNamespace(id=7, deleted_at=None, gui_login_enabled=True)
    fa = _FakeAgent({"success": False, "output": "gui login rejected"})
    r = _gui_open(monkeypatch, inst, fa)
    assert r.status_code == 200  # still opens — just lands on the login page
    assert gui_sessions.pop(_token_of(r)) == []


def test_agent_command_refuses_internal_gui_login(monkeypatch):
    # gui.login returns a live admin cookie — must not run via the generic endpoint
    # (which echoes the result back + into audit). Refused before the agent is hit.
    inst = SimpleNamespace(id=7, deleted_at=None)
    fa = _FakeAgent({"success": True, "cookies": [{"name": "PHPSESSID", "value": "x"}]})
    app = _app(monkeypatch, _FakeSession(instance=inst), agent=fa)
    with TestClient(app) as c:
        r = c.post("/api/instances/7/agent/command", json={"action": "gui.login"})
    assert r.status_code == 400
    assert fa.calls == []  # never reached the agent


def test_redact_audit_masks_credential_keys():
    out = mgmt_mod._redact_audit(
        {"success": True, "cookies": [{"name": "x"}], "secret": "s", "output": "ok"}
    )
    assert out["cookies"] == "<redacted>"
    assert out["secret"] == "<redacted>"
    assert out["success"] is True
    assert out["output"] == "ok"


# --- relay enable ------------------------------------------------------------


def test_relay_enable_503_when_not_connected(monkeypatch):
    inst = SimpleNamespace(id=7, deleted_at=None)
    app = _app(monkeypatch, _FakeSession(instance=inst), agent=None)
    with TestClient(app) as c:
        r = c.post("/api/instances/7/relay/enable")
    assert r.status_code == 503


def test_relay_enable_forwards_command(monkeypatch):
    inst = SimpleNamespace(id=7, deleted_at=None)
    fa = _FakeAgent({"success": True, "output": "relay enabled (pfsense)"})
    app = _app(monkeypatch, _FakeSession(instance=inst), agent=fa)
    with TestClient(app) as c:
        r = c.post("/api/instances/7/relay/enable")
    assert r.status_code == 200
    assert fa.calls[0][0] == "relay.enable"
    assert r.json()["result"]["success"] is True


# --- enroll-code (admin) -----------------------------------------------------


def test_enroll_code_minted_and_persisted(monkeypatch):
    inst = SimpleNamespace(id=7, deleted_at=None)
    sess = _FakeSession(instance=inst)
    app = _app(monkeypatch, sess)
    with TestClient(app) as c:
        r = c.post("/api/instances/7/agent/enroll-code")
    assert r.status_code == 200
    body = r.json()
    assert body["instance_id"] == 7
    assert len(body["code"]) > 10
    assert len(sess.added) == 1  # one EnrollmentCode row added


# --- enroll (public) ---------------------------------------------------------


def _code_row(*, used=False, expired=False, instance_id=7):
    delta = timedelta(hours=-1) if expired else timedelta(hours=1)
    return SimpleNamespace(
        used_at=datetime.now(UTC) if used else None,
        expires_at=datetime.now(UTC) + delta,
        instance_id=instance_id,
    )


def test_enroll_unknown_code_401(monkeypatch):
    app = _app(monkeypatch, _FakeSession(enroll_row=None), limiter=_FakeLimiter())
    with TestClient(app) as c:
        r = c.post("/api/agent/enroll", json={"code": "bad"})
    assert r.status_code == 401


def test_enroll_expired_code_401(monkeypatch):
    app = _app(
        monkeypatch, _FakeSession(enroll_row=_code_row(expired=True)), limiter=_FakeLimiter()
    )
    with TestClient(app) as c:
        r = c.post("/api/agent/enroll", json={"code": "x"})
    assert r.status_code == 401


def test_enroll_used_code_401(monkeypatch):
    app = _app(monkeypatch, _FakeSession(enroll_row=_code_row(used=True)), limiter=_FakeLimiter())
    with TestClient(app) as c:
        r = c.post("/api/agent/enroll", json={"code": "x"})
    assert r.status_code == 401


def test_enroll_valid_returns_token_and_consumes(monkeypatch):
    row = _code_row()
    inst = SimpleNamespace(id=7, deleted_at=None, agent_token=None, transport="direct")
    sess = _FakeSession(instance=inst, enroll_row=row)
    app = _app(monkeypatch, sess, limiter=_FakeLimiter())
    with TestClient(app) as c:
        r = c.post("/api/agent/enroll", json={"code": "good"})
    assert r.status_code == 200
    assert r.json()["agent_token"]  # a token was issued
    assert inst.transport == "push"
    assert row.used_at is not None  # single-use consumed


def test_enroll_reuses_existing_token(monkeypatch):
    row = _code_row()
    inst = SimpleNamespace(id=7, deleted_at=None, agent_token="EXISTING", transport="push")
    app = _app(monkeypatch, _FakeSession(instance=inst, enroll_row=row), limiter=_FakeLimiter())
    with TestClient(app) as c:
        r = c.post("/api/agent/enroll", json={"code": "good"})
    assert r.json()["agent_token"] == "EXISTING"


def test_enroll_rate_limited_429(monkeypatch):
    app = _app(monkeypatch, _FakeSession(), limiter=_FakeLimiter(locked=True))
    with TestClient(app) as c:
        r = c.post("/api/agent/enroll", json={"code": "x"})
    assert r.status_code == 429
