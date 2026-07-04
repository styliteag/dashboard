"""Global log-events route: mapping, default severity, query validation."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.logs.overview as overview_mod
import app.main as main_mod
from app.auth.deps import current_user
from app.db.base import get_session

_TS = datetime(2026, 7, 4, 12, 0, 0, tzinfo=UTC)


async def _noop(*a: object, **k: object) -> None:
    return None


class _Sess:
    async def commit(self) -> None:
        return None


def _event(sev: int) -> tuple[SimpleNamespace, str]:
    ev = SimpleNamespace(
        instance_id=1,
        log_name="system",
        severity=sev,
        program="syslogd",
        pattern="- sendto: Host is down",
        sample="<11>1 ... syslogd ... sendto: Host is down",
        count=3920,
        last_ts="2026-07-04T11:00:00+02:00",
        updated_at=_TS,
    )
    return ev, "fw-hq"


def _app(monkeypatch, rows: list, captured: dict):
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)

    async def _list(session: object, principal: object, max_severity: int) -> list:
        captured["max_severity"] = max_severity
        return rows

    monkeypatch.setattr(overview_mod, "list_log_events", _list)

    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id=1, role="admin", is_admin=True, is_superadmin=False, group_id_set=frozenset({1})
    )
    app.dependency_overrides[get_session] = lambda: _Sess()
    return app


def test_events_mapped_with_instance_name(monkeypatch):
    captured: dict = {}
    app = _app(monkeypatch, [_event(3)], captured)
    with TestClient(app) as c:
        r = c.get("/api/logs/events")
    assert r.status_code == 200
    body = r.json()
    assert body[0]["instance_name"] == "fw-hq"
    assert body[0]["severity"] == 3
    assert body[0]["count"] == 3920
    # Default severity ceiling is 3 (errors) — sev<=2 is empty on real fleets.
    assert captured["max_severity"] == 3


def test_max_severity_param_passed_through(monkeypatch):
    captured: dict = {}
    app = _app(monkeypatch, [], captured)
    with TestClient(app) as c:
        r = c.get("/api/logs/events?max_severity=4")
    assert r.status_code == 200
    assert captured["max_severity"] == 4


def test_max_severity_validated(monkeypatch):
    app = _app(monkeypatch, [], {})
    with TestClient(app) as c:
        assert c.get("/api/logs/events?max_severity=9").status_code == 422
        assert c.get("/api/logs/events?max_severity=-1").status_code == 422
