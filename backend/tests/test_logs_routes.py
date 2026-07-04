"""Log-snapshot read routes: metadata list (with id) + raw content endpoint.

Drives the real routes in-process via TestClient with the instance fetch and
the store functions monkeypatched — no MariaDB needed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.logs.routes as logs_mod
import app.main as main_mod
from app.auth.deps import current_user
from app.db.base import get_session

_TS = datetime(2026, 7, 4, 12, 0, 0, tzinfo=UTC)


async def _noop(*a: object, **k: object) -> None:
    return None


class _Sess:
    async def commit(self) -> None:
        return None


def _row(rid: int, name: str, content: str = "") -> SimpleNamespace:
    return SimpleNamespace(id=rid, name=name, collected_at=_TS, bytes=len(content), content=content)


def _app(monkeypatch, *, instance: object | None, rows: list, content_row: object | None):
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)

    async def _get_instance(session: object, iid: int, principal: object = None) -> object | None:
        return instance

    async def _list(session: object, iid: int) -> list:
        return rows

    async def _get_logfile(session: object, iid: int, lid: int) -> object | None:
        return content_row

    monkeypatch.setattr(logs_mod, "get_instance", _get_instance)
    monkeypatch.setattr(logs_mod, "list_logfiles", _list)
    monkeypatch.setattr(logs_mod, "get_logfile", _get_logfile)

    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id=1, role="admin", is_admin=True, is_superadmin=False, group_id_set=frozenset({1})
    )
    app.dependency_overrides[get_session] = lambda: _Sess()
    return app


def _instance() -> SimpleNamespace:
    return SimpleNamespace(id=1, deleted_at=None, group_id=1)


def test_list_includes_id(monkeypatch):
    app = _app(monkeypatch, instance=_instance(), rows=[_row(7, "system", "abc")], content_row=None)
    with TestClient(app) as c:
        r = c.get("/api/instances/1/logs")
    assert r.status_code == 200
    body = r.json()
    assert body[0]["id"] == 7
    assert body[0]["name"] == "system"
    assert body[0]["bytes"] == 3


def test_content_returns_raw_text(monkeypatch):
    row = _row(7, "system", "Jul  4 12:00:00 fw kernel: line1\nline2")
    app = _app(monkeypatch, instance=_instance(), rows=[], content_row=row)
    with TestClient(app) as c:
        r = c.get("/api/instances/1/logs/7/content")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "system"
    assert body["content"].endswith("line2")


def test_content_404_when_log_missing(monkeypatch):
    app = _app(monkeypatch, instance=_instance(), rows=[], content_row=None)
    with TestClient(app) as c:
        r = c.get("/api/instances/1/logs/99/content")
    assert r.status_code == 404


def test_content_404_when_instance_missing(monkeypatch):
    app = _app(monkeypatch, instance=None, rows=[], content_row=_row(7, "system", "x"))
    with TestClient(app) as c:
        r = c.get("/api/instances/1/logs/7/content")
    assert r.status_code == 404
