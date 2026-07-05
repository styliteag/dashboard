"""Config-backup read routes: version list, diff, download.

Drives the real routes in-process via TestClient with the instance fetch and
the store functions monkeypatched — no MariaDB needed (test_logs_routes.py
pattern).
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.configbackup.routes as cb_mod
import app.main as main_mod
from app.auth.deps import current_user
from app.db.base import get_session

_TS = datetime(2026, 7, 4, 12, 0, 0, tzinfo=UTC)


async def _noop(*a: object, **k: object) -> None:
    return None


class _Sess:
    async def commit(self) -> None:
        return None


def _row(rid: int, text: str = "<x/>\n") -> SimpleNamespace:
    return SimpleNamespace(
        id=rid,
        instance_id=1,
        collected_at=_TS,
        sha256="ab" * 32,
        bytes=len(text),
        source="agent",
        _text=text,
    )


def _app(monkeypatch, *, instance: object | None, rows: list, by_id: dict | None = None):
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)

    async def _get_instance(session: object, iid: int, principal: object = None) -> object | None:
        return instance

    async def _list(session: object, iid: int) -> list:
        return rows

    async def _get_backup(session: object, iid: int, bid: int) -> object | None:
        return (by_id or {}).get(bid)

    monkeypatch.setattr(cb_mod, "get_instance", _get_instance)
    monkeypatch.setattr(cb_mod, "list_config_backups", _list)
    monkeypatch.setattr(cb_mod, "get_config_backup", _get_backup)
    monkeypatch.setattr(cb_mod, "config_text", lambda row: row._text)
    monkeypatch.setattr(cb_mod, "write_audit", _noop)

    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id=1, role="user", is_admin=False, is_superadmin=False, group_id_set=frozenset({1})
    )
    app.dependency_overrides[get_session] = lambda: _Sess()
    return app


def _instance() -> SimpleNamespace:
    return SimpleNamespace(id=1, name="fw1", deleted_at=None, group_id=1)


def test_list_versions(monkeypatch):
    app = _app(monkeypatch, instance=_instance(), rows=[_row(7)])
    with TestClient(app) as c:
        r = c.get("/api/instances/1/config-backups")
    assert r.status_code == 200
    body = r.json()
    assert body[0]["id"] == 7
    assert body[0]["sha256"] == "ab" * 32
    assert body[0]["bytes"] == 5


def test_list_404_when_instance_missing(monkeypatch):
    app = _app(monkeypatch, instance=None, rows=[])
    with TestClient(app) as c:
        r = c.get("/api/instances/1/config-backups")
    assert r.status_code == 404


def test_download_returns_xml_attachment(monkeypatch):
    row = _row(7, "<opnsense>cfg</opnsense>\n")
    app = _app(monkeypatch, instance=_instance(), rows=[], by_id={7: row})
    with TestClient(app) as c:
        r = c.get("/api/instances/1/config-backups/7/download")
    assert r.status_code == 200
    assert r.text == "<opnsense>cfg</opnsense>\n"
    assert "attachment" in r.headers["content-disposition"]
    assert "fw1" in r.headers["content-disposition"]


def test_download_404_when_backup_missing(monkeypatch):
    app = _app(monkeypatch, instance=_instance(), rows=[], by_id={})
    with TestClient(app) as c:
        r = c.get("/api/instances/1/config-backups/99/download")
    assert r.status_code == 404


def test_diff_between_two_versions(monkeypatch):
    a = _row(1, "<x>\n<host>fw1</host>\n</x>\n")
    b = _row(2, "<x>\n<host>fw2</host>\n</x>\n")
    app = _app(monkeypatch, instance=_instance(), rows=[], by_id={1: a, 2: b})
    with TestClient(app) as c:
        r = c.get("/api/instances/1/config-backups/diff", params={"from_id": 1, "to_id": 2})
    assert r.status_code == 200
    body = r.json()
    assert "-<host>fw1</host>" in body["diff"]
    assert "+<host>fw2</host>" in body["diff"]
    assert body["truncated"] is False


def test_download_filename_sanitizes_instance_name(monkeypatch):
    row = _row(7)
    app = _app(monkeypatch, instance=_instance(), rows=[], by_id={7: row})
    app_inst = _instance()
    app_inst.name = 'evil"\r\nX-Injected: 1'

    async def _get_instance(session: object, iid: int, principal: object = None) -> object:
        return app_inst

    monkeypatch.setattr(cb_mod, "get_instance", _get_instance)
    with TestClient(app) as c:
        r = c.get("/api/instances/1/config-backups/7/download")
    assert r.status_code == 200
    cd = r.headers["content-disposition"]
    assert "\r" not in cd and "\n" not in cd and '"' not in cd.replace('"', "", 2)
    assert "evil" in cd


def test_diff_404_when_either_missing(monkeypatch):
    a = _row(1)
    app = _app(monkeypatch, instance=_instance(), rows=[], by_id={1: a})
    with TestClient(app) as c:
        r = c.get("/api/instances/1/config-backups/diff", params={"from_id": 1, "to_id": 2})
    assert r.status_code == 404
