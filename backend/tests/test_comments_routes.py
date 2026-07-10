"""Entity-comment routes: scoped reads, upsert/delete semantics, audit ordering.

DB-free house style: store + instance service monkeypatched, TestClient drives the
real app. The out-of-scope negatives (404 on by-id, dropped rows on the overview)
are the mandatory scope tests for a new instance-data endpoint.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.comments.routes as comments_mod
import app.main as main_mod
from app.auth.deps import current_user, require_write
from app.db.base import get_session

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)


def _row(instance_id: int = 1, kind: str = "ipsec", key: str = "con1", text: str = "wichtig"):
    return SimpleNamespace(
        instance_id=instance_id,
        kind=kind,
        entity_key=key,
        comment=text,
        updated_by="wb",
        updated_at=_NOW,
    )


async def _noop(*a: object, **k: object) -> None:
    return None


class _Sess:
    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


def _user() -> SimpleNamespace:
    return SimpleNamespace(
        id=1,
        username="wb",
        role="admin",
        is_admin=True,
        is_superadmin=False,
        group_id_set=frozenset({1}),
    )


def _app(monkeypatch, *, inst: object) -> object:
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)

    async def _get_instance(session: object, iid: int, principal: object = None) -> object:
        return inst

    monkeypatch.setattr(comments_mod.inst_service, "get_instance", _get_instance)
    app = main_mod.create_app()
    app.dependency_overrides[current_user] = _user
    app.dependency_overrides[require_write] = _user
    app.dependency_overrides[get_session] = lambda: _Sess()
    return app


def _audit_recorder(monkeypatch) -> list[dict]:
    calls: list[dict] = []

    async def _record(session: object, **kw: object) -> None:
        calls.append(kw)

    monkeypatch.setattr(comments_mod, "write_audit", _record)
    return calls


# --- GET /instances/{id}/comments --------------------------------------------


def test_instance_comments_lists_rows(monkeypatch) -> None:
    async def _list(session: object, iid: int) -> list:
        return [_row(), _row(kind="cert", key="ref1", text="expires soon")]

    monkeypatch.setattr(comments_mod.store, "list_for_instance", _list)
    app = _app(monkeypatch, inst=SimpleNamespace(id=1))
    with TestClient(app) as c:
        r = c.get("/api/instances/1/comments")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    assert body[0]["comment"] == "wichtig"
    assert body[0]["updated_by"] == "wb"
    assert body[0]["updated_at"].endswith("+00:00")  # naive-but-UTC gets tagged


def test_instance_comments_out_of_scope_404(monkeypatch) -> None:
    # Out-of-scope/missing instance → 404, never 403 (no existence oracle).
    app = _app(monkeypatch, inst=None)
    with TestClient(app) as c:
        r = c.get("/api/instances/1/comments")
    assert r.status_code == 404


# --- PUT /instances/{id}/comments ---------------------------------------------


def test_set_comment_upserts_and_audits_before_commit(monkeypatch) -> None:
    calls: list[tuple] = []

    async def _upsert(session, iid, kind, key, text, username):  # noqa: ANN001
        calls.append((iid, kind, key, text, username))
        return _row(iid, kind, key, text)

    monkeypatch.setattr(comments_mod.store, "upsert", _upsert)
    audits = _audit_recorder(monkeypatch)
    app = _app(monkeypatch, inst=SimpleNamespace(id=1))
    with TestClient(app) as c:
        r = c.put(
            "/api/instances/1/comments",
            json={"kind": "ipsec", "entity_key": "con1", "comment": "  primary uplink  "},
        )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert calls == [(1, "ipsec", "con1", "primary uplink", "wb")]  # stripped
    assert audits[0]["action"] == "comment.set"
    assert audits[0]["detail"]["comment"] == "primary uplink"


def test_set_comment_empty_deletes(monkeypatch) -> None:
    removed: list[tuple] = []

    async def _remove(session, iid, kind, key):  # noqa: ANN001
        removed.append((iid, kind, key))
        return True

    monkeypatch.setattr(comments_mod.store, "remove", _remove)
    audits = _audit_recorder(monkeypatch)
    app = _app(monkeypatch, inst=SimpleNamespace(id=1))
    with TestClient(app) as c:
        r = c.put(
            "/api/instances/1/comments",
            json={"kind": "cert", "entity_key": "ref1", "comment": "   "},
        )
    assert r.status_code == 200
    assert removed == [(1, "cert", "ref1")]
    assert audits[0]["action"] == "comment.delete"


def test_delete_of_absent_comment_is_silent_noop(monkeypatch) -> None:
    async def _remove(session, iid, kind, key):  # noqa: ANN001
        return False

    monkeypatch.setattr(comments_mod.store, "remove", _remove)
    audits = _audit_recorder(monkeypatch)
    app = _app(monkeypatch, inst=SimpleNamespace(id=1))
    with TestClient(app) as c:
        r = c.put(
            "/api/instances/1/comments",
            json={"kind": "firmware", "entity_key": "", "comment": ""},
        )
    assert r.status_code == 200
    assert audits == []  # nothing happened, nothing audited


def test_set_comment_out_of_scope_404(monkeypatch) -> None:
    app = _app(monkeypatch, inst=None)
    with TestClient(app) as c:
        r = c.put(
            "/api/instances/1/comments",
            json={"kind": "ipsec", "entity_key": "con1", "comment": "x"},
        )
    assert r.status_code == 404


def test_set_comment_rejects_unknown_kind(monkeypatch) -> None:
    app = _app(monkeypatch, inst=SimpleNamespace(id=1))
    with TestClient(app) as c:
        r = c.put(
            "/api/instances/1/comments",
            json={"kind": "instance", "entity_key": "", "comment": "x"},
        )
    assert r.status_code == 422  # instance notes live on Instance.notes, not here


# --- GET /comments (overview) --------------------------------------------------


def test_overview_drops_out_of_scope_rows(monkeypatch) -> None:
    # Caller sees instance 1 only; instance 2's comment must not leak.
    async def _list_instances(session: object, principal: object = None) -> list:
        return [SimpleNamespace(id=1)]

    async def _list_all(session: object, kind: str | None = None) -> list:
        return [_row(1), _row(2, text="other tenant")]

    monkeypatch.setattr(comments_mod.inst_service, "list_instances", _list_instances)
    monkeypatch.setattr(comments_mod.store, "list_all", _list_all)
    app = _app(monkeypatch, inst=SimpleNamespace(id=1))
    with TestClient(app) as c:
        r = c.get("/api/comments?kind=ipsec")
    assert r.status_code == 200
    body = r.json()
    assert [x["instance_id"] for x in body] == [1]


def test_overview_zero_group_user_sees_nothing(monkeypatch) -> None:
    # Empty visible set (zero-group user) → empty list, comments never leak.
    async def _list_instances(session: object, principal: object = None) -> list:
        return []

    async def _list_all(session: object, kind: str | None = None) -> list:
        return [_row(1)]

    monkeypatch.setattr(comments_mod.inst_service, "list_instances", _list_instances)
    monkeypatch.setattr(comments_mod.store, "list_all", _list_all)
    app = _app(monkeypatch, inst=None)
    with TestClient(app) as c:
        r = c.get("/api/comments")
    assert r.status_code == 200
    assert r.json() == []
