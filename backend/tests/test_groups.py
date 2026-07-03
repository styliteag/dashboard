"""Group CRUD (superadmin-only rights management).

DB-free in the house style — fake AsyncSession dispatching on the statement
SQL. Covers list-with-counts, unique-name 409s, the delete-while-instances 409
and the require_superadmin guard itself.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from sqlalchemy.exc import IntegrityError

import app.groups.routes as routes
from app.auth.deps import require_superadmin
from app.groups.routes import (
    create_group,
    delete_group,
    list_group_instances,
    list_groups,
    rename_group,
)
from app.groups.schemas import GroupCreate, GroupUpdate


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _noop(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(routes, "write_audit", _noop)


def _request() -> Request:
    return Request({"type": "http", "method": "POST", "headers": [], "client": ("1.2.3.4", 1234)})


def _actor(uid: int = 1) -> SimpleNamespace:
    return SimpleNamespace(id=uid, role="view_only", is_admin=False, is_superadmin=True)


def _group(gid: int, name: str) -> SimpleNamespace:
    return SimpleNamespace(id=gid, name=name, created_at=datetime.now(UTC))


class _ScalarsResult:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _ScalarsResult:
        return self

    def all(self) -> list[object]:
        return self._rows


class _PairsResult:
    def __init__(self, pairs: list[tuple[int, int]]) -> None:
        self._pairs = pairs

    def all(self) -> list[tuple[int, int]]:
        return self._pairs


class _FakeSession:
    def __init__(
        self,
        *,
        group: object = None,
        groups: list[object] | None = None,
        member_pairs: list[tuple[int, int]] | None = None,
        instance_pairs: list[tuple[int, int]] | None = None,
        instances: list[object] | None = None,
        member_count: int = 0,
        instance_count: int = 0,
        bound_keys: list[object] | None = None,
        dup: bool = False,
    ) -> None:
        self._group = group
        self._groups = groups or []
        self._member_pairs = member_pairs or []
        self._instance_pairs = instance_pairs or []
        self._instances = instances or []
        self._member_count = member_count
        self._instance_count = instance_count
        self._bound_keys = bound_keys or []
        self._dup = dup
        self.added: list[object] = []
        self.deleted: list[object] = []
        self.committed = False
        self.rolled_back = False

    async def get(self, _model: object, _pk: object) -> object:
        return self._group

    async def execute(self, stmt: object) -> object:
        sql = str(stmt).lower()
        if "count" in sql and "user_groups" in sql:
            return _PairsResult(self._member_pairs)
        if "count" in sql and "instances" in sql:
            return _PairsResult(self._instance_pairs)
        if "api_keys" in sql:  # delete-guard: keys bound to this group
            return _ScalarsResult(list(self._bound_keys))
        if "from groups" in sql:
            return _ScalarsResult(self._groups)
        if "from instances" in sql:
            return _ScalarsResult(self._instances)
        raise AssertionError(f"unexpected statement: {sql}")

    async def scalar(self, stmt: object) -> int:
        sql = str(stmt).lower()
        if "user_groups" in sql:
            return self._member_count
        return self._instance_count

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        if self._dup:
            raise IntegrityError("INSERT", {}, Exception("duplicate"))

    async def rollback(self) -> None:
        self.rolled_back = True

    async def delete(self, obj: object) -> None:
        self.deleted.append(obj)

    async def commit(self) -> None:
        self.committed = True

    async def refresh(self, obj: object) -> None:
        # Stand-in for the DB populating autoincrement + server defaults.
        if getattr(obj, "id", None) is None:
            obj.id = 1
        if getattr(obj, "created_at", None) is None:
            obj.created_at = datetime.now(UTC)


# --- guard ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_superadmin_rejects_plain_admin() -> None:
    admin = SimpleNamespace(id=1, role="admin", is_admin=True, is_superadmin=False)
    with pytest.raises(HTTPException) as exc:
        await require_superadmin(admin)  # type: ignore[arg-type]
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_require_superadmin_passes_superadmin() -> None:
    actor = _actor()
    assert await require_superadmin(actor) is actor  # type: ignore[arg-type]


# --- list ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_merges_counts_with_zero_defaults() -> None:
    session = _FakeSession(
        groups=[_group(1, "default"), _group(2, "empty")],
        member_pairs=[(1, 3)],
        instance_pairs=[(1, 7)],
    )
    out = await list_groups(session=session, _actor=_actor())  # type: ignore[arg-type]
    by_id = {g.id: g for g in out}
    assert by_id[1].member_count == 3
    assert by_id[1].instance_count == 7
    assert by_id[2].member_count == 0
    assert by_id[2].instance_count == 0


# --- create -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_group_ok() -> None:
    session = _FakeSession()
    out = await create_group(
        GroupCreate(name="branch"),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(),
    )
    assert out.name == "branch"
    assert out.member_count == 0
    assert session.committed


@pytest.mark.asyncio
async def test_create_duplicate_name_409() -> None:
    session = _FakeSession(dup=True)
    with pytest.raises(HTTPException) as exc:
        await create_group(
            GroupCreate(name="default"),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(),
        )
    assert exc.value.status_code == 409
    assert session.rolled_back


# --- rename -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rename_missing_404() -> None:
    session = _FakeSession(group=None)
    with pytest.raises(HTTPException) as exc:
        await rename_group(
            99,
            GroupUpdate(name="x"),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(),
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_rename_ok() -> None:
    group = _group(2, "old")
    session = _FakeSession(group=group, member_count=2, instance_count=4)
    out = await rename_group(
        2,
        GroupUpdate(name="new"),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(),
    )
    assert group.name == "new"
    assert out.member_count == 2
    assert out.instance_count == 4
    assert session.committed


@pytest.mark.asyncio
async def test_rename_duplicate_name_409() -> None:
    session = _FakeSession(group=_group(2, "old"), dup=True)
    with pytest.raises(HTTPException) as exc:
        await rename_group(
            2,
            GroupUpdate(name="default"),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(),
        )
    assert exc.value.status_code == 409


# --- delete -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_with_instances_409() -> None:
    session = _FakeSession(group=_group(2, "busy"), instance_count=3)
    with pytest.raises(HTTPException) as exc:
        await delete_group(
            2,
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(),
        )
    assert exc.value.status_code == 409
    assert session.deleted == []


@pytest.mark.asyncio
async def test_delete_empty_group_ok() -> None:
    group = _group(2, "empty")
    session = _FakeSession(group=group, instance_count=0)
    await delete_group(
        2,
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(),
    )
    assert group in session.deleted
    assert session.committed


@pytest.mark.asyncio
async def test_delete_blocked_when_last_binding_of_active_key() -> None:
    # apikey_groups CASCADEs: losing the last binding would flip the key to
    # GLOBAL (empty set = unscoped) — a silent privilege escalation.
    key = SimpleNamespace(name="checkmk-branch", revoked_at=None, group_id_set=frozenset({2}))
    session = _FakeSession(group=_group(2, "branch"), instance_count=0, bound_keys=[key])
    with pytest.raises(HTTPException) as exc:
        await delete_group(
            2,
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(),
        )
    assert exc.value.status_code == 409
    assert session.deleted == []


@pytest.mark.asyncio
async def test_delete_ok_when_key_has_other_bindings_or_is_revoked() -> None:
    multi = SimpleNamespace(name="multi", revoked_at=None, group_id_set=frozenset({1, 2}))
    revoked = SimpleNamespace(name="old", revoked_at=datetime.now(UTC), group_id_set=frozenset({2}))
    group = _group(2, "branch")
    session = _FakeSession(group=group, instance_count=0, bound_keys=[multi, revoked])
    await delete_group(
        2,
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(),
    )
    assert group in session.deleted


# --- instances listing ----------------------------------------------------------


@pytest.mark.asyncio
async def test_list_group_instances_missing_group_404() -> None:
    session = _FakeSession(group=None)
    with pytest.raises(HTTPException) as exc:
        await list_group_instances(
            99,
            session=session,  # type: ignore[arg-type]
            _actor=_actor(),
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_list_group_instances_returns_rows() -> None:
    rows = [SimpleNamespace(id=1, name="opn1", slug="opn1")]
    session = _FakeSession(group=_group(1, "default"), instances=rows)
    out = await list_group_instances(
        1,
        session=session,  # type: ignore[arg-type]
        _actor=_actor(),
    )
    assert out == rows
