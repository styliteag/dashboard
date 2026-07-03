"""User-management CRUD: role/superadmin changes, memberships, lockout guards.

DB-free in the house style — the AsyncSession is stubbed so we assert the guard
logic (last-admin / last-superadmin / self-lockout), validation, membership
replace-set semantics and the mutations applied to the target row without a
real MariaDB. ``write_audit`` is patched to a no-op. The actor is a superadmin:
/api/users moved from require_admin to require_superadmin with the group
permission system.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

import app.users.routes as routes
from app.db.models import Group
from app.users.routes import (
    UserCreate,
    UserUpdate,
    create_user,
    delete_user,
    update_user,
)


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _noop(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(routes, "write_audit", _noop)


def _request() -> Request:
    return Request({"type": "http", "method": "POST", "headers": [], "client": ("1.2.3.4", 1234)})


class _CountResult:
    def __init__(self, value: int) -> None:
        self._value = value

    def scalar_one(self) -> int:
        return self._value


class _RowResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _ScalarsResult:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _ScalarsResult:
        return self

    def all(self) -> list[object]:
        return self._rows


class _FakeSession:
    """Minimal AsyncSession stand-in; dispatches ``execute`` on the statement SQL."""

    def __init__(
        self,
        *,
        target: object = None,
        admin_count: int = 1,
        superadmin_count: int = 1,
        groups: list[Group] | None = None,
        dup: bool = False,
    ) -> None:
        self._target = target
        self._admin_count = admin_count
        self._superadmin_count = superadmin_count
        self._groups = groups or []
        self._dup = dup
        self.added: list[object] = []
        self.deleted: list[object] = []
        self.committed = False
        self.rolled_back = False

    async def get(self, _model: object, _pk: object) -> object:
        return self._target

    async def execute(self, stmt: object) -> object:
        sql = str(stmt).lower()
        if "count" in sql:
            if "is_superadmin" in sql:
                return _CountResult(self._superadmin_count)
            return _CountResult(self._admin_count)
        if "from groups" in sql:
            return _ScalarsResult(list(self._groups))
        if "from users" in sql:  # bootstrap-seed retirement lookup
            return _RowResult(None)
        if "delete from" in sql:  # webauthn wipe in reset-2fa
            return _RowResult(None)
        raise AssertionError(f"unexpected statement: {sql}")

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

    async def refresh(self, _obj: object) -> None:
        return None


def _actor(uid: int = 1, *, is_superadmin: bool = True) -> SimpleNamespace:
    return SimpleNamespace(id=uid, role="view_only", is_admin=False, is_superadmin=is_superadmin)


def _user_row(
    uid: int,
    role: str,
    *,
    version: int = 1,
    is_superadmin: bool = False,
    is_bootstrap: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uid,
        username=f"u{uid}",
        role=role,
        password_hash="x",
        password_version=version,
        is_superadmin=is_superadmin,
        is_bootstrap=is_bootstrap,
        groups=[],
    )


def _group(gid: int, name: str) -> Group:
    return Group(id=gid, name=name)


# --- validation -----------------------------------------------------------


def test_create_rejects_unknown_role() -> None:
    with pytest.raises(ValidationError):
        UserCreate(username="bob", password="x" * 12, role="superuser")


def test_create_rejects_short_password() -> None:
    with pytest.raises(ValidationError):
        UserCreate(username="bob", password="short", role="user")


def test_update_rejects_short_password() -> None:
    with pytest.raises(ValidationError):
        UserUpdate(new_password="short")


# --- create ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_hashes_password_and_sets_role() -> None:
    session = _FakeSession()
    created = await create_user(
        UserCreate(username="viewer", password="correct-horse", role="view_only"),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(),
    )
    assert created.role == "view_only"
    assert created.username == "viewer"
    assert created.is_superadmin is False
    assert created.password_hash != "correct-horse"  # hashed
    assert created in session.added
    assert session.committed


@pytest.mark.asyncio
async def test_create_with_groups_assigns_memberships() -> None:
    groups = [_group(1, "default"), _group(2, "branch")]
    session = _FakeSession(groups=groups)
    created = await create_user(
        UserCreate(username="op", password="x" * 12, role="user", group_ids=[1, 2]),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(),
    )
    assert [g.id for g in created.groups] == [1, 2]


@pytest.mark.asyncio
async def test_create_unknown_group_id_400() -> None:
    session = _FakeSession(groups=[_group(1, "default")])  # id 7 missing
    with pytest.raises(HTTPException) as exc:
        await create_user(
            UserCreate(username="op", password="x" * 12, role="user", group_ids=[1, 7]),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(),
        )
    assert exc.value.status_code == 400
    assert "7" in exc.value.detail


@pytest.mark.asyncio
async def test_create_duplicate_username_409() -> None:
    session = _FakeSession(dup=True)
    with pytest.raises(HTTPException) as exc:
        await create_user(
            UserCreate(username="admin", password="x" * 12, role="user"),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(),
        )
    assert exc.value.status_code == 409
    assert session.rolled_back


# --- update ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_missing_404() -> None:
    session = _FakeSession(target=None)
    with pytest.raises(HTTPException) as exc:
        await update_user(
            99,
            UserUpdate(role="user"),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(),
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_update_cannot_demote_last_admin() -> None:
    target = _user_row(2, "admin")
    session = _FakeSession(target=target, admin_count=1)
    with pytest.raises(HTTPException) as exc:
        await update_user(
            2,
            UserUpdate(role="user"),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(1),
        )
    assert exc.value.status_code == 400
    assert target.role == "admin"  # unchanged


@pytest.mark.asyncio
async def test_update_cannot_demote_own_admin_account() -> None:
    target = _user_row(1, "admin")
    session = _FakeSession(target=target, admin_count=5)
    with pytest.raises(HTTPException) as exc:
        await update_user(
            1,
            UserUpdate(role="user"),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(1),
        )
    assert exc.value.status_code == 400
    assert target.role == "admin"


@pytest.mark.asyncio
async def test_update_demotes_when_other_admins_exist() -> None:
    target = _user_row(2, "admin")
    session = _FakeSession(target=target, admin_count=3)
    result = await update_user(
        2,
        UserUpdate(role="view_only"),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(1),
    )
    assert result.role == "view_only"
    assert session.committed


@pytest.mark.asyncio
async def test_update_cannot_revoke_own_superadmin_flag() -> None:
    target = _user_row(1, "view_only", is_superadmin=True)
    session = _FakeSession(target=target, superadmin_count=5)
    with pytest.raises(HTTPException) as exc:
        await update_user(
            1,
            UserUpdate(is_superadmin=False),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(1),
        )
    assert exc.value.status_code == 400
    assert target.is_superadmin is True


@pytest.mark.asyncio
async def test_update_cannot_revoke_last_superadmin() -> None:
    target = _user_row(2, "view_only", is_superadmin=True)
    session = _FakeSession(target=target, superadmin_count=1)
    with pytest.raises(HTTPException) as exc:
        await update_user(
            2,
            UserUpdate(is_superadmin=False),
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(1),
        )
    assert exc.value.status_code == 400
    assert target.is_superadmin is True


@pytest.mark.asyncio
async def test_update_revokes_superadmin_when_others_exist() -> None:
    target = _user_row(2, "view_only", is_superadmin=True)
    session = _FakeSession(target=target, superadmin_count=3)
    result = await update_user(
        2,
        UserUpdate(is_superadmin=False),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(1),
    )
    assert result.is_superadmin is False
    assert session.committed


@pytest.mark.asyncio
async def test_update_replaces_group_memberships() -> None:
    target = _user_row(2, "user")
    target.groups = [_group(1, "default")]
    session = _FakeSession(target=target, groups=[_group(2, "branch")])
    await update_user(
        2,
        UserUpdate(group_ids=[2]),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(1),
    )
    assert [g.id for g in target.groups] == [2]


@pytest.mark.asyncio
async def test_update_empty_group_ids_clears_memberships() -> None:
    target = _user_row(2, "user")
    target.groups = [_group(1, "default")]
    session = _FakeSession(target=target)
    await update_user(
        2,
        UserUpdate(group_ids=[]),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(1),
    )
    assert target.groups == []


@pytest.mark.asyncio
async def test_update_password_reset_bumps_version() -> None:
    target = _user_row(2, "user", version=1)
    session = _FakeSession(target=target, admin_count=2)
    await update_user(
        2,
        UserUpdate(new_password="brand-new-secret"),
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(1),
    )
    assert target.password_version == 2
    assert target.password_hash != "x"


# --- delete ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_self_forbidden() -> None:
    target = _user_row(1, "admin")
    session = _FakeSession(target=target, admin_count=5)
    with pytest.raises(HTTPException) as exc:
        await delete_user(
            1,
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(1),
        )
    assert exc.value.status_code == 400
    assert session.deleted == []


@pytest.mark.asyncio
async def test_delete_last_admin_forbidden() -> None:
    target = _user_row(2, "admin")
    session = _FakeSession(target=target, admin_count=1)
    with pytest.raises(HTTPException) as exc:
        await delete_user(
            2,
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(1),
        )
    assert exc.value.status_code == 400
    assert session.deleted == []


@pytest.mark.asyncio
async def test_delete_last_superadmin_forbidden() -> None:
    target = _user_row(2, "view_only", is_superadmin=True)
    session = _FakeSession(target=target, superadmin_count=1)
    with pytest.raises(HTTPException) as exc:
        await delete_user(
            2,
            _request(),
            session=session,  # type: ignore[arg-type]
            actor=_actor(1),
        )
    assert exc.value.status_code == 400
    assert session.deleted == []


@pytest.mark.asyncio
async def test_delete_superadmin_ok_when_others_exist() -> None:
    target = _user_row(2, "view_only", is_superadmin=True)
    session = _FakeSession(target=target, superadmin_count=2)
    await delete_user(
        2,
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(1),
    )
    assert target in session.deleted


@pytest.mark.asyncio
async def test_delete_non_admin_ok() -> None:
    target = _user_row(2, "user")
    session = _FakeSession(target=target, admin_count=1)
    await delete_user(
        2,
        _request(),
        session=session,  # type: ignore[arg-type]
        actor=_actor(1),
    )
    assert target in session.deleted
    assert session.committed
