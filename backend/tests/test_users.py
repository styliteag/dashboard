"""User-management CRUD: role changes, password reset, and lockout guards.

DB-free in the house style — the AsyncSession is stubbed so we assert the guard
logic (last-admin / self-lockout), validation, and the mutations applied to the
target row without a real MariaDB. ``write_audit`` is patched to a no-op.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

import app.users.routes as routes
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


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one(self) -> object:
        return self._value


class _FakeSession:
    """Minimal AsyncSession stand-in covering only what the routes touch."""

    def __init__(self, *, target: object = None, admin_count: int = 1, dup: bool = False) -> None:
        self._target = target
        self._admin_count = admin_count
        self._dup = dup
        self.added: list[object] = []
        self.deleted: list[object] = []
        self.committed = False
        self.rolled_back = False

    async def get(self, _model: object, _pk: object) -> object:
        return self._target

    async def execute(self, _stmt: object) -> _Result:
        return _Result(self._admin_count)  # only used by _admin_count()

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


def _admin(uid: int = 1) -> SimpleNamespace:
    return SimpleNamespace(id=uid, role="admin", is_admin=True)


def _user_row(uid: int, role: str, *, version: int = 1) -> SimpleNamespace:
    return SimpleNamespace(
        id=uid, username=f"u{uid}", role=role, password_hash="x", password_version=version
    )


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
        admin=_admin(),
    )
    assert created.role == "view_only"
    assert created.username == "viewer"
    assert created.password_hash != "correct-horse"  # hashed
    assert created in session.added
    assert session.committed


@pytest.mark.asyncio
async def test_create_duplicate_username_409() -> None:
    session = _FakeSession(dup=True)
    with pytest.raises(HTTPException) as exc:
        await create_user(
            UserCreate(username="admin", password="x" * 12, role="user"),
            _request(),
            session=session,  # type: ignore[arg-type]
            admin=_admin(),
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
            admin=_admin(),
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
            admin=_admin(1),
        )
    assert exc.value.status_code == 400
    assert target.role == "admin"  # unchanged


@pytest.mark.asyncio
async def test_update_cannot_demote_self() -> None:
    target = _user_row(1, "admin")
    session = _FakeSession(target=target, admin_count=5)
    with pytest.raises(HTTPException) as exc:
        await update_user(
            1,
            UserUpdate(role="user"),
            _request(),
            session=session,  # type: ignore[arg-type]
            admin=_admin(1),
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
        admin=_admin(1),
    )
    assert result.role == "view_only"
    assert session.committed


@pytest.mark.asyncio
async def test_update_password_reset_bumps_version() -> None:
    target = _user_row(2, "user", version=1)
    session = _FakeSession(target=target, admin_count=2)
    await update_user(
        2,
        UserUpdate(new_password="brand-new-secret"),
        _request(),
        session=session,  # type: ignore[arg-type]
        admin=_admin(1),
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
            admin=_admin(1),
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
            admin=_admin(1),
        )
    assert exc.value.status_code == 400
    assert session.deleted == []


@pytest.mark.asyncio
async def test_delete_non_admin_ok() -> None:
    target = _user_row(2, "user")
    session = _FakeSession(target=target, admin_count=1)
    await delete_user(
        2,
        _request(),
        session=session,  # type: ignore[arg-type]
        admin=_admin(1),
    )
    assert target in session.deleted
    assert session.committed
