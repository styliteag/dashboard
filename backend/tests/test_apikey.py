"""Tests for API-key generation, group binding and the read_principal dependency."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request

import app.apikeys.routes as routes
from app.apikeys.routes import (
    _may_reveal,
    _resolve_binding,
    create_apikey,
    delete_apikey,
    list_apikeys,
    reveal_apikey,
    revoke_apikey,
)
from app.auth.apikey import API_KEY_PREFIX, generate_key, hash_key
from app.auth.deps import read_principal, require_admin, require_admin_or_superadmin
from app.db.models import Group


def test_generate_key_shape() -> None:
    token, key_hash, prefix = generate_key()
    assert token.startswith(API_KEY_PREFIX)
    assert key_hash == hash_key(token)
    assert token.startswith(prefix)
    # two keys differ
    assert generate_key()[0] != generate_key()[0]


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _Session:
    def __init__(self, key: object) -> None:
        self._key = key

    async def execute(self, *a, **k):
        return _Result(self._key)

    async def commit(self):
        pass


def _request(method: str, token: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "headers": [(b"authorization", f"Bearer {token}".encode())],
        }
    )


@pytest.mark.asyncio
async def test_read_principal_accepts_valid_key_on_get() -> None:
    key = SimpleNamespace(id=1, name="checkmk", last_used_at=None)
    result = await read_principal(_request("GET", "orbit_abc"), _Session(key))
    assert result is key
    assert key.last_used_at is not None  # touched


@pytest.mark.asyncio
async def test_read_principal_rejects_key_on_write() -> None:
    key = SimpleNamespace(id=1, last_used_at=None)
    with pytest.raises(HTTPException) as exc:
        await read_principal(_request("POST", "orbit_abc"), _Session(key))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_read_principal_rejects_unknown_key() -> None:
    with pytest.raises(HTTPException) as exc:
        await read_principal(_request("GET", "orbit_nope"), _Session(None))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_require_admin_allows_admin() -> None:
    user = SimpleNamespace(is_admin=True)
    assert await require_admin(user) is user


@pytest.mark.asyncio
async def test_require_admin_rejects_non_admin() -> None:
    with pytest.raises(HTTPException) as exc:
        await require_admin(SimpleNamespace(is_admin=False))
    assert exc.value.status_code == 403


class _GetSession:
    """Minimal session whose ``get`` returns a fixed object (no DB)."""

    def __init__(self, obj: object) -> None:
        self._obj = obj

    async def get(self, _model: object, _id: object) -> object:
        return self._obj

    def add(self, _obj: object) -> None:  # pragma: no cover - unused on 404 path
        pass

    async def commit(self) -> None:  # pragma: no cover - unused on 404 path
        pass


@pytest.mark.asyncio
async def test_reveal_404_when_missing() -> None:
    with pytest.raises(HTTPException) as exc:
        await reveal_apikey(
            key_id=1,
            request=_request("GET", "x"),
            session=_GetSession(None),  # type: ignore[arg-type]
            user=SimpleNamespace(id=1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_reveal_404_when_not_revealable() -> None:
    key = SimpleNamespace(revoked_at=None, revealable=False, key_enc=b"x")
    with pytest.raises(HTTPException) as exc:
        await reveal_apikey(
            key_id=1,
            request=_request("GET", "x"),
            session=_GetSession(key),  # type: ignore[arg-type]
            user=SimpleNamespace(id=1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_reveal_404_when_revoked() -> None:
    key = SimpleNamespace(revoked_at=datetime.now(UTC), revealable=True, key_enc=b"x")
    with pytest.raises(HTTPException) as exc:
        await reveal_apikey(
            key_id=1,
            request=_request("GET", "x"),
            session=_GetSession(key),  # type: ignore[arg-type]
            user=SimpleNamespace(id=1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_reveal_404_when_no_ciphertext() -> None:
    key = SimpleNamespace(revoked_at=None, revealable=True, key_enc=None)
    with pytest.raises(HTTPException) as exc:
        await reveal_apikey(
            key_id=1,
            request=_request("GET", "x"),
            session=_GetSession(key),  # type: ignore[arg-type]
            user=SimpleNamespace(id=1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_purge_404_when_missing() -> None:
    with pytest.raises(HTTPException) as exc:
        await delete_apikey(
            key_id=1,
            request=_request("DELETE", "x"),
            session=_GetSession(None),  # type: ignore[arg-type]
            user=SimpleNamespace(id=1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_purge_400_when_active() -> None:
    # An un-revoked key can't be hard-deleted — revoke first.
    key = SimpleNamespace(revoked_at=None)
    with pytest.raises(HTTPException) as exc:
        await delete_apikey(
            key_id=1,
            request=_request("DELETE", "x"),
            session=_GetSession(key),  # type: ignore[arg-type]
            user=SimpleNamespace(id=1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 400


# --- group binding ------------------------------------------------------------


def _superadmin() -> SimpleNamespace:
    return SimpleNamespace(id=1, is_superadmin=True, group_id_set=frozenset())


def _group_admin(*groups: int) -> SimpleNamespace:
    return SimpleNamespace(id=2, is_superadmin=False, group_id_set=frozenset(groups))


class _ScalarsResult:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _ScalarsResult:
        return self

    def all(self) -> list[object]:
        return self._rows


class _GroupSession:
    """Serves the Group.id IN (…) select in _resolve_binding from a fixed pool."""

    def __init__(self, existing: dict[int, Group]) -> None:
        self._existing = existing
        self.requested: list[object] = []

    async def execute(self, stmt: object) -> _ScalarsResult:
        self.requested.append(stmt)
        # The route only queries by id-set; return every pool group whose id the
        # caller could have asked for (test pools are minimal, so this is exact
        # enough: unknown ids simply have no pool entry).
        return _ScalarsResult(list(self._existing.values()))


def test_guards_are_admin_or_superadmin() -> None:
    for route in (create_apikey, list_apikeys, revoke_apikey, delete_apikey, reveal_apikey):
        params = inspect.signature(route).parameters
        dep = params.get("user") or params["_user"]
        assert dep.default.dependency is require_admin_or_superadmin, route.__name__


@pytest.mark.asyncio
async def test_binding_superadmin_empty_is_global() -> None:
    assert await _resolve_binding(_GroupSession({}), _superadmin(), None) == []  # type: ignore[arg-type]
    assert await _resolve_binding(_GroupSession({}), _superadmin(), []) == []  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_binding_superadmin_unknown_group_400() -> None:
    session = _GroupSession({1: Group(id=1, name="default")})
    with pytest.raises(HTTPException) as exc:
        await _resolve_binding(session, _superadmin(), [1, 9])  # type: ignore[arg-type]
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_binding_admin_requires_nonempty() -> None:
    with pytest.raises(HTTPException) as exc:
        await _resolve_binding(_GroupSession({}), _group_admin(1), None)  # type: ignore[arg-type]
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_binding_admin_foreign_group_403() -> None:
    with pytest.raises(HTTPException) as exc:
        await _resolve_binding(_GroupSession({}), _group_admin(1), [2])  # type: ignore[arg-type]
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_binding_admin_own_groups_ok() -> None:
    pool = {1: Group(id=1, name="default"), 2: Group(id=2, name="branch")}
    session = _GroupSession(pool)
    groups = await _resolve_binding(session, _group_admin(1, 2), [1, 2])  # type: ignore[arg-type]
    assert {g.id for g in groups} == {1, 2}


def test_may_reveal_matrix() -> None:
    bound_own = SimpleNamespace(group_id_set=frozenset({1}))
    bound_foreign = SimpleNamespace(group_id_set=frozenset({2}))
    unbound = SimpleNamespace(group_id_set=frozenset())
    assert _may_reveal(_superadmin(), unbound) is True
    assert _may_reveal(_superadmin(), bound_foreign) is True
    assert _may_reveal(_group_admin(1), bound_own) is True
    assert _may_reveal(_group_admin(1), bound_foreign) is False
    # A global key's token would bypass the admin's scoping entirely.
    assert _may_reveal(_group_admin(1), unbound) is False


@pytest.mark.asyncio
async def test_reveal_404_for_admin_on_global_key() -> None:
    key = SimpleNamespace(revoked_at=None, revealable=True, key_enc=b"x", group_id_set=frozenset())
    with pytest.raises(HTTPException) as exc:
        await reveal_apikey(
            key_id=1,
            request=_request("GET", "x"),
            session=_GetSession(key),  # type: ignore[arg-type]
            user=_group_admin(1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_reveal_ok_for_superadmin(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _noop(*a: object, **k: object) -> None:
        return None

    monkeypatch.setattr(routes, "write_audit", _noop)
    monkeypatch.setattr(routes, "decrypt", lambda _b: "orbit_secret")
    key = SimpleNamespace(
        id=5, revoked_at=None, revealable=True, key_enc=b"x", group_id_set=frozenset({2})
    )
    out = await reveal_apikey(
        key_id=5,
        request=_request("GET", "x"),
        session=_GetSession(key),  # type: ignore[arg-type]
        user=_superadmin(),  # type: ignore[arg-type]
    )
    assert out.key == "orbit_secret"
