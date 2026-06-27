"""Tests for API-key generation and the read-only read_principal dependency."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request

from app.apikeys.routes import reveal_apikey
from app.auth.apikey import API_KEY_PREFIX, generate_key, hash_key
from app.auth.deps import read_principal, require_admin


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
