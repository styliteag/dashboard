"""Tests for API-key generation and the read-only read_principal dependency."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request

from app.auth.apikey import API_KEY_PREFIX, generate_key, hash_key
from app.auth.deps import read_principal


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
