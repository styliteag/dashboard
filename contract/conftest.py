"""Fixtures for the black-box contract suite.

Backend-agnostic by design (docs/elixir-migration-plan.md M1): point
CONTRACT_BASE_URL at the Python backend (default) or at server_ex — migrated
routes must behave identically on both.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from collections.abc import Iterator

import httpx
import pytest

BASE_URL = os.environ.get("CONTRACT_BASE_URL", "http://localhost:8000")
ADMIN_USER = os.environ.get("CONTRACT_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("CONTRACT_ADMIN_PASSWORD", "admin")
SUPERADMIN_USER = os.environ.get("CONTRACT_SUPERADMIN_USER", "superadmin")
SUPERADMIN_PASSWORD = os.environ.get("CONTRACT_SUPERADMIN_PASSWORD", "superadmin")


def totp_code(secret_b32: str, at: float | None = None) -> str:
    """RFC 6238 code (SHA-1, 6 digits, 30 s) — mirrors backend app/auth/totp.py."""
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    counter = int((time.time() if at is None else at) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % 10**6).zfill(6)


def login(client: httpx.Client, username: str, password: str) -> httpx.Response:
    return client.post("/api/auth/login", json={"username": username, "password": password})


@pytest.fixture()
def anon() -> Iterator[httpx.Client]:
    """Fresh client without any session."""
    with httpx.Client(base_url=BASE_URL, timeout=10) as client:
        yield client


@pytest.fixture(scope="session")
def admin() -> Iterator[httpx.Client]:
    """Session-scoped client logged in as the bootstrap admin.

    The bootstrap admin is password-only (stage \"done\" immediately); a
    stage \"verify\"/\"enroll\" answer means MFA got enabled on the account
    and the suite cannot run against this stack.
    """
    client = httpx.Client(base_url=BASE_URL, timeout=10)
    resp = login(client, ADMIN_USER, ADMIN_PASSWORD)
    assert resp.status_code == 200, f"admin login failed: {resp.status_code} {resp.text[:200]}"
    body = resp.json()
    assert body["stage"] == "done", "contract suite needs the password-only bootstrap admin"
    yield client
    client.close()


@pytest.fixture(scope="session")
def superadmin() -> Iterator[httpx.Client]:
    """Bootstrap superadmin — rights management ONLY, zero instance access."""
    client = httpx.Client(base_url=BASE_URL, timeout=10)
    resp = login(client, SUPERADMIN_USER, SUPERADMIN_PASSWORD)
    assert resp.status_code == 200, f"superadmin login failed: {resp.status_code} {resp.text[:200]}"
    assert resp.json()["stage"] == "done", "needs the password-only bootstrap superadmin"
    yield client
    client.close()
