"""Fixtures for the black-box contract suite.

Backend-agnostic by design (docs/elixir-migration-plan.md M1): point
CONTRACT_BASE_URL at the Python backend (default) or at server_ex — migrated
routes must behave identically on both.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import httpx
import pytest

BASE_URL = os.environ.get("CONTRACT_BASE_URL", "http://localhost:8000")
ADMIN_USER = os.environ.get("CONTRACT_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("CONTRACT_ADMIN_PASSWORD", "admin")


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
