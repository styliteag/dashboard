"""Tests for the GUI-proxy auth gate (§18) — token signing + the forward_auth route.

The gate is the security-critical layer (it fronts a firewall admin GUI), so this
covers the negative path explicitly: a missing/tampered/cross-instance cookie must
be 401. Live-proven on .199 (Caddy forward_auth); these guard the contract.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

import app.agent_hub.routes as routes_mod
import app.main as main_mod
from app.agent_hub.gui_auth import COOKIE_NAME, sign_gui_token, verify_gui_token

# --- token signing -----------------------------------------------------------


def test_sign_verify_roundtrip() -> None:
    assert verify_gui_token(sign_gui_token(3, 60)) == 3
    assert verify_gui_token(sign_gui_token(7, 60)) == 7


def test_expired_token_rejected() -> None:
    assert verify_gui_token(sign_gui_token(3, -5)) is None


def test_tampered_or_garbage_rejected() -> None:
    good = sign_gui_token(3, 60)
    assert verify_gui_token(good + "x") is None
    assert verify_gui_token("garbage") is None
    assert verify_gui_token("") is None


# --- forward_auth route ------------------------------------------------------


async def _noop(*a, **k):
    return None


def _client(monkeypatch) -> TestClient:
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(routes_mod.hub, "hydrate_from_db", _noop)
    return TestClient(main_mod.create_app())


def test_authcheck_no_cookie_is_401(monkeypatch) -> None:
    with _client(monkeypatch) as client:
        r = client.get("/api/gui/authcheck", params={"instance": 3})
    assert r.status_code == 401


def test_authcheck_valid_cookie_is_200(monkeypatch) -> None:
    with _client(monkeypatch) as client:
        client.cookies.set(COOKIE_NAME, sign_gui_token(3, 60))
        r = client.get("/api/gui/authcheck", params={"instance": 3})
    assert r.status_code == 200


def test_authcheck_cross_instance_is_401(monkeypatch) -> None:
    # cookie minted for instance 3 must NOT satisfy instance 7's gate (cross-tenant).
    with _client(monkeypatch) as client:
        client.cookies.set(COOKIE_NAME, sign_gui_token(3, 60))
        r = client.get("/api/gui/authcheck", params={"instance": 7})
    assert r.status_code == 401


def test_handoff_valid_token_sets_cookie(monkeypatch) -> None:
    with _client(monkeypatch) as client:
        r = client.get(
            "/api/gui/handoff",
            params={"t": sign_gui_token(3, 60)},
            follow_redirects=False,
        )
    assert r.status_code == 302
    assert COOKIE_NAME in r.headers.get("set-cookie", "")


def test_handoff_invalid_token_is_403(monkeypatch) -> None:
    with _client(monkeypatch) as client:
        r = client.get("/api/gui/handoff", params={"t": "bad"}, follow_redirects=False)
    assert r.status_code == 403
