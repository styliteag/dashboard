"""Tests for the GUI-proxy auth gate (§18) — token signing + the forward_auth route.

The gate is the security-critical layer (it fronts a firewall admin GUI), so this
covers the negative path explicitly: a missing/tampered/cross-instance cookie must
be 401. Live-proven on .199 (Caddy forward_auth); these guard the contract.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

import app.agent_hub.routes.gui as routes_mod
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


def test_handoff_sets_firewall_session_cookie_from_stash(monkeypatch) -> None:
    # Opt-in auto-login: a cookie stashed by gui/open is set onto the proxy origin.
    from app.agent_hub.gui_session import gui_sessions

    token = sign_gui_token(3, 60)
    gui_sessions.put(token, [{"name": "PHPSESSID", "value": "sess-xyz"}], ttl_seconds=60)
    with _client(monkeypatch) as client:
        r = client.get("/api/gui/handoff", params={"t": token}, follow_redirects=False)
    assert r.status_code == 302
    setcookies = [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
    assert any(c.startswith("PHPSESSID=sess-xyz") for c in setcookies)
    assert any(c.startswith(f"{COOKIE_NAME}=") for c in setcookies)


def test_handoff_without_stash_sets_only_orbit_cookie(monkeypatch) -> None:
    with _client(monkeypatch) as client:
        r = client.get(
            "/api/gui/handoff", params={"t": sign_gui_token(5, 60)}, follow_redirects=False
        )
    setcookies = [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
    assert all(not c.startswith("PHPSESSID=") for c in setcookies)
    assert any(c.startswith(f"{COOKIE_NAME}=") for c in setcookies)


def test_authcheck_instance_from_host(monkeypatch) -> None:
    # Traefik wildcard: no ?instance, the gui-<id> Host carries it.
    with _client(monkeypatch) as client:
        client.cookies.set(COOKIE_NAME, sign_gui_token(3, 60))
        ok = client.get("/api/gui/authcheck", headers={"host": "gui-3.example.com"})
        bad = client.get("/api/gui/authcheck", headers={"host": "gui-7.example.com"})
    assert ok.status_code == 200
    assert bad.status_code == 401  # cookie-3 must not satisfy gui-7's gate
