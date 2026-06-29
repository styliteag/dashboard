"""Tests for the GUI auto-login replay (gui.login action).

The agent replays the firewall's WebUI form login locally and returns the
resulting session cookie to the dashboard, which sets it on the per-instance
proxy origin so the browser arrives already authenticated. The HTTP calls
(_http_request) and provisioning (_run PHP) are stubbed — these cover form
parsing, cookie capture, credential source per platform, success/failure
detection, and dispatch.
"""

from __future__ import annotations

import json

import orbit_agent as agent
import pytest


def _cfg(**over: object) -> agent.Config:
    cfg = agent.Config(path="/nonexistent-gui-test")
    cfg.local_api_url = "https://127.0.0.1:4444"
    cfg.relay_provision = False
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


# --- form + cookie parsing ---------------------------------------------------


def test_parse_login_form_extracts_hidden_and_action() -> None:
    html = (
        b'<form action="/index.php" method="post">'
        b'<input type="hidden" name="X-RandToken" value="tok">'
        b'<input type="text" name="usernamefld">'
        b'<input type="password" name="passwordfld"></form>'
    )
    hidden, action = agent._parse_login_form(html)
    assert hidden == {"X-RandToken": "tok"}
    assert action == "/index.php"


def test_parse_login_form_no_action_returns_none() -> None:
    hidden, action = agent._parse_login_form(b"<form><input type=hidden name=a value=b></form>")
    assert hidden == {"a": "b"}
    assert action is None


def test_parse_set_cookies_handles_multiple_headers() -> None:
    headers = [
        ("Set-Cookie", "PHPSESSID=abc; path=/; secure; HttpOnly"),
        ("Set-Cookie", "cookie_test=z; path=/"),
        ("X-Other", "1"),
    ]
    assert agent._parse_set_cookies(headers) == {"PHPSESSID": "abc", "cookie_test": "z"}


# --- credential source per platform ------------------------------------------


def test_ensure_gui_creds_pfsense_reuses_relay_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("orbit", "RELAYPW"))
    assert agent._ensure_gui_credentials(_cfg()) == ("orbit", "RELAYPW")


def test_ensure_gui_creds_pfsense_provisions_without_relay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: None)
    monkeypatch.setattr(agent, "_provision_pf_gui_credentials", lambda: ("orbit", "NEWPW"))
    assert agent._ensure_gui_credentials(_cfg()) == ("orbit", "NEWPW")


def test_ensure_gui_creds_pfsense_none_when_provision_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: None)
    monkeypatch.setattr(agent, "_provision_pf_gui_credentials", lambda: None)
    assert agent._ensure_gui_credentials(_cfg()) is None


def test_ensure_gui_creds_opnsense_uses_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_load_cached_gui_password", lambda: "CACHEDPW")
    assert agent._ensure_gui_credentials(_cfg()) == ("orbit", "CACHEDPW")


def test_ensure_gui_creds_opnsense_provisions_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_load_cached_gui_password", lambda: None)
    monkeypatch.setattr(agent, "_provision_gui_password", lambda: ("orbit", "NEWPW"))
    assert agent._ensure_gui_credentials(_cfg()) == ("orbit", "NEWPW")


def test_provision_gui_password_caches(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    cache = tmp_path / "gui.pw"
    monkeypatch.setattr(agent, "_GUIPW_CACHE", str(cache))
    monkeypatch.setattr(agent, "_run", lambda *a, **k: json.dumps({"user": "orbit", "password": "P"}))
    assert agent._provision_gui_password() == ("orbit", "P")
    assert json.loads(cache.read_text())["password"] == "P"


def test_provision_gui_password_error_returns_none(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(agent, "_GUIPW_CACHE", str(tmp_path / "gui.pw"))
    monkeypatch.setattr(agent, "_run", lambda *a, **k: json.dumps({"error": "no orbit user"}))
    assert agent._provision_gui_password() is None


# --- login replay ------------------------------------------------------------


def _fake_http(get_resp, post_resp):
    """Build an _http_request stub: first GET -> get_resp, POST -> post_resp."""
    calls: list[tuple] = []

    def fake(url, method, headers, body, timeout, *, verify=True):
        calls.append((url, method, headers, body))
        return get_resp if method == "GET" else post_resp

    return fake, calls


def test_gui_login_success_returns_session_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_ensure_gui_credentials", lambda cfg: ("orbit", "PW"))
    get_resp = (
        200,
        [("Set-Cookie", "PHPSESSID=pre; path=/"), ("Set-Cookie", "cookie_test=t; path=/")],
        b'<form action="/"><input type="hidden" name="csrf" value="tk"></form>',
    )
    post_resp = (302, [("Set-Cookie", "PHPSESSID=authed; path=/; secure; HttpOnly")], b"")
    fake, calls = _fake_http(get_resp, post_resp)
    monkeypatch.setattr(agent, "_http_request", fake)

    res = agent._gui_login(_cfg())
    assert res["success"] is True
    assert res["cookies"] == [{"name": "PHPSESSID", "value": "authed"}]

    post = next(c for c in calls if c[1] == "POST")
    body = post[3]
    assert b"csrf=tk" in body  # CSRF hidden field replayed
    assert b"usernamefld=orbit" in body
    assert b"passwordfld=PW" in body
    # pre-session cookie carried into the POST so OPNsense ties the CSRF token to it
    assert "PHPSESSID=pre" in post[2]["Cookie"]


def test_gui_login_drops_transient_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_ensure_gui_credentials", lambda cfg: ("orbit", "PW"))
    post_resp = (
        302,
        [("Set-Cookie", "PHPSESSID=authed; path=/"), ("Set-Cookie", "cookie_test=z; path=/")],
        b"",
    )
    fake, _ = _fake_http((200, [], b"<form></form>"), post_resp)
    monkeypatch.setattr(agent, "_http_request", fake)
    res = agent._gui_login(_cfg())
    assert res["cookies"] == [{"name": "PHPSESSID", "value": "authed"}]


def test_gui_login_rejected_when_no_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_ensure_gui_credentials", lambda cfg: ("orbit", "PW"))
    # Wrong password: OPNsense re-renders the login form (200) with no fresh session.
    fake, _ = _fake_http(
        (200, [("Set-Cookie", "PHPSESSID=pre")], b"<form></form>"),
        (200, [], b'<form><input name="usernamefld"></form>'),
    )
    monkeypatch.setattr(agent, "_http_request", fake)
    res = agent._gui_login(_cfg())
    assert res["success"] is False


def test_gui_login_rejected_when_redirect_without_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_ensure_gui_credentials", lambda cfg: ("orbit", "PW"))
    fake, _ = _fake_http((200, [], b"<form></form>"), (302, [], b""))
    monkeypatch.setattr(agent, "_http_request", fake)
    assert agent._gui_login(_cfg())["success"] is False


def test_gui_login_rejected_when_session_not_rotated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_ensure_gui_credentials", lambda cfg: ("orbit", "PW"))
    # 302 but the session cookie is identical to the pre-login one (no rotation) —
    # a real login always regenerates the id, so this is a failure, not success.
    fake, _ = _fake_http(
        (200, [("Set-Cookie", "PHPSESSID=same")], b"<form></form>"),
        (302, [("Set-Cookie", "PHPSESSID=same")], b""),
    )
    monkeypatch.setattr(agent, "_http_request", fake)
    assert agent._gui_login(_cfg())["success"] is False


def test_gui_login_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_ensure_gui_credentials", lambda cfg: None)
    assert agent._gui_login(_cfg())["success"] is False


def test_gui_login_nil_config() -> None:
    assert agent._gui_login(None)["success"] is False


def test_gui_login_get_transport_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_ensure_gui_credentials", lambda cfg: ("orbit", "PW"))

    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(agent, "_http_request", boom)
    res = agent._gui_login(_cfg())
    assert res["success"] is False
    assert "failed" in res["output"]


# --- dispatch ----------------------------------------------------------------


def test_execute_command_dispatches_gui_login(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_CONFIG", _cfg())
    monkeypatch.setattr(agent, "_ensure_gui_credentials", lambda cfg: ("orbit", "PW"))
    fake, _ = _fake_http(
        (200, [("Set-Cookie", "PHPSESSID=pre")], b"<form></form>"),
        (302, [("Set-Cookie", "PHPSESSID=ok")], b""),
    )
    monkeypatch.setattr(agent, "_http_request", fake)
    res = agent.execute_command("gui.login", {})
    assert res["success"] is True
    assert res["cookies"] == [{"name": "PHPSESSID", "value": "ok"}]
