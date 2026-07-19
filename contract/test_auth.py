"""Auth contract: login challenge flow, session cookie, 401 semantics."""

import httpx
from conftest import ADMIN_PASSWORD, ADMIN_USER, BASE_URL, login


def test_me_requires_auth(anon):
    resp = anon.get("/api/auth/me")
    assert resp.status_code == 401


def test_login_wrong_password_is_401_with_lowercase_detail(anon):
    resp = login(anon, ADMIN_USER, "definitely-wrong-password")

    assert resp.status_code == 401
    detail = resp.json()["detail"]
    # Human-readable, lowercase, and no username/existence oracle in the text.
    assert detail == "invalid credentials"


def test_login_ok_mints_session_and_me_works(anon):
    resp = login(anon, ADMIN_USER, ADMIN_PASSWORD)

    assert resp.status_code == 200
    body = resp.json()
    # LoginChallenge shape — bootstrap admin skips MFA entirely.
    assert set(body) == {"stage", "totp", "webauthn", "user"}
    assert body["stage"] == "done"
    user = body["user"]
    for key in ("id", "username", "role", "is_admin", "is_superadmin", "groups"):
        assert key in user, f"missing user key: {key}"
    assert user["username"] == ADMIN_USER

    me = anon.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == ADMIN_USER


def test_logout_clears_session():
    # Own client + own login — must not tear down the shared admin fixture session.
    with httpx.Client(base_url=BASE_URL, timeout=10) as client:
        assert login(client, ADMIN_USER, ADMIN_PASSWORD).status_code == 200

        resp = client.post("/api/auth/logout")
        assert resp.status_code == 204

        assert client.get("/api/auth/me").status_code == 401
