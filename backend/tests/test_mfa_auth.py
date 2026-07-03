"""The 2FA spine: no authenticated session without a passed factor.

These lock the invariants the whole feature rests on — mirroring the role-guard
test. They run DB-free: ``current_user`` / ``require_pending_mfa`` get a hand-built
Request (scope carries the session dict) and a stub session; the TOTP routes get a
real Fernet key and a stub session.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request

import app.auth.mfa_routes as mfa_routes
import app.auth.routes as auth_routes
from app.auth import totp
from app.auth.deps import current_user, require_pending_mfa
from app.auth.mfa_routes import CodeRequest, confirm_totp, setup_totp, verify_totp
from app.auth.security import limiter


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASH_MASTER_KEY", Fernet.generate_key().decode())
    from app.config import get_settings
    from app.crypto import secrets as crypto_secrets

    crypto_secrets._fernet.cache_clear()  # type: ignore[attr-defined]
    get_settings.cache_clear()  # type: ignore[attr-defined]
    limiter._state.clear()

    async def _noop(*a: object, **k: object) -> None:
        return None

    monkeypatch.setattr(auth_routes, "write_audit", _noop)
    monkeypatch.setattr(mfa_routes, "write_audit", _noop)


def _req(session: dict | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "session": {} if session is None else session,
            "headers": [],
            "client": ("1.2.3.4", 1234),
        }
    )


class _Sess:
    def __init__(self, user: object = None) -> None:
        self._user = user
        self.committed = 0

    async def get(self, _model: object, _pk: object) -> object:
        return self._user

    def add(self, _obj: object) -> None:
        pass

    async def flush(self) -> None:
        pass

    async def commit(self) -> None:
        self.committed += 1


def _user(**kw: object) -> SimpleNamespace:
    base = dict(
        id=1,
        username="u1",
        password_version=1,
        disabled=False,
        role="view_only",
        is_admin=False,
        is_superadmin=False,
        groups=[],
        totp_enabled=False,
        totp_secret_enc=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


# --- current_user gate ----------------------------------------------------


@pytest.mark.asyncio
async def test_session_without_mfa_passed_is_rejected() -> None:
    req = _req({"user_id": 1, "password_version": 1})  # no mfa_passed
    with pytest.raises(HTTPException) as exc:
        await current_user(req, _Sess(_user()))  # type: ignore[arg-type]
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_session_with_mfa_passed_is_accepted() -> None:
    req = _req({"user_id": 1, "password_version": 1, "mfa_passed": True})
    user = _user()
    out = await current_user(req, _Sess(user))  # type: ignore[arg-type]
    assert out is user


@pytest.mark.asyncio
async def test_disabled_user_session_dies() -> None:
    sess_dict = {"user_id": 1, "password_version": 1, "mfa_passed": True}
    req = _req(sess_dict)
    with pytest.raises(HTTPException) as exc:
        await current_user(req, _Sess(_user(disabled=True)))  # type: ignore[arg-type]
    assert exc.value.status_code == 401
    assert exc.value.detail == "account disabled"
    assert sess_dict == {}  # cleared


# --- pending-MFA state ----------------------------------------------------


@pytest.mark.asyncio
async def test_pending_mfa_returns_user() -> None:
    req = _req({"mfa_user_id": 1, "mfa_pw_version": 1})
    user = _user()
    out = await require_pending_mfa(req, _Sess(user))  # type: ignore[arg-type]
    assert out is user


@pytest.mark.asyncio
async def test_pending_mfa_without_pending_is_rejected() -> None:
    req = _req({})
    with pytest.raises(HTTPException) as exc:
        await require_pending_mfa(req, _Sess(_user()))  # type: ignore[arg-type]
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_pending_mfa_disabled_is_rejected() -> None:
    req = _req({"mfa_user_id": 1, "mfa_pw_version": 1})
    with pytest.raises(HTTPException) as exc:
        await require_pending_mfa(req, _Sess(_user(disabled=True)))  # type: ignore[arg-type]
    assert exc.value.status_code == 401


# --- TOTP enrollment / verify ---------------------------------------------


@pytest.mark.asyncio
async def test_setup_totp_stores_secret_disabled() -> None:
    user = _user()
    resp = await setup_totp(_req(), _Sess(user), user)  # type: ignore[arg-type]
    assert resp.otpauth_uri.startswith("otpauth://totp/")
    assert user.totp_secret_enc is not None
    assert user.totp_enabled is False  # confirm-before-enable


@pytest.mark.asyncio
async def test_confirm_totp_wrong_code_rejected_and_not_enabled() -> None:
    from app.crypto.secrets import encrypt

    secret = totp.generate_secret()
    user = _user(totp_secret_enc=encrypt(secret))
    with pytest.raises(HTTPException) as exc:
        await confirm_totp(CodeRequest(code="000000"), _req(), _Sess(user), user)  # type: ignore[arg-type]
    assert exc.value.status_code == 400
    assert user.totp_enabled is False


@pytest.mark.asyncio
async def test_confirm_totp_right_code_enables_and_mints_session() -> None:
    import time

    from app.crypto.secrets import encrypt

    secret = totp.generate_secret()
    user = _user(totp_secret_enc=encrypt(secret))
    code = totp._hotp(secret, int(time.time() // totp.PERIOD))
    sess_dict: dict = {"mfa_user_id": 1, "mfa_pw_version": 1}
    req = _req(sess_dict)
    out = await confirm_totp(CodeRequest(code=code), req, _Sess(user), user)  # type: ignore[arg-type]
    assert out.id == 1
    assert user.totp_enabled is True
    assert sess_dict["user_id"] == 1
    assert sess_dict["mfa_passed"] is True
    assert "mfa_user_id" not in sess_dict


@pytest.mark.asyncio
async def test_verify_totp_not_enrolled_rejected() -> None:
    user = _user(totp_enabled=False, totp_secret_enc=None)
    with pytest.raises(HTTPException) as exc:
        await verify_totp(CodeRequest(code="000000"), _req(), _Sess(user), user)  # type: ignore[arg-type]
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_verify_totp_right_code_mints_session() -> None:
    import time

    from app.crypto.secrets import encrypt

    secret = totp.generate_secret()
    user = _user(totp_enabled=True, totp_secret_enc=encrypt(secret))
    code = totp._hotp(secret, int(time.time() // totp.PERIOD))
    sess_dict: dict = {"mfa_user_id": 1, "mfa_pw_version": 1}
    out = await verify_totp(CodeRequest(code=code), _req(sess_dict), _Sess(user), user)  # type: ignore[arg-type]
    assert out.id == 1
    assert sess_dict["mfa_passed"] is True
