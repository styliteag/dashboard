"""Startup validation warns (never fails) when WebAuthn is left at localhost in prod."""

from __future__ import annotations

import structlog
from cryptography.fernet import Fernet

from app.config import Settings
from app.main import _validate_security


def _prod(**over) -> Settings:
    base = dict(env="production", master_key=Fernet.generate_key().decode())
    base.update(over)
    return Settings(**base)


def _events(logs: list[dict]) -> set[str]:
    return {e.get("event") for e in logs}


def test_warns_when_rp_id_is_localhost_in_prod() -> None:
    s = _prod(webauthn_rp_id="localhost", webauthn_origin="https://dash.example.com")
    with structlog.testing.capture_logs() as logs:
        _validate_security(s)  # must not raise — TOTP still works
    assert "webauthn.localhost_in_prod" in _events(logs)


def test_warns_when_origin_is_not_https_in_prod() -> None:
    s = _prod(webauthn_rp_id="dash.example.com", webauthn_origin="http://dash.example.com")
    with structlog.testing.capture_logs() as logs:
        _validate_security(s)
    assert "webauthn.insecure_origin" in _events(logs)


def test_no_webauthn_warning_when_configured() -> None:
    s = _prod(webauthn_rp_id="dash.example.com", webauthn_origin="https://dash.example.com")
    with structlog.testing.capture_logs() as logs:
        _validate_security(s)
    assert "webauthn.localhost_in_prod" not in _events(logs)
    assert "webauthn.insecure_origin" not in _events(logs)


def test_dev_localhost_does_not_warn() -> None:
    s = Settings(env="dev")  # defaults are localhost — fine in dev
    with structlog.testing.capture_logs() as logs:
        _validate_security(s)
    assert "webauthn.localhost_in_prod" not in _events(logs)
