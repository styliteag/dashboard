"""WebAuthn option generation: valid JSON, RP id/origin from settings, challenge."""

from __future__ import annotations

import json

import pytest

from app.auth import webauthn_svc


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASH_WEBAUTHN_RP_ID", "dash.example.com")
    monkeypatch.setenv("DASH_WEBAUTHN_ORIGIN", "https://dash.example.com")
    from app.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]


def test_registration_options_shape() -> None:
    options_json, challenge = webauthn_svc.registration_options(7, "alice", [])
    data = json.loads(options_json)
    assert data["rp"]["id"] == "dash.example.com"
    assert data["user"]["name"] == "alice"
    assert challenge and data["challenge"] == challenge


def test_authentication_options_shape() -> None:
    options_json, challenge = webauthn_svc.authentication_options([])
    data = json.loads(options_json)
    assert data["rpId"] == "dash.example.com"
    assert data["challenge"] == challenge
