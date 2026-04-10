"""Smoke test for the Fernet wrapper."""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet


@pytest.fixture(autouse=True)
def _set_master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASH_MASTER_KEY", Fernet.generate_key().decode())
    # The crypto module memoizes the Fernet instance; reset between tests.
    from app.crypto import secrets as crypto_secrets

    crypto_secrets._fernet.cache_clear()  # type: ignore[attr-defined]
    from app.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]


def test_encrypt_decrypt_roundtrip() -> None:
    from app.crypto.secrets import decrypt, encrypt

    token = encrypt("hunter2")
    assert isinstance(token, bytes)
    assert decrypt(token) == "hunter2"


def test_decrypt_with_wrong_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.crypto import secrets as crypto_secrets
    from app.crypto.secrets import CryptoError, decrypt, encrypt

    token = encrypt("secret")

    # Rotate the master key and clear the cache.
    monkeypatch.setenv("DASH_MASTER_KEY", Fernet.generate_key().decode())
    crypto_secrets._fernet.cache_clear()  # type: ignore[attr-defined]
    from app.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]

    with pytest.raises(CryptoError):
        decrypt(token)
