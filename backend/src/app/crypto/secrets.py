"""Symmetric encryption for OPNsense API credentials at rest.

We use Fernet (AES-128-CBC + HMAC) keyed by ``DASH_MASTER_KEY``. The plaintext
never leaves the backend process: it is decrypted only when constructing the
HTTP client for an instance, and never returned by the API.
"""
from __future__ import annotations

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


class CryptoError(RuntimeError):
    """Raised when encryption or decryption fails."""


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    key = get_settings().master_key
    if not key:
        raise CryptoError(
            "DASH_MASTER_KEY is not set. Generate one with "
            "`python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`"
        )
    try:
        return Fernet(key.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"DASH_MASTER_KEY is not a valid Fernet key: {exc}") from exc


def encrypt(plaintext: str) -> bytes:
    if plaintext is None:
        raise CryptoError("cannot encrypt None")
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt(token: bytes) -> str:
    try:
        return _fernet().decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise CryptoError("decryption failed (wrong key or corrupted data)") from exc
