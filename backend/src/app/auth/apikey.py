"""API-key generation + hashing for read-only service accounts."""

from __future__ import annotations

import hashlib
import secrets

API_KEY_PREFIX = "orbit_"


def hash_key(token: str) -> str:
    """SHA-256 hex of the token. Fine here — the token is high-entropy random."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Mint a key. Returns (full_token, key_hash, display_prefix).

    Only the hash is stored; the full token is shown to the admin once.
    """
    token = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return token, hash_key(token), token[: len(API_KEY_PREFIX) + 8]
