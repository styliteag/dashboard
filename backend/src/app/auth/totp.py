"""RFC 6238 TOTP — stdlib only (no third-party dependency).

A single 6-digit, 30-second, SHA-1 authenticator code (the universal default that
every authenticator app speaks). Secrets are base32 strings; storage encrypts them
with the Fernet helper. ``verify`` accepts a small clock-drift window and takes an
optional ``at`` so tests are deterministic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30


def generate_secret(num_bytes: int = 20) -> str:
    """Return a fresh base32 secret (no padding), suitable for an otpauth URI."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**DIGITS)).zfill(DIGITS)


def verify(secret_b32: str, code: str, *, window: int = 1, at: float | None = None) -> bool:
    """Constant-time check of ``code`` against the secret, ±``window`` time steps."""
    code = (code or "").strip()
    if not code.isdigit() or len(code) != DIGITS:
        return False
    now = time.time() if at is None else at
    counter = int(now // PERIOD)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_b32, counter + drift), code):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str, issuer: str) -> str:
    """Build the ``otpauth://`` URI the frontend renders as a QR code."""
    label = quote(f"{issuer}:{account}", safe="")
    params = (
        f"secret={secret_b32}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )
    return f"otpauth://totp/{label}?{params}"
