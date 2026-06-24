"""Self-contained signed tokens for the GUI-proxy auth gate (§18).

The GUI origin (gui-<id> subdomain in prod, a port in dev) is cross-origin from the
dashboard, so the dashboard session cookie can't gate it. Instead: the dashboard
mints a short-lived handoff token; the GUI origin exchanges it (via Caddy → backend)
for an `orbit_gui` cookie; Caddy forward_auth verifies that cookie on every request.

Tokens are HMAC-signed and carry (instance_id, exp) — verification is zero-I/O (no
DB/hub lookup) so it can run on every asset, and binding instance_id stops a cookie
for one firewall from satisfying the gate of another (cross-tenant defense).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

from app.config import get_settings

COOKIE_NAME = "orbit_gui"


def _secret() -> bytes:
    # Derive a dedicated HMAC key from the Fernet master key (kept secret already).
    return hashlib.sha256(b"orbit-gui-proxy:" + get_settings().master_key.encode()).digest()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_gui_token(instance_id: int, ttl_seconds: int) -> str:
    """Sign (instance_id, expiry) → opaque token. Used for the handoff + the cookie."""
    payload = f"{instance_id}:{int(time.time()) + ttl_seconds}".encode()
    sig = hmac.new(_secret(), payload, hashlib.sha256).digest()
    return f"{_b64(payload)}.{_b64(sig)}"


def verify_gui_token(token: str) -> int | None:
    """Return the instance_id if the token is well-formed, unexpired, and authentic."""
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _unb64(payload_b64)
        sig = _unb64(sig_b64)
    except (ValueError, AttributeError):
        return None
    expected = hmac.new(_secret(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        instance_s, exp_s = payload.decode().split(":")
        if int(exp_s) < int(time.time()):
            return None
        return int(instance_s)
    except ValueError:
        return None
