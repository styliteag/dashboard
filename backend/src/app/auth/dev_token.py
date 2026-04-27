"""Dev-only bearer token fallback for browsers that mishandle localhost cookies."""
from __future__ import annotations

import base64
import json

from itsdangerous import BadSignature, SignatureExpired, TimestampSigner

from app.config import get_settings

MAX_AGE_SECONDS = 12 * 60 * 60


def _signer() -> TimestampSigner:
    return TimestampSigner(get_settings().master_key or "dev-only-not-secret")


def issue_dev_token(user_id: int, password_version: int) -> str:
    payload = json.dumps({"user_id": user_id, "password_version": password_version}).encode()
    return _signer().sign(base64.urlsafe_b64encode(payload)).decode()


def read_dev_token(token: str) -> tuple[int, int] | None:
    try:
        raw = _signer().unsign(token, max_age=MAX_AGE_SECONDS)
        data = json.loads(base64.urlsafe_b64decode(raw))
        return int(data["user_id"]), int(data["password_version"])
    except (BadSignature, SignatureExpired, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
