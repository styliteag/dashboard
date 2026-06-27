"""Fail-closed startup validation of the master key (security F1) and
trusted proxy hops (prevent X-Forwarded-For spoofing of login/enroll rate limits + audit).
"""

import types

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.config import Settings
from app.main import _validate_security


def _settings(env="dev", key="", hops=0):
    """Minimal settings stub for _validate_security tests (matches real attrs used)."""
    return types.SimpleNamespace(env=env, master_key=key, trusted_proxy_hops=hops)


def test_non_dev_empty_key_raises():
    with pytest.raises(RuntimeError):
        _validate_security(_settings("prod", ""))


def test_non_dev_invalid_key_raises():
    with pytest.raises(RuntimeError):
        _validate_security(_settings("prod", "not-a-valid-fernet-key"))


def test_non_dev_valid_key_ok():
    # A valid Fernet key must not raise.
    _validate_security(_settings("prod", Fernet.generate_key().decode()))


def test_dev_empty_key_allowed():
    # Dev tolerates the insecure fallback (logs a warning); must not raise.
    _validate_security(_settings("dev", ""))


# --- trusted_proxy_hops validation (IP spoofing protection for rate limits) ---

def test_non_dev_too_high_trusted_proxy_hops_raises():
    """High hops in prod allows clients to spoof XFF and bypass login/enroll limiter."""
    with pytest.raises(RuntimeError, match="TRUSTED_PROXY_HOPS"):
        _validate_security(_settings("prod", Fernet.generate_key().decode(), hops=4))


def test_non_dev_max_reasonable_hops_ok():
    _validate_security(_settings("prod", Fernet.generate_key().decode(), hops=3))


def test_dev_high_hops_is_allowed():
    # Dev is intentionally permissive (with logging).
    _validate_security(_settings("dev", "", hops=10))


def test_negative_trusted_proxy_hops_rejected_by_pydantic():
    """Pydantic Field + validator rejects negative values at Settings construction time."""
    with pytest.raises(ValidationError):
        Settings(trusted_proxy_hops=-1)
