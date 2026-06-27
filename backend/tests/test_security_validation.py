"""Fail-closed startup validation of the master key (security F1)."""

import types

import pytest
from cryptography.fernet import Fernet

from app.main import _validate_security


def _settings(env, key):
    return types.SimpleNamespace(env=env, master_key=key)


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
