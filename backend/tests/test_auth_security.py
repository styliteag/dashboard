"""Unit tests for password hashing + brute-force limiter."""
from __future__ import annotations

from app.auth.security import (
    LoginLimiter,
    MAX_FAILED,
    hash_password,
    verify_password,
)


def test_hash_and_verify() -> None:
    h = hash_password("hunter2hunter2")
    assert verify_password("hunter2hunter2", h)
    assert not verify_password("wrong", h)


def test_limiter_locks_after_threshold() -> None:
    lim = LoginLimiter()
    ip = "1.2.3.4"
    triggered = False
    for _ in range(MAX_FAILED):
        triggered = lim.record_failure(ip)
    assert triggered is True
    assert lim.is_locked(ip) is True


def test_limiter_success_resets() -> None:
    lim = LoginLimiter()
    ip = "5.6.7.8"
    lim.record_failure(ip)
    lim.record_failure(ip)
    lim.record_success(ip)
    assert lim.is_locked(ip) is False
    # And the next failure isn't carried over.
    for _ in range(MAX_FAILED - 1):
        lim.record_failure(ip)
    assert lim.is_locked(ip) is False
