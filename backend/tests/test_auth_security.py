"""Unit tests for password hashing + brute-force limiter."""

from __future__ import annotations

import app.auth.security as security
from app.auth.security import (
    MAX_FAILED,
    LoginLimiter,
    hash_password,
    verify_password,
    verify_password_constant_time,
)


def test_hash_and_verify() -> None:
    h = hash_password("hunter2hunter2")
    assert verify_password("hunter2hunter2", h)
    assert not verify_password("wrong", h)


def test_constant_time_verify_matches_real_hash() -> None:
    h = hash_password("correct-horse-battery")
    assert verify_password_constant_time("correct-horse-battery", h) is True
    assert verify_password_constant_time("wrong", h) is False


def test_constant_time_verify_runs_argon2_for_absent_user(monkeypatch) -> None:
    # No user → must still spend one Argon2 verify (against the dummy hash), else
    # response latency leaks which usernames exist.
    seen: list[str] = []
    real = security.verify_password

    def spy(password: str, password_hash: str) -> bool:
        seen.append(password_hash)
        return real(password, password_hash)

    monkeypatch.setattr(security, "verify_password", spy)
    assert security.verify_password_constant_time("anything", None) is False
    assert seen == [security._DUMMY_HASH]  # verified against the dummy, not skipped


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
