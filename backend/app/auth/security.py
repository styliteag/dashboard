"""Password hashing + login rate limiter (US-1.4).

Argon2id is the recommended modern KDF; ``argon2-cffi`` defaults are sane.

The login limiter is intentionally a simple in-memory dict keyed by source IP.
This is fine for a single backend container managing one admin. If we ever
scale to multiple replicas, swap for a Redis-backed limiter.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()

# US-1.4 thresholds
MAX_FAILED = 5
WINDOW_SECONDS = 15 * 60
LOCK_SECONDS = 15 * 60


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        _hasher.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001 — never leak hash internals to caller
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


@dataclass
class _IpState:
    failures: list[float] = field(default_factory=list)
    locked_until: float = 0.0


class LoginLimiter:
    """In-memory IP-based brute-force limiter."""

    def __init__(self) -> None:
        self._state: dict[str, _IpState] = {}
        self._lock = Lock()

    def is_locked(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            st = self._state.get(ip)
            return bool(st and st.locked_until > now)

    def record_failure(self, ip: str) -> bool:
        """Record a failed login. Returns True iff this triggered a new lock."""
        now = time.monotonic()
        with self._lock:
            st = self._state.setdefault(ip, _IpState())
            # Drop failures outside the window.
            st.failures = [t for t in st.failures if now - t < WINDOW_SECONDS]
            st.failures.append(now)
            if len(st.failures) >= MAX_FAILED and st.locked_until <= now:
                st.locked_until = now + LOCK_SECONDS
                return True
            return False

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._state.pop(ip, None)


limiter = LoginLimiter()
