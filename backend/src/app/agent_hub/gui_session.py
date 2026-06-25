"""Short-lived server-side stash for firewall WebUI session cookies (see §18).

The agent replays the firewall's WebUI login and returns its session cookie. We
must hand that cookie to the browser as a Set-Cookie on the proxy origin — but it
must NEVER travel in the handoff URL (it would leak via access logs / Referer). So
``gui/open`` stashes it here keyed by the one-time handoff token, and ``gui/handoff``
pops it and sets the cookie. Entries are single-use and expire with the token.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class _Entry:
    cookies: tuple[tuple[str, str], ...]
    expires_at: float


class GuiSessionStash:
    """In-memory, single-use map of handoff token -> firewall session cookies."""

    def __init__(self) -> None:
        self._store: dict[str, _Entry] = {}

    def put(self, token: str, cookies: list[dict], ttl_seconds: float) -> None:
        self._prune()  # bound memory: an abandoned open (no handoff) can't linger
        pairs = tuple((c["name"], c["value"]) for c in cookies if c.get("name"))
        if not pairs:
            return
        self._store[token] = _Entry(pairs, time.monotonic() + ttl_seconds)

    def pop(self, token: str) -> list[tuple[str, str]]:
        """Return + remove the cookies for this token (empty if missing/expired)."""
        self._prune()
        entry = self._store.pop(token, None)
        if entry is None or entry.expires_at < time.monotonic():
            return []
        return list(entry.cookies)

    def _prune(self) -> None:
        now = time.monotonic()
        for key in [k for k, e in self._store.items() if e.expires_at < now]:
            self._store.pop(key, None)


gui_sessions = GuiSessionStash()
