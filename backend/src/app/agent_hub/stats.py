"""In-process hub self-monitoring: connection churn, push rate, error counters.

Backs GET /api/hub/stats (the hub observability page). Everything here is
in-memory and process-local BY DESIGN: the page answers "is the hub healthy
right now", not "what happened last week" — a backend restart resets the
numbers, and ``started_at`` makes that reset visible in the UI.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# Length of the pushes-per-minute window served to the UI chart.
RATE_WINDOW_MINUTES = 60

# The full counter vocabulary. record() rejects anything else so a typo in an
# instrumentation call fails loudly in tests instead of minting a new counter.
KNOWN_COUNTERS = (
    "connects",
    "disconnects",
    "auth_failures",
    "pushes",
    "command_results",
    "tunnel_frames",
    "pongs",
    "unknown_messages",
    "json_errors",
    "handler_errors",
    "ws_errors",
)


class HubStats:
    """Monotonic counters + a rolling pushes-per-minute window."""

    def __init__(self, now: datetime | None = None) -> None:
        self.reset(now=now)

    def reset(self, now: datetime | None = None) -> None:
        self.started_at = now or datetime.now(UTC)
        self._counters: dict[str, int] = dict.fromkeys(KNOWN_COUNTERS, 0)
        self._push_buckets: dict[datetime, int] = {}  # UTC minute → push count

    def record(self, counter: str) -> None:
        self._counters[counter] += 1  # KeyError on unknown counter — intended

    def record_push(self, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        self.record("pushes")
        minute = now.replace(second=0, microsecond=0)
        self._push_buckets[minute] = self._push_buckets.get(minute, 0) + 1
        self._prune(minute)

    def counters_snapshot(self) -> dict[str, int]:
        return dict(self._counters)

    def push_rate(self, now: datetime | None = None) -> list[dict]:
        """Zero-filled per-minute push counts, oldest first, current minute last."""
        now = now or datetime.now(UTC)
        newest = now.replace(second=0, microsecond=0)
        self._prune(newest)
        minutes = [newest - timedelta(minutes=i) for i in range(RATE_WINDOW_MINUTES - 1, -1, -1)]
        return [{"ts": m.isoformat(), "count": self._push_buckets.get(m, 0)} for m in minutes]

    def _prune(self, newest: datetime) -> None:
        cutoff = newest - timedelta(minutes=RATE_WINDOW_MINUTES - 1)
        for minute in [m for m in self._push_buckets if m < cutoff]:
            del self._push_buckets[minute]


stats = HubStats()
