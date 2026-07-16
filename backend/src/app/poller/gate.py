"""Pure due/staleness gating for the per-instance poll/push scheduler.

The scheduler ticks at a fixed small cadence (``DASH_POLL_TICK_SECONDS``) and uses
these helpers to decide, per instance, whether its own effective interval has
elapsed — so each box is polled at its own rate (global default + per-instance
override) without one APScheduler job per instance.

MariaDB DATETIME columns read back naive (still UTC wall-clock); every timestamp
is tagged UTC before arithmetic so it can be compared to an aware ``now()``.
"""

from __future__ import annotations

from datetime import UTC, datetime

# A push agent is considered stale after this many missed pushes, unless the
# global ``agent_stale_seconds`` floor is larger (keeps fast agents generous).
DEFAULT_MISSED_PUSHES = 4


def as_utc(dt: datetime) -> datetime:
    """Tag a naive MariaDB datetime as UTC so it can be compared to an aware now()."""
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def effective_interval(override: int | None, default: int) -> int:
    """Per-instance override when set to a positive value, else the global default."""
    return override if override and override > 0 else default


def last_attempt(
    last_success_at: datetime | None, last_error_at: datetime | None
) -> datetime | None:
    """Newest of the two poll outcomes (tz-aware), or None if never attempted."""
    candidates = [as_utc(t) for t in (last_success_at, last_error_at) if t is not None]
    return max(candidates, default=None)


def is_due(
    now: datetime,
    last_success_at: datetime | None,
    last_error_at: datetime | None,
    interval_seconds: int,
) -> bool:
    """True when the instance's effective interval has elapsed since the last attempt.

    Gating on the *last attempt* (success or error) means a failing box retries on
    its own interval instead of being hammered every tick.
    """
    last = last_attempt(last_success_at, last_error_at)
    if last is None:
        return True
    return (now - last).total_seconds() >= interval_seconds


def stale_threshold(
    push_interval: int | None,
    default_push: int,
    base_stale_seconds: int,
    missed: int = DEFAULT_MISSED_PUSHES,
) -> int:
    """Seconds of agent silence tolerated before a push instance is marked offline.

    Scales with the instance's effective push interval so a deliberately slow agent
    (e.g. 300s) is not flagged stale at the global floor.
    """
    return max(base_stale_seconds, missed * effective_interval(push_interval, default_push))


def is_stale(
    now: datetime,
    agent_last_seen: datetime | None,
    threshold_seconds: int,
    ignore_before: datetime | None = None,
) -> bool:
    """True when the agent has been silent longer than its scaled threshold.

    ``ignore_before`` caps how far back silence is counted — pass the backend
    process start time: silence accrued while the backend itself was down is
    not agent silence. Without the cap, every push instance is flagged offline
    on the first tick after a restart, before its agent had a chance to
    reconnect (incident 2026-07-12: a 5-minute container outage produced a
    140-message offline/recovered storm in Mattermost for a 50+ box fleet).
    Genuinely dead agents still alert ``threshold_seconds`` after boot.
    """
    if agent_last_seen is None:
        return False
    reference = as_utc(agent_last_seen)
    if ignore_before is not None and ignore_before > reference:
        reference = ignore_before
    return (now - reference).total_seconds() > threshold_seconds


def agent_age_seconds(now: datetime, agent_last_seen: datetime | None) -> int | None:
    """Whole seconds since the agent last reported, or None if it never has."""
    if agent_last_seen is None:
        return None
    return int((now - as_utc(agent_last_seen)).total_seconds())
