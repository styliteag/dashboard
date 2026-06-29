"""Agent-staleness overlay for evaluated checks.

A push instance whose agent has gone silent still serves its last-known
sub-states from the hub cache. Those values are stale — *unknown*, not
necessarily down. This module turns that into Checkmk-honest output:

* an explicit ``agent`` service (OK while fresh, WARN once silent past its
  scaled threshold) so the host summary goes yellow the moment contact is lost;
  and
* a severity ceiling on every other check while stale: CRIT is capped to WARN,
  because a "down" verdict on stale data is a guess, not a fact.

OK stays OK (we keep the last value), so a stale host reads yellow via the one
``agent`` service rather than emitting a wall of yellow across every sub-state.

The same :func:`staleness_for` also drives the ``stale`` flag on the instance
API — staleness is one concept with one source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.checks.models import CheckState, ServiceCheck
from app.poller.gate import agent_age_seconds, is_stale, stale_threshold


class _InstanceLike(Protocol):
    agent_mode: bool
    agent_last_seen: datetime | None
    push_interval_seconds: int | None


class _SettingsLike(Protocol):
    push_interval_seconds: int
    agent_stale_seconds: int


@dataclass(frozen=True)
class Staleness:
    """Resolved agent freshness for one push instance."""

    stale: bool
    age_seconds: int
    threshold: int


def staleness_for(inst: _InstanceLike, settings: _SettingsLike, now: datetime) -> Staleness | None:
    """Agent staleness for a push instance, or None when the concept doesn't apply.

    Returns None for direct/relay-poll instances and for push instances whose
    agent has never reported (nothing to be stale about yet). The threshold scales
    with the instance's effective push interval, floored at ``agent_stale_seconds``
    — matching the watchdog so the API/export agree with the offline flip.
    """
    if not inst.agent_mode or inst.agent_last_seen is None:
        return None
    threshold = stale_threshold(
        inst.push_interval_seconds,
        settings.push_interval_seconds,
        settings.agent_stale_seconds,
    )
    age = agent_age_seconds(now, inst.agent_last_seen)
    return Staleness(
        stale=is_stale(now, inst.agent_last_seen, threshold),
        age_seconds=age if age is not None else 0,
        threshold=threshold,
    )


def _agent_check(s: Staleness) -> ServiceCheck:
    if s.stale:
        return ServiceCheck(
            key="agent",
            state=int(CheckState.WARN),
            summary=(
                f"Agent silent for {s.age_seconds}s (>{s.threshold}s) — sub-state data is stale"
            ),
        )
    return ServiceCheck(
        key="agent",
        state=int(CheckState.OK),
        summary=f"Agent reporting ({s.age_seconds}s ago)",
    )


def apply_staleness(checks: list[ServiceCheck], s: Staleness | None) -> list[ServiceCheck]:
    """Prepend the ``agent`` service and, while stale, cap CRIT→WARN on the rest.

    Returns the input list unchanged (same object) when ``s`` is None — a
    direct-poll instance has no agent to be stale. Never mutates the input
    checks: capped checks are produced as copies.
    """
    if s is None:
        return checks
    agent = _agent_check(s)
    if not s.stale:
        return [agent, *checks]
    capped = [
        c
        if c.state != int(CheckState.CRIT)
        else c.model_copy(
            update={
                "state": int(CheckState.WARN),
                "summary": f"{c.summary} (stale: agent silent {s.age_seconds}s)",
            }
        )
        for c in checks
    ]
    return [agent, *capped]
