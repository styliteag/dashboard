"""Agent collection-runtime check: WARN when a push cycle takes too long.

Complements the staleness check (which catches a *silent* agent) by catching a
*slow-but-alive* one — a degrading collector (e.g. cert enumeration ballooning)
shows here as rising collection time before the agent ever goes silent. Push
agents only: direct-poll instances carry no ``collect_ms``, so no check is made.

Pure + DB-free, like the rest of ``app.checks``.
"""

from __future__ import annotations

from app.checks.models import CheckState, PerfMetric, ServiceCheck
from app.xsense.schemas import SystemStatus

# WARN-only: a slow cycle is a heads-up, not an outage (and WARN never trips the
# staleness CRIT->WARN cap). 10s is a third of the default 30s push interval —
# past it, collection eats a real slice of every cycle.
_COLLECT_WARN_MS = 10_000.0


def agent_collect_check(status: SystemStatus) -> ServiceCheck | None:
    """WARN when the agent's whole collection cycle took >= 10s. Returns None on the
    direct-poll path (no agent runtime to report). Only the whole-cycle total is
    emitted as perfdata; per-section timings are shown live on the Agent tab, and
    the slowest one is named in the WARN summary."""
    if status.collect_ms is None:
        return None
    total = float(status.collect_ms)
    sections = sorted(status.section_ms.items(), key=lambda kv: kv[1], reverse=True)
    metrics = [PerfMetric(name="collect_ms", value=total, warn=_COLLECT_WARN_MS, unit="ms")]

    if total >= _COLLECT_WARN_MS:
        slow = sections[0] if sections else None
        hint = f" — slowest: {slow[0]} {slow[1] / 1000:.1f}s" if slow else ""
        return ServiceCheck(
            key="agent.collect",
            state=int(CheckState.WARN),
            summary=(
                f"Agent collection took {total / 1000:.1f}s (>{_COLLECT_WARN_MS / 1000:.0f}s){hint}"
            ),
            metrics=metrics,
        )
    return ServiceCheck(
        key="agent.collect",
        state=int(CheckState.OK),
        summary=f"Agent collection {total / 1000:.1f}s",
        metrics=metrics,
    )
