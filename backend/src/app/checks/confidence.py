"""Confidence model: fold agent freshness + out-of-band probe into ping/http checks.

The probe is FRESH (just measured), so unlike the stale sub-states it is **not**
capped by the staleness overlay — it is the very signal that justifies CRIT while
the agent is silent. The rule:

    confirmed-up (agent fresh OR ICMP reply) → a failing probe is only WARN
    (the box is provably alive — a misconfigured target or a dead web service,
    not an outage);
    otherwise a failed probe is CRIT (confirmed down, nothing says it's up).

So: agent stale + ICMP down = CRIT (real outage); agent stale + ICMP up = the box
is reachable but its agent is dead (WARN); agent fresh + probe down = WARN (the box
is pushing telemetry, so the probe target is suspect, not the box).
"""

from __future__ import annotations

from app.checks.models import CheckState, PerfMetric, ServiceCheck
from app.probe import ProbeResult


def probe_checks(agent_fresh: bool, probe: ProbeResult | None) -> list[ServiceCheck]:
    """The ``ping`` / ``http`` service checks for one instance's probe result.

    Empty when there is no probe target or it wasn't measured.
    """
    if probe is None or not probe.probed:
        return []
    confirmed_up = agent_fresh or probe.icmp_up is True
    out: list[ServiceCheck] = []
    if probe.icmp_up is not None:
        out.append(_icmp_check(probe, confirmed_up))
    if probe.http_up is not None:
        out.append(_http_check(probe, confirmed_up))
    return out


def _down_state(confirmed_up: bool) -> CheckState:
    """A failed probe is WARN when something else confirms the box is up, else CRIT."""
    return CheckState.WARN if confirmed_up else CheckState.CRIT


def _icmp_check(probe: ProbeResult, confirmed_up: bool) -> ServiceCheck:
    metrics = (
        [PerfMetric(name="rtt_ms", value=round(probe.rtt_ms, 2), unit="ms")]
        if probe.rtt_ms is not None
        else []
    )
    if probe.icmp_up:
        rtt = f" ({probe.rtt_ms:.1f}ms)" if probe.rtt_ms is not None else ""
        return ServiceCheck(
            key="ping", state=int(CheckState.OK), summary=f"ICMP reachable{rtt}", metrics=metrics
        )
    extra = " — box reachable by other means" if confirmed_up else ""
    return ServiceCheck(
        key="ping",
        state=int(_down_state(confirmed_up)),
        summary=f"ICMP no echo reply{extra}",
    )


def _http_check(probe: ProbeResult, confirmed_up: bool) -> ServiceCheck:
    if probe.http_up:
        return ServiceCheck(
            key="http",
            state=int(CheckState.OK),
            summary=f"HTTP {probe.http_status} reachable",
        )
    code = f" (status {probe.http_status})" if probe.http_status is not None else ""
    extra = " — box reachable by other means" if confirmed_up else ""
    return ServiceCheck(
        key="http",
        state=int(_down_state(confirmed_up)),
        summary=f"HTTP probe failed{code}{extra}",
    )
