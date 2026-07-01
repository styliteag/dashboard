"""Collapse high-fan-out checks into one aggregate per category for the Checkmk
export. A firewall with hundreds of certs/tunnels then shows a handful of services
instead of one per item: each aggregate takes the worst member state and names the
offenders in its summary so the admin sees exactly what is wrong. Export-only — the
dashboard and the /checks list stay granular. Pure + DB-free.
"""

from __future__ import annotations

from app.checks.models import CheckState, PerfMetric, ServiceCheck

# Key category (text before the first ':') -> (aggregate key, human label). Only
# these high-fan-out families collapse; every other key (memory, cpu, agent,
# firmware, ipsec.service, ...) has no ':' and passes through as its own service.
_AGG: dict[str, tuple[str, str]] = {
    "cert": ("certs", "Certificates"),
    "ipsec.tunnel": ("ipsec.tunnels", "IPsec tunnels"),
    "ipsec.tunnel_ping": ("ipsec.pings", "IPsec pings"),
    "service": ("services", "Services"),
    "iface_errors": ("iface_errors", "Interface errors"),
    "gateway": ("gateways", "Gateways"),
    "connectivity": ("connectivity", "Connectivity"),
    "disk": ("disks", "Disks"),
}
_LABEL = {key: label for (key, label) in _AGG.values()}

# Worst-wins + offender ordering. Mirrors checks.routes._sev: CRIT > WARN > UNKNOWN > OK.
_RANK = {
    int(CheckState.CRIT): 3,
    int(CheckState.WARN): 2,
    int(CheckState.UNKNOWN): 1,
    int(CheckState.OK): 0,
}
_WORD = {
    int(CheckState.OK): "OK",
    int(CheckState.WARN): "WARN",
    int(CheckState.CRIT): "CRIT",
    int(CheckState.UNKNOWN): "UNKNOWN",
}
# Offenders named inline before the rest are summarised as "(+N more)". Keeps the
# one-line Checkmk summary readable even when many members fail.
_MAX_NAMED = 8

_STATES = (
    int(CheckState.CRIT),
    int(CheckState.WARN),
    int(CheckState.UNKNOWN),
    int(CheckState.OK),
)


def _category(key: str) -> str | None:
    head, sep, _ = key.partition(":")
    return head if sep else None


def aggregate_for_checkmk(checks: list[ServiceCheck]) -> list[ServiceCheck]:
    """Collapse each aggregatable category into one ServiceCheck and pass everything
    else through unchanged. Passthrough keeps input order; aggregates follow, in the
    order their category was first seen."""
    groups: dict[str, list[ServiceCheck]] = {}
    order: list[str] = []
    passthrough: list[ServiceCheck] = []
    for c in checks:
        cat = _category(c.key)
        agg = _AGG.get(cat) if cat else None
        if agg is None:
            passthrough.append(c)
            continue
        agg_key = agg[0]
        if agg_key not in groups:
            groups[agg_key] = []
            order.append(agg_key)
        groups[agg_key].append(c)
    return passthrough + [_build(k, groups[k]) for k in order]


def _build(agg_key: str, members: list[ServiceCheck]) -> ServiceCheck:
    label = _LABEL[agg_key]
    states = [m.state for m in members]
    worst = max(states, key=lambda s: _RANK.get(s, 0))
    total = len(members)
    counts = {st: sum(1 for s in states if s == st) for st in _STATES}
    metrics = [
        PerfMetric(name="crit", value=float(counts[int(CheckState.CRIT)])),
        PerfMetric(name="warn", value=float(counts[int(CheckState.WARN)])),
        PerfMetric(name="total", value=float(total)),
    ]

    if worst == int(CheckState.OK):
        return ServiceCheck(
            key=agg_key, state=worst, summary=f"{label}: all {total} OK", metrics=metrics
        )

    breakdown = ", ".join(f"{counts[st]} {_WORD[st]}" for st in _STATES if counts[st])
    offenders = sorted(
        (m for m in members if m.state != int(CheckState.OK)),
        key=lambda m: _RANK.get(m.state, 0),
        reverse=True,
    )
    named = "; ".join(f"{_WORD[m.state]} {m.summary}" for m in offenders[:_MAX_NAMED])
    more = f"; (+{len(offenders) - _MAX_NAMED} more)" if len(offenders) > _MAX_NAMED else ""
    return ServiceCheck(
        key=agg_key,
        state=worst,
        summary=f"{label}: {breakdown} · {named}{more}",
        metrics=metrics,
    )
