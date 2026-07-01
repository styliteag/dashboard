"""Checkmk aggregation: high-fan-out categories collapse to one worst-wins service."""

from __future__ import annotations

from app.checks.aggregate import aggregate_for_checkmk
from app.checks.models import CheckState, ServiceCheck


def _c(key: str, state: CheckState, summary: str = "") -> ServiceCheck:
    return ServiceCheck(key=key, state=int(state), summary=summary or key)


def _by_key(checks: list[ServiceCheck]) -> dict[str, ServiceCheck]:
    return {c.key: c for c in checks}


def test_singletons_pass_through_unchanged() -> None:
    ins = [
        _c("memory", CheckState.OK),
        _c("cpu", CheckState.WARN),
        _c("agent.collect", CheckState.OK),
    ]
    out = aggregate_for_checkmk(ins)
    assert out == ins  # no ':' category → untouched, order kept


def test_certs_collapse_to_worst_state() -> None:
    ins = [
        _c("cert:a", CheckState.OK, "cert A valid for 90d"),
        _c("cert:b", CheckState.CRIT, "cert B expired"),
        _c("cert:c", CheckState.WARN, "cert C expires in 5d"),
    ]
    out = _by_key(aggregate_for_checkmk(ins))
    assert "certs" in out and "cert:a" not in out  # collapsed
    agg = out["certs"]
    assert agg.state == int(CheckState.CRIT)  # worst wins
    assert "1 CRIT" in agg.summary and "1 WARN" in agg.summary and "1 OK" in agg.summary
    assert "cert B expired" in agg.summary  # worst offender named first
    # perfdata carries the counts for a Checkmk trend
    m = {p.name: p.value for p in agg.metrics}
    assert m["crit"] == 1.0 and m["warn"] == 1.0 and m["total"] == 3.0


def test_all_ok_summary_is_compact() -> None:
    ins = [_c("service:sshd", CheckState.OK), _c("service:unbound", CheckState.OK)]
    agg = _by_key(aggregate_for_checkmk(ins))["services"]
    assert agg.state == int(CheckState.OK)
    assert agg.summary == "Services: all 2 OK"


def test_categories_collapse_independently() -> None:
    ins = [
        _c("cert:a", CheckState.OK),
        _c("gateway:WAN", CheckState.CRIT),
        _c("ipsec.tunnel:t1", CheckState.WARN),
        _c("ipsec.tunnel_ping:t1/sel", CheckState.OK),
        _c("ipsec.service", CheckState.OK),  # singleton — no ':' → stays
        _c("memory", CheckState.OK),
    ]
    out = _by_key(aggregate_for_checkmk(ins))
    assert set(out) == {
        "certs",
        "gateways",
        "ipsec.tunnels",
        "ipsec.pings",
        "ipsec.service",
        "memory",
    }
    assert out["gateways"].state == int(CheckState.CRIT)
    assert out["ipsec.tunnels"].state == int(CheckState.WARN)
    assert out["ipsec.service"].key == "ipsec.service"  # untouched singleton


def test_many_offenders_are_truncated() -> None:
    ins = [_c(f"cert:{i}", CheckState.CRIT, f"cert {i} expired") for i in range(12)]
    agg = _by_key(aggregate_for_checkmk(ins))["certs"]
    assert agg.state == int(CheckState.CRIT)
    assert "(+4 more)" in agg.summary  # 12 offenders, 8 named


def test_empty_input() -> None:
    assert aggregate_for_checkmk([]) == []
