"""Tests for Phase-2 child ingest + ping-monitor service checks."""

from __future__ import annotations

from app.agent_hub.hub import ipsec_from_agent
from app.checks import CheckState
from app.checks.evaluate import ipsec_checks
from app.xsense.schemas import IPsecChild, IPsecServiceStatus, IPsecTunnel


def _tunnel_with_child(ping_state: str, **child_kw) -> IPsecServiceStatus:
    child = IPsecChild(
        name="c-a",
        local_ts="10.1.1.0/24",
        remote_ts="10.2.2.0/24",
        ping_state=ping_state,
        **child_kw,
    )
    return IPsecServiceStatus(
        running=True,
        tunnels=[
            IPsecTunnel(
                id="con1",
                description="site-a",
                phase1_status="ESTABLISHED",
                phase2_up=1,
                phase2_total=1,
                children=[child],
            )
        ],
    )


# --- ingest ------------------------------------------------------------------


def test_ipsec_from_agent_parses_children() -> None:
    data = {
        "ipsec": {
            "running": True,
            "tunnels": [
                {
                    "id": "con1",
                    "status": "established",
                    "children": [
                        {
                            "name": "c-a",
                            "local_ts": "10.1.1.0/24",
                            "remote_ts": "10.2.2.0/24",
                            "state": "INSTALLED",
                            "suggested_source": "10.1.1.1",
                            "ping_state": "ok",
                            "ping_rtt_ms": 1.5,
                            "ping_loss_pct": 0.0,
                            "ping_ts": "2026-06-26T00:00:00+00:00",
                        }
                    ],
                }
            ],
        }
    }
    status = ipsec_from_agent(data)
    child = status.tunnels[0].children[0]
    assert child.name == "c-a"
    assert child.state == "INSTALLED"
    assert child.suggested_source == "10.1.1.1"
    assert child.ping_state == "ok"
    assert child.ping_rtt_ms == 1.5


def test_ipsec_from_agent_tolerates_no_children() -> None:
    status = ipsec_from_agent({"ipsec": {"running": True, "tunnels": [{"id": "c"}]}})
    assert status.tunnels[0].children == []


# --- ping checks -------------------------------------------------------------


def test_ping_fail_is_crit_even_when_phase2_up() -> None:
    checks = {c.key: c for c in ipsec_checks(_tunnel_with_child("fail"))}
    key = "ipsec.tunnel_ping:site-a/10.2.2.0/24"
    assert checks[key].state == CheckState.CRIT
    # the plain phase-1 tunnel check is still OK — the ping check is the signal
    assert checks["ipsec.tunnel:site-a"].state == CheckState.OK


def test_ping_error_is_warn() -> None:
    checks = {c.key: c for c in ipsec_checks(_tunnel_with_child("error"))}
    assert checks["ipsec.tunnel_ping:site-a/10.2.2.0/24"].state == CheckState.WARN


def test_ping_ok_emits_perfdata() -> None:
    status = _tunnel_with_child("ok", ping_rtt_ms=2.0, ping_loss_pct=0.0)
    check = {c.key: c for c in ipsec_checks(status)}["ipsec.tunnel_ping:site-a/10.2.2.0/24"]
    assert check.state == CheckState.OK
    names = {m.name for m in check.metrics}
    assert names == {"ping_rtt_ms", "ping_loss_pct"}


def test_ping_none_is_skipped() -> None:
    keys = {c.key for c in ipsec_checks(_tunnel_with_child("none"))}
    assert not any(k.startswith("ipsec.tunnel_ping:") for k in keys)
