"""Tests for the service-state evaluation (OK/WARN/CRIT thresholds)."""

from __future__ import annotations

from app.checks import CheckState, evaluate_checks
from app.checks.evaluate import (
    cpu_check,
    disk_checks,
    firmware_check,
    gateway_checks,
    ipsec_checks,
    memory_check,
    ntp_check,
    pf_states_check,
    swap_check,
)
from app.xsense.schemas import (
    CpuUsage,
    DiskUsage,
    FirmwareStatus,
    GatewayStatus,
    IPsecServiceStatus,
    IPsecTunnel,
    MemoryUsage,
    NtpStatus,
    PfStatus,
    SystemStatus,
)


def test_swap_check_skips_without_swap_device() -> None:
    assert swap_check(MemoryUsage(swap_total_mb=0)) is None  # no data → no check


def test_swap_thresholds() -> None:
    assert swap_check(MemoryUsage(swap_total_mb=1024, swap_used_pct=10)).state == CheckState.OK
    assert swap_check(MemoryUsage(swap_total_mb=1024, swap_used_pct=50)).state == CheckState.WARN
    assert swap_check(MemoryUsage(swap_total_mb=1024, swap_used_pct=80)).state == CheckState.CRIT


def test_pf_states_skips_without_data() -> None:
    assert pf_states_check(PfStatus(states_limit=0)) is None


def test_pf_states_thresholds() -> None:
    assert pf_states_check(PfStatus(states_limit=1000, states_pct=10)).state == CheckState.OK
    assert pf_states_check(PfStatus(states_limit=1000, states_pct=85)).state == CheckState.WARN
    assert pf_states_check(PfStatus(states_limit=1000, states_pct=96)).state == CheckState.CRIT


def test_ntp_skips_without_data() -> None:
    assert ntp_check(NtpStatus(stratum=-1)) is None  # no ntpq data


def test_ntp_unsynced_is_warn_not_crit() -> None:
    # A reachable-but-unsynced clock (stratum 16) must never read CRIT.
    c = ntp_check(NtpStatus(stratum=16, synced=False))
    assert c is not None and c.state == CheckState.WARN


def test_ntp_synced_ok() -> None:
    c = ntp_check(NtpStatus(stratum=2, synced=True, offset_ms=1.2, peer="1.2.3.4"))
    assert c is not None and c.state == CheckState.OK
    assert "1.2.3.4" in c.summary


def test_service_checks_vital_and_dns() -> None:
    from app.checks.evaluate import service_checks
    from app.xsense.schemas import ServiceInfo

    assert service_checks([]) == []  # no data → no checks
    svcs = [
        ServiceInfo(name="sshd", running=True),
        ServiceInfo(name="configd", running=False),
        ServiceInfo(name="unbound", running=True),
        ServiceInfo(name="dnsmasq", running=False),  # unused resolver → not an alert
        ServiceInfo(name="iperf", running=False),  # non-vital → ignored
    ]
    by_key = {c.key: c.state for c in service_checks(svcs)}
    assert by_key["service:sshd"] == CheckState.OK
    assert by_key["service:configd"] == CheckState.CRIT
    assert by_key["service:dns"] == CheckState.OK  # unbound up → resolver present
    assert "service:iperf" not in by_key


def test_service_checks_dns_all_down_is_crit() -> None:
    from app.checks.evaluate import service_checks
    from app.xsense.schemas import ServiceInfo

    out = service_checks([ServiceInfo(name="unbound", running=False)])
    assert any(c.key == "service:dns" and c.state == CheckState.CRIT for c in out)


def test_diff_checks_baseline_and_transitions() -> None:
    from app.checks.history import current_states, diff_checks
    from app.checks.models import ServiceCheck

    checks = [
        ServiceCheck(key="memory", state=0, summary="ok"),
        ServiceCheck(key="cpu", state=0, summary="ok"),
    ]
    # No baseline yet → no events (avoids first-push / restart spam).
    assert diff_checks(None, checks) == []

    baseline = current_states(checks)
    # No change → no events.
    assert diff_checks(baseline, checks) == []

    # memory goes CRIT → one transition 0→2; cpu unchanged → not reported.
    changed = [
        ServiceCheck(key="memory", state=2, summary="crit"),
        ServiceCheck(key="cpu", state=0, summary="ok"),
    ]
    evs = diff_checks(baseline, changed)
    assert len(evs) == 1
    assert (evs[0].check_key, evs[0].old_state, evs[0].new_state) == ("memory", 0, 2)


def test_diff_checks_new_problem_vs_new_ok() -> None:
    from app.checks.history import diff_checks
    from app.checks.models import ServiceCheck

    # A brand-new key absent from the baseline: OK is silent, a problem emits.
    base = {"memory": 0}
    new_ok = diff_checks(base, [ServiceCheck(key="gateway:WAN", state=0, summary="ok")])
    assert new_ok == []
    new_bad = diff_checks(base, [ServiceCheck(key="gateway:WAN", state=2, summary="down")])
    assert len(new_bad) == 1 and new_bad[0].new_state == 2


def test_cert_checks_thresholds() -> None:
    from app.checks.evaluate import cert_checks
    from app.xsense.schemas import CertInfo

    states = {
        c.key: c.state
        for c in cert_checks(
            [
                CertInfo(refid="a", name="ok", days_remaining=200),
                CertInfo(refid="b", name="soon", days_remaining=20),
                CertInfo(refid="c", name="urgent", days_remaining=3),
                CertInfo(refid="d", name="dead", days_remaining=-5),
            ]
        )
    }
    assert states["cert:a"] == CheckState.OK
    assert states["cert:b"] == CheckState.WARN
    assert states["cert:c"] == CheckState.CRIT
    assert states["cert:d"] == CheckState.CRIT  # expired


def test_memory_thresholds() -> None:
    assert memory_check(MemoryUsage(used_pct=50)).state == CheckState.OK
    assert memory_check(MemoryUsage(used_pct=80)).state == CheckState.WARN
    assert memory_check(MemoryUsage(used_pct=95)).state == CheckState.CRIT
    c = memory_check(MemoryUsage(used_pct=95))
    assert c.metrics[0].name == "mem_used_pct"
    assert c.metrics[0].crit == 90.0


def test_cpu_warns_only() -> None:
    assert cpu_check(CpuUsage(total=99)).state == CheckState.WARN
    assert cpu_check(CpuUsage(total=90)).state == CheckState.OK  # spiky → never crit


def test_disk_thresholds_and_label() -> None:
    checks = disk_checks(
        [DiskUsage(mountpoint="/", used_pct=91), DiskUsage(mountpoint="/var", used_pct=10)]
    )
    by_key = {c.key: c for c in checks}
    assert by_key["disk:/"].state == CheckState.CRIT
    assert by_key["disk:/var"].state == CheckState.OK


def test_gateway_down_is_crit() -> None:
    c = gateway_checks([GatewayStatus(name="WAN", status="down", loss="100%")])[0]
    assert c.key == "gateway:WAN"
    assert c.state == CheckState.CRIT


def test_gateway_loss_warn_crit() -> None:
    warn = gateway_checks([GatewayStatus(name="W", status="online", loss="25%")])[0]
    crit = gateway_checks([GatewayStatus(name="W", status="online", loss="90%")])[0]
    ok = gateway_checks([GatewayStatus(name="W", status="online", loss="0.0%")])[0]
    assert (warn.state, crit.state, ok.state) == (CheckState.WARN, CheckState.CRIT, CheckState.OK)


def test_gateway_loss_unparseable_is_ok_no_perfdata() -> None:
    c = gateway_checks([GatewayStatus(name="W", status="online", loss="")])[0]
    assert c.state == CheckState.OK
    assert c.metrics == []


def test_ipsec_service_and_tunnels() -> None:
    ip = IPsecServiceStatus(
        running=True,
        tunnels=[
            IPsecTunnel(id="1", description="up-tunnel", phase1_status="ESTABLISHED"),
            IPsecTunnel(id="2", description="down-tunnel", phase1_status="connecting"),
        ],
    )
    checks = {c.key: c for c in ipsec_checks(ip)}
    assert checks["ipsec.service"].state == CheckState.OK
    assert checks["ipsec.tunnel:up-tunnel"].state == CheckState.OK
    assert checks["ipsec.tunnel:down-tunnel"].state == CheckState.CRIT


def test_ipsec_service_down_is_crit() -> None:
    assert ipsec_checks(IPsecServiceStatus(running=False))[0].state == CheckState.CRIT


def test_firmware_update_warns() -> None:
    assert (
        firmware_check(FirmwareStatus(product_version="25.7", upgrade_available=False)).state
        == CheckState.OK
    )
    assert (
        firmware_check(FirmwareStatus(product_version="25.7", upgrade_available=True)).state
        == CheckState.WARN
    )


def test_evaluate_aggregates_and_skips_missing() -> None:
    status = SystemStatus(memory=MemoryUsage(used_pct=10), cpu=CpuUsage(total=5))
    # only memory + cpu when nothing else supplied
    keys = {c.key for c in evaluate_checks(status)}
    assert keys == {"memory", "cpu"}

    full = evaluate_checks(
        status,
        gateways=[GatewayStatus(name="WAN", status="online", loss="0%")],
        ipsec=IPsecServiceStatus(running=True),
        firmware=FirmwareStatus(product_version="25.7", upgrade_available=False),
    )
    keys = {c.key for c in full}
    assert {"memory", "cpu", "gateway:WAN", "ipsec.service", "firmware"} <= keys


def test_service_alert_model_and_severity() -> None:
    """ServiceAlert carries instance info + exclusion metadata (used by /checks)."""
    from app.checks import ServiceAlert

    a = ServiceAlert(
        instance_id=7,
        instance_name="fw-01",
        key="gateway:WAN",
        state=2,
        summary="Gateway WAN down",
        excluded=True,
        excluded_by="specific",
    )
    assert a.instance_id == 7
    assert a.excluded is True
    assert a.excluded_by == "specific"
    assert a.state == 2

    # Replicate the sort key used in the route
    def _sev(s: int) -> int:
        return 3 if s == 2 else 2 if s == 1 else 1 if s == 3 else 0

    assert _sev(2) > _sev(1) > _sev(3) > _sev(0)
