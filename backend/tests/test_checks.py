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
)
from app.xsense.schemas import (
    CpuUsage,
    DiskUsage,
    FirmwareStatus,
    GatewayStatus,
    IPsecServiceStatus,
    IPsecTunnel,
    MemoryUsage,
    SystemStatus,
)


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
