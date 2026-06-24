"""Threshold logic: domain status → list[ServiceCheck]. Pure + DB-free."""

from __future__ import annotations

from app.checks.models import CheckState, PerfMetric, ServiceCheck
from app.opnsense.schemas import (
    CpuUsage,
    DiskUsage,
    FirmwareStatus,
    GatewayStatus,
    IPsecServiceStatus,
    MemoryUsage,
    SystemStatus,
)

# Thresholds (percent). Follow-up: make these configurable per instance/global.
_MEM_WARN, _MEM_CRIT = 80.0, 90.0
_DISK_WARN, _DISK_CRIT = 80.0, 90.0
_CPU_WARN = 95.0  # CPU is spiky — warn only, never crit
_GW_LOSS_WARN, _GW_LOSS_CRIT = 20.0, 80.0

_GW_DOWN_WORDS = ("down", "force_down", "offline")
_IPSEC_UP = {"established", "installed", "connected", "up", "1", "true", "yes"}


def _loss_pct(raw: str) -> float | None:
    """Parse a gateway loss string like '0.0%' / '100%' → float, else None."""
    s = (raw or "").strip().rstrip("%").strip()
    try:
        return float(s)
    except ValueError:
        return None


def memory_check(mem: MemoryUsage) -> ServiceCheck:
    pct = mem.used_pct
    if pct >= _MEM_CRIT:
        state, word = CheckState.CRIT, "critical"
    elif pct >= _MEM_WARN:
        state, word = CheckState.WARN, "high"
    else:
        state, word = CheckState.OK, "ok"
    return ServiceCheck(
        key="memory",
        state=int(state),
        summary=f"Memory {pct:.0f}% used ({word})",
        metrics=[
            PerfMetric(name="mem_used_pct", value=pct, warn=_MEM_WARN, crit=_MEM_CRIT, unit="%")
        ],
    )


def cpu_check(cpu: CpuUsage) -> ServiceCheck:
    pct = cpu.total
    state = CheckState.WARN if pct >= _CPU_WARN else CheckState.OK
    return ServiceCheck(
        key="cpu",
        state=int(state),
        summary=f"CPU {pct:.0f}%",
        metrics=[PerfMetric(name="cpu_used_pct", value=pct, warn=_CPU_WARN, unit="%")],
    )


def disk_checks(disks: list[DiskUsage]) -> list[ServiceCheck]:
    out: list[ServiceCheck] = []
    for d in disks:
        label = d.mountpoint or d.device or "?"
        pct = d.used_pct
        if pct >= _DISK_CRIT:
            state, word = CheckState.CRIT, "critical"
        elif pct >= _DISK_WARN:
            state, word = CheckState.WARN, "high"
        else:
            state, word = CheckState.OK, "ok"
        out.append(
            ServiceCheck(
                key=f"disk:{label}",
                state=int(state),
                summary=f"Disk {label} {pct:.0f}% used ({word})",
                metrics=[
                    PerfMetric(
                        name="disk_used_pct", value=pct, warn=_DISK_WARN, crit=_DISK_CRIT, unit="%"
                    )
                ],
            )
        )
    return out


def gateway_checks(gateways: list[GatewayStatus]) -> list[ServiceCheck]:
    out: list[ServiceCheck] = []
    for g in gateways:
        st = (g.status or "").lower()
        loss = _loss_pct(g.loss)
        if any(w in st for w in _GW_DOWN_WORDS):
            state, word = CheckState.CRIT, "down"
        elif loss is not None and loss >= _GW_LOSS_CRIT:
            state, word = CheckState.CRIT, f"loss {loss:.0f}%"
        elif loss is not None and loss >= _GW_LOSS_WARN:
            state, word = CheckState.WARN, f"loss {loss:.0f}%"
        else:
            state, word = CheckState.OK, "online"
        metrics = []
        if loss is not None:
            metrics.append(
                PerfMetric(
                    name="gw_loss_pct", value=loss, warn=_GW_LOSS_WARN, crit=_GW_LOSS_CRIT, unit="%"
                )
            )
        out.append(
            ServiceCheck(
                key=f"gateway:{g.name}",
                state=int(state),
                summary=f"Gateway {g.name} {word}",
                metrics=metrics,
            )
        )
    return out


def ipsec_checks(ipsec: IPsecServiceStatus) -> list[ServiceCheck]:
    out = [
        ServiceCheck(
            key="ipsec.service",
            state=int(CheckState.OK if ipsec.running else CheckState.CRIT),
            summary="IPsec service running" if ipsec.running else "IPsec service NOT running",
        )
    ]
    for t in ipsec.tunnels:
        up = str(t.phase1_status).strip().lower() in _IPSEC_UP
        label = t.description or t.id or "?"
        out.append(
            ServiceCheck(
                key=f"ipsec.tunnel:{label}",
                state=int(CheckState.OK if up else CheckState.CRIT),
                summary=f"Tunnel {label} {'up' if up else 'down'} ({t.phase1_status})",
            )
        )
    return out


def firmware_check(fw: FirmwareStatus) -> ServiceCheck:
    if fw.upgrade_available:
        latest = fw.product_latest or "?"
        return ServiceCheck(
            key="firmware",
            state=int(CheckState.WARN),
            summary=f"Update available: {fw.product_version} → {latest}",
        )
    return ServiceCheck(
        key="firmware",
        state=int(CheckState.OK),
        summary=f"Firmware up to date ({fw.product_version})",
    )


def evaluate_checks(
    status: SystemStatus,
    gateways: list[GatewayStatus] | None = None,
    ipsec: IPsecServiceStatus | None = None,
    firmware: FirmwareStatus | None = None,
) -> list[ServiceCheck]:
    """Evaluate all available aspects of an instance into service checks."""
    checks = [memory_check(status.memory), cpu_check(status.cpu)]
    checks += disk_checks(status.disks)
    if gateways:
        checks += gateway_checks(gateways)
    if ipsec is not None:
        checks += ipsec_checks(ipsec)
    if firmware is not None and firmware.product_version:
        checks.append(firmware_check(firmware))
    return checks
