"""Threshold logic: domain status → list[ServiceCheck]. Pure + DB-free."""

from __future__ import annotations

from app.checks.agent_runtime import agent_collect_check
from app.checks.models import CheckState, PerfMetric, ServiceCheck
from app.xsense.schemas import (
    CertInfo,
    ConnectivityResult,
    CpuUsage,
    DiskUsage,
    FirmwareStatus,
    GatewayStatus,
    InterfaceStats,
    IPsecServiceStatus,
    LoadAvg,
    MemoryUsage,
    NtpStatus,
    PfStatus,
    ServiceInfo,
    SystemStatus,
)

# Services that are always-on and unambiguous → a stopped one is CRIT. DNS is
# handled as a group (at least one resolver must run) to avoid false alarms when
# a box runs unbound instead of dnsmasq (the unused one shows as stopped).
_VITAL_SERVICES = frozenset({"sshd", "configd"})
_DNS_SERVICES = frozenset({"unbound", "dnsmasq"})

# Thresholds (percent). Follow-up: make these configurable per instance/global.
_MEM_WARN, _MEM_CRIT = 80.0, 90.0
_DISK_WARN, _DISK_CRIT = 80.0, 90.0
_CPU_WARN = 95.0  # CPU is spiky — warn only, never crit
# Load is saturation (run-queue depth), not utilization, so unlike CPU it gets a
# CRIT — but only on the stable 5-min average, normalised per core, and set high
# enough not to flap: a sustained run queue ≥2× cores is real contention, ≥4× is
# severe sustained overload.
_LOAD_WARN_PER_CORE, _LOAD_CRIT_PER_CORE = 2.0, 4.0
_GW_LOSS_WARN, _GW_LOSS_CRIT = 20.0, 80.0
_PF_WARN, _PF_CRIT = 80.0, 95.0  # pf state-table fill (exhaustion drops new flows)
_SWAP_WARN, _SWAP_CRIT = 50.0, 80.0  # swap in use = memory pressure
_CERT_WARN_DAYS, _CERT_CRIT_DAYS = 30, 7  # certificate expiry runway
_IFACE_ERR_WARN, _IFACE_ERR_CRIT = 1.0, 10.0  # interface (in+out) errors per second
# Pseudo/virtual interfaces have no NIC driver to report meaningful errors → skip.
# bridge/lagg in particular count Oerrs from BUM-flood-to-down-member and ENOBUFS,
# not wire faults — a real driver error already surfaces on the physical member.
_IFACE_SKIP_PREFIXES = (
    "lo",
    "enc",
    "pflog",
    "pfsync",
    "gif",
    "stf",
    "bridge",
    "lagg",
    "gre",
    "ovpn",
    "tun",
    "tap",
    "wg",
)

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


def swap_check(mem: MemoryUsage) -> ServiceCheck | None:
    """Swap-in-use check. None when the box reports no swap device (no data)."""
    if mem.swap_total_mb <= 0:
        return None
    pct = mem.swap_used_pct
    if pct >= _SWAP_CRIT:
        state, word = CheckState.CRIT, "critical"
    elif pct >= _SWAP_WARN:
        state, word = CheckState.WARN, "high"
    else:
        state, word = CheckState.OK, "ok"
    return ServiceCheck(
        key="swap",
        state=int(state),
        summary=f"Swap {pct:.0f}% used ({word})",
        metrics=[
            PerfMetric(name="swap_used_pct", value=pct, warn=_SWAP_WARN, crit=_SWAP_CRIT, unit="%")
        ],
    )


def pf_states_check(pf: PfStatus) -> ServiceCheck | None:
    """pf state-table fill. None when no data (states_limit==0, e.g. direct poll)."""
    if pf.states_limit <= 0:
        return None
    pct = pf.states_pct
    if pct >= _PF_CRIT:
        state, word = CheckState.CRIT, "critical"
    elif pct >= _PF_WARN:
        state, word = CheckState.WARN, "high"
    else:
        state, word = CheckState.OK, "ok"
    return ServiceCheck(
        key="pf_states",
        state=int(state),
        summary=f"pf states {pf.states_current}/{pf.states_limit} ({pct:.0f}%, {word})",
        metrics=[
            PerfMetric(name="pf_states_pct", value=pct, warn=_PF_WARN, crit=_PF_CRIT, unit="%"),
            PerfMetric(name="pf_states", value=float(pf.states_current)),
        ],
    )


def ntp_check(ntp: NtpStatus) -> ServiceCheck | None:
    """NTP sync. None when no data (stratum==-1). A reachable-but-unsynced clock
    (stratum 16) is WARN, never CRIT — a freshly booted box must not read red."""
    if ntp.stratum < 0:
        return None
    if ntp.synced:
        peer = f" via {ntp.peer}" if ntp.peer else ""
        return ServiceCheck(
            key="ntp",
            state=int(CheckState.OK),
            summary=f"NTP synced (stratum {ntp.stratum}, offset {ntp.offset_ms:.1f}ms){peer}",
            metrics=[PerfMetric(name="ntp_offset_ms", value=ntp.offset_ms, unit="ms")],
        )
    return ServiceCheck(
        key="ntp",
        state=int(CheckState.WARN),
        summary="NTP not synchronised (no usable peer yet)",
    )


def load_check(load: LoadAvg) -> ServiceCheck | None:
    """5-minute load average normalised per CPU core. None when no data
    (``cores==0``: direct poll or a pre-1.8.1 agent). Uses the 5-min average (not
    1-min) so a transient spike does not flap the state."""
    if load.cores <= 0:
        return None
    per_core = load.five / load.cores
    if per_core >= _LOAD_CRIT_PER_CORE:
        state, word = CheckState.CRIT, "critical"
    elif per_core >= _LOAD_WARN_PER_CORE:
        state, word = CheckState.WARN, "high"
    else:
        state, word = CheckState.OK, "ok"
    return ServiceCheck(
        key="load",
        state=int(state),
        summary=(
            f"Load {load.five:.2f} (5m) = {per_core:.2f}/core over {load.cores} cores ({word})"
        ),
        metrics=[
            PerfMetric(
                name="load_per_core",
                value=round(per_core, 2),
                warn=_LOAD_WARN_PER_CORE,
                crit=_LOAD_CRIT_PER_CORE,
            ),
            PerfMetric(name="load5", value=load.five),
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
        out += _ipsec_ping_checks(label, t)
    return out


def _ipsec_ping_checks(label: str, tunnel) -> list[ServiceCheck]:  # noqa: ANN001
    """Per-Phase-2 ping-monitor checks for one tunnel.

    A configured ping that gets no reply is CRIT even when the child SA is
    INSTALLED — that is the whole point: an installed-but-not-passing tunnel must
    surface as a problem. A misconfigured probe (bad source / no route) is WARN,
    not CRIT, so it is not mistaken for a real outage. Unconfigured children are
    skipped (ping_state "none").
    """
    out: list[ServiceCheck] = []
    for ch in getattr(tunnel, "children", []):
        ps = (ch.ping_state or "none").strip().lower()
        if ps == "none":
            continue
        selector = ch.remote_ts or ch.name or "?"
        if ps == "ok":
            state, word = CheckState.OK, "ping ok"
        elif ps == "fail":
            state, word = CheckState.CRIT, "ping FAILED (no reply)"
        else:  # "error" or anything unexpected → misconfiguration, not an outage
            state, word = CheckState.WARN, "ping error (check source/destination)"
        metrics: list[PerfMetric] = []
        if ch.ping_loss_pct is not None:
            metrics.append(PerfMetric(name="ping_loss_pct", value=ch.ping_loss_pct, unit="%"))
        if ch.ping_rtt_ms is not None:
            metrics.append(PerfMetric(name="ping_rtt_ms", value=ch.ping_rtt_ms, unit="ms"))
        out.append(
            ServiceCheck(
                key=f"ipsec.tunnel_ping:{label}/{selector}",
                state=int(state),
                summary=f"Tunnel {label} P2 {selector} {word}",
                metrics=metrics,
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


def service_checks(services: list[ServiceInfo]) -> list[ServiceCheck]:
    """Vital-service checks. Only services actually present on the box are checked,
    so an absent service never invents a (red) check. DNS is a group: CRIT only when
    no resolver is running at all."""
    if not services:
        return []
    by_name = {s.name: s for s in services}
    out: list[ServiceCheck] = []
    for name in sorted(_VITAL_SERVICES):
        svc = by_name.get(name)
        if svc is None:
            continue
        out.append(
            ServiceCheck(
                key=f"service:{name}",
                state=int(CheckState.OK if svc.running else CheckState.CRIT),
                summary=f"Service {name} {'running' if svc.running else 'STOPPED'}",
            )
        )
    dns = [by_name[n] for n in sorted(_DNS_SERVICES) if n in by_name]
    if dns:
        running = any(s.running for s in dns)
        out.append(
            ServiceCheck(
                key="service:dns",
                state=int(CheckState.OK if running else CheckState.CRIT),
                summary="DNS resolver running" if running else "No DNS resolver running",
            )
        )
    return out


def iface_error_checks(interfaces: list[InterfaceStats]) -> list[ServiceCheck]:
    """Per-interface driver error rate ((in+out errors)/sec, derived in the agent
    hub from two consecutive pushes). Skips pseudo interfaces and down links, and
    skips any interface whose rate is unknown (``err_rate < 0`` — single snapshot,
    counter reset, or direct poll) so a check is never invented from no data."""
    out: list[ServiceCheck] = []
    for i in interfaces:
        if i.err_rate < 0 or i.status != "up" or i.name.startswith(_IFACE_SKIP_PREFIXES):
            continue
        if i.err_rate >= _IFACE_ERR_CRIT:
            state, word = CheckState.CRIT, "critical"
        elif i.err_rate >= _IFACE_ERR_WARN:
            state, word = CheckState.WARN, "elevated"
        else:
            state, word = CheckState.OK, "ok"
        out.append(
            ServiceCheck(
                key=f"iface_errors:{i.name}",
                state=int(state),
                summary=f"Interface {i.name} errors {i.err_rate:.2f}/s ({word})",
                metrics=[
                    PerfMetric(
                        name="iface_err_rate",
                        value=i.err_rate,
                        warn=_IFACE_ERR_WARN,
                        crit=_IFACE_ERR_CRIT,
                        unit="/s",
                    )
                ],
            )
        )
    return out


def cert_checks(certs: list[CertInfo]) -> list[ServiceCheck]:
    """Certificate-expiry checks. CRIT when expired or <7 days left, WARN <30 days."""
    out: list[ServiceCheck] = []
    for c in certs:
        days = c.days_remaining
        if days < _CERT_CRIT_DAYS:
            state = CheckState.CRIT
            word = "EXPIRED" if days < 0 else f"expires in {days}d"
        elif days < _CERT_WARN_DAYS:
            state, word = CheckState.WARN, f"expires in {days}d"
        else:
            state, word = CheckState.OK, f"valid for {days}d"
        label = c.name or c.refid or "certificate"
        gui = " [GUI]" if c.is_gui else ""
        out.append(
            ServiceCheck(
                key=f"cert:{c.refid or label}",
                state=int(state),
                summary=f"Certificate {label}{gui} {word}",
                metrics=[
                    PerfMetric(
                        name="cert_days_remaining",
                        value=float(days),
                        warn=float(_CERT_WARN_DAYS),
                        crit=float(_CERT_CRIT_DAYS),
                        unit="d",
                    )
                ],
            )
        )
    return out


def connectivity_checks(results: list[ConnectivityResult]) -> list[ServiceCheck]:
    """Standalone connectivity-ping checks (one per configured monitor).

    Same categorical semantics as the IPsec Phase-2 ping: a probe that gets no
    reply is CRIT, a misconfigured probe (bad source / no route) is WARN, an
    unevaluated monitor (ping_state "none") is skipped. Keyed by the monitor id so
    the key survives renames and same-destination monitors.
    """
    out: list[ServiceCheck] = []
    for r in results:
        ps = (r.ping_state or "none").strip().lower()
        if ps == "none":
            continue
        label = r.name or r.destination or str(r.id)
        if ps == "ok":
            state, word = CheckState.OK, "ping ok"
        elif ps == "fail":
            state, word = CheckState.CRIT, "ping FAILED (no reply)"
        else:  # "error" or anything unexpected → misconfiguration, not an outage
            state, word = CheckState.WARN, "ping error (check source/destination)"
        metrics: list[PerfMetric] = []
        if r.ping_loss_pct is not None:
            metrics.append(PerfMetric(name="ping_loss_pct", value=r.ping_loss_pct, unit="%"))
        if r.ping_rtt_ms is not None:
            metrics.append(PerfMetric(name="ping_rtt_ms", value=r.ping_rtt_ms, unit="ms"))
        out.append(
            ServiceCheck(
                key=f"connectivity:{r.id}",
                state=int(state),
                summary=f"Connectivity {label} → {r.destination} {word}",
                metrics=metrics,
            )
        )
    return out


def evaluate_checks(
    status: SystemStatus,
    gateways: list[GatewayStatus] | None = None,
    ipsec: IPsecServiceStatus | None = None,
    firmware: FirmwareStatus | None = None,
    services: list[ServiceInfo] | None = None,
    certs: list[CertInfo] | None = None,
    connectivity: list[ConnectivityResult] | None = None,
) -> list[ServiceCheck]:
    """Evaluate all available aspects of an instance into service checks."""
    checks = [memory_check(status.memory), cpu_check(status.cpu)]
    checks += disk_checks(status.disks)
    # Optional system-telemetry checks — each returns None when the box reported
    # no data (e.g. direct-poll instances, which don't carry pf/ntp/swap).
    for opt in (
        load_check(status.load),
        swap_check(status.memory),
        pf_states_check(status.pf),
        ntp_check(status.ntp),
    ):
        if opt is not None:
            checks.append(opt)
    checks += iface_error_checks(status.interfaces)
    if gateways:
        checks += gateway_checks(gateways)
    if ipsec is not None:
        checks += ipsec_checks(ipsec)
    if services:
        checks += service_checks(services)
    if certs:
        checks += cert_checks(certs)
    if firmware is not None and firmware.product_version:
        checks.append(firmware_check(firmware))
    if connectivity:
        checks += connectivity_checks(connectivity)
    # Agent collection runtime (push agents only; None on the direct-poll path).
    agent_collect = agent_collect_check(status)
    if agent_collect is not None:
        checks.append(agent_collect)
    return checks
