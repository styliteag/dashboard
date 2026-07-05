"""Agent → domain conversion (pure; testable without a DB).

These map the agent's push payload (see agent/orbit_agent.py collect_all)
onto our domain schemas. Keep them in sync with the agent's output shape.
"""

from __future__ import annotations

import contextlib

from app.xsense.schemas import (
    CertInfo,
    ConfigInfo,
    ConnectivityResult,
    CpuUsage,
    DiskUsage,
    FirmwareStatus,
    GatewayStatus,
    InterfaceStats,
    IPsecChild,
    IPsecServiceStatus,
    IPsecTunnel,
    LoadAvg,
    MemoryUsage,
    NtpStatus,
    PfStatus,
    PfTopSummary,
    ServiceInfo,
    SystemStatus,
)

# onto our domain schemas. Keep them in sync with the agent's output shape.


def status_from_agent(data: dict) -> SystemStatus:
    cpu_data = data.get("cpu", {})
    mem_data = data.get("memory", {})
    system = data.get("system", {})
    load_data = data.get("loadavg", {})
    pf_data = data.get("pf", {})
    ntp_data = data.get("ntp", {})
    config_data = data.get("config", {})
    return SystemStatus(
        name=system.get("hostname"),
        version=data.get("firmware", {}).get("product_version"),
        uptime=data.get("uptime"),
        platform=system.get("platform"),
        collect_ms=data.get("collect_ms"),
        section_ms=data.get("section_ms") or {},
        cpu=CpuUsage(total=cpu_data.get("total_pct", 0)),
        memory=MemoryUsage(
            used_pct=mem_data.get("used_pct", 0),
            total_mb=mem_data.get("total_mb", 0),
            used_mb=mem_data.get("used_mb", 0),
            swap_total_mb=mem_data.get("swap_total_mb", 0),
            swap_used_mb=mem_data.get("swap_used_mb", 0),
            swap_used_pct=mem_data.get("swap_used_pct", 0),
        ),
        load=LoadAvg(
            one=load_data.get("one", 0),
            five=load_data.get("five", 0),
            fifteen=load_data.get("fifteen", 0),
            cores=load_data.get("cores", 0),
        ),
        pf=PfStatus(
            states_current=pf_data.get("states_current", 0),
            states_limit=pf_data.get("states_limit", 0),
            states_pct=pf_data.get("states_pct", 0),
        ),
        ntp=NtpStatus(
            synced=bool(ntp_data.get("synced", False)),
            stratum=ntp_data.get("stratum", -1),
            offset_ms=ntp_data.get("offset_ms", 0),
            jitter_ms=ntp_data.get("jitter_ms", 0),
            peer=ntp_data.get("peer", ""),
        ),
        config=ConfigInfo(
            revision_time=config_data.get("revision_time", ""),
            revision_description=config_data.get("revision_description", ""),
            revision_user=config_data.get("revision_user", ""),
        ),
        disks=[
            DiskUsage(
                device=d.get("device", ""),
                mountpoint=d.get("mountpoint", ""),
                used_pct=d.get("used_pct", 0),
            )
            for d in data.get("disks", [])
        ],
        interfaces=[
            InterfaceStats(
                name=i.get("name", ""),
                status=i.get("status", "up"),
                address=i.get("address"),
                bytes_received=i.get("bytes_received", 0),
                bytes_transmitted=i.get("bytes_transmitted", 0),
                in_errors=i.get("in_errors", 0),
                out_errors=i.get("out_errors", 0),
                collisions=i.get("collisions", 0),
            )
            for i in data.get("interfaces", [])
        ],
    )


# Map a check's new state to a notification level + label/icon for the alert text.
_STATE_LEVEL = {0: "info", 1: "warning", 2: "error", 3: "warning"}
_STATE_ICON = {0: "✅", 1: "⚠️", 2: "🔴", 3: "❔"}


def check_alert(instance_name: str, transition) -> tuple[str, str, str, str]:  # noqa: ANN001
    """Build ``(title, message, level, check_key)`` for one check state transition.
    The full check key is passed to selection so a channel can be routed per service
    (``gateway:WAN``), not just per category."""
    icon = _STATE_ICON.get(transition.new_state, "❔")
    title = f"{icon} {instance_name}: {transition.summary}"
    level = _STATE_LEVEL.get(transition.new_state, "warning")
    return title, transition.summary, level, transition.check_key


def annotate_iface_error_rates(
    new: SystemStatus, prev: SystemStatus | None, dt_seconds: float
) -> SystemStatus:
    """Return a copy of ``new`` whose interfaces carry derived per-second rates
    (``err_rate`` = (in+out errors)/sec, ``rx_rate``/``tx_rate`` = bytes/sec)
    computed against ``prev``. Counters are cumulative, so a rate needs two
    samples; each rate keeps the -1.0 "no data" sentinel when there is no previous
    sample, when its counter went backwards (reboot / counter reset), or when
    ``dt_seconds`` is not positive (e.g. first push after restart). The three rates
    are guarded independently so one reset counter doesn't void the others."""
    if prev is None or dt_seconds <= 0:
        return new
    prev_by_name = {i.name: i for i in prev.interfaces}
    ifaces = []
    for i in new.interfaces:
        p = prev_by_name.get(i.name)
        err_rate = rx_rate = tx_rate = -1.0
        if p is not None:
            if i.in_errors >= p.in_errors and i.out_errors >= p.out_errors:
                delta = (i.in_errors - p.in_errors) + (i.out_errors - p.out_errors)
                err_rate = round(delta / dt_seconds, 3)
            if i.bytes_received >= p.bytes_received:
                rx_rate = round((i.bytes_received - p.bytes_received) / dt_seconds, 3)
            if i.bytes_transmitted >= p.bytes_transmitted:
                tx_rate = round((i.bytes_transmitted - p.bytes_transmitted) / dt_seconds, 3)
        ifaces.append(
            i.model_copy(update={"err_rate": err_rate, "rx_rate": rx_rate, "tx_rate": tx_rate})
        )
    return new.model_copy(update={"interfaces": ifaces})


def connectivity_from_agent(data: dict) -> list[ConnectivityResult]:
    """Parse the agent's ``connectivity`` push section into result schemas.

    Skips malformed entries (anything without a usable id) rather than failing the
    whole push."""
    out: list[ConnectivityResult] = []
    for c in data.get("connectivity", []):
        if not isinstance(c, dict) or c.get("id") is None:
            continue
        with contextlib.suppress(Exception):
            out.append(ConnectivityResult.model_validate(c))
    return out


def gateways_from_agent(data: dict) -> list[GatewayStatus]:
    return [
        GatewayStatus(
            name=g.get("name", ""),
            address=g.get("address", ""),
            status=g.get("status", ""),
            delay=g.get("delay", ""),
            stddev=g.get("stddev", ""),
            loss=g.get("loss", ""),
            interface=g.get("interface", ""),
        )
        for g in data.get("gateways", [])
    ]


def _child_from_agent(c: dict) -> IPsecChild:
    return IPsecChild(
        name=c.get("name", ""),
        local_ts=c.get("local_ts", ""),
        remote_ts=c.get("remote_ts", ""),
        state=c.get("state", ""),
        bytes_in=int(c.get("bytes_in", 0)),
        bytes_out=int(c.get("bytes_out", 0)),
        spi_in=c.get("spi_in", ""),
        spi_out=c.get("spi_out", ""),
        dup_count=int(c.get("dup_count", 1) or 1),
        suggested_source=c.get("suggested_source", ""),
        ping_state=c.get("ping_state", "none"),
        ping_rtt_ms=c.get("ping_rtt_ms"),
        ping_loss_pct=c.get("ping_loss_pct"),
        ping_ts=c.get("ping_ts"),
    )


def ipsec_from_agent(data: dict) -> IPsecServiceStatus:
    ipsec_data = data.get("ipsec", {})
    return IPsecServiceStatus(
        running=ipsec_data.get("running", False),
        tunnels=[
            IPsecTunnel(
                id=t.get("id", ""),
                description=t.get("description", ""),
                remote=t.get("remote", ""),
                local=t.get("local", ""),
                phase1_status=t.get("status", "unknown"),
                phase2_up=int(t.get("phase2_up", 0)),
                phase2_total=int(t.get("phase2_total", 0)),
                seconds_established=int(t.get("seconds_established", 0)),
                bytes_in=int(t.get("bytes_in", 0)),
                bytes_out=int(t.get("bytes_out", 0)),
                unique_id=t.get("unique_id", ""),
                ike_init_spi=t.get("ike_init_spi", ""),
                ike_resp_spi=t.get("ike_resp_spi", ""),
                children=[_child_from_agent(c) for c in t.get("children", [])],
            )
            for t in ipsec_data.get("tunnels", [])
        ],
    )


def pf_top_from_agent(data: dict) -> PfTopSummary | None:
    """Parse the agent's ``pf_top`` push section (state-table top talkers).
    Returns None when the section is missing (older agent) or malformed —
    the hub then keeps its previous cache entry."""
    raw = data.get("pf_top")
    if not isinstance(raw, dict) or not raw:
        return None
    try:
        return PfTopSummary.model_validate(raw)
    except Exception:  # noqa: BLE001 — a malformed section must not fail the push
        return None


def services_from_agent(data: dict) -> list[ServiceInfo]:
    return [
        ServiceInfo(
            name=s.get("name", ""),
            description=s.get("description", ""),
            running=bool(s.get("running", False)),
        )
        for s in data.get("services", [])
        if isinstance(s, dict) and s.get("name")
    ]


def certs_from_agent(data: dict) -> list[CertInfo]:
    return [
        CertInfo(
            refid=c.get("refid", ""),
            name=c.get("name", ""),
            type=c.get("type", "cert"),
            is_gui=bool(c.get("is_gui", False)),
            not_after=c.get("not_after", ""),
            days_remaining=int(c.get("days_remaining", 0)),
            subject=c.get("subject", ""),
            issuer=c.get("issuer", ""),
        )
        for c in data.get("certificates", [])
        if isinstance(c, dict)
    ]


def firmware_from_agent(data: dict, last_check: str) -> FirmwareStatus:
    fw_data = data.get("firmware", {})
    upgrade_available = bool(fw_data.get("upgrade_available", False))
    return FirmwareStatus(
        product_version=fw_data.get("product_version", ""),
        branch=fw_data.get("branch", ""),
        known_branches=fw_data.get("known_branches", []) or [],
        # Agent now reports the available version (OPNsense pkg rquery); older
        # agents omit it → fall back to installed so "Latest" never goes blank.
        product_latest=fw_data.get("product_latest") or fw_data.get("product_version", ""),
        upgrade_available=upgrade_available,
        check_failed=bool(fw_data.get("check_failed", False)),
        updates_available=1 if upgrade_available else 0,
        status_msg=fw_data.get("update_check_output", ""),
        last_check=last_check,
    )
