"""Pydantic models for OPNsense API responses.

These shapes are pinned to what we have observed; if you change OPNsense
versions and a field disappears, expect a Pydantic validation error rather
than silent data loss. We use ``extra="allow"`` so unknown keys don't blow up.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class SystemInformation(BaseModel):
    """Subset of GET /api/diagnostics/system/system_information."""

    model_config = ConfigDict(extra="allow")

    name: str | None = None
    versions: list[str] | None = None


class CpuUsage(BaseModel):
    """GET /api/diagnostics/cpu_usage/getCPUType or stream endpoint.

    OPNsense returns various shapes depending on version; we normalize to a
    single total percentage.
    """

    model_config = ConfigDict(extra="allow")

    total: float = 0.0  # 0..100


class MemoryUsage(BaseModel):
    """Derived from /api/diagnostics/system/systemResources."""

    model_config = ConfigDict(extra="allow")

    used_pct: float = 0.0  # 0..100
    total_mb: float = 0.0
    used_mb: float = 0.0
    # Swap (agent push only; direct poll leaves these 0 → swap_total_mb==0 means
    # "no data", which the swap check treats as "skip" rather than "0% used").
    swap_total_mb: float = 0.0
    swap_used_mb: float = 0.0
    swap_used_pct: float = 0.0


class LoadAvg(BaseModel):
    """System load average over 1/5/15 minutes (agent push only). ``cores==0`` means
    no data (direct poll, or a pre-1.8.1 agent) → the load check skips, since load
    is only meaningful normalised per CPU core."""

    model_config = ConfigDict(extra="allow")

    one: float = 0.0
    five: float = 0.0
    fifteen: float = 0.0
    cores: int = 0


class PfStatus(BaseModel):
    """pf state-table usage (agent push only). ``states_limit==0`` means no data."""

    model_config = ConfigDict(extra="allow")

    states_current: int = 0
    states_limit: int = 0
    states_pct: float = 0.0


class NtpStatus(BaseModel):
    """NTP sync state (agent push only). ``stratum==-1`` means no data; ``stratum==16``
    is a reachable-but-unsynced clock (a soft state, never CRIT)."""

    model_config = ConfigDict(extra="allow")

    synced: bool = False
    stratum: int = -1
    offset_ms: float = 0.0
    jitter_ms: float = 0.0
    peer: str = ""


class ConfigInfo(BaseModel):
    """Last config-change metadata from ``config.xml`` <revision> (agent push only)."""

    model_config = ConfigDict(extra="allow")

    revision_time: str = ""  # ISO 8601, "" when unknown
    revision_description: str = ""
    revision_user: str = ""


class DiskUsage(BaseModel):
    """Derived from /api/diagnostics/system/systemDisk."""

    model_config = ConfigDict(extra="allow")

    device: str = ""
    mountpoint: str = ""
    used_pct: float = 0.0  # 0..100


class InterfaceStats(BaseModel):
    """One interface from /api/diagnostics/interface/getInterfaceStatistics."""

    model_config = ConfigDict(extra="allow")

    name: str = ""
    status: str = ""  # "up" / "down" / ...
    address: str | None = None
    bytes_received: int = 0
    bytes_transmitted: int = 0
    # These are raw counters. Throughput (bytes/sec) is derived on read — via
    # to_rate() on the metrics endpoint (?rate=true) and client-side in the UI.
    # Driver error/collision counters (agent push only; '-' columns map to 0). A
    # NIC driver that exposes no counter always reports 0 here.
    in_errors: int = 0
    out_errors: int = 0
    collisions: int = 0
    # Derived in the agent hub from two consecutive pushes: (in+out errors)/sec.
    # -1.0 = no rate yet (no previous sample, counter reset, or the direct-poll
    # path) → the iface-error check skips it. Not collected by the agent.
    err_rate: float = -1.0
    # Throughput (bytes/sec), derived the same way from the cumulative byte
    # counters. -1.0 = no rate yet (same conditions as err_rate). Lets the UI show
    # a correct rate in agent mode, where consecutive /status reads return the same
    # cached push and a client-side delta would be 0. Direct-poll path leaves -1.0
    # (the UI falls back to its own client-side delta, which works there).
    rx_rate: float = -1.0
    tx_rate: float = -1.0


class SystemStatus(BaseModel):
    """Aggregated poll snapshot for one instance."""

    name: str | None = None
    version: str | None = None
    uptime: str | None = None
    # Set by push agents that self-identify ('opnsense'|'pfsense'); None on the
    # direct-poll path. Lets the dashboard show the real platform per instance.
    platform: str | None = None
    cpu: CpuUsage = CpuUsage()
    memory: MemoryUsage = MemoryUsage()
    load: LoadAvg = LoadAvg()
    pf: PfStatus = PfStatus()
    ntp: NtpStatus = NtpStatus()
    config: ConfigInfo = ConfigInfo()
    disks: list[DiskUsage] = []
    interfaces: list[InterfaceStats] = []
    # Agent collection runtime (push agents only; None/empty on the direct-poll
    # path). ``collect_ms`` is the whole cycle; ``section_ms`` maps collector name
    # -> milliseconds. Lets the dashboard flag a slow-but-alive agent.
    collect_ms: float | None = None
    section_ms: dict[str, float] = {}


class ConnectivityResult(BaseModel):
    """One standalone connectivity-ping result pushed by the agent.

    Tunnel-independent source->dest probe (see app.connectivity). ``id`` is the
    dashboard monitor id the agent echoes back so the check key
    ``connectivity:<id>`` is stable. ``ping_state`` mirrors the IPsec ping
    vocabulary: none | ok | fail | error.
    """

    model_config = ConfigDict(extra="allow")

    id: int
    name: str = ""
    source: str = ""
    destination: str = ""
    ping_state: str = "none"
    ping_rtt_ms: float | None = None
    ping_loss_pct: float | None = None
    ping_ts: str | None = None
    enabled: bool = True


# --- IPsec ------------------------------------------------------------------


class IPsecChild(BaseModel):
    """One Phase-2 entry (child SA) of a tunnel, plus its optional ping result.

    ``state`` is the live child SA state (INSTALLED / REKEYING / …) or "" when the
    Phase 2 is configured but down. The ``ping_*`` fields are populated only when a
    ping monitor is configured for this child (else ``ping_state`` stays "none").
    """

    model_config = ConfigDict(extra="allow")

    name: str = ""  # child SA name (Phase-2 id; UUID on OPNsense)
    local_ts: str = ""  # local traffic selector, e.g. "10.1.1.0/24"
    remote_ts: str = ""  # remote traffic selector, e.g. "10.2.2.0/24"
    state: str = ""  # INSTALLED / REKEYING / … ; "" = configured but down
    bytes_in: int = 0
    bytes_out: int = 0
    # ESP SPIs — shared across both ends (A.spi_out == B.spi_in); for tunnel pairing.
    spi_in: str = ""
    spi_out: str = ""
    # Duplicate Phase-2 (note, not a warning): how many INSTALLED child SAs share
    # this selector pair this poll (1 = normal). >1 means the same Phase-2 is
    # installed more than once — under one IKE_SA or split across two.
    dup_count: int = 1
    # Set by the hub once dup_count>1 has persisted across several consecutive
    # polls — a transient make-before-break rekey blip stays False.
    phase2_dup_persistent: bool = False
    # Agent-suggested local source IP (box-owned, inside local_ts) for the monitor.
    suggested_source: str = ""
    # Ping monitor result: none (unconfigured) | ok | fail (no reply) | error (misconfig).
    ping_state: str = "none"
    ping_rtt_ms: float | None = None
    ping_loss_pct: float | None = None
    ping_ts: str | None = None  # ISO timestamp of the last ping check


class IPsecTunnel(BaseModel):
    """One IPsec tunnel (Phase 1 + Phase 2 combined)."""

    model_config = ConfigDict(extra="allow")

    id: str = ""  # connection name — `swanctl --initiate --ike <id>` (Connect)
    description: str = ""
    phase1_status: str = ""  # "established" / "connecting" / "down" / ...
    phase2_status: str = ""
    remote: str = ""
    local: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    unique_id: str = (
        ""  # active IKE_SA id — `swanctl --terminate --ike-id <unique_id>` (Disconnect)
    )
    established: str | None = None  # timestamp or duration string
    seconds_established: int = 0  # phase-1 uptime in seconds (agent path; 0 if down/unknown)
    phase2_up: int = 0  # installed child (phase-2) SAs
    phase2_total: int = 0  # configured child (phase-2) SAs — the "n" in "x/n up"
    children: list[IPsecChild] = []  # per-Phase-2 detail (agent path); [] in direct mode
    # IKE cookie pair — IDENTICAL on both tunnel ends; NAT-proof pairing key (agent path).
    ike_init_spi: str = ""
    ike_resp_spi: str = ""


class IPsecServiceStatus(BaseModel):
    running: bool = False
    tunnels: list[IPsecTunnel] = []


class DiagnosisSection(BaseModel):
    """One titled block of readable diagnostic text (config, SA state, log, …)."""

    title: str
    content: str


class IPsecDiagnosis(BaseModel):
    """Readable diagnostic bundle for one tunnel — for the human and for pasting
    into an LLM. Raw text per section, deliberately not over-parsed."""

    tunnel_id: str
    sections: list[DiagnosisSection] = []


class ActionResult(BaseModel):
    """Generic result for start/stop/update actions."""

    success: bool
    message: str = ""


# --- Firmware ----------------------------------------------------------------


class FirmwareStatus(BaseModel):
    """Firmware/update status."""

    model_config = ConfigDict(extra="allow")

    product_name: str = ""
    product_version: str = ""
    # update branch / software train (pfSense "26.03" / "Latest stable version", OPNsense series)
    branch: str = ""
    known_branches: list[str] = []  # other locally known trains (best-effort)
    product_latest: str = ""  # available version (agent: OPNsense pkg rquery); else = installed
    needs_reboot: bool = False
    upgrade_available: bool = False
    # True when the box could not actually check (repo unreachable, broken pkg):
    # the verdict is "unknown" — must not render as "up to date".
    check_failed: bool = False
    updates_available: int = 0
    packages: list[dict] = []  # list of package/set dicts with name, current, new
    status_msg: str = ""
    download_size: str = ""
    last_check: str = ""


class FirmwareUpgradeStatus(BaseModel):
    """Progress while an upgrade is running."""

    model_config = ConfigDict(extra="allow")

    status: str = ""  # "running", "done", "error"
    log: list[str] = []


# --- Gateway ----------------------------------------------------------------


class GatewayStatus(BaseModel):
    """One WAN gateway."""

    model_config = ConfigDict(extra="allow")

    name: str = ""
    address: str = ""
    status: str = ""  # "none" (up), "down", "force_down", "unknown"
    delay: str = ""  # e.g. "1.234ms"
    stddev: str = ""
    loss: str = ""  # e.g. "0.0%"
    interface: str = ""


# --- Services ----------------------------------------------------------------


class ServiceInfo(BaseModel):
    """One system service and whether it is running (agent push only).

    OPNsense: ``configctl service list``; pfSense: ``get_services()`` via PHP.
    """

    model_config = ConfigDict(extra="allow")

    name: str = ""
    description: str = ""
    running: bool = False


# --- Certificates ------------------------------------------------------------


class CertInfo(BaseModel):
    """One certificate (or CA) and its expiry (agent push only).

    Parsed from ``config.xml`` <cert>/<ca> via ``openssl``. ``days_remaining`` may
    be negative for an already-expired certificate.
    """

    model_config = ConfigDict(extra="allow")

    refid: str = ""
    name: str = ""
    type: str = "cert"  # "cert" | "ca"
    is_gui: bool = False  # the active web-GUI certificate
    not_after: str = ""  # ISO 8601 expiry
    days_remaining: int = 0
    subject: str = ""
    issuer: str = ""
