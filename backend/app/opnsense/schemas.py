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
    # Rates are computed by the poller by diffing two consecutive polls.


class SystemStatus(BaseModel):
    """Aggregated poll snapshot for one instance."""

    name: str | None = None
    version: str | None = None
    uptime: str | None = None
    cpu: CpuUsage = CpuUsage()
    memory: MemoryUsage = MemoryUsage()
    disks: list[DiskUsage] = []
    interfaces: list[InterfaceStats] = []


# --- IPsec ------------------------------------------------------------------

class IPsecTunnel(BaseModel):
    """One IPsec tunnel (Phase 1 + Phase 2 combined)."""

    model_config = ConfigDict(extra="allow")

    id: str = ""
    description: str = ""
    phase1_status: str = ""  # "established" / "connecting" / "down" / ...
    phase2_status: str = ""
    remote: str = ""
    local: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    established: str | None = None  # timestamp or duration string


class IPsecServiceStatus(BaseModel):
    running: bool = False
    tunnels: list[IPsecTunnel] = []


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
    product_latest: str = ""
    needs_reboot: bool = False
    upgrade_available: bool = False
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
