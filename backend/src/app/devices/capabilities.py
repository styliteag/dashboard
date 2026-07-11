"""Central device-capability map (DR-8, docs/agent-architecture.md §25).

One frozen row per :class:`DeviceType`. Backend surfaces that gate on the
device *class* (agent enrollment, firewall rules, web UI, tunnels) read from
here instead of comparing enum values inline — a fourth device type must not
add another scattered ``device_type != ...`` check.

Mirrors ``frontend/src/lib/capabilities.ts`` — update both together.
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import DeviceType


@dataclass(frozen=True)
class DeviceCaps:
    """What a device class supports. Defaults describe an agent-capable firewall."""

    agent: bool = True
    tunnels: bool = True
    firewall_rules: bool = False
    webif: bool = True
    capture: bool = True
    connectivity: bool = True
    ssh_enrichment: bool = False
    # The dashboard can reach an HTTP API on the box (poller, test-connection,
    # relay). False = push-only: base_url is optional and no client is built.
    direct_api: bool = True
    # The box has a versioned config backup (config.xml Config tab + download).
    config_backup: bool = True
    updates_label: str = "Firmware"
    # Per-instance push cadence applied at creation when the operator sets none.
    # None = inherit the global DASH_PUSH_INTERVAL_SECONDS default.
    default_push_interval: int | None = None


DEVICE_CAPS: dict[DeviceType, DeviceCaps] = {
    DeviceType.OPNSENSE: DeviceCaps(firewall_rules=True),
    DeviceType.PFSENSE: DeviceCaps(),
    DeviceType.PROXMOX: DeviceCaps(),
    DeviceType.TRUENAS: DeviceCaps(),
    DeviceType.QNAP: DeviceCaps(),
    # Securepoint is direct-only (no agent); shell + IPsec status via SSH enrichment.
    DeviceType.SECUREPOINT: DeviceCaps(
        agent=False,
        capture=False,
        connectivity=False,
        ssh_enrichment=True,
    ),
    # Generic Linux server (§25, DR-9): push-only, no web UI/tunnels/rule editor;
    # servers push calmer than firewalls (120s vs the global 30s default).
    DeviceType.LINUX: DeviceCaps(
        tunnels=False,
        webif=False,
        direct_api=False,
        config_backup=False,
        updates_label="Updates",
        default_push_interval=120,
    ),
}

_DEFAULT = DeviceCaps()


def device_caps(device_type: str | DeviceType | None) -> DeviceCaps:
    """Caps for a device_type value; unknown/legacy values fall back to defaults."""
    try:
        return DEVICE_CAPS[DeviceType(device_type)]
    except (KeyError, ValueError):
        return _DEFAULT
