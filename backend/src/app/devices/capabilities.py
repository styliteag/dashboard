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
    updates_label: str = "Firmware"


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
}

_DEFAULT = DeviceCaps()


def device_caps(device_type: str | DeviceType | None) -> DeviceCaps:
    """Caps for a device_type value; unknown/legacy values fall back to defaults."""
    try:
        return DEVICE_CAPS[DeviceType(device_type)]
    except (KeyError, ValueError):
        return _DEFAULT
