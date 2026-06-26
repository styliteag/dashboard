"""Transport and device-type enums.

These two axes replace the old boolean ``Instance.agent_mode``
(see ``docs/agent-architecture.md``, DR-1).
"""

from __future__ import annotations

from enum import StrEnum


class Transport(StrEnum):
    """How the dashboard reaches a device."""

    DIRECT = "direct"  # dashboard polls the device API directly
    PUSH = "push"  # device runs an agent that pushes via the WebSocket hub
    RELAY = "relay"  # dashboard reaches the device API through an agent tunnel


class DeviceType(StrEnum):
    """What kind of device an instance represents."""

    OPNSENSE = "opnsense"
    PFSENSE = "pfsense"
    PROXMOX = "proxmox"
    TRUENAS = "truenas"
    QNAP = "qnap"
    SECUREPOINT = "securepoint"
