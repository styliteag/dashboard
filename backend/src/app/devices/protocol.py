"""The ``DeviceClient`` protocol — the transport-agnostic contract that the poller
and the client registry depend on.

Concrete clients implement it (today ``OPNsenseClient``; later ``PfSenseClient``,
``ProxmoxClient``, …). Device-specific capabilities (IPsec, firmware, gateways, …)
stay on the concrete classes for now and may graduate to optional sub-protocols
later.

Note: ``SystemStatus`` currently lives under ``app.xsense.schemas`` for historical
reasons but is a shared, device-agnostic shape. Moving it to a neutral location is
out of scope for Phase 0.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.xsense.schemas import ActionResult, IPsecServiceStatus, SystemStatus


@runtime_checkable
class DeviceClient(Protocol):
    """Minimal contract a device client must satisfy to be polled and cached."""

    async def poll_status(self) -> SystemStatus:
        """Return a full status snapshot for the device."""
        ...

    async def aclose(self) -> None:
        """Release any held resources (HTTP pool, sockets, …)."""
        ...


@runtime_checkable
class SupportsIPsec(Protocol):
    """Optional capability: a device client that exposes IPsec status + actions.

    Both ``OPNsenseClient`` and ``SecurepointClient`` satisfy this. IPsec routes
    narrow a ``DeviceClient`` to this via ``isinstance`` and 501 otherwise, so
    IPsec-less device types (proxmox/truenas) get a clean unsupported path.
    """

    async def ipsec_status(self) -> IPsecServiceStatus: ...

    async def ipsec_connect(self, tunnel_id: str) -> ActionResult: ...

    async def ipsec_disconnect(self, tunnel_id: str) -> ActionResult: ...

    async def ipsec_restart(self) -> ActionResult: ...
