"""The ``DeviceClient`` protocol — the transport-agnostic contract that the poller
and the client registry depend on.

Concrete clients implement it (today ``OPNsenseClient``; later ``PfSenseClient``,
``ProxmoxClient``, …). Device-specific capabilities (IPsec, firmware, gateways, …)
stay on the concrete classes for now and may graduate to optional sub-protocols
later.

Note: ``SystemStatus`` currently lives under ``app.opnsense.schemas`` for historical
reasons but is a shared, device-agnostic shape. Moving it to a neutral location is
out of scope for Phase 0.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.opnsense.schemas import SystemStatus


@runtime_checkable
class DeviceClient(Protocol):
    """Minimal contract a device client must satisfy to be polled and cached."""

    async def poll_status(self) -> SystemStatus:
        """Return a full status snapshot for the device."""
        ...

    async def aclose(self) -> None:
        """Release any held resources (HTTP pool, sockets, …)."""
        ...
