"""Securepoint UTM connector (PoC).

Pulls VPN/tunnel + service status from a Securepoint UTM appliance over its
``/spcgi.cgi`` JSON API and maps the result onto the shared Orbit DTOs in
``app.xsense.schemas`` (``IPsecServiceStatus`` / ``IPsecTunnel`` / ``SystemStatus``),
so a Securepoint instance can be polled through the same ``DeviceClient`` contract
as OPNsense/pfSense.

Scope: read-only status pull. Connect/disconnect actions, poller/registry wiring,
instance-config + crypto storage and the full metrics surface are the *integration*
step and intentionally out of scope here.
"""

from __future__ import annotations

from app.securepoint.client import SecurepointClient, SecurepointError

__all__ = ["SecurepointClient", "SecurepointError"]
