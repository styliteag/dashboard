"""Device abstraction: the transport + device-type axes and the DeviceClient protocol.

See ``docs/agent-architecture.md`` (DR-1): ``transport`` says *how* the dashboard
reaches a device, ``device_type`` says *what kind* of device it is. Together they
replace the old boolean ``Instance.agent_mode``.
"""

from app.devices.protocol import DeviceClient
from app.devices.types import DeviceType, Transport

__all__ = ["DeviceClient", "DeviceType", "Transport"]
