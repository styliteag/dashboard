"""WebSocket hub for connected agents.

Tracks connected agents, routes incoming metrics to the DB, and dispatches
commands from the dashboard to the correct agent.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone

import structlog
from fastapi import WebSocket
from sqlalchemy import select

from app.db.base import get_sessionmaker
from app.db.models import Instance
from app.metrics.store import write_poll_metrics
from app.opnsense.schemas import (
    CpuUsage,
    DiskUsage,
    FirmwareStatus,
    GatewayStatus,
    InterfaceStats,
    IPsecServiceStatus,
    IPsecTunnel,
    MemoryUsage,
    SystemStatus,
)

log = structlog.get_logger("app.agent_hub")


class ConnectedAgent:
    def __init__(self, ws: WebSocket, instance_id: int, instance_name: str):
        self.ws = ws
        self.instance_id = instance_id
        self.instance_name = instance_name
        self.connected_at = datetime.now(timezone.utc)
        self._pending_commands: dict[str, asyncio.Future] = {}

    async def send_command(self, action: str, params: dict | None = None, timeout: float = 30) -> dict:
        """Send a command and wait for the result."""
        request_id = uuid.uuid4().hex
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_commands[request_id] = future

        await self.ws.send_json({
            "type": "command",
            "request_id": request_id,
            "action": action,
            "params": params or {},
        })

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            return {"success": False, "output": "command timed out"}
        finally:
            self._pending_commands.pop(request_id, None)

    def resolve_command(self, request_id: str, result: dict) -> None:
        future = self._pending_commands.get(request_id)
        if future and not future.done():
            future.set_result(result)


class AgentHub:
    """Singleton registry of connected agents."""

    def __init__(self):
        self._agents: dict[int, ConnectedAgent] = {}  # instance_id -> agent
        self._last_status: dict[int, SystemStatus] = {}
        self._last_firmware: dict[int, FirmwareStatus] = {}
        self._last_gateways: dict[int, list[GatewayStatus]] = {}
        self._last_ipsec: dict[int, IPsecServiceStatus] = {}
        self._last_firewall_log: dict[int, list[dict]] = {}

    def get(self, instance_id: int) -> ConnectedAgent | None:
        return self._agents.get(instance_id)

    def is_connected(self, instance_id: int) -> bool:
        return instance_id in self._agents

    def list_connected(self) -> list[dict]:
        return [
            {
                "instance_id": a.instance_id,
                "instance_name": a.instance_name,
                "connected_at": a.connected_at.isoformat(),
            }
            for a in self._agents.values()
        ]

    async def register(self, ws: WebSocket, instance_id: int, instance_name: str) -> ConnectedAgent:
        # Disconnect old connection if exists
        old = self._agents.get(instance_id)
        if old:
            try:
                await old.ws.close()
            except Exception:
                pass

        agent = ConnectedAgent(ws, instance_id, instance_name)
        self._agents[instance_id] = agent
        log.info("agent.connected", instance=instance_name, instance_id=instance_id)
        return agent

    def unregister(self, instance_id: int) -> None:
        agent = self._agents.pop(instance_id, None)
        if agent:
            log.info("agent.disconnected", instance=agent.instance_name)

    def get_last_status(self, instance_id: int) -> SystemStatus | None:
        return self._last_status.get(instance_id)

    def get_last_firmware(self, instance_id: int) -> FirmwareStatus | None:
        return self._last_firmware.get(instance_id)

    def set_firmware(self, instance_id: int, fw: FirmwareStatus) -> None:
        self._last_firmware[instance_id] = fw

    def get_last_gateways(self, instance_id: int) -> list[GatewayStatus] | None:
        return self._last_gateways.get(instance_id)

    def get_last_ipsec(self, instance_id: int) -> IPsecServiceStatus | None:
        return self._last_ipsec.get(instance_id)

    def get_last_firewall_log(self, instance_id: int) -> list[dict] | None:
        return self._last_firewall_log.get(instance_id)

    async def handle_metrics(self, instance_id: int, data: dict) -> None:
        """Process a metrics push from an agent."""
        sessionmaker = get_sessionmaker()
        ts = datetime.now(timezone.utc)

        # Convert agent data format to our SystemStatus
        cpu_data = data.get("cpu", {})
        mem_data = data.get("memory", {})
        disk_data = data.get("disks", [])
        iface_data = data.get("interfaces", [])

        status = SystemStatus(
            name=data.get("system", {}).get("hostname"),
            version=data.get("firmware", {}).get("product_version"),
            uptime=data.get("uptime"),
            cpu=CpuUsage(total=cpu_data.get("total_pct", 0)),
            memory=MemoryUsage(
                used_pct=mem_data.get("used_pct", 0),
                total_mb=mem_data.get("total_mb", 0),
                used_mb=mem_data.get("used_mb", 0),
            ),
            disks=[
                DiskUsage(
                    device=d.get("device", ""),
                    mountpoint=d.get("mountpoint", ""),
                    used_pct=d.get("used_pct", 0),
                )
                for d in disk_data
            ],
            interfaces=[
                InterfaceStats(
                    name=i.get("name", ""),
                    status=i.get("status", "up"),
                    address=i.get("address"),
                    bytes_received=i.get("bytes_received", 0),
                    bytes_transmitted=i.get("bytes_transmitted", 0),
                )
                for i in iface_data
            ],
        )

        self._last_status[instance_id] = status

        # Cache gateways — only update when the agent actually sent entries;
        # an empty list most likely means pluginctl failed, not that all gateways
        # were removed. This prevents wiping the cache on a failed collection.
        gw_data = data.get("gateways", [])
        if gw_data:
            self._last_gateways[instance_id] = [
                GatewayStatus(
                    name=g.get("name", ""),
                    address=g.get("address", ""),
                    status=g.get("status", ""),
                    delay=g.get("delay", ""),
                    stddev=g.get("stddev", ""),
                    loss=g.get("loss", ""),
                    interface=g.get("interface", ""),
                )
                for g in gw_data
            ]

        # Cache IPsec
        ipsec_data = data.get("ipsec", {})
        if ipsec_data:
            self._last_ipsec[instance_id] = IPsecServiceStatus(
                running=ipsec_data.get("running", False),
                tunnels=[
                    IPsecTunnel(
                        id=t.get("id", ""),
                        description=t.get("description", ""),
                        remote=t.get("remote", ""),
                        local=t.get("local", ""),
                        phase1_status=t.get("status", "unknown"),
                        bytes_in=int(t.get("bytes_in", 0)),
                        bytes_out=int(t.get("bytes_out", 0)),
                    )
                    for t in ipsec_data.get("tunnels", [])
                ],
            )

        # Cache firewall log
        fw_log = data.get("firewall_log")
        if fw_log is not None:
            self._last_firewall_log[instance_id] = fw_log

        # Cache firmware data from agent push
        fw_data = data.get("firmware", {})
        if fw_data:
            upgrade_available = bool(fw_data.get("upgrade_available", False))
            self._last_firmware[instance_id] = FirmwareStatus(
                product_version=fw_data.get("product_version", ""),
                product_latest=fw_data.get("product_version", ""),  # agent doesn't know latest
                upgrade_available=upgrade_available,
                updates_available=1 if upgrade_available else 0,
                status_msg=fw_data.get("update_check_output", ""),
                last_check=ts.isoformat(),
            )

        async with sessionmaker() as session:
            inst = await session.get(Instance, instance_id)
            if inst is None:
                return
            await write_poll_metrics(session, instance_id, ts, status)
            inst.last_success_at = ts
            inst.last_error_at = None
            inst.last_error_message = None
            inst.agent_last_seen = ts
            await session.commit()

        log.debug("agent.metrics", instance_id=instance_id, cpu=status.cpu.total)


# Global singleton
hub = AgentHub()
