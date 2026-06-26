"""WebSocket hub for connected agents.

Tracks connected agents, routes incoming metrics to the DB, and dispatches
commands from the dashboard to the correct agent.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime

import structlog
from fastapi import WebSocket
from sqlalchemy import select

from app.db.base import get_sessionmaker
from app.db.models import Instance
from app.metrics.store import is_online, write_poll_metrics
from app.notifications.notifier import send_notification
from app.xsense.schemas import (
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


# --- Agent → domain conversion (pure; testable without a DB) ------------------
# These map the agent's push payload (see agent/orbit_agent.py collect_all)
# onto our domain schemas. Keep them in sync with the agent's output shape.


def status_from_agent(data: dict) -> SystemStatus:
    cpu_data = data.get("cpu", {})
    mem_data = data.get("memory", {})
    system = data.get("system", {})
    return SystemStatus(
        name=system.get("hostname"),
        version=data.get("firmware", {}).get("product_version"),
        uptime=data.get("uptime"),
        platform=system.get("platform"),
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
            for d in data.get("disks", [])
        ],
        interfaces=[
            InterfaceStats(
                name=i.get("name", ""),
                status=i.get("status", "up"),
                address=i.get("address"),
                bytes_received=i.get("bytes_received", 0),
                bytes_transmitted=i.get("bytes_transmitted", 0),
            )
            for i in data.get("interfaces", [])
        ],
    )


def gateways_from_agent(data: dict) -> list[GatewayStatus]:
    return [
        GatewayStatus(
            name=g.get("name", ""),
            address=g.get("address", ""),
            status=g.get("status", ""),
            delay=g.get("delay", ""),
            stddev=g.get("stddev", ""),
            loss=g.get("loss", ""),
            interface=g.get("interface", ""),
        )
        for g in data.get("gateways", [])
    ]


def ipsec_from_agent(data: dict) -> IPsecServiceStatus:
    ipsec_data = data.get("ipsec", {})
    return IPsecServiceStatus(
        running=ipsec_data.get("running", False),
        tunnels=[
            IPsecTunnel(
                id=t.get("id", ""),
                description=t.get("description", ""),
                remote=t.get("remote", ""),
                local=t.get("local", ""),
                phase1_status=t.get("status", "unknown"),
                phase2_up=int(t.get("phase2_up", 0)),
                phase2_total=int(t.get("phase2_total", 0)),
                seconds_established=int(t.get("seconds_established", 0)),
                bytes_in=int(t.get("bytes_in", 0)),
                bytes_out=int(t.get("bytes_out", 0)),
                unique_id=t.get("unique_id", ""),
            )
            for t in ipsec_data.get("tunnels", [])
        ],
    )


def firmware_from_agent(data: dict, last_check: str) -> FirmwareStatus:
    fw_data = data.get("firmware", {})
    upgrade_available = bool(fw_data.get("upgrade_available", False))
    return FirmwareStatus(
        product_version=fw_data.get("product_version", ""),
        product_latest=fw_data.get("product_version", ""),  # agent doesn't know latest
        upgrade_available=upgrade_available,
        updates_available=1 if upgrade_available else 0,
        status_msg=fw_data.get("update_check_output", ""),
        last_check=last_check,
    )


class ConnectedAgent:
    def __init__(self, ws: WebSocket, instance_id: int, instance_name: str):
        self.ws = ws
        self.instance_id = instance_id
        self.instance_name = instance_name
        self.connected_at = datetime.now(UTC)
        # Reported in the agent's hello frame.
        self.agent_version: str = ""
        self.platform: str = ""
        # Last self-update attempt that did NOT take effect (e.g. signature/sha256
        # rejected). Surfaced in agent status so the reason is visible in the GUI
        # even after a page reload. Cleared by a connection reset (a successful
        # update restarts the agent → fresh connection).
        self.last_update_error: str | None = None
        self.last_update_version: str | None = None
        self._pending_commands: dict[str, asyncio.Future] = {}

    async def send_command(
        self, action: str, params: dict | None = None, timeout: float = 30
    ) -> dict:
        """Send a command and wait for the result."""
        request_id = uuid.uuid4().hex
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_commands[request_id] = future

        await self.ws.send_json(
            {
                "type": "command",
                "request_id": request_id,
                "action": action,
                "params": params or {},
            }
        )

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError:
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
        # GUI-proxy tunnels: stream_id -> queue of frames coming back from the agent.
        self._tunnels: dict[str, asyncio.Queue] = {}

    # --- GUI-proxy tunnel registry (see §18) ---------------------------------

    def open_tunnel(self, stream_id: str) -> asyncio.Queue:
        """Register a tunnel stream; returns the queue agent frames are delivered to."""
        queue: asyncio.Queue = asyncio.Queue()
        self._tunnels[stream_id] = queue
        return queue

    def close_tunnel(self, stream_id: str) -> None:
        self._tunnels.pop(stream_id, None)

    def deliver_tunnel(self, stream_id: str, frame: dict) -> None:
        """Route a `tunnel` frame from the agent to its client handler's queue."""
        queue = self._tunnels.get(stream_id)
        if queue is not None:
            queue.put_nowait(frame)

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
                "agent_version": a.agent_version,
                "platform": a.platform,
            }
            for a in self._agents.values()
        ]

    async def register(self, ws: WebSocket, instance_id: int, instance_name: str) -> ConnectedAgent:
        # Disconnect old connection if exists
        old = self._agents.get(instance_id)
        if old:
            with contextlib.suppress(Exception):
                await old.ws.close()

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

    # --- restart persistence (DB snapshot) -----------------------------------

    def _snapshot_for(self, instance_id: int) -> dict | None:
        """Serialize this instance's in-memory caches to a JSON-safe dict, or None."""
        status = self._last_status.get(instance_id)
        if status is None:
            return None
        snap: dict = {"status": status.model_dump(mode="json")}
        fw = self._last_firmware.get(instance_id)
        if fw is not None:
            snap["firmware"] = fw.model_dump(mode="json")
        gws = self._last_gateways.get(instance_id)
        if gws is not None:
            snap["gateways"] = [g.model_dump(mode="json") for g in gws]
        ipsec = self._last_ipsec.get(instance_id)
        if ipsec is not None:
            snap["ipsec"] = ipsec.model_dump(mode="json")
        fwl = self._last_firewall_log.get(instance_id)
        if fwl is not None:
            snap["firewall_log"] = fwl
        return snap

    def hydrate_instance(self, instance_id: int, snapshot: dict | None) -> None:
        """Restore one instance's caches from a persisted snapshot (startup only).

        Best-effort: skips when there is no snapshot or a live push already
        populated the cache since restart; tolerates schema drift by logging and
        moving on rather than failing startup.
        """
        if not snapshot or instance_id in self._last_status:
            return
        try:
            if snapshot.get("status"):
                self._last_status[instance_id] = SystemStatus.model_validate(snapshot["status"])
            if snapshot.get("firmware"):
                self._last_firmware[instance_id] = FirmwareStatus.model_validate(
                    snapshot["firmware"]
                )
            if snapshot.get("gateways"):
                self._last_gateways[instance_id] = [
                    GatewayStatus.model_validate(g) for g in snapshot["gateways"]
                ]
            if snapshot.get("ipsec"):
                self._last_ipsec[instance_id] = IPsecServiceStatus.model_validate(snapshot["ipsec"])
            if snapshot.get("firewall_log"):
                self._last_firewall_log[instance_id] = snapshot["firewall_log"]
        except Exception as exc:  # noqa: BLE001 — a bad snapshot must not block startup
            log.warning("hub.hydrate_skip", instance_id=instance_id, error=str(exc))

    async def hydrate_from_db(self) -> int:
        """Load persisted status snapshots into the caches at startup. Returns count."""
        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(Instance).where(
                            Instance.deleted_at.is_(None),
                            Instance.status_snapshot.is_not(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
        for inst in rows:
            self.hydrate_instance(inst.id, inst.status_snapshot)
        return len(rows)

    async def handle_metrics(self, instance_id: int, data: dict) -> None:
        """Process a metrics push from an agent."""
        sessionmaker = get_sessionmaker()
        ts = datetime.now(UTC)

        status = status_from_agent(data)
        self._last_status[instance_id] = status

        # Cache gateways — only update when the agent actually sent entries;
        # an empty list most likely means the collector failed, not that all
        # gateways were removed. This prevents wiping the cache on a failure.
        if data.get("gateways"):
            self._last_gateways[instance_id] = gateways_from_agent(data)

        # Cache IPsec — same guard: only when the agent sent an ipsec section.
        if data.get("ipsec"):
            self._last_ipsec[instance_id] = ipsec_from_agent(data)

        # Cache firewall log
        fw_log = data.get("firewall_log")
        if fw_log is not None:
            self._last_firewall_log[instance_id] = fw_log

        # Cache firmware data from agent push
        if data.get("firmware"):
            self._last_firmware[instance_id] = firmware_from_agent(data, ts.isoformat())

        recovered_name: str | None = None
        async with sessionmaker() as session:
            inst = await session.get(Instance, instance_id)
            if inst is None:
                return
            # Was this instance offline (e.g. flagged by the staleness watchdog)?
            # If so, this push is a recovery — notify once.
            if not is_online(inst.last_success_at, inst.last_error_at) and inst.last_error_at:
                recovered_name = inst.name
            await write_poll_metrics(session, instance_id, ts, status)
            inst.last_success_at = ts
            inst.last_error_at = None
            inst.last_error_message = None
            inst.agent_last_seen = ts
            # Persist the just-updated caches so a backend restart can re-hydrate.
            inst.status_snapshot = self._snapshot_for(instance_id)
            await session.commit()

        if recovered_name:
            await send_notification(
                f"✅ {recovered_name} agent back online",
                f"Agent for {recovered_name} resumed pushing metrics.",
                level="info",
            )
        log.debug("agent.metrics", instance_id=instance_id, cpu=status.cpu.total)


# Global singleton
hub = AgentHub()
