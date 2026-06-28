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
from app.ipsec.event_store import record_tunnel_events
from app.ipsec.history import diff_ipsec
from app.metrics.store import is_online, write_poll_metrics
from app.notifications.notifier import send_notification
from app.xsense.schemas import (
    ConfigInfo,
    CpuUsage,
    DiskUsage,
    FirmwareStatus,
    GatewayStatus,
    InterfaceStats,
    IPsecChild,
    IPsecServiceStatus,
    IPsecTunnel,
    LoadAvg,
    MemoryUsage,
    NtpStatus,
    PfStatus,
    ServiceInfo,
    SystemStatus,
)

log = structlog.get_logger("app.agent_hub")

# Max buffered frames per GUI-proxy/relay tunnel stream. The producer
# (deliver_tunnel, driven by the agent's WS loop) must never grow this without
# bound: a compromised/buggy firewall agent — or a fast firewall + slow local
# client — would otherwise exhaust backend memory. On overflow the stream is torn
# down instead of buffered.
_TUNNEL_QUEUE_MAX = 1000


# --- Agent → domain conversion (pure; testable without a DB) ------------------
# These map the agent's push payload (see agent/orbit_agent.py collect_all)
# onto our domain schemas. Keep them in sync with the agent's output shape.


def status_from_agent(data: dict) -> SystemStatus:
    cpu_data = data.get("cpu", {})
    mem_data = data.get("memory", {})
    system = data.get("system", {})
    load_data = data.get("loadavg", {})
    pf_data = data.get("pf", {})
    ntp_data = data.get("ntp", {})
    config_data = data.get("config", {})
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
            swap_total_mb=mem_data.get("swap_total_mb", 0),
            swap_used_mb=mem_data.get("swap_used_mb", 0),
            swap_used_pct=mem_data.get("swap_used_pct", 0),
        ),
        load=LoadAvg(
            one=load_data.get("one", 0),
            five=load_data.get("five", 0),
            fifteen=load_data.get("fifteen", 0),
        ),
        pf=PfStatus(
            states_current=pf_data.get("states_current", 0),
            states_limit=pf_data.get("states_limit", 0),
            states_pct=pf_data.get("states_pct", 0),
        ),
        ntp=NtpStatus(
            synced=bool(ntp_data.get("synced", False)),
            stratum=ntp_data.get("stratum", -1),
            offset_ms=ntp_data.get("offset_ms", 0),
            jitter_ms=ntp_data.get("jitter_ms", 0),
            peer=ntp_data.get("peer", ""),
        ),
        config=ConfigInfo(
            revision_time=config_data.get("revision_time", ""),
            revision_description=config_data.get("revision_description", ""),
            revision_user=config_data.get("revision_user", ""),
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
                in_errors=i.get("in_errors", 0),
                out_errors=i.get("out_errors", 0),
                collisions=i.get("collisions", 0),
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


def _child_from_agent(c: dict) -> IPsecChild:
    return IPsecChild(
        name=c.get("name", ""),
        local_ts=c.get("local_ts", ""),
        remote_ts=c.get("remote_ts", ""),
        state=c.get("state", ""),
        bytes_in=int(c.get("bytes_in", 0)),
        bytes_out=int(c.get("bytes_out", 0)),
        spi_in=c.get("spi_in", ""),
        spi_out=c.get("spi_out", ""),
        suggested_source=c.get("suggested_source", ""),
        ping_state=c.get("ping_state", "none"),
        ping_rtt_ms=c.get("ping_rtt_ms"),
        ping_loss_pct=c.get("ping_loss_pct"),
        ping_ts=c.get("ping_ts"),
    )


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
                ike_init_spi=t.get("ike_init_spi", ""),
                ike_resp_spi=t.get("ike_resp_spi", ""),
                children=[_child_from_agent(c) for c in t.get("children", [])],
            )
            for t in ipsec_data.get("tunnels", [])
        ],
    )


def services_from_agent(data: dict) -> list[ServiceInfo]:
    return [
        ServiceInfo(
            name=s.get("name", ""),
            description=s.get("description", ""),
            running=bool(s.get("running", False)),
        )
        for s in data.get("services", [])
        if isinstance(s, dict) and s.get("name")
    ]


def firmware_from_agent(data: dict, last_check: str) -> FirmwareStatus:
    fw_data = data.get("firmware", {})
    upgrade_available = bool(fw_data.get("upgrade_available", False))
    return FirmwareStatus(
        product_version=fw_data.get("product_version", ""),
        branch=fw_data.get("branch", ""),
        known_branches=fw_data.get("known_branches", []) or [],
        # Agent now reports the available version (OPNsense pkg rquery); older
        # agents omit it → fall back to installed so "Latest" never goes blank.
        product_latest=fw_data.get("product_latest") or fw_data.get("product_version", ""),
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

    async def send_config(self, **fields: object) -> None:
        """Fire-and-forget a live config update (e.g. push_interval) to the agent.

        Uses the agent's existing ``config_update`` channel (``data`` payload).
        Best-effort: a send failure must never bubble into the request that
        triggered it — the value is re-sent in the welcome frame on (re)connect.
        """
        with contextlib.suppress(Exception):
            await self.ws.send_json({"type": "config_update", "data": dict(fields)})


class AgentHub:
    """Singleton registry of connected agents."""

    def __init__(self):
        self._agents: dict[int, ConnectedAgent] = {}  # instance_id -> agent
        self._last_status: dict[int, SystemStatus] = {}
        self._last_firmware: dict[int, FirmwareStatus] = {}
        self._last_gateways: dict[int, list[GatewayStatus]] = {}
        self._last_ipsec: dict[int, IPsecServiceStatus] = {}
        self._last_firewall_log: dict[int, list[dict]] = {}
        self._last_services: dict[int, list[ServiceInfo]] = {}
        # GUI-proxy tunnels: stream_id -> queue of frames coming back from the agent.
        self._tunnels: dict[str, asyncio.Queue] = {}

    # --- GUI-proxy tunnel registry (see §18) ---------------------------------

    def open_tunnel(self, stream_id: str) -> asyncio.Queue:
        """Register a tunnel stream; returns the queue agent frames are delivered to."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=_TUNNEL_QUEUE_MAX)
        self._tunnels[stream_id] = queue
        return queue

    def close_tunnel(self, stream_id: str) -> None:
        self._tunnels.pop(stream_id, None)

    def deliver_tunnel(self, stream_id: str, frame: dict) -> None:
        """Route a `tunnel` frame from the agent to its client handler's queue.

        Bounded: if the client can't keep up and the buffer is full, stop buffering
        and tear the stream down (apply backpressure / fail the slow stream) rather
        than grow unboundedly. We unregister the stream, free one slot, and enqueue a
        close sentinel so the consumer ends cleanly (its finally then closes the WS
        and tells the agent to close too).
        """
        queue = self._tunnels.get(stream_id)
        if queue is None:
            return
        try:
            queue.put_nowait(frame)
        except asyncio.QueueFull:
            self._tunnels.pop(stream_id, None)
            with contextlib.suppress(asyncio.QueueEmpty):
                queue.get_nowait()  # make room for the close sentinel
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait({"op": "close"})
            log.warning("tunnel.overflow_closed", stream=stream_id, maxsize=_TUNNEL_QUEUE_MAX)

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
                "last_update_error": a.last_update_error,
                "last_update_version": a.last_update_version,
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

    def unregister(self, instance_id: int, agent: ConnectedAgent | None = None) -> None:
        # Identity-aware teardown: when ``agent`` is given (the normal WS finally
        # path), only remove it if it is still the registered connection. Otherwise
        # an overlapping reconnect race lets a dying OLD connection's teardown evict
        # the freshly-registered NEW connection — the box keeps pushing metrics (so
        # it still looks online) but hub.get() is None, so every command/relay/
        # tunnel/update/GUI/uninstall returns 503 until a clean reconnect.
        # ``agent=None`` force-drops whatever is registered (admin disable/uninstall).
        current = self._agents.get(instance_id)
        if current is None:
            return
        if agent is not None and current is not agent:
            return
        self._agents.pop(instance_id, None)
        log.info("agent.disconnected", instance=current.instance_name)

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

    def get_last_services(self, instance_id: int) -> list[ServiceInfo] | None:
        return self._last_services.get(instance_id)

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
        services = self._last_services.get(instance_id)
        if services is not None:
            snap["services"] = [s.model_dump(mode="json") for s in services]
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
            if snapshot.get("services"):
                self._last_services[instance_id] = [
                    ServiceInfo.model_validate(s) for s in snapshot["services"]
                ]
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
        # Capture the previous snapshot BEFORE overwriting so we can diff it into
        # the tunnel state-change history below (prev survives a backend restart
        # via the hydrated status_snapshot, so we don't spam events on startup).
        tunnel_events = []
        if data.get("ipsec"):
            prev_ipsec = self._last_ipsec.get(instance_id)
            new_ipsec = ipsec_from_agent(data)
            self._last_ipsec[instance_id] = new_ipsec
            tunnel_events = diff_ipsec(prev_ipsec, new_ipsec)

        # Cache firewall log
        fw_log = data.get("firewall_log")
        if fw_log is not None:
            self._last_firewall_log[instance_id] = fw_log

        # Cache services — only when the agent actually sent a services list (an
        # empty list on a collector failure must not wipe the cache).
        if data.get("services"):
            self._last_services[instance_id] = services_from_agent(data)

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
            # Append any IPsec tunnel state transitions (same commit as the push).
            await record_tunnel_events(session, instance_id, ts, tunnel_events)
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
