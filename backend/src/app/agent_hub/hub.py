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

from app.agent_hub.converters import (
    annotate_iface_error_rates,
    certs_from_agent,
    check_alert,
    connectivity_from_agent,
    firmware_from_agent,
    gateways_from_agent,
    ipsec_from_agent,
    pf_top_from_agent,
    services_from_agent,
    status_from_agent,
)
from app.checks.evaluate import evaluate_checks
from app.checks.event_store import record_availability_event, record_check_events
from app.checks.history import current_states, diff_checks
from app.checks.models import CheckState, ServiceCheck
from app.db.base import get_sessionmaker
from app.db.models import Instance
from app.ipsec.event_store import record_tunnel_events
from app.ipsec.history import diff_ipsec
from app.logs.store import record_logfiles
from app.metrics.store import is_online, write_poll_metrics
from app.notifications.notifier import dispatch_async
from app.xsense.schemas import (
    CertInfo,
    ConnectivityResult,
    FirmwareStatus,
    GatewayStatus,
    IPsecServiceStatus,
    PfTopSummary,
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

# A duplicate Phase-2 (more than one INSTALLED child SA for one selector pair) is
# only surfaced as a note after it has been seen this many consecutive pushes —
# a make-before-break rekey shows two INSTALLED SAs for at most a poll or two, so
# this filters the routine churn and keeps only the stuck/orphaned duplicates.
_DUP_PERSIST_POLLS = 3

# A connectivity/IPsec Phase-2 ping monitor CRITs only after this many consecutive
# failed pushes; recovery is immediate on the first OK. Each push is a single ping
# measurement, so without this a lone dropped packet flips the check (and its
# Telegram/e-mail/Mattermost notification) OK→CRIT→OK inside a minute.
_PING_FLAP_POLLS = 3


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
        # Per-instance consecutive-poll counter for duplicate Phase-2 selectors
        # ({"tunnel|local_ts|remote_ts": polls}). In-memory only: a restart just
        # re-accrues the streak, so the note reappears after a few pushes.
        self._ipsec_dup_streak: dict[int, dict[str, int]] = {}
        # Per-instance consecutive-fail counter for connectivity/IPsec Phase-2 ping
        # checks ({check_key: consecutive CRIT pushes}) — flap debounce, see
        # ``_debounce_ping_checks``. In-memory only, same trade-off as the dup streak.
        self._ping_fail_streak: dict[int, dict[str, int]] = {}
        self._last_connectivity: dict[int, list[ConnectivityResult]] = {}
        self._last_firewall_log: dict[int, list[dict]] = {}
        self._last_services: dict[int, list[ServiceInfo]] = {}
        self._last_certs: dict[int, list[CertInfo]] = {}
        self._last_pf_top: dict[int, PfTopSummary] = {}
        # Timestamp of the previous metrics push per instance — the time base for
        # deriving per-interface error *rates* (counters are cumulative). In-memory
        # only (not hydrated), so the first push after a restart gets one no-data round.
        self._last_metrics_ts: dict[int, datetime] = {}
        # Last evaluated check states ({key: state}) per instance — the baseline
        # the next push diffs against to record check-history transitions. Survives
        # a backend restart via the persisted status_snapshot (no restart spam).
        self._last_check_states: dict[int, dict[str, int]] = {}
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

    def get_last_connectivity(self, instance_id: int) -> list[ConnectivityResult] | None:
        return self._last_connectivity.get(instance_id)

    def get_last_firewall_log(self, instance_id: int) -> list[dict] | None:
        return self._last_firewall_log.get(instance_id)

    def get_last_services(self, instance_id: int) -> list[ServiceInfo] | None:
        return self._last_services.get(instance_id)

    def get_last_certs(self, instance_id: int) -> list[CertInfo] | None:
        return self._last_certs.get(instance_id)

    def get_last_pf_top(self, instance_id: int) -> PfTopSummary | None:
        return self._last_pf_top.get(instance_id)

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
        connectivity = self._last_connectivity.get(instance_id)
        if connectivity is not None:
            snap["connectivity"] = [c.model_dump(mode="json") for c in connectivity]
        fwl = self._last_firewall_log.get(instance_id)
        if fwl is not None:
            snap["firewall_log"] = fwl
        services = self._last_services.get(instance_id)
        if services is not None:
            snap["services"] = [s.model_dump(mode="json") for s in services]
        certs = self._last_certs.get(instance_id)
        if certs is not None:
            snap["certificates"] = [c.model_dump(mode="json") for c in certs]
        pf_top = self._last_pf_top.get(instance_id)
        if pf_top is not None:
            snap["pf_top"] = pf_top.model_dump(mode="json")
        check_states = self._last_check_states.get(instance_id)
        if check_states is not None:
            snap["check_states"] = check_states
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
                ipsec = IPsecServiceStatus.model_validate(snapshot["ipsec"])
                self._last_ipsec[instance_id] = ipsec
                # Re-seed the per-selector dup streak so a restart with an active
                # *persistent* duplicate Phase-2 doesn't reset to 0 and re-derive
                # False on the next push — which would emit a spurious phase2_dup_off
                # then phase2_dup_on flap (and drop the UI note for a few polls).
                seeded = {
                    f"{t.id}|{c.local_ts}|{c.remote_ts}": _DUP_PERSIST_POLLS
                    for t in ipsec.tunnels
                    for c in t.children
                    if c.phase2_dup_persistent
                }
                if seeded:
                    self._ipsec_dup_streak[instance_id] = seeded
            if snapshot.get("connectivity"):
                self._last_connectivity[instance_id] = [
                    ConnectivityResult.model_validate(c) for c in snapshot["connectivity"]
                ]
            if snapshot.get("firewall_log"):
                self._last_firewall_log[instance_id] = snapshot["firewall_log"]
            if snapshot.get("services"):
                self._last_services[instance_id] = [
                    ServiceInfo.model_validate(s) for s in snapshot["services"]
                ]
            if snapshot.get("certificates"):
                self._last_certs[instance_id] = [
                    CertInfo.model_validate(c) for c in snapshot["certificates"]
                ]
            if snapshot.get("pf_top"):
                self._last_pf_top[instance_id] = PfTopSummary.model_validate(snapshot["pf_top"])
            if snapshot.get("check_states"):
                self._last_check_states[instance_id] = {
                    str(k): int(v) for k, v in snapshot["check_states"].items()
                }
                # Re-seed the ping fail-streak to the threshold for any ping-monitor
                # key that was already CRIT — otherwise the in-memory streak starts
                # at 0, the first still-failing push after restart gets held to OK by
                # _debounce_ping_checks, and diffing that against the hydrated CRIT
                # baseline fires a false "recovered" notification (same rationale as
                # the dup-streak re-seed above).
                self._ping_fail_streak[instance_id] = {
                    key: _PING_FLAP_POLLS
                    for key, state in self._last_check_states[instance_id].items()
                    if state == int(CheckState.CRIT)
                    and (key.startswith("connectivity:") or key.startswith("ipsec.tunnel_ping:"))
                }
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

    def _annotate_dup_persistence(
        self, instance_id: int, status: IPsecServiceStatus
    ) -> IPsecServiceStatus:
        """Set ``phase2_dup_persistent`` on children whose duplicate Phase-2 has
        survived ``_DUP_PERSIST_POLLS`` consecutive pushes.

        The agent reports an instantaneous ``dup_count`` (>1 = duplicated this
        poll). We keep a per-selector streak: a selector duplicated this poll
        increments its counter, anything else drops out (resets to 0). Only once a
        streak reaches the threshold is the note shown — so a transient rekey blip
        never lights it. Returns a copy with the flag applied (no mutation)."""
        prev = self._ipsec_dup_streak.get(instance_id, {})
        streaks: dict[str, int] = {}
        tunnels = []
        for t in status.tunnels:
            children = []
            for c in t.children:
                persistent = False
                if c.dup_count > 1:
                    key = f"{t.id}|{c.local_ts}|{c.remote_ts}"
                    streaks[key] = prev.get(key, 0) + 1
                    persistent = streaks[key] >= _DUP_PERSIST_POLLS
                children.append(
                    c
                    if persistent == c.phase2_dup_persistent
                    else c.model_copy(update={"phase2_dup_persistent": persistent})
                )
            tunnels.append(t.model_copy(update={"children": children}))
        self._ipsec_dup_streak[instance_id] = streaks
        return status.model_copy(update={"tunnels": tunnels})

    def _debounce_ping_checks(
        self, instance_id: int, checks: list[ServiceCheck]
    ) -> list[ServiceCheck]:
        """Hold connectivity/IPsec Phase-2 ping checks at OK until a failure has
        persisted for ``_PING_FLAP_POLLS`` consecutive pushes; recovery is immediate
        on the first OK (same shape as ``_annotate_dup_persistence`` above). Only
        affects the two agent-pushed ping-monitor families — every other check
        (memory, gateways, IPsec tunnel state, …) passes through unchanged."""
        prev = self._ping_fail_streak.get(instance_id, {})
        streaks: dict[str, int] = {}
        out: list[ServiceCheck] = []
        for c in checks:
            is_ping_key = c.key.startswith("connectivity:") or c.key.startswith(
                "ipsec.tunnel_ping:"
            )
            if not is_ping_key or c.state != int(CheckState.CRIT):
                out.append(c)
                continue
            streak = prev.get(c.key, 0) + 1
            streaks[c.key] = streak
            out.append(
                c
                if streak >= _PING_FLAP_POLLS
                else c.model_copy(update={"state": int(CheckState.OK)})
            )
        self._ping_fail_streak[instance_id] = streaks
        return out

    async def handle_metrics(self, instance_id: int, data: dict) -> None:
        """Process a metrics push from an agent."""
        sessionmaker = get_sessionmaker()
        ts = datetime.now(UTC)

        # Derive per-interface error rates from the previous snapshot BEFORE it is
        # overwritten (same prev-then-overwrite pattern the IPsec diff uses below),
        # then cache and evaluate the one annotated status object.
        prev_status = self._last_status.get(instance_id)
        prev_ts = self._last_metrics_ts.get(instance_id)
        dt = (ts - prev_ts).total_seconds() if prev_ts is not None else 0.0
        status = annotate_iface_error_rates(status_from_agent(data), prev_status, dt)
        self._last_status[instance_id] = status
        self._last_metrics_ts[instance_id] = ts

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
            new_ipsec = self._annotate_dup_persistence(instance_id, ipsec_from_agent(data))
            self._last_ipsec[instance_id] = new_ipsec
            tunnel_events = diff_ipsec(prev_ipsec, new_ipsec)

        # Cache standalone connectivity-ping results. Unlike the collector-failure
        # guards above, an empty list here is legitimate (no monitors configured),
        # so cache whenever the key is present — every modern agent always sends it.
        conn = data.get("connectivity")
        if conn is not None:
            self._last_connectivity[instance_id] = connectivity_from_agent(data)

        # Cache firewall log
        fw_log = data.get("firewall_log")
        if fw_log is not None:
            self._last_firewall_log[instance_id] = fw_log

        # Cache services — only when the agent actually sent a services list (an
        # empty list on a collector failure must not wipe the cache).
        if data.get("services"):
            self._last_services[instance_id] = services_from_agent(data)

        # Cache certificates — same guard (empty list = collector failure, keep cache).
        if data.get("certificates"):
            self._last_certs[instance_id] = certs_from_agent(data)

        # Cache pf state-table insight — converter returns None for a missing
        # (older agent) or malformed section, keeping the previous entry.
        pf_top = pf_top_from_agent(data)
        if pf_top is not None:
            self._last_pf_top[instance_id] = pf_top

        # Cache firmware data from agent push
        if data.get("firmware"):
            self._last_firmware[instance_id] = firmware_from_agent(data, ts.isoformat())

        # Re-evaluate checks from the just-updated caches and diff against the
        # previous states to record check-history transitions. The previous states
        # survive a restart via the hydrated snapshot, so a restart doesn't re-fire
        # every check (same property the IPsec history relies on).
        checks = evaluate_checks(
            status,
            self._last_gateways.get(instance_id),
            self._last_ipsec.get(instance_id),
            self._last_firmware.get(instance_id),
            self._last_services.get(instance_id),
            self._last_certs.get(instance_id),
            self._last_connectivity.get(instance_id),
        )
        # Flap-debounce the ping-monitor checks before diffing/recording — a single
        # dropped ping must not fire (and un-fire) a notification a few seconds later.
        checks = self._debounce_ping_checks(instance_id, checks)
        check_transitions = diff_checks(self._last_check_states.get(instance_id), checks)
        self._last_check_states[instance_id] = current_states(checks)

        recovered_name: str | None = None
        cleared_maintenance = False
        instance_name = ""
        async with sessionmaker() as session:
            inst = await session.get(Instance, instance_id)
            if inst is None:
                return
            instance_name = inst.name
            # Was this instance offline (e.g. flagged by the staleness watchdog)?
            # If so, this push is a recovery — notify once.
            if not is_online(inst.last_success_at, inst.last_error_at) and inst.last_error_at:
                recovered_name = inst.name
                # Persist the offline→online edge into availability history (same commit).
                await record_availability_event(
                    session, instance_id, ts, online=True, summary="agent resumed pushing metrics"
                )
            await write_poll_metrics(session, instance_id, ts, status)
            # Append any IPsec tunnel state transitions (same commit as the push).
            await record_tunnel_events(session, instance_id, ts, tunnel_events)
            # Append any service-check state transitions (same commit as the push).
            await record_check_events(session, instance_id, ts, check_transitions)
            # Store any pushed logfile snapshots (hourly) for AI analysis; the store
            # prunes to the newest few per name so this table never grows unbounded.
            if data.get("logfiles"):
                await record_logfiles(session, instance_id, data["logfiles"])
            inst.last_success_at = ts
            inst.last_error_at = None
            inst.last_error_message = None
            inst.agent_last_seen = ts
            # Maintenance auto-clears the moment the agent reports again — a healthy
            # heartbeat means the planned-down window is over (admin's intent).
            if inst.maintenance:
                inst.maintenance = False
                cleared_maintenance = True
            # Persist the just-updated caches so a backend restart can re-hydrate.
            inst.status_snapshot = self._snapshot_for(instance_id)
            await session.commit()

        if cleared_maintenance:
            dispatch_async(
                f"🛠️ {instance_name} maintenance ended",
                f"{instance_name} reported in again — maintenance flag cleared.",
                instance_id,
                level="info",
                check_key="availability",
            )
        if recovered_name:
            dispatch_async(
                f"✅ {recovered_name} agent back online",
                f"Agent for {recovered_name} resumed pushing metrics.",
                instance_id,
                level="info",
                check_key="availability",
            )
        # Fire a per-check alert for every state transition. Each is routed by its
        # category, so a channel only gets it when subscribed (history is recorded
        # regardless, above). Transitions are sparse — one per actual state change.
        # Sends are fire-and-forget so channel send latency never blocks ingest.
        for transition in check_transitions:
            title, msg, level, key = check_alert(instance_name, transition)
            dispatch_async(title, msg, instance_id, level=level, check_key=key)
        log.debug("agent.metrics", instance_id=instance_id, cpu=status.cpu.total)


# Global singleton
hub = AgentHub()
