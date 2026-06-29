"""APScheduler-based poller that runs inside the FastAPI process.

It ticks every ``DASH_POLL_TICK_SECONDS`` (default 10s) and, on each tick, polls
the active direct-API instances whose own effective interval has elapsed — the
per-instance ``poll_interval_seconds`` override or the global default
``DASH_POLL_INTERVAL_SECONDS`` (default 30s). Polls run in parallel with a
concurrency limit of ``DASH_POLL_CONCURRENCY`` (default 20). See ``poller.gate``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select, update

from app.db.base import get_sessionmaker
from app.db.models import Instance
from app.devices.types import Transport
from app.maintenance.jobs import (
    prune_check_events,
    prune_ipsec_events,
    prune_logfiles,
    prune_metrics,
)
from app.metrics.store import is_online, write_poll_metrics
from app.notifications.notifier import dispatch_async
from app.poller.gate import effective_interval, is_due, is_stale, stale_threshold
from app.probe import run_probe
from app.probe.registry import probe_registry
from app.settings.store import effective_settings
from app.xsense.registry import registry

log = structlog.get_logger("app.poller")

_scheduler: AsyncIOScheduler | None = None


async def _poll_instance(instance_id: int, instance_name: str) -> None:
    """Poll a single instance, persist metrics, update status columns."""
    sessionmaker = get_sessionmaker()
    ts = datetime.now(UTC)

    try:
        async with sessionmaker() as session:
            inst = await session.get(Instance, instance_id)
            if inst is None or inst.deleted_at is not None:
                return
            client = await registry.get(inst)

        status = await client.poll_status()

        async with sessionmaker() as session:
            inst = await session.get(Instance, instance_id)
            if inst is None:
                return
            # Detect recovery: was offline, now back
            was_offline = inst.last_error_at and (
                not inst.last_success_at or inst.last_error_at > inst.last_success_at
            )
            await write_poll_metrics(session, instance_id, ts, status)
            inst.last_success_at = ts
            inst.last_error_at = None
            inst.last_error_message = None
            await session.commit()

        if was_offline:
            dispatch_async(
                f"✅ {instance_name} is back online",
                f"Instance {instance_name} recovered.",
                instance_id,
                level="info",
                category="availability",
            )
        log.debug("poll.ok", instance=instance_name, cpu=status.cpu.total)

    except Exception as exc:  # noqa: BLE001
        log.warning("poll.error", instance=instance_name, error=str(exc))
        try:
            async with sessionmaker() as session:
                inst = await session.get(Instance, instance_id)
                if inst is not None:
                    # Detect transition to offline: was online, now failing
                    was_online = inst.last_success_at and (
                        not inst.last_error_at or inst.last_success_at > inst.last_error_at
                    )
                    inst.last_error_at = ts
                    inst.last_error_message = str(exc)[:500]
                    await session.commit()
                    if was_online:
                        dispatch_async(
                            f"🔴 {instance_name} is offline",
                            f"Instance {instance_name} failed: {str(exc)[:200]}",
                            instance_id,
                            level="error",
                            category="availability",
                        )
        except Exception:  # noqa: BLE001
            log.error("poll.error_update_failed", instance=instance_name)


async def _poll_all() -> None:
    """Poll every direct instance whose own interval has elapsed (tick-and-gate).

    The job fires every ``poll_tick_seconds``; each instance is polled only once its
    effective interval (per-instance override or the global default) has elapsed
    since the last attempt — so a box can run faster *or* slower than the default.
    """
    settings = effective_settings()
    sessionmaker = get_sessionmaker()
    now = datetime.now(UTC)

    async with sessionmaker() as session:
        rows = (
            await session.execute(
                select(
                    Instance.id,
                    Instance.name,
                    Instance.poll_interval_seconds,
                    Instance.last_success_at,
                    Instance.last_error_at,
                ).where(
                    Instance.deleted_at.is_(None),
                    Instance.transport == Transport.DIRECT.value,  # only poll direct-API devices
                )
            )
        ).all()

    due = [
        r
        for r in rows
        if is_due(
            now,
            r.last_success_at,
            r.last_error_at,
            effective_interval(r.poll_interval_seconds, settings.poll_interval_seconds),
        )
    ]
    if not due:
        return

    semaphore = asyncio.Semaphore(settings.poll_concurrency)

    async def bounded(instance_id: int, name: str) -> None:
        async with semaphore:
            await _poll_instance(instance_id, name)

    log.info("poll.cycle_start", count=len(due))
    await asyncio.gather(*(bounded(r.id, r.name) for r in due))
    log.info("poll.cycle_end", count=len(due))


async def _check_stale_agents() -> None:
    """Flip push-mode instances offline when their agent stops pushing.

    Direct-poll instances get offline detection from the poller; push instances
    would otherwise stay green forever after their agent dies, because nothing
    polls them. The silence threshold scales with each instance's effective push
    interval (~4 missed pushes), floored at ``agent_stale_seconds`` — so a
    deliberately slow agent is not flagged offline at the global floor, while the
    floor still tolerates the brief reconnect during a self-update restart.
    """
    settings = effective_settings()
    sessionmaker = get_sessionmaker()

    # Collect instances we actually flipped offline, notify AFTER the session is
    # closed: the send is fire-and-forget, but it must not run while the session is
    # held (it would tie up a DB conn) — keep notification scheduling off the DB path.
    flagged: list[tuple[str, int, int]] = []
    async with sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(Instance).where(
                        Instance.deleted_at.is_(None),
                        Instance.transport == Transport.PUSH.value,
                        Instance.agent_last_seen.is_not(None),
                    )
                )
            )
            .scalars()
            .all()
        )

        for inst in rows:
            now = datetime.now(UTC)  # per-iteration; the loop must not reuse a stale clock
            threshold = stale_threshold(
                inst.push_interval_seconds,
                settings.push_interval_seconds,
                settings.agent_stale_seconds,
            )
            if not is_stale(now, inst.agent_last_seen, threshold):
                continue
            # Only the online→offline transition fires a notification (idempotent).
            if not is_online(inst.last_success_at, inst.last_error_at):
                continue
            # Guarded flip: mark offline only if no fresher push landed since our
            # snapshot (agent_last_seen unchanged — only handle_metrics writes it).
            # Without this, an agent that reconnects mid-pass gets clobbered off a
            # stale snapshot and a false offline alert fires.
            result = await session.execute(
                update(Instance)
                .where(
                    Instance.id == inst.id,
                    Instance.agent_last_seen == inst.agent_last_seen,
                )
                .values(
                    last_error_at=now,
                    last_error_message=f"agent silent for >{threshold}s",
                )
            )
            await session.commit()
            if result.rowcount:
                log.warning("agent.stale", instance=inst.name, instance_id=inst.id)
                flagged.append((inst.name, inst.id, threshold))

    for name, instance_id, threshold in flagged:
        dispatch_async(
            f"🔴 {name} agent offline",
            f"No metrics push from {name} for over {threshold}s.",
            instance_id,
            level="error",
            category="availability",
        )


def _probe_confirms_up(view) -> bool:  # noqa: ANN001 — ProbeResult | None
    """True when a debounced probe view positively confirms reachability."""
    return view is not None and (view.icmp_up is True or view.http_up is True)


async def _probe_targets() -> None:
    """Run the out-of-band ICMP+HTTP probe for every instance with a ``ping_url``.

    Independent of the agent: distinguishes "box up, agent dead" from "box down".
    Results feed the debounced :data:`probe_registry`, which the check routes read.
    Registry state for instances that dropped their ``ping_url`` is pruned so it
    can't go stale.
    """
    settings = effective_settings()
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(Instance).where(
                        Instance.deleted_at.is_(None),
                        Instance.ping_url.is_not(None),
                    )
                )
            )
            .scalars()
            .all()
        )
    targets = [(r.id, r.ping_url, r.maintenance) for r in rows if (r.ping_url or "").strip()]
    probe_registry.prune({iid for iid, _, _ in targets})
    if not targets:
        return

    semaphore = asyncio.Semaphore(settings.poll_concurrency)
    threshold = settings.probe_fail_threshold

    async def one(instance_id: int, ping_url: str) -> None:
        async with semaphore:
            result = await run_probe(ping_url)
        probe_registry.update(instance_id, result, threshold)

    await asyncio.gather(*(one(iid, url) for iid, url, _ in targets))

    # Auto-clear maintenance for any flagged instance the probe now confirms up
    # (the direct/probe-only counterpart to the agent-heartbeat clear in the hub).
    recovered = [
        iid for iid, _, maint in targets if maint and _probe_confirms_up(probe_registry.get(iid))
    ]
    if recovered:
        async with sessionmaker() as session:
            await session.execute(
                update(Instance).where(Instance.id.in_(recovered)).values(maintenance=False)
            )
            await session.commit()
        log.info("probe.maintenance_cleared", instance_ids=recovered)


def start_scheduler() -> None:
    global _scheduler
    settings = effective_settings()
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(
        _poll_all,
        "interval",
        seconds=settings.poll_tick_seconds,  # scheduler granularity; per-instance gated
        id="poll_all",
        max_instances=1,
        next_run_time=datetime.now(UTC),  # run immediately on startup
    )
    _scheduler.add_job(
        _check_stale_agents,
        "interval",
        seconds=settings.poll_tick_seconds,
        id="check_stale_agents",
        max_instances=1,
    )
    # Out-of-band reachability probe (ICMP+HTTP) for instances with a ping_url.
    _scheduler.add_job(
        _probe_targets,
        "interval",
        seconds=settings.probe_interval_seconds,
        id="probe_targets",
        max_instances=1,
        next_run_time=datetime.now(UTC),
    )
    # Metrics maintenance: raw-metrics retention prune (replaces TimescaleDB).
    _scheduler.add_job(prune_metrics, "interval", hours=1, id="metrics_prune", max_instances=1)
    # IPsec tunnel-event history retention (tiny table — daily is plenty).
    _scheduler.add_job(
        prune_ipsec_events, "interval", hours=24, id="ipsec_events_prune", max_instances=1
    )
    # Service-check event history retention (tiny transition log — daily prune).
    _scheduler.add_job(
        prune_check_events, "interval", hours=24, id="check_events_prune", max_instances=1
    )
    # Logfile snapshots: ingest prunes on write; this is a daily safety net.
    _scheduler.add_job(prune_logfiles, "interval", hours=24, id="logfiles_prune", max_instances=1)
    _scheduler.start()
    log.info(
        "scheduler.started",
        tick_s=settings.poll_tick_seconds,
        default_interval_s=settings.poll_interval_seconds,
    )


async def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("scheduler.stopped")
