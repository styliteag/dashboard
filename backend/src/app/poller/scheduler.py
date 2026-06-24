"""APScheduler-based poller that runs inside the FastAPI process.

Every ``DASH_POLL_INTERVAL_SECONDS`` (default 30s) it fetches all active
instances and polls them in parallel with a concurrency limit of
``DASH_POLL_CONCURRENCY`` (default 20).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from app.config import get_settings
from app.db.base import get_sessionmaker
from app.db.models import Instance
from app.devices.types import Transport
from app.maintenance.jobs import prune_metrics, rollup_5m
from app.metrics.store import is_online, write_poll_metrics
from app.notifications.notifier import send_notification
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
            await send_notification(
                f"✅ {instance_name} is back online",
                f"Instance {instance_name} recovered.",
                level="info",
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
                        await send_notification(
                            f"🔴 {instance_name} is offline",
                            f"Instance {instance_name} failed: {str(exc)[:200]}",
                            level="error",
                        )
        except Exception:  # noqa: BLE001
            log.error("poll.error_update_failed", instance=instance_name)


async def _poll_all() -> None:
    """Run one poll cycle across all active instances."""
    settings = get_settings()
    sessionmaker = get_sessionmaker()

    async with sessionmaker() as session:
        rows = (
            await session.execute(
                select(Instance.id, Instance.name).where(
                    Instance.deleted_at.is_(None),
                    Instance.transport == Transport.DIRECT.value,  # only poll direct-API devices
                )
            )
        ).all()

    if not rows:
        return

    semaphore = asyncio.Semaphore(settings.poll_concurrency)

    async def bounded(instance_id: int, name: str) -> None:
        async with semaphore:
            await _poll_instance(instance_id, name)

    log.info("poll.cycle_start", count=len(rows))
    await asyncio.gather(*(bounded(r.id, r.name) for r in rows))
    log.info("poll.cycle_end", count=len(rows))


async def _check_stale_agents() -> None:
    """Flip push-mode instances offline when their agent stops pushing.

    Direct-poll instances get offline detection from the poller; push instances
    would otherwise stay green forever after their agent dies, because nothing
    polls them. A push older than ``agent_stale_seconds`` is treated as offline
    (the threshold tolerates the brief reconnect during a self-update restart).
    """
    settings = get_settings()
    sessionmaker = get_sessionmaker()
    now = datetime.now(UTC)
    cutoff = now - timedelta(seconds=settings.agent_stale_seconds)

    async with sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(Instance).where(
                        Instance.deleted_at.is_(None),
                        Instance.transport == Transport.PUSH.value,
                        Instance.agent_last_seen.is_not(None),
                        Instance.agent_last_seen < cutoff,
                    )
                )
            )
            .scalars()
            .all()
        )

        for inst in rows:
            # Only the online→offline transition fires a notification (idempotent).
            if not is_online(inst.last_success_at, inst.last_error_at):
                continue
            inst.last_error_at = now
            inst.last_error_message = f"agent silent for >{settings.agent_stale_seconds}s"
            await session.commit()
            log.warning("agent.stale", instance=inst.name, instance_id=inst.id)
            await send_notification(
                f"🔴 {inst.name} agent offline",
                f"No metrics push from {inst.name} for over {settings.agent_stale_seconds}s.",
                level="error",
            )


def start_scheduler() -> None:
    global _scheduler
    settings = get_settings()
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(
        _poll_all,
        "interval",
        seconds=settings.poll_interval_seconds,
        id="poll_all",
        max_instances=1,
        next_run_time=datetime.now(UTC),  # run immediately on startup
    )
    _scheduler.add_job(
        _check_stale_agents,
        "interval",
        seconds=settings.poll_interval_seconds,
        id="check_stale_agents",
        max_instances=1,
    )
    # Metrics maintenance: 5-min rollup + retention prune (replaces TimescaleDB).
    _scheduler.add_job(rollup_5m, "interval", minutes=5, id="metrics_rollup", max_instances=1)
    _scheduler.add_job(prune_metrics, "interval", hours=1, id="metrics_prune", max_instances=1)
    _scheduler.start()
    log.info("scheduler.started", interval_s=settings.poll_interval_seconds)


async def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("scheduler.stopped")
