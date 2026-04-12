"""APScheduler-based poller that runs inside the FastAPI process.

Every ``DASH_POLL_INTERVAL_SECONDS`` (default 30s) it fetches all active
instances and polls them in parallel with a concurrency limit of
``DASH_POLL_CONCURRENCY`` (default 20).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from app.config import get_settings
from app.db.base import get_sessionmaker
from app.db.models import Instance
from app.metrics.store import write_poll_metrics
from app.opnsense.registry import registry

log = structlog.get_logger("app.poller")

_scheduler: AsyncIOScheduler | None = None


async def _poll_instance(instance_id: int, instance_name: str) -> None:
    """Poll a single instance, persist metrics, update status columns."""
    sessionmaker = get_sessionmaker()
    ts = datetime.now(timezone.utc)

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
            await write_poll_metrics(session, instance_id, ts, status)
            inst.last_success_at = ts
            inst.last_error_at = None
            inst.last_error_message = None
            await session.commit()

        log.debug("poll.ok", instance=instance_name, cpu=status.cpu.total)

    except Exception as exc:  # noqa: BLE001
        log.warning("poll.error", instance=instance_name, error=str(exc))
        try:
            async with sessionmaker() as session:
                inst = await session.get(Instance, instance_id)
                if inst is not None:
                    inst.last_error_at = ts
                    inst.last_error_message = str(exc)[:500]
                    await session.commit()
        except Exception:  # noqa: BLE001
            log.error("poll.error_update_failed", instance=instance_name)


async def _poll_all() -> None:
    """Run one poll cycle across all active instances."""
    settings = get_settings()
    sessionmaker = get_sessionmaker()

    async with sessionmaker() as session:
        rows = (
            await session.execute(
                select(Instance.id, Instance.name).where(Instance.deleted_at.is_(None))
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
        next_run_time=datetime.now(timezone.utc),  # run immediately on startup
    )
    _scheduler.start()
    log.info("scheduler.started", interval_s=settings.poll_interval_seconds)


async def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("scheduler.stopped")
