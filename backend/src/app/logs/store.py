"""Persist + prune agent-pushed logfile snapshots.

Only the newest ``KEEP_PER_NAME`` snapshots per ``(instance_id, name)`` are kept;
older ones are dropped on write (and by the scheduled ``prune_logfiles`` safety
net). The pure helpers (``clamp``, ``sanitize_logfiles``, ``surplus_ids``) carry
the logic and are unit-tested; the DB functions are thin wrappers verified live.
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import LogEvent, Logfile
from app.logs.events import ExtractedEvent, extract_events

KEEP_PER_NAME = 3
MAX_BYTES = 1_000_000  # per-logfile safety cap (agent tails first, this is a backstop)
_NAME_MAX = 64


def clamp(content: str, max_bytes: int = MAX_BYTES) -> str:
    """Keep only the last ``max_bytes`` characters (newest log lines)."""
    return content[-max_bytes:] if len(content) > max_bytes else content


def sanitize_logfiles(raw: list[dict]) -> list[tuple[str, str]]:
    """Clean an agent ``logfiles`` payload into ``(name, content)`` pairs.

    Drops entries with no name or no content; trims the name and caps content."""
    out: list[tuple[str, str]] = []
    for entry in raw:
        name = str(entry.get("name") or "").strip()[:_NAME_MAX]
        content = entry.get("content") or ""
        if name and content:
            out.append((name, clamp(content)))
    return out


def surplus_ids(ordered_ids: list[int], keep: int = KEEP_PER_NAME) -> list[int]:
    """Given ids newest-first, the ones beyond the keep window (to delete)."""
    return ordered_ids[keep:]


async def _newest_first_ids(session: AsyncSession, instance_id: int, name: str) -> list[int]:
    rows = await session.execute(
        select(Logfile.id)
        .where(Logfile.instance_id == instance_id, Logfile.name == name)
        .order_by(Logfile.collected_at.desc(), Logfile.id.desc())
    )
    return list(rows.scalars().all())


async def record_logfiles(session: AsyncSession, instance_id: int, raw: list[dict]) -> int:
    """Insert pushed snapshots, prune each touched name, refresh critical events."""
    pairs = sanitize_logfiles(raw)
    if not pairs:
        return 0
    for name, content in pairs:
        session.add(
            Logfile(instance_id=instance_id, name=name, bytes=len(content), content=content)
        )
    await session.flush()
    for name in {name for name, _ in pairs}:
        extra = surplus_ids(await _newest_first_ids(session, instance_id, name))
        if extra:
            await session.execute(delete(Logfile).where(Logfile.id.in_(extra)))
    for name, content in pairs:
        await replace_log_events(session, instance_id, name, extract_events(name, content))
    return len(pairs)


async def replace_log_events(
    session: AsyncSession, instance_id: int, log_name: str, events: list[ExtractedEvent]
) -> None:
    """Swap the stored events for one (instance, log) with the latest extraction."""
    await session.execute(
        delete(LogEvent).where(LogEvent.instance_id == instance_id, LogEvent.log_name == log_name)
    )
    for e in events:
        session.add(
            LogEvent(
                instance_id=instance_id,
                log_name=log_name,
                severity=e.severity,
                program=e.program,
                pattern=e.pattern,
                sample=e.sample,
                count=e.count,
                last_ts=e.last_ts,
            )
        )


async def list_logfiles(session: AsyncSession, instance_id: int) -> list[Logfile]:
    rows = await session.execute(
        select(Logfile.id, Logfile.name, Logfile.collected_at, Logfile.bytes)
        .where(Logfile.instance_id == instance_id)
        .order_by(Logfile.name.asc(), Logfile.collected_at.desc())
    )
    return list(rows.all())


async def get_logfile(session: AsyncSession, instance_id: int, logfile_id: int) -> Logfile | None:
    """A single stored snapshot, scoped to the instance (cross-instance ids miss)."""
    row = await session.execute(
        select(Logfile).where(Logfile.id == logfile_id, Logfile.instance_id == instance_id)
    )
    return row.scalars().first()


async def latest_per_name(session: AsyncSession, instance_id: int) -> list[Logfile]:
    """The newest snapshot of each distinct log name for an instance."""
    names = await session.execute(
        select(Logfile.name).where(Logfile.instance_id == instance_id).distinct()
    )
    out: list[Logfile] = []
    for name in sorted(names.scalars().all()):
        row = await session.execute(
            select(Logfile)
            .where(Logfile.instance_id == instance_id, Logfile.name == name)
            .order_by(Logfile.collected_at.desc(), Logfile.id.desc())
            .limit(1)
        )
        latest = row.scalars().first()
        if latest is not None:
            out.append(latest)
    return out


async def backfill_log_events(session: AsyncSession) -> int:
    """Populate an empty log_events table from the newest stored snapshots.

    No-op when events already exist — ingest keeps them current. Returns the
    number of events created."""
    from sqlalchemy import func

    existing = await session.scalar(select(func.count()).select_from(LogEvent))
    if existing:
        return 0
    newest = (
        select(func.max(Logfile.id).label("mid"))
        .group_by(Logfile.instance_id, Logfile.name)
        .subquery()
    )
    rows = await session.execute(select(Logfile).where(Logfile.id.in_(select(newest.c.mid))))
    created = 0
    for lf in rows.scalars():
        events = extract_events(lf.name, lf.content)
        await replace_log_events(session, lf.instance_id, lf.name, events)
        created += len(events)
    return created


async def prune_logfiles(session: AsyncSession) -> int:
    """Keep only KEEP_PER_NAME newest per (instance, name) across all rows."""
    pairs = await session.execute(select(Logfile.instance_id, Logfile.name).distinct())
    deleted = 0
    for instance_id, name in pairs.all():
        extra = surplus_ids(await _newest_first_ids(session, instance_id, name))
        if extra:
            result = await session.execute(delete(Logfile).where(Logfile.id.in_(extra)))
            deleted += result.rowcount or 0
    return deleted
