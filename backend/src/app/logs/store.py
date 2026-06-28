"""Persist + prune agent-pushed logfile snapshots.

Only the newest ``KEEP_PER_NAME`` snapshots per ``(instance_id, name)`` are kept;
older ones are dropped on write (and by the scheduled ``prune_logfiles`` safety
net). The pure helpers (``clamp``, ``sanitize_logfiles``, ``surplus_ids``) carry
the logic and are unit-tested; the DB functions are thin wrappers verified live.
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Logfile

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
    """Insert pushed snapshots and prune each touched name to KEEP_PER_NAME."""
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
    return len(pairs)


async def list_logfiles(session: AsyncSession, instance_id: int) -> list[Logfile]:
    rows = await session.execute(
        select(Logfile.id, Logfile.name, Logfile.collected_at, Logfile.bytes)
        .where(Logfile.instance_id == instance_id)
        .order_by(Logfile.name.asc(), Logfile.collected_at.desc())
    )
    return list(rows.all())


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
