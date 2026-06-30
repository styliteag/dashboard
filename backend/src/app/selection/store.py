"""Selection rules: a process-local cache for the dispatch hot path + DB reads.

The cache (``_rules``) mirrors ``app.settings.store``: a single-worker in-memory
set, loaded at startup and re-synced after every write. The notification dispatch
path reads it with no DB round-trip (``is_on_live``).

Read-heavy *external* endpoints (the Checkmk export, the Alerts ``/checks`` view,
the Settings preview) must NOT rely on the single-worker cache — a multi-worker
deployment would serve stale rules to a Checkmk agent polling forever. Those call
``fetch_rules`` for a fresh DB read and feed it to the pure ``resolve``.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SelectionRule
from app.selection.model import Rule, is_on


def _as_rule(row: SelectionRule) -> Rule:
    return (row.consumer, row.instance_id, row.selector, row.mode)


# --- DB reads (always-fresh; for export / checks / preview) --------------------


async def fetch_rules(session: AsyncSession) -> set[Rule]:
    """Read all rules straight from the DB (no cache). Use on read endpoints that
    must stay correct under multiple workers."""
    rows = (await session.execute(select(SelectionRule))).scalars().all()
    return {_as_rule(r) for r in rows}


# --- Process cache (dispatch hot path) ----------------------------------------

_rules: set[Rule] = set()


async def load_rules(session: AsyncSession) -> int:
    """(Re)load all rules from the DB into the process cache. Returns count."""
    fresh = await fetch_rules(session)
    _rules.clear()
    _rules.update(fresh)
    return len(_rules)


def current_rules() -> set[Rule]:
    """A copy of the cached rules."""
    return set(_rules)


def is_on_live(consumer: str, check_key: str, instance_id: int) -> bool:
    """Whether ``consumer`` is interested in ``check_key`` for ``instance_id`` (cache)."""
    return is_on(consumer, check_key, instance_id, _rules)


# --- Writes (DB only; caller commits then calls load_rules to resync) ----------


def _rule_query(consumer: str, selector: str, instance_id: int | None):  # noqa: ANN202
    """Identity filter for one rule. ``instance_id`` NULL needs ``IS NULL`` — a
    ``== None`` predicate never matches in SQL."""
    stmt = select(SelectionRule).where(
        SelectionRule.consumer == consumer, SelectionRule.selector == selector
    )
    return stmt.where(
        SelectionRule.instance_id.is_(None)
        if instance_id is None
        else SelectionRule.instance_id == instance_id
    )


async def set_rule(
    session: AsyncSession,
    consumer: str,
    selector: str,
    mode: str,
    instance_id: int | None = None,
) -> SelectionRule:
    """Upsert a rule's ``mode`` (idempotent). Does NOT touch the cache."""
    row = (await session.execute(_rule_query(consumer, selector, instance_id))).scalar_one_or_none()
    if row is None:
        row = SelectionRule(
            consumer=consumer, instance_id=instance_id, selector=selector, mode=mode
        )
        session.add(row)
        await session.flush()
    elif row.mode != mode:
        row.mode = mode
        await session.flush()
    return row


async def remove_rule(
    session: AsyncSession, consumer: str, selector: str, instance_id: int | None = None
) -> bool:
    """Drop a rule (back to inherit / base default). Returns True if a row existed."""
    row = (await session.execute(_rule_query(consumer, selector, instance_id))).scalar_one_or_none()
    if row is not None:
        await session.delete(row)
        await session.flush()
    return row is not None
