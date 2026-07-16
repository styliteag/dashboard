"""Access log read endpoints (ADR docs/access-log.md, DR-AL7/AL9).

Everything here is ``require_admin_or_superadmin`` (DR-AL1): the data is IPs
and activity of ALL users — deliberately admin-visible, never view_only. The
superadmin is included (security oversight is rights-management territory; its
role is view_only, so plain ``require_admin`` would lock it out). Read-only
surface; writes happen in ``store.py`` via the scheduler.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.access.store import ONLINE_WINDOW_S
from app.auth.deps import require_admin_or_superadmin
from app.db.base import get_session
from app.db.models import (
    AccessEvent,
    AccessStat,
    AuditLog,
    AuthSession,
    GeoipDenialEvent,
    Instance,
    User,
)
from app.geoip import lookup as geoip_lookup

router = APIRouter(prefix="/access-log", tags=["access-log"])

# Timeline sources are merged newest-first; per source we fetch the page limit
# and cut after sorting, so a chatty source can't starve the others.
_KINDS = ("auth", "access", "denial", "request")

# "access" = a user reaching into a box: web GUI (via agent proxy), shell
# console, packet capture, firewall-rule edits. Sourced from the audit trail —
# extend when a new instance-access feature starts auditing.
_ACCESS_ACTION_PREFIXES = (
    "agent.gui_open",
    "shell.",
    "capture.",
    "packet_capture.",
    "firewall.rule.",
)


def _access_action_clause():
    return or_(*[AuditLog.action.startswith(p) for p in _ACCESS_ACTION_PREFIXES])


class OnlineSession(BaseModel):
    username: str | None
    user_id: int
    ip: str | None
    country: str | None = None  # via local GeoIP DB (display only)
    country_name: str | None = None
    login_at: str
    last_seen_at: str


class PrincipalStat(BaseModel):
    principal: str  # "user:3" resolved to a username where possible
    requests: int
    last_ip: str | None
    last_country: str | None = None


class AccessSummary(BaseModel):
    online: list[OnlineSession]
    logins_ok_24h: int
    logins_failed_24h: int
    denials_24h: int
    denials_by_reason_24h: dict[str, int]
    requests_24h: list[PrincipalStat]


class TimelineItem(BaseModel):
    ts: str
    kind: str  # auth | access | denial | request
    # auth/access: audit action/result; denial: reason; request: "GET /api/..."
    label: str
    result: str | None = None
    username: str | None = None
    ip: str | None = None
    country: str | None = None
    country_name: str | None = None  # hover label from the local GeoIP DB
    instance: str | None = None  # access: resolved instance name (or raw target)
    detail: dict | None = None


class TimelinePage(BaseModel):
    items: list[TimelineItem]
    next_before: str | None  # pass back as ?before= to fetch the next page


async def _usernames(session: AsyncSession, user_ids: set[int]) -> dict[int, str]:
    if not user_ids:
        return {}
    rows = (
        await session.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
    ).all()
    return {r.id: r.username for r in rows}


async def _instance_names(session: AsyncSession, target_ids: set[str | None]) -> dict[str, str]:
    """Resolve audit target_ids ("3") to instance names — deleted boxes keep the raw id."""
    numeric = {int(t) for t in target_ids if t and str(t).isdigit()}
    if not numeric:
        return {}
    rows = (
        await session.execute(select(Instance.id, Instance.name).where(Instance.id.in_(numeric)))
    ).all()
    return {str(r.id): r.name for r in rows}


async def _search_instance_ids(session: AsyncSession, q: str) -> set[str]:
    """Audit target_ids whose instance name matches the free-text search."""
    rows = (await session.execute(select(Instance.id).where(Instance.name.like(f"%{q}%")))).all()
    return {str(r[0]) for r in rows}


@router.get("/summary", response_model=AccessSummary)
async def access_summary(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_admin_or_superadmin)],
) -> AccessSummary:
    now = datetime.now(UTC)
    online_cutoff = now - timedelta(seconds=ONLINE_WINDOW_S)
    day_cutoff = now - timedelta(hours=24)

    online_rows = (
        (
            await session.execute(
                select(AuthSession)
                .where(AuthSession.ended_at.is_(None), AuthSession.last_seen_at >= online_cutoff)
                .order_by(AuthSession.last_seen_at.desc())
            )
        )
        .scalars()
        .all()
    )
    names = await _usernames(session, {s.user_id for s in online_rows})

    logins_ok = (
        await session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "auth.login", AuditLog.result == "ok", AuditLog.ts >= day_cutoff
            )
        )
        or 0
    )
    logins_failed = (
        await session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "auth.login",
                AuditLog.result.in_(("error", "denied")),
                AuditLog.ts >= day_cutoff,
            )
        )
        or 0
    )

    denial_rows = (
        await session.execute(
            select(GeoipDenialEvent.reason, func.count())
            .where(GeoipDenialEvent.ts >= day_cutoff)
            .group_by(GeoipDenialEvent.reason)
        )
    ).all()
    denials_by_reason = {r[0]: int(r[1]) for r in denial_rows}

    stat_rows = (
        await session.execute(
            select(
                AccessStat.principal_type,
                AccessStat.principal_key,
                func.sum(AccessStat.count),
                func.max(AccessStat.last_ip),
            )
            .where(AccessStat.bucket >= day_cutoff)
            .group_by(AccessStat.principal_type, AccessStat.principal_key)
            .order_by(func.sum(AccessStat.count).desc())
        )
    ).all()
    stat_user_ids = {int(r[1]) for r in stat_rows if r[0] == "user" and str(r[1]).isdigit()}
    stat_names = await _usernames(session, stat_user_ids)
    requests_24h = [
        PrincipalStat(
            principal=(
                stat_names.get(int(pkey), f"user:{pkey}")
                if ptype == "user" and str(pkey).isdigit()
                else f"{ptype}:{pkey}"
                if ptype != "anon"
                else "anonymous"
            ),
            requests=int(n or 0),
            last_ip=last_ip,
            last_country=geoip_lookup.country_display(last_ip)[0],
        )
        for ptype, pkey, n, last_ip in stat_rows
    ]

    online = []
    for s in online_rows:
        country, country_name = geoip_lookup.country_display(s.ip)
        online.append(
            OnlineSession(
                username=names.get(s.user_id),
                user_id=s.user_id,
                ip=s.ip,
                country=country,
                country_name=country_name,
                login_at=s.created_at.isoformat(),
                last_seen_at=s.last_seen_at.isoformat(),
            )
        )

    return AccessSummary(
        online=online,
        logins_ok_24h=int(logins_ok),
        logins_failed_24h=int(logins_failed),
        denials_24h=sum(denials_by_reason.values()),
        denials_by_reason_24h=denials_by_reason,
        requests_24h=requests_24h,
    )


async def _search_user_ids(session: AsyncSession, q: str) -> set[int]:
    """User ids whose username matches the free-text search."""
    rows = (await session.execute(select(User.id).where(User.username.like(f"%{q}%")))).all()
    return {r[0] for r in rows}


@router.get("/timeline", response_model=TimelinePage)
async def access_timeline(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_admin_or_superadmin)],
    kinds: str = Query(
        default="auth,access,denial,request", description="CSV of auth|access|denial|request"
    ),
    before: str | None = Query(default=None, description="ISO ts cursor from next_before"),
    q: str | None = Query(
        default=None, max_length=100, description="Free-text: user/IP/action/path"
    ),
    hours: int | None = Query(default=None, ge=1, le=8760, description="Only the last N hours"),
    limit: int = Query(default=50, ge=1, le=200),
) -> TimelinePage:
    wanted = [k.strip() for k in kinds.split(",") if k.strip() in _KINDS]
    cutoff = datetime.fromisoformat(before) if before else None
    since = datetime.now(UTC) - timedelta(hours=hours) if hours else None
    needle = (q or "").strip()
    like = f"%{needle}%"
    # Free-text matches usernames too — resolve ids once, filter per source.
    uids = await _search_user_ids(session, needle) if needle else set()

    items: list[tuple[datetime, TimelineItem]] = []

    if "auth" in wanted:
        stmt = select(AuditLog).where(AuditLog.action.startswith("auth."))
        if cutoff is not None:
            stmt = stmt.where(AuditLog.ts < cutoff)
        if since is not None:
            stmt = stmt.where(AuditLog.ts >= since)
        if needle:
            conds = [
                AuditLog.source_ip.like(like),
                AuditLog.action.like(like),
                # Failed logins carry the attempted username only in detail
                # (no user row matched) — search must still find them.
                AuditLog.detail["username"].as_string().like(like),
            ]
            if uids:
                conds.append(AuditLog.user_id.in_(uids))
            stmt = stmt.where(or_(*conds))
        rows = (
            (await session.execute(stmt.order_by(AuditLog.ts.desc()).limit(limit))).scalars().all()
        )
        names = await _usernames(session, {r.user_id for r in rows if r.user_id is not None})
        for r in rows:
            country, country_name = geoip_lookup.country_display(r.source_ip)
            items.append(
                (
                    r.ts,
                    TimelineItem(
                        ts=r.ts.isoformat(),
                        kind="auth",
                        label=r.action,
                        result=r.result,
                        username=names.get(r.user_id) if r.user_id else None,
                        ip=r.source_ip,
                        country=country,
                        country_name=country_name,
                        detail=r.detail,
                    ),
                )
            )

    if "access" in wanted:
        stmt = select(AuditLog).where(_access_action_clause())
        if cutoff is not None:
            stmt = stmt.where(AuditLog.ts < cutoff)
        if since is not None:
            stmt = stmt.where(AuditLog.ts >= since)
        if needle:
            conds = [
                AuditLog.source_ip.like(like),
                AuditLog.action.like(like),
            ]
            if uids:
                conds.append(AuditLog.user_id.in_(uids))
            iids = await _search_instance_ids(session, needle)
            if iids:
                conds.append(AuditLog.target_id.in_(iids))
            stmt = stmt.where(or_(*conds))
        rows = (
            (await session.execute(stmt.order_by(AuditLog.ts.desc()).limit(limit))).scalars().all()
        )
        names = await _usernames(session, {r.user_id for r in rows if r.user_id is not None})
        inames = await _instance_names(session, {r.target_id for r in rows})
        for r in rows:
            country, country_name = geoip_lookup.country_display(r.source_ip)
            items.append(
                (
                    r.ts,
                    TimelineItem(
                        ts=r.ts.isoformat(),
                        kind="access",
                        label=r.action,
                        result=r.result,
                        username=names.get(r.user_id) if r.user_id else None,
                        ip=r.source_ip,
                        country=country,
                        country_name=country_name,
                        instance=inames.get(r.target_id or "", r.target_id),
                        detail=r.detail,
                    ),
                )
            )

    if "denial" in wanted:
        stmt = select(GeoipDenialEvent)
        if cutoff is not None:
            stmt = stmt.where(GeoipDenialEvent.ts < cutoff)
        if since is not None:
            stmt = stmt.where(GeoipDenialEvent.ts >= since)
        if needle:
            stmt = stmt.where(
                or_(
                    GeoipDenialEvent.ip.like(like),
                    GeoipDenialEvent.reason.like(like),
                    GeoipDenialEvent.country.like(like),
                    GeoipDenialEvent.path.like(like),
                )
            )
        rows = (
            (await session.execute(stmt.order_by(GeoipDenialEvent.ts.desc()).limit(limit)))
            .scalars()
            .all()
        )
        for r in rows:
            # Stored code is event-time truth; the hover label is a live lookup —
            # only attach it while both still agree (DB updates can reassign IPs).
            live_code, live_name = geoip_lookup.country_display(r.ip)
            items.append(
                (
                    r.ts,
                    TimelineItem(
                        ts=r.ts.isoformat(),
                        kind="denial",
                        label=r.reason,
                        result="denied",
                        ip=r.ip,
                        country=r.country,
                        country_name=live_name if live_code == r.country else None,
                        detail={"path": r.path},
                    ),
                )
            )

    if "request" in wanted:
        stmt = select(AccessEvent)
        if cutoff is not None:
            stmt = stmt.where(AccessEvent.ts < cutoff)
        if since is not None:
            stmt = stmt.where(AccessEvent.ts >= since)
        if needle:
            conds = [
                AccessEvent.ip.like(like),
                AccessEvent.path.like(like),
            ]
            if uids:
                conds.append(AccessEvent.user_id.in_(uids))
            stmt = stmt.where(or_(*conds))
        rows = (
            (await session.execute(stmt.order_by(AccessEvent.ts.desc()).limit(limit)))
            .scalars()
            .all()
        )
        names = await _usernames(session, {r.user_id for r in rows if r.user_id is not None})
        for r in rows:
            country, country_name = geoip_lookup.country_display(r.ip)
            items.append(
                (
                    r.ts,
                    TimelineItem(
                        ts=r.ts.isoformat(),
                        kind="request",
                        label=f"{r.method} {r.path}",
                        result=str(r.status),
                        username=names.get(r.user_id) if r.user_id else None,
                        ip=r.ip,
                        country=country,
                        country_name=country_name,
                    ),
                )
            )

    items.sort(key=lambda pair: pair[0], reverse=True)
    page = [it for _, it in items[:limit]]
    # More may exist whenever any source could have filled the page on its own.
    next_before = items[limit - 1][0].isoformat() if len(items) >= limit else None
    return TimelinePage(items=page, next_before=next_before)


class GroupedRow(BaseModel):
    kind: str
    label: str  # auth/access: action · denial: reason · request: "GET /api/x/#"
    result: str | None = None
    username: str | None = None
    ip: str | None = None
    country: str | None = None
    country_name: str | None = None
    instance: str | None = None
    count: int
    last_ts: str


@router.get("/grouped", response_model=list[GroupedRow])
async def access_grouped(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_admin_or_superadmin)],
    kinds: str = Query(
        default="auth,access,denial", description="CSV of auth|access|denial|request"
    ),
    q: str | None = Query(default=None, max_length=100),
    hours: int = Query(default=24, ge=1, le=8760),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[GroupedRow]:
    """Aggregated timeline (Logs-page pattern): one row per recurring event with
    count + last seen, instead of one row per occurrence."""
    wanted = [k.strip() for k in kinds.split(",") if k.strip() in _KINDS]
    since = datetime.now(UTC) - timedelta(hours=hours)
    needle = (q or "").strip()
    like = f"%{needle}%"
    uids = await _search_user_ids(session, needle) if needle else set()

    rows_out: list[GroupedRow] = []

    if "auth" in wanted:
        stmt = (
            select(
                AuditLog.action,
                AuditLog.result,
                AuditLog.user_id,
                AuditLog.source_ip,
                func.count(),
                func.max(AuditLog.ts),
            )
            .where(AuditLog.action.startswith("auth."), AuditLog.ts >= since)
            .group_by(AuditLog.action, AuditLog.result, AuditLog.user_id, AuditLog.source_ip)
        )
        if needle:
            conds = [
                AuditLog.source_ip.like(like),
                AuditLog.action.like(like),
                AuditLog.detail["username"].as_string().like(like),
            ]
            if uids:
                conds.append(AuditLog.user_id.in_(uids))
            stmt = stmt.where(or_(*conds))
        rows = (await session.execute(stmt.order_by(func.count().desc()).limit(limit))).all()
        names = await _usernames(session, {r[2] for r in rows if r[2] is not None})
        for action, result, user_id, ip, n, last in rows:
            country, country_name = geoip_lookup.country_display(ip)
            rows_out.append(
                GroupedRow(
                    kind="auth",
                    label=action,
                    result=result,
                    username=names.get(user_id) if user_id else None,
                    ip=ip,
                    country=country,
                    country_name=country_name,
                    count=int(n or 0),
                    last_ts=last.isoformat(),
                )
            )

    if "access" in wanted:
        stmt = (
            select(
                AuditLog.action,
                AuditLog.result,
                AuditLog.user_id,
                AuditLog.target_id,
                func.count(),
                func.max(AuditLog.ts),
            )
            .where(_access_action_clause(), AuditLog.ts >= since)
            .group_by(AuditLog.action, AuditLog.result, AuditLog.user_id, AuditLog.target_id)
        )
        if needle:
            conds = [
                AuditLog.source_ip.like(like),
                AuditLog.action.like(like),
            ]
            if uids:
                conds.append(AuditLog.user_id.in_(uids))
            iids = await _search_instance_ids(session, needle)
            if iids:
                conds.append(AuditLog.target_id.in_(iids))
            stmt = stmt.where(or_(*conds))
        rows = (await session.execute(stmt.order_by(func.count().desc()).limit(limit))).all()
        names = await _usernames(session, {r[2] for r in rows if r[2] is not None})
        inames = await _instance_names(session, {r[3] for r in rows})
        for action, result, user_id, target_id, n, last in rows:
            rows_out.append(
                GroupedRow(
                    kind="access",
                    label=action,
                    result=result,
                    username=names.get(user_id) if user_id else None,
                    instance=inames.get(target_id or "", target_id),
                    count=int(n or 0),
                    last_ts=last.isoformat(),
                )
            )

    if "denial" in wanted:
        stmt = (
            select(
                GeoipDenialEvent.reason,
                GeoipDenialEvent.country,
                GeoipDenialEvent.ip,
                func.count(),
                func.max(GeoipDenialEvent.ts),
            )
            .where(GeoipDenialEvent.ts >= since)
            .group_by(GeoipDenialEvent.reason, GeoipDenialEvent.country, GeoipDenialEvent.ip)
        )
        if needle:
            stmt = stmt.where(
                or_(
                    GeoipDenialEvent.ip.like(like),
                    GeoipDenialEvent.reason.like(like),
                    GeoipDenialEvent.country.like(like),
                )
            )
        rows = (await session.execute(stmt.order_by(func.count().desc()).limit(limit))).all()
        for reason, country, ip, n, last in rows:
            live_code, live_name = geoip_lookup.country_display(ip)
            rows_out.append(
                GroupedRow(
                    kind="denial",
                    label=reason,
                    result="denied",
                    ip=ip,
                    country=country,
                    country_name=live_name if live_code == country else None,
                    count=int(n or 0),
                    last_ts=last.isoformat(),
                )
            )

    if "request" in wanted:
        # Collapse numeric path segments (instance ids, event ids) into one
        # pattern per endpoint — the Logs-page trick, in MariaDB SQL.
        pattern = func.regexp_replace(AccessEvent.path, "[0-9]+", "#")
        stmt = (
            select(
                AccessEvent.user_id,
                AccessEvent.method,
                pattern,
                func.count(),
                func.max(AccessEvent.ts),
            )
            .where(AccessEvent.ts >= since)
            .group_by(AccessEvent.user_id, AccessEvent.method, pattern)
        )
        if needle:
            conds = [AccessEvent.ip.like(like), AccessEvent.path.like(like)]
            if uids:
                conds.append(AccessEvent.user_id.in_(uids))
            stmt = stmt.where(or_(*conds))
        rows = (await session.execute(stmt.order_by(func.count().desc()).limit(limit))).all()
        names = await _usernames(session, {r[0] for r in rows if r[0] is not None})
        for user_id, method, path_pattern, n, last in rows:
            rows_out.append(
                GroupedRow(
                    kind="request",
                    label=f"{method} {path_pattern}",
                    username=names.get(user_id) if user_id else None,
                    count=int(n or 0),
                    last_ts=last.isoformat(),
                )
            )

    rows_out.sort(key=lambda r: r.count, reverse=True)
    return rows_out[:limit]
