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
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.access.store import ONLINE_WINDOW_S
from app.auth.deps import require_admin_or_superadmin
from app.db.base import get_session
from app.db.models import AccessEvent, AccessStat, AuditLog, AuthSession, GeoipDenialEvent, User

router = APIRouter(prefix="/access-log", tags=["access-log"])

# Timeline sources are merged newest-first; per source we fetch the page limit
# and cut after sorting, so a chatty source can't starve the others.
_KINDS = ("auth", "denial", "request")


class OnlineSession(BaseModel):
    username: str | None
    user_id: int
    ip: str | None
    login_at: str
    last_seen_at: str


class PrincipalStat(BaseModel):
    principal: str  # "user:3" resolved to a username where possible
    requests: int
    last_ip: str | None


class AccessSummary(BaseModel):
    online: list[OnlineSession]
    logins_ok_24h: int
    logins_failed_24h: int
    denials_24h: int
    denials_by_reason_24h: dict[str, int]
    requests_24h: list[PrincipalStat]


class TimelineItem(BaseModel):
    ts: str
    kind: str  # auth | denial | request
    # auth: audit action/result; denial: reason; request: "GET /api/..."
    label: str
    result: str | None = None
    username: str | None = None
    ip: str | None = None
    country: str | None = None
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
        )
        for ptype, pkey, n, last_ip in stat_rows
    ]

    return AccessSummary(
        online=[
            OnlineSession(
                username=names.get(s.user_id),
                user_id=s.user_id,
                ip=s.ip,
                login_at=s.created_at.isoformat(),
                last_seen_at=s.last_seen_at.isoformat(),
            )
            for s in online_rows
        ],
        logins_ok_24h=int(logins_ok),
        logins_failed_24h=int(logins_failed),
        denials_24h=sum(denials_by_reason.values()),
        denials_by_reason_24h=denials_by_reason,
        requests_24h=requests_24h,
    )


@router.get("/timeline", response_model=TimelinePage)
async def access_timeline(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_admin_or_superadmin)],
    kinds: str = Query(default="auth,denial,request", description="CSV of auth|denial|request"),
    before: str | None = Query(default=None, description="ISO ts cursor from next_before"),
    limit: int = Query(default=50, ge=1, le=200),
) -> TimelinePage:
    wanted = [k.strip() for k in kinds.split(",") if k.strip() in _KINDS]
    cutoff = datetime.fromisoformat(before) if before else None

    items: list[tuple[datetime, TimelineItem]] = []

    if "auth" in wanted:
        q = select(AuditLog).where(AuditLog.action.startswith("auth."))
        if cutoff is not None:
            q = q.where(AuditLog.ts < cutoff)
        rows = (await session.execute(q.order_by(AuditLog.ts.desc()).limit(limit))).scalars().all()
        names = await _usernames(session, {r.user_id for r in rows if r.user_id is not None})
        for r in rows:
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
                        detail=r.detail,
                    ),
                )
            )

    if "denial" in wanted:
        q = select(GeoipDenialEvent)
        if cutoff is not None:
            q = q.where(GeoipDenialEvent.ts < cutoff)
        rows = (
            (await session.execute(q.order_by(GeoipDenialEvent.ts.desc()).limit(limit)))
            .scalars()
            .all()
        )
        for r in rows:
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
                        detail={"path": r.path},
                    ),
                )
            )

    if "request" in wanted:
        q = select(AccessEvent)
        if cutoff is not None:
            q = q.where(AccessEvent.ts < cutoff)
        rows = (
            (await session.execute(q.order_by(AccessEvent.ts.desc()).limit(limit))).scalars().all()
        )
        names = await _usernames(session, {r.user_id for r in rows if r.user_id is not None})
        for r in rows:
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
                    ),
                )
            )

    items.sort(key=lambda pair: pair[0], reverse=True)
    page = [it for _, it in items[:limit]]
    # More may exist whenever any source could have filled the page on its own.
    next_before = items[limit - 1][0].isoformat() if len(items) >= limit else None
    return TimelinePage(items=page, next_before=next_before)
