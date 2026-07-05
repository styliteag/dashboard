"""Hub self-monitoring endpoint (backend observability page).

GET /api/hub/stats — connected agents, push rate, error counters.

Admin-only: the counters are hub-global aggregates (no per-instance data), and
the page is an operations surface. The agent LIST is per-instance data and
therefore still scope-filtered — an admin without group memberships gets the
global counters but an empty agent table (no admin scope bypass, see
app.auth.scope).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.agent_hub.routes.update import _visible_instance_ids
from app.agent_hub.stats import stats
from app.auth.deps import require_admin
from app.db.base import get_session
from app.db.models import User

router = APIRouter(tags=["agent"])


class HubAgent(BaseModel):
    instance_id: int
    instance_name: str
    connected_at: str
    agent_version: str
    platform: str
    pushes: int
    last_push_at: str | None


class RatePoint(BaseModel):
    ts: str
    count: int


class HubStatsResponse(BaseModel):
    started_at: str
    uptime_seconds: int
    connected_agents: int
    counters: dict[str, int]
    push_rate: list[RatePoint]
    agents: list[HubAgent]


@router.get("/hub/stats", response_model=HubStatsResponse)
async def hub_stats(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin),
) -> HubStatsResponse:
    """Hub health right now — all numbers are in-memory since ``started_at``."""
    visible = await _visible_instance_ids(session, user)
    agents = [
        HubAgent(**{k: a[k] for k in HubAgent.model_fields})
        for a in hub.list_connected()
        if visible is None or a["instance_id"] in visible
    ]
    now = datetime.now(UTC)
    return HubStatsResponse(
        started_at=stats.started_at.isoformat(),
        uptime_seconds=int((now - stats.started_at).total_seconds()),
        connected_agents=len(agents),
        counters=stats.counters_snapshot(),
        push_rate=[RatePoint(**p) for p in stats.push_rate(now=now)],
        agents=agents,
    )
