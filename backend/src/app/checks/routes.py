"""REST: evaluated service checks for an instance (drives green/red + Checkmk)."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.auth.deps import current_user, read_principal
from app.checks import ServiceAlert, ServiceCheck, evaluate_checks
from app.checks.aggregate import aggregate_for_checkmk
from app.checks.event_store import read_check_events
from app.checks.overlay import overlay_checks
from app.checks.prometheus import CONTENT_TYPE, render_prometheus
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances.service import get_instance, list_instances
from app.selection.model import CHECKMK, resolve
from app.selection.store import fetch_rules
from app.settings.store import effective_settings
from app.xsense.registry import registry
from app.xsense.schemas import (
    CertInfo,
    ConnectivityResult,
    FirmwareStatus,
    GatewayStatus,
    IPsecServiceStatus,
    ServiceInfo,
    SystemStatus,
)

log = structlog.get_logger("app.checks")

router = APIRouter(tags=["checks"])


async def _safe(coro_fn, default):
    try:
        return await coro_fn()
    except Exception:  # noqa: BLE001 — one failing aspect must not sink the rest
        return default


async def _gather(
    inst: Instance, instance_id: int
) -> tuple[
    SystemStatus,
    list[GatewayStatus] | None,
    IPsecServiceStatus | None,
    FirmwareStatus | None,
    list[ServiceInfo] | None,
    list[CertInfo] | None,
    list[ConnectivityResult] | None,
]:
    """Collect the aspects: from the agent-hub cache (push) or live (direct).

    Services, certificates and connectivity-ping results are agent-push only;
    direct/Securepoint poll returns None for them.
    """
    if inst.agent_mode:
        return (
            hub.get_last_status(instance_id) or SystemStatus(),
            hub.get_last_gateways(instance_id),
            hub.get_last_ipsec(instance_id),
            hub.get_last_firmware(instance_id),
            hub.get_last_services(instance_id),
            hub.get_last_certs(instance_id),
            hub.get_last_connectivity(instance_id),
        )
    client = await registry.get(inst)
    # The four aspects are independent round-trips to the same appliance — fetch
    # them concurrently (each _safe swallows its own failure, so one bad aspect
    # can't sink the gather). Bounded by the appliance's own connection limit.
    sys_status, gateways, ipsec, firmware = await asyncio.gather(
        _safe(client.poll_status, SystemStatus()),
        _safe(client.gateway_status, None),
        _safe(client.ipsec_status, None),
        _safe(client.firmware_status, None),
    )
    return (sys_status, gateways, ipsec, firmware, None, None, None)


GatheredAspects = tuple[
    SystemStatus,
    list[GatewayStatus] | None,
    IPsecServiceStatus | None,
    FirmwareStatus | None,
    list[ServiceInfo] | None,
    list[CertInfo] | None,
    list[ConnectivityResult] | None,
]


async def gather_many(rows: list[Instance]) -> list[tuple[Instance, GatheredAspects]]:
    """Gather every instance's aspects concurrently, preserving input order.

    Push instances resolve from the hub cache (cheap); direct/Securepoint instances
    are polled live. Bounded by ``poll_concurrency`` so a sweep over many direct
    appliances doesn't open an unbounded fan-out of sessions at once.
    """
    sem = asyncio.Semaphore(max(1, effective_settings().poll_concurrency))

    async def one(inst: Instance) -> tuple[Instance, GatheredAspects]:
        async with sem:
            return inst, await _gather(inst, inst.id)

    return list(await asyncio.gather(*(one(inst) for inst in rows)))


# Shared TTL cache for every machine-cadenced aggregate (Checkmk pull, Prometheus
# scrape, and the Alerts page with its 30s auto-refetch). All of them poll
# direct/Securepoint appliances via ``_gather`` (push instances come from the
# cheap hub cache) — and a fleet running several consumers, each on its own
# cadence, would otherwise poll the same box several times over. The cached
# value is scope-independent (just the box's polled status), so the key is the
# instance id alone. Stale-while-revalidate: an expired entry is served
# immediately and refreshed by a deduped background task — a slow appliance
# (Securepoint login+status ≈ 1.3s measured in prod) must never sit inside a
# scrape/page request. Only the interactive single-instance ``/checks`` stays
# live/uncached. Worst-case data age ≈ ttl + one poll; the staleness overlay
# still applies on top.
_EXPORT_CACHE_TTL = 20.0  # seconds
_export_aspect_cache: dict[int, tuple[float, GatheredAspects]] = {}
# Instance ids with a background re-poll in flight (dedupe — Checkmk +
# Prometheus + an open Alerts page must not triple-poll one box).
_export_refresh_inflight: set[int] = set()


def _refresh_aspects_soon(inst: Instance) -> None:
    """Kick a deduped background re-poll of one direct instance."""
    if inst.id in _export_refresh_inflight:
        return
    _export_refresh_inflight.add(inst.id)

    async def _refresh() -> None:
        try:
            aspects = await _gather(inst, inst.id)
            _export_aspect_cache[inst.id] = (time.monotonic(), aspects)
        except Exception:
            log.warning("export.aspect_refresh_failed", instance_id=inst.id)
        finally:
            _export_refresh_inflight.discard(inst.id)

    asyncio.create_task(_refresh())


async def gather_many_cached(
    rows: list[Instance], ttl: float = _EXPORT_CACHE_TTL
) -> list[tuple[Instance, GatheredAspects]]:
    """Like :func:`gather_many`, but direct instances serve the TTL cache with
    stale-while-revalidate (see above). Push instances are always read live
    from the hub cache. Only a box seen for the very first time blocks the
    request on a real poll — there is nothing to serve yet.
    """
    sem = asyncio.Semaphore(max(1, effective_settings().poll_concurrency))

    async def one(inst: Instance) -> tuple[Instance, GatheredAspects]:
        if inst.agent_mode:  # hub-cache read — already cheap and current
            return inst, await _gather(inst, inst.id)
        cached = _export_aspect_cache.get(inst.id)
        if cached is not None:
            if time.monotonic() - cached[0] >= ttl:
                _refresh_aspects_soon(inst)
            return inst, cached[1]
        async with sem:
            aspects = await _gather(inst, inst.id)
        _export_aspect_cache[inst.id] = (time.monotonic(), aspects)
        return inst, aspects

    return list(await asyncio.gather(*(one(inst) for inst in rows)))


@router.get("/instances/{instance_id}/checks", response_model=list[ServiceCheck])
async def instance_checks(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    principal=Depends(read_principal),
) -> list[ServiceCheck]:
    """Evaluated OK/WARN/CRIT checks for one instance (memory, disks, gateways, IPsec, firmware)."""
    inst = await get_instance(session, instance_id, principal)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    sys_status, gateways, ipsec, firmware, services, certs, connectivity = await _gather(
        inst, instance_id
    )
    base = evaluate_checks(sys_status, gateways, ipsec, firmware, services, certs, connectivity)
    return overlay_checks(inst, base, effective_settings(), datetime.now(UTC))


class CheckHistoryEvent(BaseModel):
    ts: str
    check_key: str
    old_state: int
    new_state: int
    summary: str


@router.get("/instances/{instance_id}/checks/history", response_model=list[CheckHistoryEvent])
async def instance_check_history(
    instance_id: int,
    limit: int = 100,
    key: str | None = None,
    key_prefix: str | None = None,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[CheckHistoryEvent]:
    """Recorded check state-change history for one instance, most recent first.

    ``key`` exact-matches one entity (``connectivity:5``, ``availability``);
    ``key_prefix`` matches a whole category (``gateway:``). Populated by the
    agent-push ingest (plus availability from the scheduler); direct-API instances
    have only availability history.
    """
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    limit = max(1, min(limit, 500))
    rows = await read_check_events(session, instance_id, limit, key=key, key_prefix=key_prefix)
    return [
        CheckHistoryEvent(
            ts=row.ts.isoformat(),
            check_key=row.check_key,
            old_state=row.old_state,
            new_state=row.new_state,
            summary=row.summary,
        )
        for row in rows
    ]


@router.get("/export/checkmk")
async def export_checkmk(
    session: AsyncSession = Depends(get_session),
    principal=Depends(read_principal),
) -> dict:
    """All visible instances' checks in one call — consumed by the Checkmk special agent.

    API-key callers honor the key's group binding (unbound = global); a session
    user only gets their groups' instances.

    Push instances use the hub cache (cheap); direct instances are polled live but
    cached for a short TTL, shared with the Prometheus export so the two integrations
    don't each poll the same appliance.
    """
    settings = effective_settings()
    # Maintenance blackout: return no instances so Checkmk sees every service go
    # stale/gone. Checked first — during a blackout we skip the (potentially slow,
    # firewall-hammering) live polls below entirely.
    if getattr(settings, "checkmk_blackout", False):
        return {"version": 1, "instances": []}

    rows = await list_instances(session, principal)

    rules = await fetch_rules(session)

    now = datetime.now(UTC)
    gathered = await gather_many_cached(rows)

    # Pure CPU from here (evaluate + overlay + selection + dumps over the whole
    # fleet — 1.3-1.5s at 65 instances, measured in prod) — off the event loop,
    # or every scrape stalls all pushes/shells for that long.
    def _build() -> list[dict]:
        instances = []
        for inst, (sys_status, gateways, ipsec, firmware, services, certs, conn) in gathered:
            evaluated = overlay_checks(
                inst,
                evaluate_checks(sys_status, gateways, ipsec, firmware, services, certs, conn),
                settings,
                now,
            )
            checks = [c for c in evaluated if resolve(CHECKMK, c.key, inst.id, rules)[0]]
            # Collapse high-fan-out categories into one aggregate service each
            # (opt-out). After selection so aggregates reflect exported checks.
            if settings.checkmk_aggregate:
                checks = aggregate_for_checkmk(checks)
            instances.append(
                {
                    "instance_id": inst.id,
                    "name": inst.name,
                    "host": inst.name,  # piggyback host name
                    "device_type": inst.device_type,
                    "checks": [c.model_dump() for c in checks],
                }
            )
        return instances

    return {"version": 1, "instances": await asyncio.to_thread(_build)}


@router.get("/export/prometheus", response_class=PlainTextResponse)
async def export_prometheus(
    session: AsyncSession = Depends(get_session),
    principal=Depends(read_principal),
) -> PlainTextResponse:
    """All visible instances' checks in Prometheus text format (Grafana-ready scrape).

    Same auth and group scoping as the Checkmk export: API-key callers honor the
    key's group binding (unbound = global), session users get their groups'
    instances. Unlike Checkmk there is no selection filtering, no aggregation and
    no blackout — every evaluated check becomes a series; filter in PromQL. Push
    instances read the hub cache (cheap); direct instances are polled live but
    cached for a short TTL so frequent scrapes don't hammer the appliances.
    """
    settings = effective_settings()
    now = datetime.now(UTC)
    rows = await list_instances(session, principal)
    gathered = await gather_many_cached(rows)

    # Fleet-wide evaluate + text rendering is CPU — same off-loop rule as the
    # Checkmk export above.
    def _render() -> str:
        pairs = []
        for inst, (sys_status, gateways, ipsec, firmware, services, certs, conn) in gathered:
            evaluated = overlay_checks(
                inst,
                evaluate_checks(sys_status, gateways, ipsec, firmware, services, certs, conn),
                settings,
                now,
            )
            pairs.append((inst, evaluated))
        return render_prometheus(pairs)

    return PlainTextResponse(await asyncio.to_thread(_render), media_type=CONTENT_TYPE)


def _sev(s: int) -> int:
    """Severity for sorting (worst first): CRIT=3, WARN=2, UNKNOWN=1, OK=0."""
    return 3 if s == 2 else 2 if s == 1 else 1 if s == 3 else 0


@router.get("/checks", response_model=list[ServiceAlert])
async def all_checks(
    session: AsyncSession = Depends(get_session),
    principal=Depends(read_principal),
) -> list[ServiceAlert]:
    """All evaluated service checks across the caller's visible instances (the
    data Checkmk receives; API keys honor their group binding, unbound = global).

    Each entry is annotated with whether it is currently exported to Checkmk. The
    export is opt-in (base default off): ``excluded`` is true for any check no
    selection rule has included. The Alerts page consumes this — and auto-
    refetches every 30s, which is machine cadence: direct-poll instances serve
    the shared stale-while-revalidate cache (prod incident: every page refresh
    live-polled the Securepoint appliances at 1.3s+ per request).
    """
    rules = await fetch_rules(session)

    rows = await list_instances(session, principal)

    settings = effective_settings()
    now = datetime.now(UTC)
    gathered = await gather_many_cached(rows)

    # Fleet-wide evaluate + thousands of ServiceAlert objects is CPU — off the
    # loop (prod: 1.3s+ per Alerts-page refresh stalled every push meanwhile).
    def _build() -> list[ServiceAlert]:
        alerts: list[ServiceAlert] = []
        for inst, (sys_status, gateways, ipsec, firmware, services, certs, conn) in gathered:
            evaluated = overlay_checks(
                inst,
                evaluate_checks(sys_status, gateways, ipsec, firmware, services, certs, conn),
                settings,
                now,
            )
            for c in evaluated:
                on, by = resolve(CHECKMK, c.key, inst.id, rules)
                alerts.append(
                    ServiceAlert(
                        instance_id=inst.id,
                        instance_name=inst.name,
                        key=c.key,
                        state=c.state,
                        summary=c.summary,
                        metrics=c.metrics,
                        excluded=not on,
                        excluded_by=None if on or by == "default" else by,
                    )
                )
        # Sort: worst states first, then by instance name, then key (stable)
        alerts.sort(key=lambda a: (-_sev(a.state), a.instance_name.lower(), a.key))
        return alerts

    return await asyncio.to_thread(_build)
