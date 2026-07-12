"""Superadmin surface for the GeoIP restriction (DR-G6).

Everything here is ``require_superadmin`` — deliberately NOT the admin-gated
generic settings routes. Saving supports a dry-run so the UI can warn when the
caller would lock themselves out (DR-G5: warn, don't block).
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_superadmin
from app.config import get_settings
from app.db.base import get_session
from app.db.models import GeoipConfig, User
from app.geoip import crowdsec, dyndns, lookup, updater
from app.geoip.rules import classify_entry, decide, parse_rules
from app.geoip.store import current_rules, load_config, save_config
from app.net import client_ip

router = APIRouter(prefix="/geoip", tags=["geoip"])

_MAX_ENTRIES = 100


class GeoipSettingsBody(BaseModel):
    enabled: bool
    countries: list[str] = Field(default_factory=list, max_length=_MAX_ENTRIES)
    whitelist: list[str] = Field(default_factory=list, max_length=_MAX_ENTRIES)


class GeoipSettings(BaseModel):
    enabled: bool
    countries: list[str]
    whitelist: list[str]
    updated_at: str | None = None
    updated_by: str | None = None


class GeoipSaveResult(BaseModel):
    saved: bool  # False on dry_run
    # True when the caller's own IP would be denied under the NEW rules — the
    # UI shows a confirm dialog before the real save (DR-G5: warn, allow).
    self_blocked: bool
    self_ip: str
    self_country: str | None
    settings: GeoipSettings


class GeoipStatus(BaseModel):
    kill_switch_active: bool
    enforcing: bool
    db: dict
    last_download: dict
    dyndns: list[dict]
    credentials_set: bool
    crowdsec: dict


def _validate(body: GeoipSettingsBody) -> None:
    for code in body.countries:
        if len(code) != 2 or not code.isalpha():
            raise HTTPException(status_code=422, detail=f"invalid country code: {code!r}")
    for entry in body.whitelist:
        try:
            classify_entry(entry)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


def _settings_of(row: GeoipConfig | None) -> GeoipSettings:
    if row is None:
        return GeoipSettings(enabled=False, countries=[], whitelist=[])
    return GeoipSettings(
        enabled=row.enabled,
        countries=json.loads(row.countries or "[]"),
        whitelist=json.loads(row.whitelist or "[]"),
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        updated_by=row.updated_by,
    )


@router.get("/settings", response_model=GeoipSettings)
async def get_geoip_settings(
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(require_superadmin)],
) -> GeoipSettings:
    return _settings_of(await session.get(GeoipConfig, 1))


@router.put("/settings", response_model=GeoipSaveResult)
async def put_geoip_settings(
    body: GeoipSettingsBody,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_superadmin)],
    dry_run: bool = False,
) -> GeoipSaveResult:
    _validate(body)
    # Evaluate the NEW rules against the caller's own IP. New hostnames are
    # resolved right here (once, bounded) so the self-check and, after a real
    # save, the middleware immediately know their addresses.
    candidate = parse_rules(
        body.enabled,
        json.dumps([c.upper() for c in body.countries]),
        json.dumps(body.whitelist),
    )
    await dyndns.refresh(candidate.hostnames)
    ip = client_ip(request)
    country = lookup.country_for(ip) if lookup.db_available() else None
    verdict = decide(ip, candidate, country, dyndns.resolved_ips(), lookup.db_available())
    self_blocked = not verdict.allowed and not get_settings().geoip_disable

    if dry_run:
        # Restore the resolver state to the ACTIVE rules — a dry-run of a
        # narrower whitelist must not shrink the enforced resolved set.
        await dyndns.refresh(current_rules().hostnames)
        return GeoipSaveResult(
            saved=False,
            self_blocked=self_blocked,
            self_ip=ip,
            self_country=country,
            settings=GeoipSettings(
                enabled=body.enabled, countries=body.countries, whitelist=body.whitelist
            ),
        )

    row = await save_config(
        session,
        enabled=body.enabled,
        countries=body.countries,
        whitelist=body.whitelist,
        updated_by=user.username,
    )
    await write_audit(
        session,
        action="geoip.config.update",
        result="ok",
        user_id=user.id,
        detail={
            "enabled": body.enabled,
            "countries": sorted({c.upper() for c in body.countries}),
            "whitelist_entries": len(body.whitelist),
            "self_blocked_warning": self_blocked,
        },
        source_ip=ip,
    )
    await session.commit()
    await load_config(session)
    await session.refresh(row)
    return GeoipSaveResult(
        saved=True,
        self_blocked=self_blocked,
        self_ip=ip,
        self_country=country,
        settings=_settings_of(row),
    )


@router.get("/status", response_model=GeoipStatus)
async def geoip_status(
    _user: Annotated[User, Depends(require_superadmin)],
) -> GeoipStatus:
    settings = get_settings()
    return GeoipStatus(
        kill_switch_active=settings.geoip_disable,
        enforcing=current_rules().restricting and not settings.geoip_disable,
        db=lookup.db_status(),
        last_download=updater.last_download(),
        dyndns=dyndns.snapshot(),
        credentials_set=bool(settings.maxmind_account_id and settings.maxmind_license_key),
        crowdsec=crowdsec.status(),
    )


@router.post("/db/refresh", response_model=dict)
async def refresh_db_now(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_superadmin)],
) -> dict:
    result = await updater.refresh_geoip_db()
    await write_audit(
        session,
        action="geoip.db.refresh",
        result="ok" if result.get("ok") else "error",
        user_id=user.id,
        detail={"detail": str(result.get("detail", ""))[:200]},
        source_ip=client_ip(request),
    )
    await session.commit()
    return result
