"""Process-local cache of the geoip_config row (single worker by design).

The middleware consults ``current_rules()`` on every request — it must never
touch the DB. ``load_config`` runs at startup and after every save; a missing
row means "never configured" and stays at the DISABLED default (DR-G3).
"""

from __future__ import annotations

import json

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import GeoipConfig
from app.geoip.rules import DISABLED, GeoipRules, parse_rules

log = structlog.get_logger("app.geoip")

_rules: GeoipRules = DISABLED


def current_rules() -> GeoipRules:
    return _rules


async def load_config(session: AsyncSession) -> GeoipRules:
    """(Re)load the config row into the process cache."""
    global _rules
    row = await session.get(GeoipConfig, 1)
    _rules = parse_rules(row.enabled, row.countries, row.whitelist) if row is not None else DISABLED
    log.info(
        "geoip.config_loaded",
        enabled=_rules.enabled,
        countries=sorted(_rules.countries),
        cidrs=len(_rules.cidrs),
        hostnames=len(_rules.hostnames),
    )
    return _rules


async def save_config(
    session: AsyncSession,
    *,
    enabled: bool,
    countries: list[str],
    whitelist: list[str],
    updated_by: str,
) -> GeoipConfig:
    """Upsert the single row. Flushes only — the route owns the commit, then
    calls ``load_config`` so a rolled-back commit never leaves a stale cache."""
    row = await session.get(GeoipConfig, 1)
    countries_json = json.dumps(sorted({c.upper() for c in countries}))
    whitelist_json = json.dumps(list(dict.fromkeys(whitelist)))  # dedupe, keep order
    if row is None:
        row = GeoipConfig(
            id=1,
            enabled=enabled,
            countries=countries_json,
            whitelist=whitelist_json,
            updated_by=updated_by,
        )
        session.add(row)
    else:
        row.enabled = enabled
        row.countries = countries_json
        row.whitelist = whitelist_json
        row.updated_by = updated_by
    await session.flush()
    return row
