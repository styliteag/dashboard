"""Runtime settings store: a process-local cache of DB overrides over Settings.

The effective value of an editable key is its DB override (if set) else the env
default from ``app.config.Settings``. ``effective_settings()`` returns a thin
overlay whose attribute access yields overridden values; the hot consumers
(poller, maintenance) read through it so a change applies without restart.

Process-local cache: assumes a single backend worker (the combined image runs
one uvicorn process). A write updates this process's cache immediately; with
multiple workers, others would pick up the change only on their next restart.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.crypto.secrets import decrypt, encrypt
from app.db.models import AppSetting
from app.settings.registry import EDITABLE, SettingDef, coerce_value, to_storage

log = structlog.get_logger("app.settings")

# key -> stored string value (decrypted for secrets). Only overridden keys present.
_overrides: dict[str, str] = {}


async def load_overrides(session: AsyncSession) -> int:
    """(Re)load all overrides from the DB into the process cache. Returns count."""
    rows = (await session.execute(select(AppSetting))).scalars().all()
    fresh: dict[str, str] = {}
    for r in rows:
        if r.key not in EDITABLE:
            continue  # stale key (e.g. removed from the whitelist) — ignore
        try:
            fresh[r.key] = decrypt(r.value.encode()) if r.is_secret else r.value
        except Exception as exc:  # noqa: BLE001 — never let one bad row break load
            log.warning("settings.decode_failed", key=r.key, error=str(exc))
    _overrides.clear()
    _overrides.update(fresh)
    return len(_overrides)


def get_override(key: str) -> str | None:
    """The raw (decrypted) override string for a key, or None if not overridden."""
    return _overrides.get(key)


async def set_override(session: AsyncSession, defn: SettingDef, raw: str) -> str:
    """Validate + write an override row (does NOT touch the cache). Returns the
    stored string. Caller must commit, then ``load_overrides`` to resync the cache
    — so a rolled-back commit never leaves the cache out of sync with the DB."""
    stored = to_storage(defn, raw)
    row = await session.get(AppSetting, defn.key)
    db_value = encrypt(stored).decode() if defn.is_secret else stored
    if row is None:
        session.add(AppSetting(key=defn.key, value=db_value, is_secret=defn.is_secret))
    else:
        row.value = db_value
        row.is_secret = defn.is_secret
    await session.flush()
    return stored


async def clear_override(session: AsyncSession, key: str) -> bool:
    """Delete an override row (does NOT touch the cache; see ``set_override``).
    Returns True if a row existed."""
    row = await session.get(AppSetting, key)
    if row is not None:
        await session.delete(row)
        await session.flush()
    return row is not None


class _Effective:
    """Read-only overlay: editable keys with an override return the coerced value;
    everything else delegates to the base ``Settings``."""

    def __init__(self, base: Settings) -> None:
        self._base = base

    def __getattr__(self, name: str) -> object:
        # Only reached for attrs not on the instance — i.e. all Settings fields.
        if name in EDITABLE and name in _overrides:
            return coerce_value(EDITABLE[name], _overrides[name])
        return getattr(self._base, name)


def effective_settings() -> _Effective:
    """Settings overlay honouring live DB overrides for editable keys."""
    return _Effective(get_settings())
