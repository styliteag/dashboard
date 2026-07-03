"""Admin REST for editable application settings (DB overrides over env)."""

from __future__ import annotations

import asyncio
import os
import signal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_admin
from app.config import get_settings
from app.db.base import get_session
from app.db.models import User
from app.net import client_ip
from app.settings.registry import EDITABLE, SettingDef
from app.settings.store import clear_override, get_override, load_overrides, set_override

router = APIRouter(prefix="/settings", tags=["settings"])

_MASK = "••••••"


class SettingItem(BaseModel):
    key: str
    label: str
    group: str
    type: str
    help: str
    value: str  # effective value (masked if secret)
    default: str  # env default (masked if secret)
    source: str  # "db" | "env"
    restart_required: bool
    is_secret: bool
    options: list[str] | None
    min: int | None
    max: int | None


class SettingUpdate(BaseModel):
    key: str
    value: str


def _item(defn: SettingDef) -> SettingItem:
    # Keys with an explicit catalog default (LLM provider settings) carry it on the
    # def; everything else falls back to its env/Settings field.
    env_default = defn.default if defn.default is not None else getattr(get_settings(), defn.key)
    override = get_override(defn.key)
    if defn.is_secret:
        value = _MASK if override is not None else ""
        default = ""
    else:
        value = override if override is not None else str(env_default)
        default = str(env_default)
    return SettingItem(
        key=defn.key,
        label=defn.label,
        group=defn.group,
        type=defn.type,
        help=defn.help,
        value=value,
        default=default,
        source="db" if override is not None else "env",
        restart_required=defn.restart_required,
        is_secret=defn.is_secret,
        options=list(defn.options) if defn.options else None,
        min=defn.min,
        max=defn.max,
    )


def _defn_or_404(key: str) -> SettingDef:
    defn = EDITABLE.get(key)
    if defn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown setting")
    return defn


@router.get("", response_model=list[SettingItem])
async def list_settings(_admin: User = Depends(require_admin)) -> list[SettingItem]:
    return [_item(defn) for defn in EDITABLE.values()]


@router.put("", response_model=SettingItem)
async def update_setting(
    payload: SettingUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> SettingItem:
    defn = _defn_or_404(payload.key)
    try:
        stored = await set_override(session, defn, payload.value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    await write_audit(
        session,
        action="settings.update",
        result="ok",
        user_id=admin.id,
        target_type="setting",
        target_id=defn.key,
        source_ip=client_ip(request),
        detail={"value": _MASK if defn.is_secret else stored},
    )
    await session.commit()
    await load_overrides(session)  # resync cache from committed state
    return _item(defn)


# Long enough for the 202 response to flush to the client, short enough that the
# UI's health polling never races a still-alive old process.
_RESTART_DELAY_SECONDS = 0.5

_PID1_CMDLINE = "/proc/1/cmdline"


def _restart_target_pid() -> int:
    """PID to SIGTERM for a restart.

    Normally our own process: in the combined prod container the start.sh
    supervisor loop restarts uvicorn while nginx (PID 1) stays up. But when
    PID 1 is uvicorn itself — the dev --reload supervisor or a bare-uvicorn
    container — a dead worker is NOT resupervised (verified: the reloader idles
    forever next to its dead child). There the whole PID-1 process must exit so
    the container restart policy brings up a fresh one.
    """
    try:
        with open(_PID1_CMDLINE, "rb") as f:
            if b"uvicorn" in f.read():
                return 1
    except OSError:
        pass
    return os.getpid()


def _schedule_self_terminate() -> None:
    """SIGTERM the restart target shortly after the current response is sent."""
    loop = asyncio.get_running_loop()
    loop.call_later(_RESTART_DELAY_SECONDS, os.kill, _restart_target_pid(), signal.SIGTERM)


@router.post("/restart", status_code=status.HTTP_202_ACCEPTED)
async def restart_backend(
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> dict[str, str]:
    """Restart the backend process (applies "needs restart" settings)."""
    await write_audit(
        session,
        action="settings.restart",
        result="ok",
        user_id=admin.id,
        target_type="service",
        target_id="backend",
        source_ip=client_ip(request),
    )
    await session.commit()
    _schedule_self_terminate()
    return {"status": "restarting"}


@router.delete("/{key}", response_model=SettingItem)
async def reset_setting(
    key: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> SettingItem:
    defn = _defn_or_404(key)
    await clear_override(session, key)
    await write_audit(
        session,
        action="settings.reset",
        result="ok",
        user_id=admin.id,
        target_type="setting",
        target_id=key,
        source_ip=client_ip(request),
    )
    await session.commit()
    await load_overrides(session)  # resync cache from committed state
    return _item(defn)
