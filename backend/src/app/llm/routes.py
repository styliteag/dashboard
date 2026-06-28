"""Admin REST for LLM providers: list the catalog + run a key-validation test."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.auth.deps import require_admin
from app.db.models import User
from app.llm.probe import ProbeResult, test_provider
from app.llm.providers import PROVIDERS, PROVIDERS_BY_ID, api_key_setting
from app.settings.store import get_override

router = APIRouter(prefix="/llm", tags=["llm"])


class ProviderItem(BaseModel):
    id: str
    label: str
    configured: bool


class ProbeResponse(BaseModel):
    provider: str
    configured: bool
    ok: bool
    detail: str
    status: int | None = None


@router.get("/providers", response_model=list[ProviderItem])
async def list_providers(_admin: User = Depends(require_admin)) -> list[ProviderItem]:
    return [
        ProviderItem(
            id=p.id,
            label=p.label,
            configured=bool(get_override(api_key_setting(p.id))),
        )
        for p in PROVIDERS
    ]


@router.post("/test", response_model=ProbeResponse)
async def test(provider: str, _admin: User = Depends(require_admin)) -> ProbeResponse:
    defn = PROVIDERS_BY_ID.get(provider)
    if defn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")
    result: ProbeResult = await test_provider(defn)
    return ProbeResponse(
        provider=result.provider,
        configured=result.configured,
        ok=result.ok,
        detail=result.detail,
        status=result.status,
    )
