"""Admin REST for LLM providers: list the catalog + run a key-validation test."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.auth.deps import require_admin
from app.db.models import User
from app.llm.analyze import AnalyzeResult, analyze_logs
from app.llm.anonymize import anonymize
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


class PreviewRequest(BaseModel):
    text: str


class PreviewResponse(BaseModel):
    anonymized: str


class AnalyzeRequest(BaseModel):
    provider: str
    text: str


class AnalyzeResponse(BaseModel):
    ok: bool
    provider: str
    model: str
    findings: str
    sent_chars: int
    error: str | None = None


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


@router.post("/preview", response_model=PreviewResponse)
async def preview(
    payload: PreviewRequest, _admin: User = Depends(require_admin)
) -> PreviewResponse:
    """Show exactly what anonymized text would leave the box before sending it."""
    return PreviewResponse(anonymized=anonymize(payload.text))


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    payload: AnalyzeRequest, _admin: User = Depends(require_admin)
) -> AnalyzeResponse:
    defn = PROVIDERS_BY_ID.get(payload.provider)
    if defn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")
    result: AnalyzeResult = await analyze_logs(defn, payload.text)
    return AnalyzeResponse(
        ok=result.ok,
        provider=result.provider,
        model=result.model,
        findings=result.findings,
        sent_chars=result.sent_chars,
        error=result.error,
    )
