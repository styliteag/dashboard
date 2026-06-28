"""Connectivity / key-validation probe for a configured LLM provider.

Hits the provider's models-list endpoint with the stored (decrypted) API key:
HTTP 200 means the key authenticates. Never returns or logs the key itself.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import structlog

from app.llm.providers import (
    LLMProvider,
    api_key_setting,
    auth_headers,
    base_url_setting,
)
from app.settings.store import get_override

log = structlog.get_logger("app.llm")

_TIMEOUT = httpx.Timeout(10.0)


@dataclass(frozen=True)
class ProbeResult:
    provider: str
    configured: bool
    ok: bool
    detail: str
    status: int | None = None


def _effective_base_url(provider: LLMProvider) -> str:
    return (get_override(base_url_setting(provider.id)) or provider.default_base_url).rstrip("/")


async def test_provider(provider: LLMProvider) -> ProbeResult:
    """Validate the stored key for ``provider`` against its models endpoint."""
    key = get_override(api_key_setting(provider.id))
    if not key:
        return ProbeResult(provider.id, configured=False, ok=False, detail="No API key configured")
    url = f"{_effective_base_url(provider)}{provider.models_path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=auth_headers(provider, key))
    except httpx.HTTPError as exc:
        log.warning("llm.probe_failed", provider=provider.id, error=str(exc))
        return ProbeResult(provider.id, configured=True, ok=False, detail=f"Request failed: {exc}")
    ok = resp.status_code == 200
    detail = "Key valid" if ok else f"HTTP {resp.status_code}"
    if resp.status_code in (401, 403):
        detail = f"Key rejected (HTTP {resp.status_code})"
    return ProbeResult(provider.id, configured=True, ok=ok, detail=detail, status=resp.status_code)
