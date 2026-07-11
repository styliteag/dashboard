"""Send anonymized log text to a configured LLM provider and return findings.

The request/response shapes differ by provider (OpenAI-style chat completions vs
Anthropic messages); the builders/parsers below are pure and unit-tested, while
``analyze_logs`` wires in the stored key, anonymization and the HTTP call.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from app.llm.anonymize import anonymize
from app.llm.providers import (
    CHAT_ANTHROPIC,
    LLMProvider,
    api_key_setting,
    auth_headers,
    base_url_setting,
    model_setting,
)
from app.settings.store import get_override

log = structlog.get_logger("app.llm")

_TIMEOUT = httpx.Timeout(60.0)
_MAX_INPUT_CHARS = 40_000  # bound tokens/cost; the payload is already capped upstream
# Output budget. On reasoning models (gpt-5.x) this also covers reasoning tokens,
# so too low a value yields an empty answer — keep enough headroom for both.
_MAX_TOKENS = 4000

SYSTEM_PROMPT = (
    "You are a senior network and firewall log analyst for OPNsense/pfSense "
    "systems. Review the log excerpt and report anomalies, errors and "
    "misconfigurations — e.g. ARP flapping or duplicate IPs, interface/driver "
    "errors, failing or restarting services, IPsec tunnel problems, gateway "
    "packet loss, certificate or DNS issues. For each finding give a short "
    "title, a severity (info/warn/critical), the supporting evidence and a "
    "suggested fix. If nothing looks wrong, say so plainly. Be concise and do "
    "not invent issues. Note: IPs/MACs/hostnames may be anonymized."
)


@dataclass(frozen=True)
class AnalyzeResult:
    ok: bool
    provider: str
    model: str
    findings: str
    sent_chars: int
    error: str | None = None


def build_chat_request(
    provider: LLMProvider, key: str, model: str, system: str, user: str
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """URL, headers and JSON body for one chat-completion request. Pure."""
    base = (get_override(base_url_setting(provider.id)) or provider.default_base_url).rstrip("/")
    url = f"{base}{provider.chat_path}"
    headers = auth_headers(provider, key)
    if provider.chat_style == CHAT_ANTHROPIC:
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": _MAX_TOKENS,  # required by Anthropic
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
    else:
        # OpenAI standardized on max_completion_tokens; newer models (gpt-5.x, o*)
        # reject the legacy max_tokens. OpenRouter accepts it for OpenAI-style too.
        body = {
            "model": model,
            "max_completion_tokens": _MAX_TOKENS,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
    return url, headers, body


def parse_chat_response(chat_style: str, data: dict[str, Any]) -> str:
    """Extract the assistant text from a provider response. Pure."""
    if chat_style == CHAT_ANTHROPIC:
        blocks = data.get("content") or []
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
    choices = data.get("choices") or []
    if not choices:
        return ""
    return (choices[0].get("message") or {}).get("content", "").strip()


async def analyze_logs(provider: LLMProvider, log_text: str) -> AnalyzeResult:
    """Anonymize ``log_text`` and ask ``provider`` to analyze it."""
    key = get_override(api_key_setting(provider.id))
    model = get_override(model_setting(provider.id)) or provider.default_model
    if not key:
        return AnalyzeResult(False, provider.id, model, "", 0, error="No API key configured")
    # anonymize() regex-walks the full log text (up to several hundred KB) —
    # CPU work; a user-triggered analysis must not stall pushes/shells.
    anonymized = (await asyncio.to_thread(anonymize, log_text))[:_MAX_INPUT_CHARS]
    url, headers, body = build_chat_request(provider, key, model, SYSTEM_PROMPT, anonymized)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        log.warning("llm.analyze_failed", provider=provider.id, error=str(exc))
        return AnalyzeResult(
            False, provider.id, model, "", len(anonymized), error=f"Request failed: {exc}"
        )
    if resp.status_code != 200:
        return AnalyzeResult(
            False,
            provider.id,
            model,
            "",
            len(anonymized),
            error=f"HTTP {resp.status_code}: {resp.text[:300]}",
        )
    findings = parse_chat_response(provider.chat_style, resp.json())
    return AnalyzeResult(True, provider.id, model, findings, len(anonymized))
