"""Catalog of supported LLM providers — pure data, DB-free.

Code-extensible: adding a provider means appending one ``LLMProvider`` here. Each
provider contributes three editable settings (``llm_<id>_api_key`` secret,
``llm_<id>_base_url``, ``llm_<id>_model``) and a connectivity probe against its
models-list endpoint. OpenAI and OpenRouter are OpenAI-compatible (Bearer auth);
Anthropic uses ``x-api-key`` + a version header.
"""

from __future__ import annotations

from dataclasses import dataclass

# Auth styles for the models-list probe.
AUTH_BEARER = "bearer"  # Authorization: Bearer <key>  (OpenAI, OpenRouter)
AUTH_X_API_KEY = "x-api-key"  # x-api-key + anthropic-version  (Anthropic)

# Chat-completion request/response shapes.
CHAT_OPENAI = "openai"  # POST /chat/completions, choices[0].message.content
CHAT_ANTHROPIC = "anthropic"  # POST /v1/messages, content[0].text

_ANTHROPIC_VERSION = "2023-06-01"


@dataclass(frozen=True)
class LLMProvider:
    id: str
    label: str
    default_base_url: str
    default_model: str
    auth: str  # AUTH_BEARER | AUTH_X_API_KEY
    models_path: str  # appended to base_url for the connectivity/key probe
    chat_path: str  # appended to base_url for a chat-completion request
    chat_style: str  # CHAT_OPENAI | CHAT_ANTHROPIC


PROVIDERS: tuple[LLMProvider, ...] = (
    LLMProvider(
        id="openai",
        label="OpenAI",
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-5.5",
        auth=AUTH_BEARER,
        models_path="/models",
        chat_path="/chat/completions",
        chat_style=CHAT_OPENAI,
    ),
    LLMProvider(
        id="anthropic",
        label="Anthropic",
        default_base_url="https://api.anthropic.com",
        default_model="claude-opus-4-8",
        auth=AUTH_X_API_KEY,
        models_path="/v1/models",
        chat_path="/v1/messages",
        chat_style=CHAT_ANTHROPIC,
    ),
    LLMProvider(
        id="openrouter",
        label="OpenRouter",
        default_base_url="https://openrouter.ai/api/v1",
        default_model="openai/gpt-5.5",
        auth=AUTH_BEARER,
        models_path="/models",
        chat_path="/chat/completions",
        chat_style=CHAT_OPENAI,
    ),
)

PROVIDERS_BY_ID: dict[str, LLMProvider] = {p.id: p for p in PROVIDERS}


def api_key_setting(provider_id: str) -> str:
    return f"llm_{provider_id}_api_key"


def base_url_setting(provider_id: str) -> str:
    return f"llm_{provider_id}_base_url"


def model_setting(provider_id: str) -> str:
    return f"llm_{provider_id}_model"


def auth_headers(provider: LLMProvider, key: str) -> dict[str, str]:
    """Auth headers for a request to ``provider`` with ``key``. Pure + testable."""
    if provider.auth == AUTH_X_API_KEY:
        return {"x-api-key": key, "anthropic-version": _ANTHROPIC_VERSION}
    return {"Authorization": f"Bearer {key}"}
