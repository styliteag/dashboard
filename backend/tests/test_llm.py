"""LLM provider catalog + settings wiring."""

from __future__ import annotations

from app.llm.providers import (
    PROVIDERS,
    PROVIDERS_BY_ID,
    api_key_setting,
    auth_headers,
    base_url_setting,
    model_setting,
)
from app.settings.registry import EDITABLE
from app.settings.routes import _item


def test_each_provider_registers_three_settings() -> None:
    for p in PROVIDERS:
        key = EDITABLE[api_key_setting(p.id)]
        assert key.is_secret and key.group == "LLM"
        assert EDITABLE[base_url_setting(p.id)].default == p.default_base_url
        assert EDITABLE[model_setting(p.id)].default == p.default_model


def test_auth_headers_bearer_vs_x_api_key() -> None:
    assert auth_headers(PROVIDERS_BY_ID["openai"], "sk-x") == {"Authorization": "Bearer sk-x"}
    anth = auth_headers(PROVIDERS_BY_ID["anthropic"], "sk-ant")
    assert anth["x-api-key"] == "sk-ant"
    assert anth["anthropic-version"]  # version header present


def test_item_uses_catalog_default_without_settings_field() -> None:
    # base URL has no Settings field — its default comes from the catalog.
    item = _item(EDITABLE[base_url_setting("openai")])
    assert item.default == PROVIDERS_BY_ID["openai"].default_base_url
    assert item.source == "env"
    # an unset secret masks to an empty value.
    key_item = _item(EDITABLE[api_key_setting("openai")])
    assert key_item.is_secret and key_item.value == ""
