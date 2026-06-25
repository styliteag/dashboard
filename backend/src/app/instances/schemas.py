"""Pydantic schemas for the instances API.

The API never returns the API key/secret. On update, empty strings mean
"don't change" — only the fields the user actually re-typed are rotated.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.devices.types import DeviceType, Transport


def _normalize_base_urls(value: str) -> str:
    """Validate a comma-separated list of http(s) URLs; return them ', '-joined.

    ``base_url`` may carry several clickable web-UI links (the first is also the
    API endpoint for direct/relay mode). Each entry must be a real http(s) URL.
    """
    urls = [u.strip() for u in value.split(",") if u.strip()]
    if not urls:
        raise ValueError("at least one base URL is required")
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"invalid URL: {url!r}")
    return ", ".join(urls)


class InstanceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    base_url: str
    # API key/secret are optional when using agent mode (agent collects data locally).
    api_key: str | None = None
    api_secret: str | None = None
    # Transport/device-type are the source of truth (see docs/agent-architecture.md).
    # ``agent_mode`` is kept as a back-compat input: when ``transport`` is omitted,
    # agent_mode=True maps to transport=push, else direct.
    transport: Transport | None = None
    device_type: DeviceType = DeviceType.OPNSENSE
    agent_mode: bool = False
    ca_bundle: str | None = None
    ssl_verify: bool = True
    location: str | None = None
    notes: str | None = None
    tags: list[str] | None = None

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, v: str) -> str:
        return _normalize_base_urls(v)


class InstanceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    base_url: str | None = None
    # Empty/omitted means "keep existing".
    api_key: str | None = None
    api_secret: str | None = None
    ca_bundle: str | None = None
    ssl_verify: bool | None = None
    gui_login_enabled: bool | None = None
    location: str | None = None
    notes: str | None = None
    tags: list[str] | None = None

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, v: str | None) -> str | None:
        return _normalize_base_urls(v) if v is not None else None


class InstanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    base_url: str
    ssl_verify: bool
    gui_login_enabled: bool
    transport: str
    device_type: str
    agent_mode: bool
    agent_last_seen: datetime | None
    location: str | None
    notes: str | None
    tags: list[str] | None
    last_success_at: datetime | None
    last_error_at: datetime | None
    last_error_message: str | None
    created_at: datetime
    updated_at: datetime


class TestConnectionResponse(BaseModel):
    ok: bool
    status_code: int | None = None
    latency_ms: int | None = None
    error: str | None = None
