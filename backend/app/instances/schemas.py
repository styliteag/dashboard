"""Pydantic schemas for the instances API.

The API never returns the API key/secret. On update, empty strings mean
"don't change" — only the fields the user actually re-typed are rotated.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field


class InstanceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    base_url: AnyHttpUrl
    # API key/secret are optional when using agent mode (agent collects data locally).
    api_key: str | None = None
    api_secret: str | None = None
    agent_mode: bool = False
    ca_bundle: str | None = None
    ssl_verify: bool = True
    location: str | None = None
    notes: str | None = None
    tags: list[str] | None = None


class InstanceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    base_url: AnyHttpUrl | None = None
    # Empty/omitted means "keep existing".
    api_key: str | None = None
    api_secret: str | None = None
    ca_bundle: str | None = None
    ssl_verify: bool | None = None
    location: str | None = None
    notes: str | None = None
    tags: list[str] | None = None


class InstanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    base_url: str
    ssl_verify: bool
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
