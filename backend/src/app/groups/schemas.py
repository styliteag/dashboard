"""Shared group schemas (used by the groups, users and auth routers)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class GroupBrief(BaseModel):
    """Minimal group reference embedded in user payloads (/auth/me, /users)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class GroupUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class GroupOut(BaseModel):
    id: int
    name: str
    created_at: datetime
    member_count: int
    instance_count: int


class GroupInstanceOut(BaseModel):
    """Instance reference for the move-UI — deliberately no status/config data,
    so a pure superadmin can reassign instances without instance access."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
