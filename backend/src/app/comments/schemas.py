"""Schemas for entity comments (operator notes on non-DB entities).

Instance comments stay on ``Instance.notes`` (PATCH /instances/{id}); this
feature covers the kinds below, keyed per instance by the family's stable id.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# Instance notes are NOT a kind here — they live on the Instance row itself.
CommentKind = Literal["ipsec", "connectivity", "firmware", "cert"]


class CommentSet(BaseModel):
    """Upsert payload. An empty/whitespace ``comment`` deletes the entry."""

    kind: CommentKind
    # "" is valid — the firmware note is per-instance and has no sub-entity key.
    entity_key: str = Field(default="", max_length=255)
    comment: str = Field(default="", max_length=2000)


class CommentRead(BaseModel):
    instance_id: int
    kind: str
    entity_key: str
    comment: str
    updated_by: str
    updated_at: str | None  # ISO-8601 with explicit UTC offset (see _iso_utc)
