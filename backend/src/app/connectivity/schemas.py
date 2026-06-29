"""Pydantic schemas for standalone connectivity ping monitors.

A monitor is a (source, destination) probe with no tunnel binding. The agent runs
``ping -S <source> <destination>`` on the firewall each push cycle; results come
back keyed by the monitor id.
"""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, ConfigDict, field_validator


def _clean_ip(value: str, *, required: bool, field: str) -> str:
    """Strip + validate an IPv4/IPv6 literal. Empty allowed unless ``required``."""
    v = (value or "").strip()
    if not v:
        if required:
            raise ValueError(f"{field} is required")
        return v
    try:
        ipaddress.ip_address(v)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid IP address") from exc
    return v


def _clean_count(value: int) -> int:
    if not 1 <= value <= 10:
        raise ValueError("ping_count must be between 1 and 10")
    return value


def _clean_name(value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ValueError("name is required")
    if len(v) > 128:
        raise ValueError("name must be at most 128 characters")
    return v


class ConnMonitorBase(BaseModel):
    name: str
    # Local source IP (box-owned). "" → ping uses the default route.
    source: str = ""
    destination: str
    enabled: bool = True
    ping_count: int = 3

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        return _clean_name(v)

    @field_validator("source")
    @classmethod
    def _v_source(cls, v: str) -> str:
        return _clean_ip(v, required=False, field="source")

    @field_validator("destination")
    @classmethod
    def _v_destination(cls, v: str) -> str:
        return _clean_ip(v, required=True, field="destination")

    @field_validator("ping_count")
    @classmethod
    def _v_count(cls, v: int) -> int:
        return _clean_count(v)


class ConnMonitorCreate(ConnMonitorBase):
    pass


class ConnMonitorUpdate(BaseModel):
    """Partial update — only provided fields are applied."""

    name: str | None = None
    source: str | None = None
    destination: str | None = None
    enabled: bool | None = None
    ping_count: int | None = None

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str | None) -> str | None:
        return None if v is None else _clean_name(v)

    @field_validator("source")
    @classmethod
    def _v_source(cls, v: str | None) -> str | None:
        return None if v is None else _clean_ip(v, required=False, field="source")

    @field_validator("destination")
    @classmethod
    def _v_destination(cls, v: str | None) -> str | None:
        return None if v is None else _clean_ip(v, required=True, field="destination")

    @field_validator("ping_count")
    @classmethod
    def _v_count(cls, v: int | None) -> int | None:
        return None if v is None else _clean_count(v)


class ConnMonitorRead(ConnMonitorBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    instance_id: int


class ConnPingTestRequest(BaseModel):
    """Ad-hoc ping test from the config dialog (not persisted)."""

    source: str = ""
    destination: str
    ping_count: int = 3

    @field_validator("source")
    @classmethod
    def _v_source(cls, v: str) -> str:
        return _clean_ip(v, required=False, field="source")

    @field_validator("destination")
    @classmethod
    def _v_destination(cls, v: str) -> str:
        return _clean_ip(v, required=True, field="destination")

    @field_validator("ping_count")
    @classmethod
    def _v_count(cls, v: int) -> int:
        return _clean_count(v)


class ConnPingTestResult(BaseModel):
    ok: bool
    ping_state: str = "error"  # ok | fail | error
    ping_rtt_ms: float | None = None
    ping_loss_pct: float | None = None
    message: str = ""


class ConnMonitorState(ConnMonitorRead):
    """A monitor joined with its latest pushed ping result (for the status view)."""

    ping_state: str = "none"  # none | ok | fail | error
    ping_rtt_ms: float | None = None
    ping_loss_pct: float | None = None
    ping_ts: str | None = None
