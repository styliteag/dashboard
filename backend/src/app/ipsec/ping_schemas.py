"""Pydantic schemas for IPsec Phase-2 ping monitors.

A monitor pins an optional (source, destination) probe to one IPsec child SA
(Phase 2). The agent runs ``ping -S <source> <destination>`` each push cycle so
a tunnel that is INSTALLED but not actually passing traffic is caught.
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


class PingMonitorBase(BaseModel):
    tunnel_id: str
    child_name: str = ""
    local_ts: str = ""
    remote_ts: str = ""
    description: str = ""
    # Local source IP (box-owned, inside local_ts). "" → ping uses the default route.
    source: str = ""
    destination: str
    enabled: bool = True
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


class PingMonitorCreate(PingMonitorBase):
    pass


class PingMonitorUpdate(BaseModel):
    """Partial update — only provided fields are applied."""

    tunnel_id: str | None = None
    child_name: str | None = None
    local_ts: str | None = None
    remote_ts: str | None = None
    description: str | None = None
    source: str | None = None
    destination: str | None = None
    enabled: bool | None = None
    ping_count: int | None = None

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


class PingMonitorRead(PingMonitorBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    instance_id: int
