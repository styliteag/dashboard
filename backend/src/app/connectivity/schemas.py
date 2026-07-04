"""Pydantic schemas for standalone connectivity ping monitors.

A monitor is a (source, destination) probe with no tunnel binding. The agent runs
``ping -S <source> <destination>`` on the firewall each push cycle; results come
back keyed by the monitor id. The destination may be a hostname — FreeBSD ``ping``
resolves it on the box (its DNS view is the one that matters); an empty
destination falls back to the monitor name when that is host-shaped.
"""

from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# RFC 1123 hostname: dot-separated labels of [a-z0-9-], no leading/trailing
# hyphen, 253 chars total. Case is preserved (DNS is case-insensitive anyway).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
# Only digits and dots → the user meant an IPv4 literal; never treat a broken
# one ("999.1.1.1", "10.2.2") as a hostname.
_IPV4_SHAPED_RE = re.compile(r"^[\d.]+$")


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


def _clean_destination(value: str, *, required: bool) -> str:
    """Strip + validate an IP literal **or** hostname.

    Names are resolved on the box by ``ping`` itself — the firewall's DNS view
    is what matters for a connectivity check, so the backend never resolves."""
    v = (value or "").strip()
    if not v:
        if required:
            raise ValueError("destination is required")
        return v
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    if _IPV4_SHAPED_RE.match(v) or not _HOSTNAME_RE.match(v):
        raise ValueError("destination must be an IP address or hostname")
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
    # IP or hostname; "" → falls back to the (host-shaped) name below.
    destination: str = ""
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
        return _clean_destination(v, required=False)

    @field_validator("ping_count")
    @classmethod
    def _v_count(cls, v: int) -> int:
        return _clean_count(v)

    @model_validator(mode="after")
    def _default_destination_to_name(self) -> ConnMonitorBase:
        if not self.destination:
            try:
                self.destination = _clean_destination(self.name, required=True)
            except ValueError as exc:
                raise ValueError(
                    "destination is required (the name is not usable as a host)"
                ) from exc
        return self


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
        return None if v is None else _clean_destination(v, required=False)

    @field_validator("ping_count")
    @classmethod
    def _v_count(cls, v: int | None) -> int | None:
        return None if v is None else _clean_count(v)

    @model_validator(mode="after")
    def _default_destination_to_name(self) -> ConnMonitorUpdate:
        # "" destination falls back to a host-shaped name from the SAME request;
        # partial updates without destination (None) stay untouched.
        if self.destination == "":
            if self.name is None:
                raise ValueError("destination is required (or send a name to fall back to)")
            try:
                self.destination = _clean_destination(self.name, required=True)
            except ValueError as exc:
                raise ValueError(
                    "destination is required (the name is not usable as a host)"
                ) from exc
        return self


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
        return _clean_destination(v, required=True)

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
