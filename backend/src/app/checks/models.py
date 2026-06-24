"""Models for service-state evaluation. ``state`` follows the Checkmk convention
(0=OK, 1=WARN, 2=CRIT, 3=UNKNOWN) so the export maps 1:1."""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel


class CheckState(IntEnum):
    OK = 0
    WARN = 1
    CRIT = 2
    UNKNOWN = 3


class PerfMetric(BaseModel):
    """One performance datum (Checkmk perfdata: name=value;warn;crit)."""

    name: str
    value: float
    warn: float | None = None
    crit: float | None = None
    unit: str = ""


class ServiceCheck(BaseModel):
    """One evaluated service for one instance."""

    key: str  # stable id, e.g. "memory", "disk:/", "gateway:WAN", "ipsec.tunnel:site-a"
    state: int  # CheckState value (0|1|2|3)
    summary: str
    metrics: list[PerfMetric] = []
