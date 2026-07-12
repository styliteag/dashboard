"""Write and read metric time-series from the metrics table.

Metric names follow the pattern ``<category>.<name>`` — e.g. ``cpu.total``,
``memory.used_pct``, ``disk.root.used_pct``, ``iface.wan.bytes_rx``.

Backend is MariaDB; bucketing is done client-side via UNIX_TIMESTAMP / DIV.
A periodic APScheduler job (``prune_metrics``) enforces raw-metrics retention
(replaces TimescaleDB built-ins).
"""

from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.xsense.schemas import SystemStatus

# ``SystemStatus.uptime`` is a human string whose shape depends on the source:
# agent push relays the ``uptime`` binary ("18 days, 22:03", "5 mins", "1:02"),
# the OPNsense direct poll pre-formats "1d 18h 18m", Securepoint reports
# "13 days, 4:07:32". The unit tokens and an optional hh:mm[:ss] clock cover
# all of them; anything else (e.g. a bare number) parses to None and no metric
# row is written — never guess a wrong uptime into the series.
_UPTIME_UNITS: list[tuple[re.Pattern[str], int]] = [
    (re.compile(r"(\d+)\s*(?:d\b|day)"), 86400),
    (re.compile(r"(\d+)\s*(?:h\b|hr|hour)"), 3600),
    (re.compile(r"(\d+)\s*(?:m\b|min)"), 60),
    (re.compile(r"(\d+)\s*(?:s\b|sec)"), 1),
]
_UPTIME_CLOCK = re.compile(r"\b(\d+):(\d{2})(?::(\d{2}))?\b")


def uptime_to_seconds(uptime: str | None) -> float | None:
    """Parse a human uptime string into seconds; None when unparseable."""
    if not uptime:
        return None
    s = uptime.strip().lower()
    total = 0.0
    matched = False
    for pattern, mult in _UPTIME_UNITS:
        m = pattern.search(s)
        if m:
            total += int(m.group(1)) * mult
            matched = True
    m = _UPTIME_CLOCK.search(s)
    if m:
        hours, minutes, seconds = m.group(1), m.group(2), m.group(3)
        total += int(hours) * 3600 + int(minutes) * 60 + int(seconds or 0)
        matched = True
    return total if matched else None


def to_rate(points: list[dict]) -> list[dict]:
    """Turn a monotonic counter series into a per-second rate.

    Used for interface byte counters (iface.*.bytes_rx/tx) → bytes/sec. Drops the
    first point (no predecessor) and clamps counter resets (negative deltas, e.g.
    after a reboot) to 0. Works for both push and poll — they store the same raw
    counters, so the rate is derived on read with no in-memory state.
    """
    out: list[dict] = []
    for prev, cur in zip(points, points[1:], strict=False):
        dt = (
            datetime.fromisoformat(cur["ts"]) - datetime.fromisoformat(prev["ts"])
        ).total_seconds()
        if dt <= 0:
            continue
        delta = cur["value"] - prev["value"]
        out.append({"ts": cur["ts"], "value": (delta / dt) if delta >= 0 else 0.0})
    return out


def is_online(last_success_at: datetime | None, last_error_at: datetime | None) -> bool:
    """A target is online when its last success is more recent than its last error.

    Shared by the poller, the agent hub (recovery), and the staleness watchdog so
    the online/offline transition is decided in exactly one place.
    """
    return bool(last_success_at and (not last_error_at or last_success_at > last_error_at))


async def write_poll_metrics(
    session: AsyncSession,
    instance_id: int,
    ts: datetime,
    status: SystemStatus,
) -> int:
    """Persist a poll snapshot as individual metric rows. Returns row count."""
    rows: list[dict] = []

    def add(metric: str, value: float) -> None:
        rows.append({"instance_id": instance_id, "ts": ts, "metric": metric, "value": value})

    # Uptime sawtooth (drops to ~0 on every reboot). Only stored when the human
    # uptime string parsed — absent/odd formats must not fake a 0-uptime reboot.
    uptime_seconds = uptime_to_seconds(status.uptime)
    if uptime_seconds is not None:
        add("system.uptime_seconds", uptime_seconds)

    add("cpu.total", status.cpu.total)
    add("memory.used_pct", status.memory.used_pct)
    add("memory.total_mb", status.memory.total_mb)
    add("memory.used_mb", status.memory.used_mb)

    # Load average (agent push only; direct poll leaves load at 0).
    add("load.1m", status.load.one)
    add("load.5m", status.load.five)
    add("load.15m", status.load.fifteen)

    # Swap + pf state-table — only when the agent actually reported them
    # (total/limit 0 means "no data"; don't store a misleading 0-series).
    if status.memory.swap_total_mb > 0:
        add("memory.swap_used_pct", status.memory.swap_used_pct)
    if status.pf.states_limit > 0:
        add("pf.states_current", float(status.pf.states_current))
        add("pf.states_pct", status.pf.states_pct)

    for disk in status.disks:
        label = disk.mountpoint.replace("/", "_").strip("_") or "root"
        add(f"disk.{label}.used_pct", disk.used_pct)

    for iface in status.interfaces:
        # Sanitize name: "[LAN] vmx0" -> "lan_vmx0", keep under 128 chars total
        safe = (
            iface.name.replace("[", "")
            .replace("]", "")
            .replace(" ", "_")
            .replace("(", "")
            .replace(")", "")
            .lower()
        )
        safe = safe[:40]  # cap at 40 chars to stay well within VARCHAR(128) with prefix+suffix
        add(f"iface.{safe}.bytes_rx", float(iface.bytes_received))
        add(f"iface.{safe}.bytes_tx", float(iface.bytes_transmitted))

    # Agent collection runtime — push agents only (None on the direct-poll path).
    # Only the whole-cycle total is stored/graphed; per-section timings are shown
    # live on the Agent tab (last snapshot), not persisted as history.
    if status.collect_ms is not None:
        add("agent.collect_ms", float(status.collect_ms))

    if rows:
        await session.execute(
            text(
                "INSERT IGNORE INTO metrics (instance_id, ts, metric, value) "
                "VALUES (:instance_id, :ts, :metric, :value)"
            ),
            rows,
        )
    return len(rows)


async def read_metrics(
    session: AsyncSession,
    instance_id: int,
    metric: str,
    start: datetime,
    end: datetime,
    bucket_seconds: int = 0,
) -> list[dict]:
    """Read metric time-series. If bucket_seconds > 0 use Timescale time_bucket
    for server-side downsampling; otherwise return raw rows."""
    if bucket_seconds > 0:
        # Bucket size is inlined — must be a literal because we group by the
        # expression. bucket_seconds comes from our own RANGE_BUCKETS dict,
        # never from user input.
        query = text(
            f"SELECT FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV {bucket_seconds} "
            f"* {bucket_seconds}) AS ts, avg(value) AS value "
            "FROM metrics "
            "WHERE instance_id = :iid AND metric = :m AND ts >= :start AND ts <= :end "
            "GROUP BY 1 ORDER BY 1"
        )
        params = {
            "iid": instance_id,
            "m": metric,
            "start": start,
            "end": end,
        }
    else:
        query = text(
            "SELECT ts, value FROM metrics "
            "WHERE instance_id = :iid AND metric = :m AND ts >= :start AND ts <= :end "
            "ORDER BY ts"
        )
        params = {"iid": instance_id, "m": metric, "start": start, "end": end}

    result = await session.execute(query, params)
    return [{"ts": row.ts.isoformat(), "value": float(row.value)} for row in result]
