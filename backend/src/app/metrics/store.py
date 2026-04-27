"""Write and read metric time-series from the metrics table.

Metric names follow the pattern ``<category>.<name>`` — e.g. ``cpu.total``,
``memory.used_pct``, ``disk.root.used_pct``, ``iface.wan.bytes_rx``.

Backend is MariaDB; bucketing is done client-side via UNIX_TIMESTAMP / DIV.
A periodic APScheduler job is responsible for retention and the metrics_5m
roll-up (replaces TimescaleDB built-ins).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.opnsense.schemas import SystemStatus


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

    add("cpu.total", status.cpu.total)
    add("memory.used_pct", status.memory.used_pct)
    add("memory.total_mb", status.memory.total_mb)
    add("memory.used_mb", status.memory.used_mb)

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
