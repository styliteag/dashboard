"""Uptime string parsing + the system.uptime_seconds metric row.

The instance overview draws an uptime sawtooth from ``system.uptime_seconds``.
``SystemStatus.uptime`` is a human string with a source-dependent shape; the
parser must cover all three producers and refuse everything else — a wrongly
parsed value would paint a phantom reboot (or hide a real one) in the graph.

DB-free house style: write_poll_metrics is exercised with a fake session that
captures the INSERT parameter rows.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.metrics.store import uptime_to_seconds, write_poll_metrics
from app.xsense.schemas import SystemStatus


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Agent push (FreeBSD/Linux `uptime` output segment)
        ("18 days, 22:03", 18 * 86400 + 22 * 3600 + 3 * 60),
        ("1 day, 5 mins", 86400 + 300),
        ("5 mins", 300),
        ("1:02", 3720),
        # OPNsense direct poll (pre-formatted by _parse_uptime)
        ("1d 18h 18m", 86400 + 18 * 3600 + 18 * 60),
        ("18h 18m", 18 * 3600 + 18 * 60),
        # Securepoint `system info` Uptime
        ("13 days, 4:07:32", 13 * 86400 + 4 * 3600 + 7 * 60 + 32),
    ],
)
def test_uptime_to_seconds_known_formats(raw: str, expected: int) -> None:
    assert uptime_to_seconds(raw) == float(expected)


@pytest.mark.parametrize("raw", [None, "", "59", "unknown"])
def test_uptime_to_seconds_unparseable_is_none(raw: str | None) -> None:
    assert uptime_to_seconds(raw) is None


class _CaptureSession:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def execute(self, query, params=None):  # noqa: ANN001, ANN202
        self.rows.extend(params or [])


def _metric_names(session: _CaptureSession) -> set[str]:
    return {r["metric"] for r in session.rows}


async def test_write_poll_metrics_stores_uptime_seconds() -> None:
    session = _CaptureSession()
    status = SystemStatus(uptime="2 days, 1:30")
    await write_poll_metrics(session, 1, datetime.now(UTC), status)  # type: ignore[arg-type]
    row = next(r for r in session.rows if r["metric"] == "system.uptime_seconds")
    assert row["value"] == 2 * 86400 + 3600 + 30 * 60


async def test_write_poll_metrics_skips_unparseable_uptime() -> None:
    session = _CaptureSession()
    await write_poll_metrics(session, 1, datetime.now(UTC), SystemStatus(uptime=None))
    assert "system.uptime_seconds" not in _metric_names(session)
