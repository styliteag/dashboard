"""Maintenance ceiling: cap an instance's checks at WARN while it's flagged.

An admin sets ``Instance.maintenance`` when a box is down on purpose (planned work,
decommission). While set, every check is capped at WARN — yellow, never red — so a
known-down box doesn't page, and a dedicated ``maintenance`` service makes the host
visibly yellow with the reason even when nothing else is failing. The flag
auto-clears the moment the agent or probe reports healthy again (see the hub ingest
and the probe scheduler job).
"""

from __future__ import annotations

from app.checks.models import CheckState, ServiceCheck


def apply_maintenance(checks: list[ServiceCheck], in_maintenance: bool) -> list[ServiceCheck]:
    """Prepend the ``maintenance`` service and cap every other check at WARN.

    No-op (returns the input list unchanged) when not in maintenance. Never mutates
    the input checks — capped checks are produced as copies.
    """
    if not in_maintenance:
        return checks
    banner = ServiceCheck(
        key="maintenance",
        state=int(CheckState.WARN),
        summary="In maintenance — alerts capped at WARN",
    )
    capped = [
        c
        if c.state <= int(CheckState.WARN)
        else c.model_copy(
            update={"state": int(CheckState.WARN), "summary": f"{c.summary} (maintenance)"}
        )
        for c in checks
    ]
    return [banner, *capped]
