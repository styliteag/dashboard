"""Diff successive check evaluations into a state-change event log.

Pure and DB-free. ``diff_checks`` compares the previous check states (a
``{key: state}`` map) with the freshly evaluated checks and returns the
transitions worth remembering — one per key whose state changed.

``prev is None`` means there is no baseline yet (a brand-new instance, or a
backend that has not re-hydrated): we return nothing and let the caller record
the baseline, so the very first push (and a post-restart re-hydration) does not
spam the history with every check. A key absent from the baseline is treated as
having been OK, so only a *new problem* (non-OK) emits an event, never a new
green check.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.checks.models import CheckState, ServiceCheck


@dataclass(frozen=True)
class CheckTransition:
    """One recorded check state change. ``ts``/``instance_id`` are added on write."""

    check_key: str
    old_state: int
    new_state: int
    summary: str


def current_states(checks: list[ServiceCheck]) -> dict[str, int]:
    """The ``{key: state}`` snapshot to persist as the next baseline."""
    return {c.key: c.state for c in checks}


def diff_checks(prev: dict[str, int] | None, checks: list[ServiceCheck]) -> list[CheckTransition]:
    """Transitions between ``prev`` states and the current ``checks``.

    Returns an empty list when there is no baseline yet (``prev is None``).
    """
    if prev is None:
        return []
    out: list[CheckTransition] = []
    for c in checks:
        old = prev.get(c.key, int(CheckState.OK))
        if old != c.state:
            out.append(
                CheckTransition(
                    check_key=c.key,
                    old_state=old,
                    new_state=c.state,
                    summary=c.summary,
                )
            )
    return out
