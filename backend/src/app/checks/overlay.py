"""Compose the per-instance check overlays in one place.

The raw ``evaluate_checks`` output is layered with, in order:

1. the agent-staleness overlay — adds the ``agent`` service (OK fresh / WARN
   stale) and caps stale sub-states CRIT→WARN;
2. the freshly-measured out-of-band probe — ``ping`` / ``http`` services,
   appended *after* the staleness cap (the probe is live, not stale, and is the
   signal that can take a stale-but-confirmed-down box to CRIT); and
3. the maintenance ceiling — caps everything at WARN and adds a ``maintenance``
   banner while the instance is flagged.

Used by the Checkmk export, the Alerts page, the per-instance checks endpoint AND
the export-exclusion preview, so all four show exactly the same services.
"""

from __future__ import annotations

from datetime import datetime

from app.checks.confidence import probe_checks
from app.checks.maintenance import apply_maintenance
from app.checks.models import ServiceCheck
from app.checks.staleness import apply_staleness, staleness_for
from app.probe.registry import probe_registry


def overlay_checks(inst, base: list[ServiceCheck], settings, now: datetime) -> list[ServiceCheck]:  # noqa: ANN001 — inst: Instance, settings: Settings
    """Layer staleness + out-of-band probe + maintenance onto raw checks.

    ``agent_fresh`` (a push agent reporting within its threshold) feeds the
    confidence model so a box still pushing telemetry caps a failing probe at WARN,
    not CRIT.
    """
    s = staleness_for(inst, settings, now)
    checks = apply_staleness(base, s)
    checks += probe_checks(s is not None and not s.stale, probe_registry.get(inst.id))
    return apply_maintenance(checks, inst.maintenance)
