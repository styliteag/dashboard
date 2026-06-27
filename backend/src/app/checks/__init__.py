"""Service-state evaluation: raw metrics → OK/WARN/CRIT per check.

One place that turns a device's status into pass/fail decisions, used by both
the dashboard (green/red) and the future Checkmk export (see
docs/agent-architecture.md §13). Thresholds are module constants for now;
making them configurable (global + per-instance) is a follow-up.
"""

from app.checks.evaluate import evaluate_checks
from app.checks.models import CheckState, PerfMetric, ServiceAlert, ServiceCheck

__all__ = ["CheckState", "PerfMetric", "ServiceAlert", "ServiceCheck", "evaluate_checks"]
