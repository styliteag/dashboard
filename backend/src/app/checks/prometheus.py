"""Prometheus text exposition (format 0.0.4) of the evaluated service checks.

Rendered by ``GET /api/export/prometheus`` — the Grafana/Prometheus sibling of
the Checkmk export. Unlike Checkmk there is no selection filtering and no
aggregation: every evaluated check becomes a series and consumers filter in
PromQL. ``state`` keeps the Checkmk convention (0=OK, 1=WARN, 2=CRIT,
3=UNKNOWN) so both exports read the same.
"""

from __future__ import annotations

from app.checks.models import ServiceCheck

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# Family → HELP text. Emission order is fixed; empty families are skipped.
_HELP = {
    "orbit_instance_info": "Instance metadata; value is always 1",
    "orbit_check_state": "Evaluated check state: 0=OK, 1=WARN, 2=CRIT, 3=UNKNOWN",
    "orbit_check_metric": "Performance value of an evaluated check",
    "orbit_check_metric_warn": "WARN threshold of the corresponding orbit_check_metric",
    "orbit_check_metric_crit": "CRIT threshold of the corresponding orbit_check_metric",
}


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt(value: float) -> str:
    # repr() keeps full float precision; integral values drop the ".0" — never
    # scientific notation for counters like uptime seconds or byte totals.
    v = float(value)
    return str(int(v)) if v.is_integer() else repr(v)


def _sample(name: str, labels: list[tuple[str, str]], value: float) -> str:
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in labels)
    return f"{name}{{{inner}}} {_fmt(value)}"


def render_prometheus(rows: list[tuple[object, list[ServiceCheck]]]) -> str:
    """Render (instance, evaluated checks) pairs as Prometheus text format.

    ``instance`` is duck-typed (id, name, device_type, agent_mode) so tests can
    pass plain namespaces. Labels avoid the reserved ``instance`` name — the
    scraper would rename it to ``exported_instance``.
    """
    families: dict[str, list[str]] = {name: [] for name in _HELP}
    for inst, checks in rows:
        base = [("instance_id", str(inst.id)), ("instance_name", inst.name)]
        info_labels = [
            *base,
            ("device_type", inst.device_type or ""),
            ("mode", "push" if inst.agent_mode else "poll"),
        ]
        families["orbit_instance_info"].append(_sample("orbit_instance_info", info_labels, 1))
        for check in checks:
            key_labels = [*base, ("key", check.key)]
            families["orbit_check_state"].append(
                _sample("orbit_check_state", key_labels, check.state)
            )
            for m in check.metrics:
                labels = [*key_labels, ("metric", m.name), ("unit", m.unit)]
                families["orbit_check_metric"].append(
                    _sample("orbit_check_metric", labels, m.value)
                )
                if m.warn is not None:
                    families["orbit_check_metric_warn"].append(
                        _sample("orbit_check_metric_warn", labels, m.warn)
                    )
                if m.crit is not None:
                    families["orbit_check_metric_crit"].append(
                        _sample("orbit_check_metric_crit", labels, m.crit)
                    )

    lines: list[str] = []
    for name, samples in families.items():
        if not samples:
            continue
        lines.append(f"# HELP {name} {_HELP[name]}")
        lines.append(f"# TYPE {name} gauge")
        lines.extend(samples)
    return "\n".join(lines) + "\n" if lines else ""
