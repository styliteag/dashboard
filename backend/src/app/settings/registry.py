"""Whitelist of editable settings + value coercion — pure, DB-free.

Only keys listed here can be overridden via the Settings page. Infra/security
settings (``database_url``, ``master_key``, ``env``, ``trusted_proxy_hops``,
``gui_caddy_admin_url``, ``admin_password``) are intentionally absent — they stay
env-only. ``restart_required`` marks settings read only at process startup (the
override applies on the next restart).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SettingDef:
    key: str
    type: str  # "int" | "str" | "bool"
    label: str
    group: str
    help: str = ""
    restart_required: bool = False
    is_secret: bool = False
    min: int | None = None
    max: int | None = None
    options: tuple[str, ...] | None = None


_DEFS: tuple[SettingDef, ...] = (
    SettingDef(
        "poll_interval_seconds",
        "int",
        "Default poll interval",
        "Polling",
        help="Default per-instance poll cadence for direct-API devices (seconds). "
        "Instances can override it.",
        min=5,
        max=86400,
    ),
    SettingDef(
        "poll_tick_seconds",
        "int",
        "Scheduler tick",
        "Polling",
        help="How often the poller wakes to check which instances are due (seconds). "
        "Finest achievable poll resolution.",
        min=1,
        max=3600,
        restart_required=True,
    ),
    SettingDef(
        "poll_concurrency",
        "int",
        "Poll concurrency",
        "Polling",
        help="Max instances polled in parallel per tick.",
        min=1,
        max=200,
    ),
    SettingDef(
        "push_interval_seconds",
        "int",
        "Default agent push interval",
        "Polling",
        help="Default agent push cadence (seconds), mirrored to the agent. "
        "Instances can override it.",
        min=5,
        max=86400,
    ),
    SettingDef(
        "agent_stale_seconds",
        "int",
        "Agent offline floor",
        "Polling",
        help="Floor for marking a push-mode instance offline when no push arrives "
        "(seconds). The real threshold scales up with a slower push interval.",
        min=30,
        max=86400,
    ),
    SettingDef(
        "metrics_retention_days",
        "int",
        "Metrics retention",
        "Retention",
        help="Raw metrics are pruned after this many days.",
        min=1,
        max=3650,
    ),
    SettingDef(
        "ipsec_event_retention_days",
        "int",
        "IPsec event retention",
        "Retention",
        help="IPsec tunnel state-change history kept this many days.",
        min=1,
        max=3650,
    ),
    SettingDef(
        "check_event_retention_days",
        "int",
        "Check event retention",
        "Retention",
        help="Service-check state-change history kept this many days.",
        min=1,
        max=3650,
    ),
    SettingDef(
        "gui_idle_minutes",
        "int",
        "GUI proxy idle close",
        "GUI proxy",
        help="Close an idle GUI-proxy forwarder after this many minutes (0 = never).",
        min=0,
        max=1440,
        restart_required=True,
    ),
    SettingDef(
        "log_level",
        "str",
        "Log level",
        "Service",
        help="Backend log verbosity.",
        options=("debug", "info", "warning", "error"),
        restart_required=True,
    ),
    SettingDef(
        "notify_mattermost_url",
        "str",
        "Mattermost webhook URL",
        "Notifications",
        help="Incoming-webhook URL of a Mattermost channel. Alerts (instance "
        "up/down) are posted here. Stored encrypted.",
        is_secret=True,
    ),
)

EDITABLE: dict[str, SettingDef] = {d.key: d for d in _DEFS}


def coerce_value(defn: SettingDef, raw: str) -> int | str | bool:
    """Parse + validate a raw string against a setting's type/range/options.

    Raises ``ValueError`` with a human message on anything invalid.
    """
    if defn.type == "int":
        try:
            value = int(str(raw).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{defn.key} must be an integer") from exc
        if defn.min is not None and value < defn.min:
            raise ValueError(f"{defn.key} must be ≥ {defn.min}")
        if defn.max is not None and value > defn.max:
            raise ValueError(f"{defn.key} must be ≤ {defn.max}")
        return value
    if defn.type == "bool":
        s = str(raw).strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off"):
            return False
        raise ValueError(f"{defn.key} must be a boolean")
    # str
    s = str(raw)
    if defn.options is not None and s not in defn.options:
        raise ValueError(f"{defn.key} must be one of {', '.join(defn.options)}")
    return s


def to_storage(defn: SettingDef, raw: str) -> str:
    """Validate then return the canonical string to persist."""
    return str(coerce_value(defn, raw))
