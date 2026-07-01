"""Whitelist of editable settings + value coercion — pure, DB-free.

Only keys listed here can be overridden via the Settings page. Infra/security
settings (``database_url``, ``master_key``, ``env``, ``trusted_proxy_hops``,
``gui_caddy_admin_url``, ``admin_password``) are intentionally absent — they stay
env-only. ``restart_required`` marks settings read only at process startup (the
override applies on the next restart).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.llm.providers import (
    PROVIDERS,
    api_key_setting,
    base_url_setting,
    model_setting,
)


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
    # Keys whose default does NOT come from a ``Settings`` field (e.g. LLM provider
    # base URLs / models) carry it here, so ``Settings`` needs no extra fields.
    default: str | None = None


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
    # --- Notification channels. One ``group`` per channel so the Settings UI can
    # render a tab each (Mattermost / Telegram / Email). Which alert categories
    # each channel receives is a separate per-channel routing table.
    SettingDef(
        "notify_mattermost_url",
        "str",
        "Webhook URL",
        "Mattermost",
        help="Incoming-webhook URL of a Mattermost channel. Stored encrypted.",
        is_secret=True,
    ),
    SettingDef(
        "notify_telegram_token",
        "str",
        "Bot token",
        "Telegram",
        help="Telegram bot API token. Stored encrypted. Telegram is used only when "
        "both token and chat ID are set.",
        is_secret=True,
    ),
    SettingDef(
        "notify_telegram_chat_id",
        "str",
        "Chat ID",
        "Telegram",
        help="Target chat/channel ID the bot posts to.",
    ),
    SettingDef(
        "notify_email_smtp_host",
        "str",
        "SMTP host",
        "Email",
        help="SMTP server hostname. Email is used only when host, from and to are all set.",
    ),
    SettingDef(
        "notify_email_smtp_port",
        "int",
        "SMTP port",
        "Email",
        help="SMTP server port (587 for STARTTLS, 465 for implicit TLS, 25 for none).",
        min=1,
        max=65535,
    ),
    SettingDef(
        "notify_email_security",
        "str",
        "Transport security",
        "Email",
        help="STARTTLS (587), implicit TLS/SSL (465) or none (plaintext, 25).",
        options=("starttls", "ssl", "none"),
    ),
    SettingDef(
        "notify_email_from",
        "str",
        "From address",
        "Email",
        help="Envelope/From sender address for alert emails.",
    ),
    SettingDef(
        "notify_email_to",
        "str",
        "Recipients",
        "Email",
        help="One or more recipient addresses, comma- or space-separated.",
    ),
    SettingDef(
        "notify_email_username",
        "str",
        "SMTP username",
        "Email",
        help="SMTP auth username. Leave empty for an unauthenticated relay.",
    ),
    SettingDef(
        "notify_email_password",
        "str",
        "SMTP password",
        "Email",
        help="SMTP auth password. Stored encrypted.",
        is_secret=True,
    ),
    # --- Temporary mute / maintenance. Manual on/off toggles rendered as switches
    # by the Settings UI (not the generic key/value list). A muted channel is
    # skipped for real alerts; an explicit "Send test" still fires. Blackout empties
    # the Checkmk export so every service goes stale/gone during maintenance.
    SettingDef(
        "notify_mattermost_muted",
        "bool",
        "Mute Mattermost alerts",
        "Maintenance",
        help="Pause Mattermost alert delivery. Real alerts are skipped while muted; "
        "an explicit Send test still fires. Toggle off to resume.",
    ),
    SettingDef(
        "notify_telegram_muted",
        "bool",
        "Mute Telegram alerts",
        "Maintenance",
        help="Pause Telegram alert delivery. Real alerts are skipped while muted; "
        "an explicit Send test still fires. Toggle off to resume.",
    ),
    SettingDef(
        "notify_email_muted",
        "bool",
        "Mute Email alerts",
        "Maintenance",
        help="Pause Email alert delivery. Real alerts are skipped while muted; "
        "an explicit Send test still fires. Toggle off to resume.",
    ),
    SettingDef(
        "checkmk_blackout",
        "bool",
        "Checkmk blackout",
        "Maintenance",
        help="Return an empty Checkmk export so every service goes stale/gone. Use "
        "during maintenance to suppress Checkmk alerting. Toggle off to resume.",
    ),
)


def _llm_defs() -> tuple[SettingDef, ...]:
    """One API-key (secret) + base-URL + model setting per LLM provider, grouped
    under ``LLM`` so the Settings UI renders them on a single AI tab. Defaults come
    from the provider catalog, not env, so ``Settings`` needs no extra fields."""
    defs: list[SettingDef] = []
    for p in PROVIDERS:
        defs.append(
            SettingDef(
                api_key_setting(p.id),
                "str",
                f"{p.label} API key",
                "LLM",
                help=f"{p.label} API key. Stored encrypted; used only for the AI log analysis.",
                is_secret=True,
                default="",
            )
        )
        defs.append(
            SettingDef(
                base_url_setting(p.id),
                "str",
                f"{p.label} base URL",
                "LLM",
                help="Override the API base URL (e.g. a proxy or self-hosted, "
                "OpenAI-compatible endpoint).",
                default=p.default_base_url,
            )
        )
        defs.append(
            SettingDef(
                model_setting(p.id),
                "str",
                f"{p.label} model",
                "LLM",
                help="Model id used for analysis requests.",
                default=p.default_model,
            )
        )
    return tuple(defs)


EDITABLE: dict[str, SettingDef] = {d.key: d for d in (*_DEFS, *_llm_defs())}


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
