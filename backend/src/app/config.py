"""Application configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DASH_", env_file=".env", extra="ignore")

    # Service
    env: str = "dev"
    log_level: str = "info"

    # Reverse-proxy hops in front of the app. The client IP used for login/enroll
    # rate-limiting and audit is taken as the Nth-from-last entry of
    # X-Forwarded-For (each appended by a proxy we control); 0 = trust none and
    # use the direct peer.
    #
    # CRITICAL SECURITY SETTING (F2):
    #   Set to EXACTLY the number of trusted reverse proxies *you* operate.
    #   Too high lets an attacker prepend fake entries and spoof their IP,
    #   completely bypassing the login + enrollment brute-force rate limiter.
    #   Default (0) is the safe choice when there is no front proxy.
    #   Bundled compose sets 1 (its nginx). Add 1 for each additional proxy you control.
    trusted_proxy_hops: int = Field(
        default=0,
        ge=0,
        description="Exact number of trusted X-Forwarded-For hops (login rate limit + audit IP).",
    )

    # Database (async DSN, e.g. mysql+aiomysql://user:pass@host:3306/db)
    database_url: str = Field(
        default="mysql+aiomysql://dash:dash@db:3306/dash",
        description="SQLAlchemy async URL for MariaDB",
    )

    # Master key for Fernet encryption of OPNsense API secrets at rest.
    # Generate with: just gen-key
    master_key: str = Field(default="", description="Fernet master key (base64, 32 bytes)")

    # Initial admin password (used only on first start when no admin exists yet)
    admin_password: str = Field(default="", description="Initial admin password")

    # Polling. ``poll_interval_seconds`` is the *default* per-instance poll cadence
    # for direct-API devices; an instance may override it (instances.poll_interval_
    # seconds). The scheduler ticks every ``poll_tick_seconds`` and polls only the
    # instances whose own interval has elapsed — so a box can run faster *or* slower
    # than the default. The tick is the finest achievable resolution (floor).
    poll_interval_seconds: int = 30
    poll_tick_seconds: int = 10
    poll_concurrency: int = 20

    # Default per-instance agent push cadence, mirrored to the agent in the welcome
    # message (instances.push_interval_seconds overrides it). The agent applies it
    # live; on (re)connect it is re-sent.
    push_interval_seconds: int = 30

    # Agent push staleness floor: mark a push-mode instance offline if no metrics
    # push arrives for this long. The real per-instance threshold scales up with a
    # slower push interval (~4 missed pushes), so this is just the floor — generous
    # enough to tolerate the brief reconnect during a self-update restart.
    agent_stale_seconds: int = 120

    # Metrics maintenance (replaces TimescaleDB retention).
    metrics_retention_days: int = 30  # raw metrics kept this long
    # IPsec tunnel state-change history (VPN-overview popup); transition log is
    # tiny, so a longer window is cheap.
    ipsec_event_retention_days: int = 90
    # Service-check state-change history (alert/check history); transition log,
    # same rationale as the IPsec events.
    check_event_retention_days: int = 90

    # GUI proxy (optional): tunnel a firewall's web GUI through its agent, fronted
    # by a reverse proxy giving a per-instance origin (Caddy/port in dev, Traefik/
    # wildcard subdomain in prod). OFF by default — needs that proxy set up.
    gui_proxy_enabled: bool = False
    # Public origin template for the prod proxy; ``{slug}`` is the instance slug,
    # e.g. https://gui-{slug}.gui.example.com. Empty → dev per-port convention.
    gui_base_template: str = ""
    # Caddy admin /load endpoint the backend pushes the regenerated vhost map to
    # (prod, decision B). Empty → no hot-load (dev, or a statically-mounted file).
    gui_caddy_admin_url: str = ""
    # Close an instance's forwarder after this many idle minutes (0 = never).
    gui_idle_minutes: int = 15

    # Notifications (all optional)
    notify_webhook_url: str = ""
    notify_telegram_token: str = ""
    notify_telegram_chat_id: str = ""
    notify_ntfy_url: str = ""
    # Mattermost incoming-webhook URL (contains a secret token). Editable in the
    # Settings UI as a secret; env default here for first-boot/ops parity.
    notify_mattermost_url: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
