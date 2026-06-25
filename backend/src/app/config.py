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

    # Polling
    poll_interval_seconds: int = 30
    poll_concurrency: int = 20

    # Agent push staleness: mark a push-mode instance offline if no metrics push
    # arrives within this many seconds (~4 missed 30s pushes). Generous enough to
    # tolerate the brief reconnect during a self-update restart.
    agent_stale_seconds: int = 120

    # Metrics maintenance (replaces TimescaleDB retention + continuous aggregate).
    metrics_retention_days: int = 30  # raw metrics kept this long
    metrics_5m_retention_days: int = 365  # 5-min rollup kept this long

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
