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

    # Database (async DSN, e.g. postgresql+asyncpg://user:pass@host:5432/db)
    database_url: str = Field(
        default="postgresql+asyncpg://dash:dash@db:5432/dash",
        description="SQLAlchemy async URL for Postgres/Timescale",
    )

    # Master key for Fernet encryption of OPNsense API secrets at rest.
    # Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
    master_key: str = Field(default="", description="Fernet master key (base64, 32 bytes)")

    # Initial admin password (used only on first start when no admin exists yet)
    admin_password: str = Field(default="", description="Initial admin password")

    # Polling
    poll_interval_seconds: int = 30
    poll_concurrency: int = 20

    # Notifications (all optional)
    notify_webhook_url: str = ""
    notify_telegram_token: str = ""
    notify_telegram_chat_id: str = ""
    notify_ntfy_url: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
