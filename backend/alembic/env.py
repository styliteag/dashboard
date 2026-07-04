"""Alembic environment — sync engine derived from the async DSN."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.config import get_settings
from app.db.base import Base

# Make sure all models are imported so Base.metadata is populated.
from app.db import models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Convert async DSN to sync (aiomysql -> pymysql) for Alembic.
settings = get_settings()
sync_url = settings.database_url.replace("+aiomysql", "+pymysql")
config.set_main_option("sqlalchemy.url", sync_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=sync_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        # Serialize concurrent upgrades: multi-replica deployments run
        # `alembic upgrade head` in every container at boot, and Alembic has no
        # built-in lock on MySQL — without this, replicas race the same revision
        # (e.g. two CREATE INDEX, loser dies with 1061 and crash-loops the task).
        # The advisory lock is released automatically when the connection closes;
        # the waiter re-reads alembic_version afterwards and no-ops.
        if connection.dialect.name == "mysql":
            locked = connection.exec_driver_sql(
                "SELECT GET_LOCK('orbit_alembic_upgrade', 600)"
            ).scalar()
            if not locked:
                raise RuntimeError("another migration run held the lock for >600s")
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
