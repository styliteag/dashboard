"""ORM models for Orbit Dashboard."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.devices.types import DeviceType, Transport


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    # Bumped on every password change to invalidate all existing sessions (US-1.2)
    password_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_admin: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    audit_entries: Mapped[list[AuditLog]] = relationship(back_populates="user")


class Instance(Base):
    __tablename__ = "instances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    # Encrypted with Fernet at rest. Stored as base64 token bytes.
    api_key_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    api_secret_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Optional pinned CA bundle in PEM format. NULL means use system trust store.
    ca_bundle: Mapped[str | None] = mapped_column(Text, nullable=True)
    # When False, skip TLS certificate verification (self-signed certs).
    ssl_verify: Mapped[bool] = mapped_column(default=True, nullable=False, server_default="true")
    # Transport: how the dashboard reaches this device (see docs/agent-architecture.md, DR-1).
    # direct = poll the API; push = agent pushes via the hub; relay = API through agent tunnel.
    transport: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=Transport.DIRECT.value,
        server_default=text("'direct'"),
    )
    # Device kind: opnsense | pfsense | proxmox | truenas | qnap.
    device_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=DeviceType.OPNSENSE.value,
        server_default=text("'opnsense'"),
    )
    agent_token: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    agent_last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # Health/poll status (updated by the poller)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Last-known live status snapshot (push mode): the hub's in-memory caches
    # serialized to JSON on every metrics push, so a backend restart doesn't blank
    # the dashboard until the next push (the hub re-hydrates from this at startup).
    status_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Soft-delete (US-2.3): keep historical metrics linked to a deleted instance.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    @property
    def agent_mode(self) -> bool:
        """Back-compat: True when push-mode (data arrives via the agent hub)."""
        return self.transport == Transport.PUSH.value


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Free-form action label, e.g. "auth.login", "instance.create", "ipsec.connect"
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(16), nullable=False)  # ok|error|denied
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[User | None] = relationship(back_populates="audit_entries")


class Metric(Base):
    """Time-series metric. Promoted to a Timescale hypertable in the migration."""

    __tablename__ = "metrics"

    # Composite PK so Timescale can chunk on ts.
    instance_id: Mapped[int] = mapped_column(
        ForeignKey("instances.id", ondelete="CASCADE"), primary_key=True
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    metric: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[float] = mapped_column(nullable=False)


class ApiKey(Base):
    """Read-only API key for service accounts (e.g. the Checkmk special agent).

    Stores only the SHA-256 of the token (the token is high-entropy random, so a
    fast hash is fine); the full token is shown once at creation.
    """

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(20), nullable=False)  # for display
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EnrollmentCode(Base):
    """One-time agent enrollment code (see §16 chunk C2).

    The admin mints a short-lived code for an instance; the agent exchanges it at
    /api/agent/enroll for that instance's agent_token. Single-use (used_at) and
    time-limited (expires_at). Only the SHA-256 of the code is stored.
    """

    __tablename__ = "enrollment_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    instance_id: Mapped[int] = mapped_column(
        ForeignKey("instances.id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
