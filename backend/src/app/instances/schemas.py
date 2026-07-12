"""Pydantic schemas for the instances API.

The API never returns the API key/secret. On update, empty strings mean
"don't change" — only the fields the user actually re-typed are rotated.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.devices.capabilities import device_caps
from app.devices.types import DeviceType, Transport
from app.instances.slug import is_valid_slug


def _check_slug(value: str | None) -> str | None:
    """Reject a malformed user-supplied slug early (uniqueness is checked in the service)."""
    if value is None:
        return None
    if not is_valid_slug(value):
        raise ValueError(
            "slug must be a DNS label: lowercase a-z, 0-9, hyphen; "
            "no leading/trailing hyphen; 1-63 chars"
        )
    return value


def _check_ping_url(value: str | None) -> str | None:
    """Validate the optional out-of-band probe target.

    Accepts an empty string (→ None, "no probe"), a bare host/IP (ICMP only), or a
    full http(s) URL (ICMP to its host + HTTP-200 check). Anything with a scheme
    must be http(s); a non-empty value is length-bounded to the column.
    """
    if value is None:
        return None
    v = value.strip()
    if not v:
        return None
    if len(v) > 512:
        raise ValueError("ping_url too long (max 512 chars)")
    if "://" in v:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"invalid ping URL: {v!r}")
    return v


def _normalize_base_urls(value: str) -> str:
    """Validate a comma-separated list of http(s) URLs; return them ', '-joined.

    ``base_url`` may carry several clickable web-UI links (the first is also the
    API endpoint for direct/relay mode). Each entry must be a real http(s) URL.
    """
    urls = [u.strip() for u in value.split(",") if u.strip()]
    if not urls:
        raise ValueError("at least one base URL is required")
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"invalid URL: {url!r}")
    return ", ".join(urls)


class InstanceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    # Target group. Omit only when the creating user is member of exactly one
    # group (then that group is implied); must be one of the user's groups
    # (superadmins may target any existing group).
    group_id: int | None = None
    # Optional: omit to auto-derive a URL-safe slug from ``name`` (§18 GUI proxy).
    slug: str | None = Field(default=None, max_length=63)
    # Required for direct-API device types; push-only types (linux) have no
    # web UI/API and must omit it — see _apply_device_class_rules below.
    base_url: str | None = None
    # API key/secret are optional when using agent mode (agent collects data locally).
    api_key: str | None = None
    api_secret: str | None = None
    # Transport/device-type are the source of truth (see docs/agent-architecture.md).
    # ``agent_mode`` is kept as a back-compat input: when ``transport`` is omitted,
    # agent_mode=True maps to transport=push, else direct.
    transport: Transport | None = None
    device_type: DeviceType = DeviceType.OPNSENSE
    agent_mode: bool = False
    ca_bundle: str | None = None
    ssl_verify: bool = True
    # Browser terminal (root PTY) opt-in. Deliberately defaults ON for new
    # instances (operator request) — still inert unless the server-wide
    # DASH_SHELL_ENABLED gate is on too; both must be set (§22).
    shell_enabled: bool = True
    # "Open GUI" login replay (§18). Also defaults ON for new instances —
    # without an agent-side provisioned credential it degrades gracefully to
    # the plain login page, so the flag alone grants nothing.
    gui_login_enabled: bool = True
    # Per-instance poll/push cadence override (seconds). Omit/null = inherit the
    # global default. poll applies to direct-API devices, push to agent (push) mode.
    poll_interval_seconds: int | None = Field(default=None, ge=5, le=86400)
    push_interval_seconds: int | None = Field(default=None, ge=5, le=86400)
    # Securepoint SSH enrichment (opt-in): rich IPsec via `swanctl --raw`.
    ssh_enabled: bool = False
    ssh_port: int = 9922
    ssh_user: str = "root"
    ssh_key: str | None = None  # ed25519 private key (PEM); encrypted at rest
    location: str | None = None
    notes: str | None = None
    tags: list[str] | None = None
    # Optional out-of-band reachability probe target (URL or host); empty = none.
    ping_url: str | None = None

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, v: str | None) -> str | None:
        return _normalize_base_urls(v) if v is not None else None

    @field_validator("slug")
    @classmethod
    def _validate_slug(cls, v: str | None) -> str | None:
        return _check_slug(v)

    @field_validator("ping_url")
    @classmethod
    def _validate_ping_url(cls, v: str | None) -> str | None:
        return _check_ping_url(v)

    @model_validator(mode="after")
    def _apply_device_class_rules(self) -> InstanceCreate:
        """Enforce the capability contract at the API boundary (DR-9).

        Direct-API types keep requiring a base_url. Push-only types (linux)
        are the inverse: no base_url, transport forced to push, and the
        class default push cadence applied when the operator set none.
        """
        caps = device_caps(self.device_type)
        if caps.direct_api:
            if not self.base_url:
                raise ValueError("base_url is required for this device type")
            return self
        if self.base_url:
            raise ValueError(f"{self.device_type.value} instances have no base_url (push-only)")
        if self.transport not in (None, Transport.PUSH):
            raise ValueError(f"{self.device_type.value} instances are push-only")
        self.transport = Transport.PUSH
        self.base_url = ""
        if self.push_interval_seconds is None:
            self.push_interval_seconds = caps.default_push_interval
        return self


class InstanceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    # Stable across name edits → persistent GUI URL; change it explicitly here.
    slug: str | None = Field(default=None, max_length=63)
    base_url: str | None = None
    # Empty/omitted means "keep existing".
    api_key: str | None = None
    api_secret: str | None = None
    ca_bundle: str | None = None
    ssl_verify: bool | None = None
    gui_login_enabled: bool | None = None
    shell_enabled: bool | None = None
    # Send null to clear an override back to the global default; a number sets it;
    # omit to leave unchanged (the service distinguishes these via model_fields_set).
    poll_interval_seconds: int | None = Field(default=None, ge=5, le=86400)
    push_interval_seconds: int | None = Field(default=None, ge=5, le=86400)
    # Securepoint SSH enrichment. ssh_key empty/omitted means "keep existing".
    ssh_enabled: bool | None = None
    ssh_port: int | None = None
    ssh_user: str | None = None
    ssh_key: str | None = None
    location: str | None = None
    notes: str | None = None
    tags: list[str] | None = None
    # Empty string clears the probe target; omit to leave unchanged.
    ping_url: str | None = None
    # Maintenance flag (yellow ceiling). Admin-toggled; auto-cleared on recovery.
    maintenance: bool | None = None
    # Firmware update lock: blocks single-instance + bulk firmware updates.
    firmware_locked: bool | None = None

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, v: str | None) -> str | None:
        return _normalize_base_urls(v) if v is not None else None

    @field_validator("slug")
    @classmethod
    def _validate_slug(cls, v: str | None) -> str | None:
        return _check_slug(v)

    @field_validator("ping_url")
    @classmethod
    def _validate_ping_url(cls, v: str | None) -> str | None:
        return _check_ping_url(v)


class InstanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    group_id: int
    slug: str
    base_url: str
    ssl_verify: bool
    gui_login_enabled: bool
    shell_enabled: bool
    transport: str
    device_type: str
    agent_mode: bool
    # Raw nullable overrides (null = inherit global) so the UI can show inherit vs set.
    poll_interval_seconds: int | None = None
    push_interval_seconds: int | None = None
    ssh_enabled: bool
    ssh_port: int
    ssh_user: str
    ssh_key_set: bool  # whether a private key is stored (never returns the key itself)
    ssh_host_key_pinned: bool
    agent_last_seen: datetime | None
    location: str | None
    notes: str | None
    tags: list[str] | None
    last_success_at: datetime | None
    last_error_at: datetime | None
    last_error_message: str | None
    # Out-of-band probe target + maintenance ceiling (P2 availability).
    ping_url: str | None = None
    maintenance: bool = False
    firmware_locked: bool = False
    # Observed from the firewall (via agent push status): whether the "Password protect
    # the console menu" option (disableconsolemenu) is enabled. We want this OFF.
    # UI surfaces a non-alert warning when True on /instances and instance pages.
    console_password_protected: bool | None = None
    # Agent-staleness overlay (push mode): True once the agent has been silent past
    # its scaled threshold, so the UI can flag last-known sub-states as stale rather
    # than trust them as live. Always False for direct-poll instances.
    stale: bool = False
    stale_seconds: int | None = None
    created_at: datetime
    updated_at: datetime


def instance_response(inst, settings, now: datetime) -> InstanceResponse:  # noqa: ANN001
    """Serialize an instance, layering in the computed agent-staleness flags.

    Single source of truth for staleness is :func:`app.checks.staleness.staleness_for`
    — the same calc that drives the Checkmk ``agent`` service, so API and export agree.
    """
    # Imported lazily to avoid an import cycle (checks.staleness pulls in checks.models).
    from app.checks.staleness import staleness_for

    s = staleness_for(inst, settings, now)
    return InstanceResponse.model_validate(inst).model_copy(
        update={
            "stale": bool(s and s.stale),
            "stale_seconds": s.age_seconds if s else None,
        }
    )


class TestConnectionResponse(BaseModel):
    ok: bool
    status_code: int | None = None
    latency_ms: int | None = None
    error: str | None = None
