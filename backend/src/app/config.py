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
    log_format: str = "console"  # "console" (human-readable key=value) | "json"

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

    # DB connection pool. SQLAlchemy's default (5 + 10 overflow) starved with ~60
    # push agents: one slow writer (e.g. the hourly prune) queued every metrics
    # INSERT, exhausted the 15 connections and 500ed the whole API for its duration.
    # Keep pool_size + max_overflow well below MariaDB's max_connections (151 default).
    db_pool_size: int = 20
    db_max_overflow: int = 30

    # Master key for Fernet encryption of OPNsense API secrets at rest.
    # Generate with: just gen-key
    master_key: str = Field(default="", description="Fernet master key (base64, 32 bytes)")

    # Initial admin password (used only on first start when no admin exists yet)
    admin_password: str = Field(default="", description="Initial admin password")
    # Bootstrap-admin lifecycle (see app.auth.bootstrap). Three values:
    #   "auto" (default) — disable the seed admin automatically once another admin
    #                      exists; re-enable it when none remains.
    #   "0"              — force the seed admin ENABLED (manual break-glass / keep on).
    #   "1"              — force the seed admin DISABLED.
    admin_disabled: str = Field(default="auto", description="Bootstrap admin: auto|0|1")
    # Initial superadmin password (seed account "superadmin", rights management
    # only). Same lifecycle as the bootstrap admin: auto-retired once a real
    # superadmin exists (see app.auth.bootstrap).
    superadmin_password: str = Field(default="", description="Initial superadmin password")
    superadmin_disabled: str = Field(default="auto", description="Bootstrap superadmin: auto|0|1")
    # Issuer label shown in the user's authenticator app for TOTP enrollment.
    mfa_issuer: str = Field(default="Orbit Dashboard", description="TOTP issuer label")
    # WebAuthn / passkeys. ``rp_id`` is the registrable domain (no scheme/port);
    # ``origin`` is the EXACT scheme+host+port the browser shows. Dev defaults match
    # the Vite dev server (which proxies /api). In prod set both to the real domain,
    # e.g. DASH_WEBAUTHN_RP_ID=dash.example.com,
    # DASH_WEBAUTHN_ORIGIN=https://dash.example.com — a mismatch silently refuses.
    webauthn_rp_id: str = Field(default="localhost", description="WebAuthn relying-party id")
    webauthn_rp_name: str = Field(default="Orbit Dashboard", description="WebAuthn RP name")
    webauthn_origin: str = Field(
        default="http://localhost:5173", description="WebAuthn expected origin"
    )

    # --- GeoIP access restriction (docs/geoip-access-restriction.md) ---
    # Emergency kill switch: True disables ALL GeoIP enforcement regardless of the
    # DB config — the rescue hatch when a bad country list / whitelist locks
    # everyone out. Deliberately env-only (container restart applies it), never
    # editable via the UI: a UI toggle would be unreachable while locked out.
    geoip_disable: bool = False
    # MaxMind credentials for the weekly GeoLite2-Country auto-download job
    # (download.maxmind.com uses HTTP basic auth: account id + license key).
    # Either empty = the job stays idle; mount/update the mmdb manually instead.
    maxmind_account_id: str = Field(default="", description="MaxMind account id")
    maxmind_license_key: str = Field(default="", description="MaxMind GeoLite2 license key")
    # Path of the GeoLite2-Country database inside the container (volume-backed
    # so a downloaded update survives restarts).
    geoip_db_path: str = "/data/geoip/GeoLite2-Country.mmdb"

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
    # enough to tolerate the brief reconnect during a backend restart or self-update
    # (120s proved too tight in practice: a backend restart alone flapped every
    # connected agent to offline/back-online within the same minute).
    agent_stale_seconds: int = 300

    # Out-of-band reachability probe (instances.ping_url, opt-in per instance). The
    # probe job runs every ``probe_interval_seconds``; an axis (ICMP/HTTP) only flips
    # to *down* after ``probe_fail_threshold`` consecutive failures (flap protection,
    # so a single dropped packet or backend network blip can't red a box).
    probe_interval_seconds: int = 60
    probe_fail_threshold: int = 3

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

    # Interactive shell (SPIKE, see docs/agent-architecture.md §22): a browser
    # terminal to a root PTY on the firewall, tunneled through the agent WS. This
    # is arbitrary root RCE on the box — OFF by default and the ONLY server-side
    # gate; when false the backend never opens a shell stream to the agent.
    shell_enabled: bool = False
    # Extra hostnames (comma-separated) allowed as the Origin of a shell/GUI-tunnel
    # WebSocket handshake, on top of the WebAuthn origin's host. localhost/127.0.0.1
    # are always allowed (dev). Blocks cross-site WS hijack from the same-eTLD+1
    # firewall GUI-proxy subdomains (gui-<slug>.…).
    ws_allowed_origin_hosts: str = ""
    # When set, the backend records each terminal session's I/O to a capped file in
    # this directory (forensics). Empty = no recording. Files hold plaintext root
    # session data — point this at an access-controlled, retained volume.
    shell_record_dir: str = ""

    # Notifications (all optional). Three channels — Mattermost, Telegram, Email —
    # all editable (and overridable) in the Settings UI; env defaults here for
    # first-boot/ops parity. Per-channel service selection lives in the
    # ``selection_rules`` table (see app.selection).
    # Mattermost incoming-webhook URL (contains a secret token; stored encrypted).
    notify_mattermost_url: str = ""
    # Telegram bot token (secret) + target chat id. Configured when both are set.
    notify_telegram_token: str = ""
    notify_telegram_chat_id: str = ""
    # Email (SMTP). Editable in the Settings UI; the password is a secret. Email is
    # "configured" (and attempted) only when host, from and to are all set.
    notify_email_smtp_host: str = ""
    notify_email_smtp_port: int = 587
    notify_email_security: str = "starttls"  # "starttls" | "ssl" | "none"
    notify_email_from: str = ""
    notify_email_to: str = ""  # comma/space-separated recipients
    notify_email_username: str = ""
    notify_email_password: str = ""

    # Temporary per-channel mute + Checkmk blackout (Settings UI, group "Maintenance").
    # Manual on/off toggles: a muted channel is skipped for real alerts (explicit
    # "Send test" still fires); checkmk_blackout makes the export return no instances
    # so Checkmk sees every service go stale/gone. Runtime overrides via app_settings.
    notify_mattermost_muted: bool = False
    notify_telegram_muted: bool = False
    notify_email_muted: bool = False
    checkmk_blackout: bool = False
    # Collapse high-fan-out checks (certs, IPsec tunnels, services, …) into one
    # aggregate service per category in the Checkmk export, so a box shows a handful
    # of services instead of hundreds. On by default; turn off for per-item services.
    checkmk_aggregate: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
