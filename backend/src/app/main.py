"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from cryptography.fernet import Fernet
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.agent_hub import gui_caddy
from app.agent_hub.gui_tunnel import gui_tunnels
from app.agent_hub.hub import hub
from app.agent_hub.routes import router as agent_router
from app.apikeys.routes import router as apikeys_router
from app.audit.routes import router as audit_router
from app.auth.bootstrap import ensure_admin
from app.auth.mfa_routes import router as mfa_router
from app.auth.routes import router as auth_router
from app.bulk.routes import router as bulk_router
from app.checks.routes import router as checks_router
from app.config import Settings, get_settings
from app.connectivity.routes import router as connectivity_router
from app.db.base import dispose_engine, get_sessionmaker
from app.firmware.routes import router as firmware_router
from app.http_log import AccessLogMiddleware
from app.instances.routes import router as instances_router
from app.ipsec.routes import router as ipsec_router
from app.llm.routes import router as llm_router
from app.logs.routes import router as logs_router
from app.logsetup import configure_logging
from app.metrics.routes import router as metrics_router
from app.poller.scheduler import start_scheduler, stop_scheduler
from app.routes import health
from app.selection.routes import router as selection_router
from app.selection.store import load_rules
from app.settings.routes import router as settings_router
from app.settings.store import effective_settings, load_overrides
from app.system.routes import router as system_router
from app.users.routes import router as users_router
from app.views.routes import router as views_router
from app.xsense.registry import registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    log = structlog.get_logger("app.lifespan")
    log.info("startup")

    # Load DB setting overrides into the runtime cache first, then re-apply the
    # ones read only at startup (log level) — create_app() configured logging from
    # the env default before the DB was reachable.
    try:
        async with get_sessionmaker()() as session:
            count = await load_overrides(session)
            rules = await load_rules(session)
        log.info("settings.loaded", overrides=count, selection_rules=rules)
    except Exception as exc:  # noqa: BLE001 — never block startup on settings load
        log.error("settings.load_failed", error=str(exc))
    eff = effective_settings()
    configure_logging(eff.log_level, eff.log_format)

    try:
        await ensure_admin()
    except Exception as exc:  # noqa: BLE001
        log.error("admin_bootstrap.failed", error=str(exc))

    # Re-hydrate the agent hub's live-status caches from the last persisted
    # snapshots so a backend restart doesn't blank the dashboard until the next push.
    try:
        restored = await hub.hydrate_from_db()
        log.info("hub.hydrated", instances=restored)
    except Exception as exc:  # noqa: BLE001 — never block startup on hydration
        log.error("hub.hydrate_failed", error=str(exc))

    # Start the background poller
    start_scheduler()

    # GUI-proxy forwarders are started on demand by POST /instances/{id}/gui/open
    # (each on a stable per-instance port); a reverse proxy (Caddy) fronts them to
    # give a per-instance origin + valid cert. The reaper closes ones idle past
    # DASH_GUI_IDLE_MINUTES.
    gui_tunnels.start_reaper(effective_settings().gui_idle_minutes)

    # Push the full GUI-proxy vhost map to Caddy (prod, decision B) so a fresh
    # Caddy container — booted from the empty bootstrap file — learns every live
    # instance's slug→port binding. No-op when the proxy is off. Never blocks boot.
    _settings = get_settings()
    if _settings.gui_proxy_enabled and not _settings.gui_caddy_admin_url:
        # Loud, actionable signal: the proxy is on but the push has nowhere to go —
        # Caddy stays on the empty bootstrap and every gui-<slug> host returns blank.
        log.warning(
            "gui_caddy.admin_url_unset",
            hint="set DASH_GUI_CADDY_ADMIN_URL=http://gui-proxy:2019/load",
        )
    try:
        async with get_sessionmaker()() as session:
            await gui_caddy.reconcile(session)
    except Exception as exc:  # noqa: BLE001
        log.error("gui_caddy.startup_reconcile_failed", error=str(exc))

    try:
        yield
    finally:
        log.info("shutdown")
        gui_tunnels.close_all()
        await stop_scheduler()
        await registry.close_all()
        await dispose_engine()


def _validate_security(settings: Settings) -> None:
    """Fail closed outside dev for critical security settings.

    - master_key: session cookies and GUI HMAC are derived from it.
    - trusted_proxy_hops: controls how much of X-Forwarded-For we trust for
      login/enroll rate limiting and audit source_ip. Too high = spoofing risk
      that disables the brute-force limiter.
    """
    # --- master key ---------------------------------------------------------
    if settings.env != "dev":
        try:
            Fernet((settings.master_key or "").encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                "DASH_MASTER_KEY must be a valid Fernet key when DASH_ENV is not 'dev' "
                "(generate one with `just gen-key`). Refusing to start with an "
                "insecure session key."
            ) from exc
    elif not settings.master_key:
        structlog.get_logger("app.security").warning(
            "master_key.unset_dev",
            hint="running with an insecure default session key — dev only, never in prod",
        )

    # --- trusted proxy hops (XFF trust for rate limits + audit) -------------
    hops = getattr(settings, "trusted_proxy_hops", 0)
    if hops > 3 and settings.env != "dev":
        raise RuntimeError(
            f"DASH_TRUSTED_PROXY_HOPS={hops} is too high for a non-dev environment. "
            "This value determines how many rightmost X-Forwarded-For entries are "
            "treated as trustworthy. Setting it higher than the actual number of "
            "proxies you control allows clients to spoof their source IP by "
            "prepending entries, bypassing the login and enrollment rate limiters "
            "entirely. Use the exact hop count (1 for the bundled nginx image; "
            "typically 2 when Traefik is also in front). Refusing to start."
        )
    if hops > 0:
        structlog.get_logger("app.security").info(
            "trusted_proxy_hops",
            hops=hops,
            env=settings.env,
            note="X-Forwarded-For: trusting the last N entries for rate-limiting and audit IP",
        )

    # --- WebAuthn / passkeys (RP id + origin) -------------------------------
    # Not fail-closed: a broken passkey setup still leaves TOTP as a valid second
    # factor, so we must not refuse startup. But the localhost defaults behind a
    # real domain make passkey *registration* fail with an opaque browser
    # SecurityError ("rp_id not a registrable suffix of <host>"), so surface it
    # loudly. WebAuthn also needs a secure (https) context outside localhost.
    if settings.env != "dev":
        origin = settings.webauthn_origin or ""
        if settings.webauthn_rp_id == "localhost" or "localhost" in origin:
            structlog.get_logger("app.security").warning(
                "webauthn.localhost_in_prod",
                rp_id=settings.webauthn_rp_id,
                origin=origin,
                hint="passkey registration will fail behind your domain — set "
                "DASH_WEBAUTHN_RP_ID to the public host (e.g. dash.example.com) and "
                "DASH_WEBAUTHN_ORIGIN to the exact https origin "
                "(e.g. https://dash.example.com), then restart. TOTP is unaffected.",
            )
        elif not origin.startswith("https://"):
            structlog.get_logger("app.security").warning(
                "webauthn.insecure_origin",
                origin=origin,
                hint="WebAuthn needs a secure (https) context outside localhost — "
                "passkeys will not work when DASH_WEBAUTHN_ORIGIN is not https.",
            )


def create_app() -> FastAPI:
    settings = get_settings()
    # Logging first: _validate_security emits warnings that must render through
    # the unified pipeline.
    configure_logging(settings.log_level, settings.log_format)
    _validate_security(settings)

    app = FastAPI(
        title="Orbit Dashboard",
        version="0.0.1",
        lifespan=lifespan,
    )

    # Same-site Strict trips up some embedded browsers (Cursor's preview) and
    # any setup where the SPA is reached on a different host than the cookie
    # was set on. In prod we still get good CSRF protection because the API
    # and the SPA are served from the same origin (nginx in the combined
    # image) — Lax is sufficient and avoids the edge cases.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.master_key or "dev-only-not-secret",
        session_cookie="dash_session",
        https_only=settings.env != "dev",
        same_site="lax",
        max_age=12 * 60 * 60,
    )

    # Added last ⇒ outermost: times the full stack and reads scope["session"]
    # (populated by the inner SessionMiddleware) when logging the request.
    app.add_middleware(AccessLogMiddleware)

    app.include_router(health.router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(mfa_router, prefix="/api")
    app.include_router(instances_router, prefix="/api")
    app.include_router(metrics_router, prefix="/api")
    app.include_router(ipsec_router, prefix="/api")
    app.include_router(firmware_router, prefix="/api")
    app.include_router(audit_router, prefix="/api")
    app.include_router(views_router, prefix="/api")
    app.include_router(system_router, prefix="/api")
    app.include_router(bulk_router, prefix="/api")
    app.include_router(agent_router, prefix="/api")
    app.include_router(checks_router, prefix="/api")
    app.include_router(connectivity_router, prefix="/api")
    app.include_router(apikeys_router, prefix="/api")
    app.include_router(settings_router, prefix="/api")
    app.include_router(users_router, prefix="/api")
    app.include_router(selection_router, prefix="/api")
    app.include_router(llm_router, prefix="/api")
    app.include_router(logs_router, prefix="/api")
    return app


app = create_app()
