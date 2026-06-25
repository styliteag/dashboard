# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] - 2026-06-26

### Added

- **Multiple base URLs per instance** — the Base URL field accepts a comma-separated list; every entry renders as a clickable web-UI link (header + card views). The first URL is the API endpoint used for direct-mode polling.

### Changed

- **Mode-aware instance edit form** — agent-mode instances now hide the direct-API-only fields (API key/secret, Skip-SSL) and expose the GUI **Auto-login** toggle instead (moved here from the agent panel), matching the add-instance dialog.

## [1.1.0] - 2026-06-25

### Added

- **GUI auto-login** — opt-in per instance ("Auto-login" toggle on the agent's Firewall GUI card). When enabled, "Open GUI" replays the firewall's WebUI login through the agent and lands the browser already signed in instead of on the login page. The agent reuses the existing `orbit` user (no new dashboard-stored secret): on pfSense the relay password doubles as the WebUI password; on OPNsense the agent mints + caches a dedicated WebUI password. Verified end-to-end on OPNsense 26.1 and pfSense 2.8.

### Fixed

- Agent credential cache files (`*.apikey`, `*.guipw`) are now created mode 0600 from the start (no brief world-readable window before chmod).
- The generic `/agent/command` endpoint refuses internal actions and masks credential-bearing keys before writing command results to the audit log.

## [1.0.0] - 2026-06-25

### Added

- **pfSense support** alongside OPNsense — a platform-dispatch layer in the agent (shared collectors for CPU/mem/disk/interfaces/IPsec; per-platform gateways + firmware).
- **Push agent** (`agent/orbit_agent.py`, stdlib-only) for firewalls behind NAT: outbound `wss://…/api/ws/agent`, periodic metric pushes, FreeBSD `rc.d` service + supervisor.
- **Agent lifecycle** — one-time enrollment (trade a code for a token), dashboard-triggered self-update (Ed25519 signing tooling via `just sign-agent`; verification off by default), and uninstall.
- **Relay** — the dashboard tunnels HTTP to a box's own REST API over the agent WebSocket, so it stays keyless; local API port auto-discovered from `config.xml`.
- **Checkmk/OMD export** — `/api/export/checkmk` + a special-agent plugin (`checkmk/`): one piggyback host per firewall with OK/WARN/CRIT service checks.
- **Service checks** — per-service OK/WARN/CRIT evaluation and a `/api/checks` endpoint.
- **Read-only API keys** for service accounts (hashed at rest, non-GET rejected) — used by the Checkmk integration.
- **Bulk actions + CSV export** across multiple instances (`firmware_check`, `ipsec_restart`).
- **Metrics retention + 5-minute rollup** scheduler jobs (replacing TimescaleDB) and derived interface throughput rates.
- **Notifications** via webhook, Telegram, and ntfy.
- Last-known status persistence so a backend restart re-hydrates the dashboard before the next push.

### Changed

- **Rebranded** to STYLiTE Orbit (agent → `orbit`, backend package `app.opnsense` → `app.xsense`).
- **Database switched from PostgreSQL/TimescaleDB to MariaDB 11** (`mysql+aiomysql`).

## [0.10.0] - 2026-04-27

## [0.9.0] - 2026-04-27

## [0.1.3] - 2026-04-27

## [0.1.2] - 2026-04-27

## [0.1.1] - 2026-04-27

## [0.1.0] - 2026-04-27

### Added

- Initial release pipeline. Combined production container (frontend + backend served by nginx on :80, uvicorn on :8000 internally). Split dev compose with bind-mounted source for hot-reload. Backend migrated to `uv` + `src/` layout. `release.sh` for `major|minor|patch` version bumps. GitHub Actions workflow publishes multi-arch images to Docker Hub and GHCR on tag push.
