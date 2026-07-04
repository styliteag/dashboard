# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

STYLiTE Orbit — multi-firewall dashboard (OPNsense, pfSense, Securepoint UTM). Three deployable apps in one repo:

- `backend/` — FastAPI + async SQLAlchemy on **MariaDB** (Python 3.12)
- `frontend/` — React 18 + Vite + TypeScript (npm)
- `agent/` — stdlib-only WebSocket push agent that runs **on OPNsense/pfSense (FreeBSD)**; also does relay tunneling, dashboard-triggered self-update, enrollment, and uninstall

Not a monorepo — three independent apps orchestrated by `compose.yml` (production, single combined image) or `compose-dev.yml` (development, backend + frontend split with src bind mounts). Two more stdlib-only sidecars live alongside: `checkmk/` (special-agent plugin pulling `/api/export/checkmk`) and `scripts/sign_agent.py` (Ed25519 signing for agent self-update).

## Commands (use `just`)

All workflows go through the `justfile`. Don't invent ad-hoc invocations — read `justfile` first if a recipe seems missing.

- Backend: `just backend-install` · `just backend-run` · `just backend-test` · `just backend-lint` · `just backend-fmt`
- Agent / sidecars: `just agent-test` · `just checkmk-test` · `just sign-agent` (needs the offline Ed25519 key)
- Frontend: `just frontend-install` · `just frontend-dev` · `just frontend-build` · `just frontend-lint` · `just frontend-fmt`
- Prod stack: `just up` · `just down` · `just logs`
- Dev stack: `just dev-up` · `just dev-down` · `just dev-logs`
- Release: `just release patch|minor|major` (bumps `VERSION`, promotes the `CHANGELOG.md` `[Unreleased]` section, tags, pushes — CI publishes image to Docker Hub + GHCR). See [CHANGELOG](#changelog) — release does **not** generate entries.
- Misc: `just gen-key`

`backend-test` runs `pytest -q` against `backend/tests/`. There are **no frontend tests** — `just frontend-build` (which runs `tsc -b`) is the only frontend gate.

## Done-criteria for backend changes

Run all three before declaring a backend task done:

1. `just backend-lint` (ruff: `E,F,I,B,UP,SIM`, line-length 100, py312)
2. `just backend-test`
3. If any SQLAlchemy model in `backend/src/app/**` changed: a new Alembic revision must exist in `backend/alembic/versions/` (numbered `NNN_*.py`, sequential).

Migrations run automatically via `alembic upgrade head` in `docker/start.sh` (combined prod container) and in the dev backend's `Dockerfile.dev` CMD — never call it manually inside dev workflows.

## Done-criteria for agent changes

When you touch `agent/orbit_agent.py`: **bump `__version__`** (self-update gates on a version diff — an unchanged version means the fix never deploys to a box) and run `just agent-test`. Likewise run `just checkmk-test` after any `checkmk/` change.

- **The agent must run on Python 3.8.** Older pfSense boxes (2.6/2.7-era, FreeBSD) ship Python 3.8 — newer OPNsense/pfSense run 3.11, so a 3.9+ feature passes every test box yet silently bricks the old ones on self-update. Before declaring an agent change done, scan for **runtime** 3.9+ APIs: `str.removeprefix`/`removesuffix` (3.9), `dict |` merge (3.9), `math.lcm`/`isqrt`, `int.bit_count` (3.10), `match`/`case` (3.10), `zoneinfo`/`graphlib`, `functools.cache`. The file has `from __future__ import annotations`, so `list[dict]` / `X | None` **annotations** are fine (stored as strings, never evaluated) — only real *calls/statements* break. Past incident: `str.removesuffix()` in the cert collector took a 3.8 pfSense agent permanently silent ("agent silent for >120s"). If you can't test on a 3.8 box, `python3.8 -W error -c "import ast,sys; ast.parse(open('agent/orbit_agent.py').read())"` catches syntax-level breaks at least.

## CHANGELOG

`CHANGELOG.md` is kept and follows [Keep a Changelog](https://keepachangelog.com/) + SemVer. For any user-visible change, add a bullet under `## [Unreleased]` (`### Added` / `Changed` / `Fixed` / `Removed` …) **as part of the same change** — don't leave it for later.

`just release` (via `release.sh`) only **promotes** `[Unreleased]` to a dated `[X.Y.Z]` section and opens a fresh empty `[Unreleased]`; it does **not** read git history or generate entries. An empty `[Unreleased]` ships empty release notes. Never delete the file or hand-edit already-released sections.

## Hard rules

- **Database is MariaDB, async-only.** Use `AsyncSession` + `aiomysql` (`mysql+aiomysql://`). Never import the sync `Session`, and don't reach for Postgres/TimescaleDB-isms — metrics retention + the 5-min rollup are plain scheduler jobs (`backend/src/app/maintenance/`), use MariaDB equivalents.
- **Settings prefix is `DASH_`** (pydantic-settings). All env vars and config keys use it; don't introduce another prefix.
- **OPNsense API secrets are encrypted at rest** with the Fernet helper in `backend/src/app/crypto/`. Never store, log, or return them in plaintext.
- **`agent/` runs on FreeBSD** (OPNsense/pfSense base). Keep its dependencies minimal and avoid Linux-only assumptions (no `/proc` parsing, no glibc-specific calls, no systemd hooks).
- **Every user-facing instance query is group-scoped.** Apply `scope_clause(principal)` (list/aggregate queries) or `can_access(principal, inst)` (by-id fetches) from `backend/src/app/auth/scope.py` — new endpoints that return instance data without one of these leak across groups. Two invariants, never "simplify" them: a **User** with zero group memberships sees NOTHING, an **ApiKey** with zero bindings is GLOBAL (keys predate groups); and **superadmin grants rights management only, no instance access** — there is no superadmin bypass in scoping.

## Frontend

TypeScript **strict mode** is enabled (`noUnusedLocals`, `noUnusedParameters` on). Path alias `@/*` → `src/*`. Three gates:

- `just frontend-build` — `tsc -b && vite build` (type-check + production bundle)
- `just frontend-lint` — ESLint flat config (`eslint.config.js`), React + react-hooks rules, prettier-aware
- `just frontend-fmt` — Prettier rewrite (config: `.prettierrc.json`, line width 100, double quotes, trailing commas)

`src/` is Prettier-formatted (initial mass-format 2026-07-04) — `just frontend-fmt` should only touch files you changed. Don't bundle format-only rewrites of unrelated files into a feature commit.

## Logs pipeline (agent → UI)

The agent pushes the box's important logs **hourly** (`collect_logfiles`, 250 KB per log / 1 MB total). `app/logs/store.py` keeps the newest **3 snapshots** per `(instance, name)` in `logfiles` and, on every ingest, re-extracts critical lines into `log_events` (one row per normalized message pattern, per-`(instance, log)` replace — idempotent, no history beyond the snapshot window). The extraction rules live in `app/logs/events.py` and are **calibrated against real prod data**: syslog `<PRI>` severity where present (OPNsense + most pfSense), curated patterns for PRI-less BSD lines, and a hardcoded noise list (dpinger `sendto error`, filterdns `failed to resolve` — steady-state on half the fleet). Real fleets have **zero sev≤2 lines** — don't make crit-only the default anywhere. Raw snapshot content is admin-only viewable; the LLM analysis path must only ever send the **anonymized** text (`app/llm/anonymize`).

## Required env (`.env` at repo root)

`DASH_MASTER_KEY` (generate with `just gen-key`), `DASH_ADMIN_PASSWORD`, `DASH_SUPERADMIN_PASSWORD` (seeds the rights-management account), the MariaDB vars `DB_PASSWORD` / `DB_ROOT_PASSWORD` (and optionally `DB_USER` / `DB_NAME`), and `DASH_ENV`. Note the DB vars are **un-prefixed** — they're consumed by the MariaDB container and composed into `DASH_DATABASE_URL` in compose; only the app's own settings use the `DASH_` prefix. See `.env.example` for the full list. Both `compose.yml` and `compose-dev.yml` read this file via Docker Compose's default `.env` loader.

## CI

`.github/workflows/release.yml` triggers on `*.*.*` tags (created by `./release.sh` / `just release`). Builds multi-arch (`linux/amd64,linux/arm64`) and publishes to `docker.io/styliteag/dashboard` and `ghcr.io/styliteag/dashboard`. No CI runs on push to `main` — local `just backend-test` + `just frontend-build` are the gates.


@CLAUDE.local.md