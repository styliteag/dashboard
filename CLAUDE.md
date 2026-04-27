# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

STYLiTE Orbit — multi-OPNsense firewall dashboard. Three deployable apps in one repo:

- `backend/` — FastAPI + async SQLAlchemy (Python 3.12)
- `frontend/` — React 18 + Vite + TypeScript (npm)
- `agent/` — WebSocket push-mode agent that runs **on OPNsense (FreeBSD)**

Not a monorepo — three independent apps orchestrated by `deploy/docker-compose.yml`.

## Commands (use `just`)

All workflows go through the `justfile`. Don't invent ad-hoc invocations — read `justfile` first if a recipe seems missing.

- Backend: `just backend-install` · `just backend-run` · `just backend-test` · `just backend-lint` · `just backend-fmt`
- Frontend: `just frontend-install` · `just frontend-dev` · `just frontend-build` · `just frontend-lint` · `just frontend-fmt`
- Stack: `just up` · `just down` · `just logs` · `just gen-key`

`backend-test` runs `pytest -q` against `backend/tests/`. There are **no frontend tests** — `just frontend-build` (which runs `tsc -b`) is the only frontend gate.

## Done-criteria for backend changes

Run all three before declaring a backend task done:

1. `just backend-lint` (ruff: `E,F,I,B,UP,SIM`, line-length 100, py312)
2. `just backend-test`
3. If any SQLAlchemy model in `backend/app/**` changed: a new Alembic revision must exist in `backend/alembic/versions/` (numbered `NNN_*.py`, sequential).

Migrations run automatically via `alembic upgrade head` in the container entrypoint — never call it manually inside dev workflows.

## Hard rules

- **Database is async-only.** Use `AsyncSession` + asyncpg. Never import the sync `Session`.
- **Settings prefix is `DASH_`** (pydantic-settings). All env vars and config keys use it; don't introduce another prefix.
- **OPNsense API secrets are encrypted at rest** with the Fernet helper in `backend/app/crypto/`. Never store, log, or return them in plaintext.
- **`agent/` runs on FreeBSD** (OPNsense base). Keep its dependencies minimal and avoid Linux-only assumptions (no `/proc` parsing, no glibc-specific calls, no systemd hooks).

## Frontend

TypeScript **strict mode** is enabled (`noUnusedLocals`, `noUnusedParameters` on). Path alias `@/*` → `src/*`. Three gates:

- `just frontend-build` — `tsc -b && vite build` (type-check + production bundle)
- `just frontend-lint` — ESLint flat config (`eslint.config.js`), React + react-hooks rules, prettier-aware
- `just frontend-fmt` — Prettier rewrite (config: `.prettierrc.json`, line width 100, double quotes, trailing commas)

The existing `src/` was never run through Prettier — first `just frontend-fmt` will rewrite ~20 files. Don't bundle that mass-format with an unrelated change.

## Required env (deploy/.env)

`DASH_MASTER_KEY` (generate with `just gen-key`), `DASH_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `DASH_DOMAIN`, `DASH_ENV`. See `deploy/.env.example` for the full list.

## CI

None yet. All checks are local via `just`.
