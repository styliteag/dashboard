# STYLiTE Orbit dashboard

Central dashboard for managing multiple OPNsense firewalls.

## Status

Skeleton. The stack boots and the frontend renders the backend `/api/health` response. No
features beyond that yet — all user stories are tracked as GitHub issues, see the
[project board](https://github.com/users/rw-sty/projects/1).

## Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic, httpx, APScheduler
- **Frontend:** React + TypeScript, Vite, Tailwind, TanStack Query
- **Database:** PostgreSQL 16 + TimescaleDB extension
- **Reverse proxy:** Caddy (auto-TLS)
- **Deployment:** Docker Compose

## Quickstart

Prerequisites: Docker, Docker Compose, and (optionally) [`just`](https://github.com/casey/just).

```bash
# 1. Configure secrets
cp deploy/.env.example deploy/.env
just gen-key            # paste output into DASH_MASTER_KEY in deploy/.env
# also set POSTGRES_PASSWORD and DASH_ADMIN_PASSWORD

# 2. Start the stack
just up                 # or: docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build

# 3. Open
# http://localhost (Caddy on :80 by default; set DASH_DOMAIN for auto-TLS)
```

## Layout

```
backend/    FastAPI app, tests, Dockerfile
frontend/   Vite + React + TS app, Dockerfile
deploy/     docker-compose.yml, Caddyfile, .env.example
docs/       endpoint notes, design docs (TBD)
```

## Development

```bash
# Backend (host venv, no Docker)
just backend-install
just backend-run            # http://localhost:8000/api/health
just backend-test

# Frontend (host node, no Docker)
just frontend-install
just frontend-dev           # http://localhost:5173
```

## Security notes

- OPNsense API credentials are stored encrypted at rest using Fernet.
  The master key (`DASH_MASTER_KEY`) lives only in `deploy/.env`.
- Each OPNsense instance should expose its API only over HTTPS, with a
  source-IP allowlist for the dashboard host. Pin the per-instance CA bundle
  in the dashboard rather than disabling TLS verification.
- Use a dedicated OPNsense service user with the minimum ACLs required
  (Diagnostics read, IPsec service start/stop, Firmware update). Never use root.
