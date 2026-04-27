# STYLiTE Orbit dashboard

Central dashboard for managing multiple OPNsense firewalls.

## Status

Skeleton. The stack boots and the frontend renders the backend `/api/health` response. No
features beyond that yet — all user stories are tracked as GitHub issues, see the
[project board](https://github.com/users/rw-sty/projects/1).

## Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic, httpx, APScheduler. Managed with [`uv`](https://docs.astral.sh/uv/), `src/`-layout package.
- **Frontend:** React + TypeScript, Vite, Tailwind, TanStack Query
- **Database:** PostgreSQL 16 + TimescaleDB extension
- **Container:** single combined image — nginx serves the built frontend on `:80` and proxies `/api/` to uvicorn at `127.0.0.1:8000` inside the same container.
- **Deployment:** Docker Compose. TLS is operator-side (host reverse proxy, cloud LB).

## Quickstart (production)

Prerequisites: Docker, Docker Compose, and (optionally) [`just`](https://github.com/casey/just).

```bash
# 1. Configure secrets
cp .env.example .env
just gen-key            # paste output into DASH_MASTER_KEY in .env
# also set POSTGRES_PASSWORD and DASH_ADMIN_PASSWORD

# 2. Start the stack
just up                 # or: docker compose up -d --build

# 3. Open
# http://localhost  (DASH_PORT in .env to remap)
```

To pull a published image instead of building locally, edit `compose.yml` —
swap the `build:` block under `app` for `image: ghcr.io/styliteag/dashboard:latest`.

## Layout

```
Dockerfile              combined prod image (multi-stage: frontend + backend)
compose.yml             production stack (db + app + db-backup)
compose-dev.yml         dev stack (db + backend + frontend, src bind-mounted)
docker/                 nginx.conf + start.sh used by the prod image
backend/                FastAPI app (src/app/), tests, Dockerfile.dev
frontend/               Vite + React + TS app, Dockerfile.dev
.github/workflows/      release.yml — multi-arch publish on tag push
VERSION                 source of truth, baked into image at build
release.sh              version bump + tag + push helper
```

## Development

Two workflows — pick one:

### A) Local (fast feedback, recommended)

Backend and frontend run on the host. Database can run in Docker (just `db` from the dev compose) or locally.

```bash
just backend-install        # uv sync --all-extras (creates backend/.venv)
just backend-run            # uvicorn --reload on http://localhost:8000
just backend-test           # pytest

just frontend-install       # npm install
just frontend-dev           # vite on http://localhost:5173 (proxies /api → backend)
```

### B) Docker dev compose (everything in containers)

Both backend and frontend run as separate containers with their `src/` bind-mounted, so saving a file triggers `uvicorn --reload` (backend) or Vite HMR (frontend).

```bash
cp .env.example .env        # set DASH_MASTER_KEY at minimum
just dev-up                 # docker compose -f compose-dev.yml up -d --build
just dev-logs

# Browse: http://localhost:5173 (frontend)
# Direct: http://localhost:8000/api/health (backend)
```

## Releasing

```bash
just release patch          # or: minor / major
```

`release.sh` bumps `VERSION`, inserts a dated section in `CHANGELOG.md`, commits, tags `${VERSION}`, and pushes. The `.github/workflows/release.yml` workflow then builds a multi-arch image (`linux/amd64,linux/arm64`) and publishes it to:

- `docker.io/styliteag/dashboard:${VERSION}` and `:latest`
- `ghcr.io/styliteag/dashboard:${VERSION}` and `:latest`

Required CI secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` (GHCR uses the default `GITHUB_TOKEN`).

## Security notes

- OPNsense API credentials are stored encrypted at rest using Fernet.
  The master key (`DASH_MASTER_KEY`) lives only in `.env`.
- Each OPNsense instance should expose its API only over HTTPS, with a
  source-IP allowlist for the dashboard host. Pin the per-instance CA bundle
  in the dashboard rather than disabling TLS verification.
- Use a dedicated OPNsense service user with the minimum ACLs required
  (Diagnostics read, IPsec service start/stop, Firmware update). Never use root.
