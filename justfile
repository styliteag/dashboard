# https://github.com/casey/just
set shell := ["bash", "-cu"]

default:
    @just --list

# --- Backend ---------------------------------------------------------------

backend-install:
    cd backend && uv sync --all-extras

backend-run: _sign-if-key
    cd backend && uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

backend-test:
    cd backend && uv run pytest -q

backend-lint:
    cd backend && uv run ruff check src tests

backend-fmt:
    cd backend && uv run ruff format src tests

# --- Agent (runs on OPNsense/pfSense; pure stdlib, tested via the backend venv) ---

agent-test:
    cd backend && uv run pytest -o asyncio_mode=auto ../agent/tests -q

# Checkmk special agent (stdlib; runs on the Checkmk server)
checkmk-test:
    cd backend && uv run pytest ../checkmk/tests -q

# Sign the agent for self-update (needs the OFFLINE Ed25519 private key).
# Set DASH_AGENT_SIGNING_KEY (base64) or pass --key-file. `--gen` mints a keypair.
sign-agent *ARGS:
    uv --project backend run python scripts/sign_agent.py {{ARGS}}

# Re-sign the agent IF a signing key is available (env or gitignored .env);
# no-op + skip message otherwise. A dependency of the dev/run recipes so the
# served orbit_agent.py.sig stays fresh and self-update verifies. Never fails.
_sign-if-key:
    #!/usr/bin/env bash
    set -uo pipefail
    if [[ -z "${DASH_AGENT_SIGNING_KEY:-}" && -f .env ]]; then
        DASH_AGENT_SIGNING_KEY=$(grep -E '^DASH_AGENT_SIGNING_KEY=' .env | head -1 \
            | sed -E 's/^[^=]+=//; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/')
    fi
    if [[ -z "${DASH_AGENT_SIGNING_KEY:-}" ]]; then
        echo "agent signing: no DASH_AGENT_SIGNING_KEY (env or .env) — skipping"
        exit 0
    fi
    export DASH_AGENT_SIGNING_KEY
    uv --project backend run python scripts/sign_agent.py

# --- Frontend --------------------------------------------------------------

frontend-install:
    cd frontend && npm install

frontend-dev:
    cd frontend && npm run dev

frontend-build:
    cd frontend && npm run build

frontend-lint:
    cd frontend && npm run lint

frontend-fmt:
    cd frontend && npm run fmt

# --- Stack (production: single combined image) -----------------------------

up: _sign-if-key
    docker compose up -d --build

down:
    docker compose down

logs:
    docker compose logs -f --tail=200

# --- Stack (development: backend + frontend separate, src bind-mounted) ----

dev: _sign-if-key
    docker compose -f compose-dev.yml up --build

dev-up: _sign-if-key
    docker compose -f compose-dev.yml up -d --build

dev-down:
    docker compose -f compose-dev.yml down

dev-logs:
    docker compose -f compose-dev.yml logs -f --tail=200

# --- Release ----------------------------------------------------------------

# Bump version, update CHANGELOG.md, tag, push. CI builds + publishes image.
# Usage: just release patch|minor|major
release type="patch":
    ./release.sh {{type}}

# Generate a Fernet master key for DASH_MASTER_KEY
gen-key:
    cd backend && uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
