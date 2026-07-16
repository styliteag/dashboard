# https://github.com/casey/just
set shell := ["bash", "-cu"]

default:
    @just --list

# --- Backend ---------------------------------------------------------------

backend-install:
    cd backend && uv sync --all-extras

backend-run: _sign-if-key
    cd backend && uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 --no-access-log

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

# Sign the agent for self-update. Auto-loads the OFFLINE Ed25519 private key from
# env or the gitignored .env (DASH_AGENT_SIGNING_KEY) — no manual export needed.
# Pass ARGS through: `--verify` (no key), `--gen` (mint keypair), `--key-file PATH`.
sign-agent *ARGS:
    uv --project backend run python scripts/sign_agent.py {{ARGS}}

# Re-sign the agent IF a signing key is available (env or gitignored .env);
# no-op + skip message otherwise. A dependency of the dev/run recipes so the
# served orbit_agent.py.sig stays fresh and self-update verifies. Never fails.
_sign-if-key:
    #!/usr/bin/env bash
    set -uo pipefail
    # -r, not -f: .env may be a named pipe (1Password Environments FIFO).
    if [[ -z "${DASH_AGENT_SIGNING_KEY:-}" && -r .env ]]; then
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

# --- Orbit (Elixir/Phoenix LiveView rewrite — docs/elixir-liveview-rewrite.md) ---
# Everything runs in the orbit container; no local Elixir toolchain.

# One-time (and after dep changes): install hex/rebar + fetch deps into the caches
orbit-setup:
    docker compose -f compose-dev.yml run --rm orbit sh -c "mix local.hex --force && mix local.rebar --force && mix deps.get"

# Tests; arguments are passed through: just orbit-test test/orbit_web
orbit-test *ARGS:
    docker compose -f compose-dev.yml run --rm orbit mix test {{ARGS}}

orbit-fmt:
    docker compose -f compose-dev.yml run --rm orbit mix format

orbit-lint:
    docker compose -f compose-dev.yml run --rm orbit sh -c "mix format --check-formatted && mix compile --warnings-as-errors"

orbit-sh:
    docker compose -f compose-dev.yml run --rm orbit bash

orbit-iex:
    docker compose -f compose-dev.yml run --rm orbit iex -S mix

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

# Regenerate THIRD-PARTY-NOTICES.md AND sbom.cdx.json (CycloneDX 1.6) from the
# shipped runtime deps. Needs `backend-install` + `frontend-install` first (reads
# the backend venv metadata and frontend node_modules). Run after changing any
# runtime dependency. Covers app dependencies only — for an SBOM that also
# includes base-image OS packages, scan the built image with syft.
notices:
    cd backend && uv run python ../scripts/gen_notices.py

# Alias: same generator, emphasises the SBOM artifact.
sbom: notices

# Generate a Fernet master key for DASH_MASTER_KEY
gen-key:
    cd backend && uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'

# Generate an ed25519 keypair for Securepoint SSH enrichment (private key → paste
# into the instance form; public key → install on the box, see docs/securepoint-ssh.md)
gen-ssh-key:
    cd backend && uv run python -c 'import asyncssh; k=asyncssh.generate_private_key("ssh-ed25519"); print(k.export_private_key().decode()); print(k.export_public_key().decode().strip())'
