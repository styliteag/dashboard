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

# Black-box API contract suite against a RUNNING backend (`just dev-up` first).
# CONTRACT_BASE_URL switches the target: Python :8000 (default), orbit :4000.
# Machine-contract pins (checkmk/prometheus/apikey scoping) are the migration
# gate for the LiveView rewrite (docs/elixir-liveview-rewrite.md M2/M4); the
# session-JSON fixtures pin the python backend only — its UI api dies with react.
contract-test *ARGS:
    cd backend && uv run pytest ../contract -q {{ARGS}}

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

# Schema is now orbit-owned (Ecto). Daily workflow:
#   just orbit-migration add_widget_flag   # scaffold priv/repo/migrations/NNN_*.exs
#   # edit the migration, then apply it:
#   just orbit-migrate                      # mix ecto.migrate (also runs at app boot)
#   just orbit-rollback                     # mix ecto.rollback (last migration)
orbit-migration NAME:
    docker compose -f compose-dev.yml run --rm orbit mix ecto.gen.migration {{NAME}}

orbit-migrate:
    docker compose -f compose-dev.yml run --rm orbit mix ecto.migrate

orbit-rollback *ARGS:
    docker compose -f compose-dev.yml run --rm orbit mix ecto.rollback {{ARGS}}

# Provision the throwaway test DB (create + migrate to head) — gives the suite
# every table, incl. ones the old partial dump lacked.
orbit-test-db:
    docker compose -f compose-dev.yml run --rm -e MIX_ENV=test orbit sh -c "mix ecto.create && mix ecto.migrate"

# Regenerate priv/repo/baseline_schema.sql from the running dev DB. RARE — for
# an established schema you add an incremental migration instead; this only
# re-captures the baseline (e.g. after a fresh greenfield bring-up). Needs the
# dev `db` container up.
orbit-dump-baseline:
    #!/usr/bin/env bash
    set -euo pipefail
    out=orbit/priv/repo/baseline_schema.sql
    # FK-dependency order (parents first) — mariadb-dump keeps the CLI table
    # order, and the baseline relies on it (see the migration's comment). A new
    # table must be added here in an order where its FK targets come first.
    order="groups users api_keys access_events access_stats app_settings \
      geoip_config geoip_denial_events geoip_denial_stats instances \
      apikey_groups audit_log auth_sessions check_events config_backups \
      connectivity_monitors enrollment_codes entity_comments group_channels \
      ipsec_ping_monitors ipsec_tunnel_events log_events logfiles metrics \
      selection_rules user_groups webauthn_credentials"
    {
      echo "-- Baseline schema (MariaDB) captured from the current DB head."
      echo "-- Idempotent (IF NOT EXISTS), emitted in FK-dependency order so an empty"
      echo "-- DB creates cleanly. Regenerate via 'just orbit-dump-baseline'. Do not hand-edit."
      echo "SET FOREIGN_KEY_CHECKS = 0;"
      docker compose -f compose-dev.yml exec -T db sh -c \
        "mariadb-dump -u\"\$MYSQL_USER\" -p\"\$MYSQL_PASSWORD\" --no-data --skip-comments --no-tablespaces \"\$MYSQL_DATABASE\" $order" \
        | grep -vE '^/\*|^--|^$' \
        | sed -E 's/^CREATE TABLE /CREATE TABLE IF NOT EXISTS /; s/ AUTO_INCREMENT=[0-9]+//'
      echo "SET FOREIGN_KEY_CHECKS = 1;"
    } > "$out"
    echo "wrote $out"

# Build the production release image locally (CI builds/publishes on release tags)
orbit-image:
    docker build -f orbit/Dockerfile -t dashboard-orbit:local .

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
