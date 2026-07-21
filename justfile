# https://github.com/casey/just
set shell := ["bash", "-cu"]

default:
    @just --list

# --- Tooling (tools/pyproject.toml) -----------------------------------------
# The FastAPI backend is gone (orbit cutover). tools/ is the venv host for the
# python bits that outlived it: agent signing, the agent + checkmk test suites,
# notices/SBOM generation and the key generators. Nothing here imports app code.

tools-install:
    cd tools && uv sync --all-extras

tools-lint:
    cd tools && uv run ruff check ../scripts

tools-fmt:
    cd tools && uv run ruff format ../scripts

# --- Agent (runs on OPNsense/pfSense; pure stdlib, tested via the tools venv) ---

agent-test:
    cd tools && uv run pytest -o asyncio_mode=auto ../agent/tests -q

# Checkmk special agent (stdlib; runs on the Checkmk server)
checkmk-test:
    cd tools && uv run pytest ../checkmk/tests -q

# Sign the agent for self-update. Auto-loads the OFFLINE Ed25519 private key from
# env or the gitignored .env (DASH_AGENT_SIGNING_KEY) — no manual export needed.
# Pass ARGS through: `--verify` (no key), `--gen` (mint keypair), `--key-file PATH`.
sign-agent *ARGS:
    uv --project tools run python scripts/sign_agent.py {{ARGS}}

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
    uv --project tools run python scripts/sign_agent.py

# --- Orbit (Elixir/Phoenix LiveView rewrite) ---
# Everything runs in the orbit container; no local Elixir toolchain.

# One-time (and after dep changes): install hex/rebar + fetch deps into the caches
orbit-setup:
    docker compose -f compose-dev.yml run --rm orbit sh -c "mix local.hex --force && mix local.rebar --force && mix deps.get"

# Tests; arguments are passed through: just orbit-test test/orbit_web
orbit-test *ARGS:
    docker compose -f compose-dev.yml run --rm orbit mix test {{ARGS}}

orbit-fmt:
    docker compose -f compose-dev.yml run --rm orbit mix format

# Lint gate. MIX_ENV=test on purpose: dev's _build is shared live with the
# running `dev-up` container, so compiling into it races the dev server and
# can corrupt its beams ("__live__ is undefined", module not available).
# _build/test belongs to the throwaway run containers, so this is safe to
# run at any time. --force because an incremental build re-emits no
# warnings, which made the gate silently pass on warning-laden code.
orbit-lint:
    docker compose -f compose-dev.yml run --rm -e MIX_ENV=test orbit sh -c "mix format --check-formatted && mix compile --force --warnings-as-errors"

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
    #
    # --skip-add-drop-table is NOT optional: mariadb-dump emits DROP TABLE IF
    # EXISTS per table by default, and the comment filter below does not strip
    # it. A baseline carrying DROPs is no longer the promised no-op — on the
    # first orbit boot against a populated database it deletes every table.
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
        "mariadb-dump -u\"\$MYSQL_USER\" -p\"\$MYSQL_PASSWORD\" --no-data --skip-comments \\
           --skip-add-drop-table --no-tablespaces \"\$MYSQL_DATABASE\" $order" \
        | grep -vE '^/\*|^--|^$' \
        | sed -E 's/^CREATE TABLE /CREATE TABLE IF NOT EXISTS /; s/ AUTO_INCREMENT=[0-9]+//'
      echo "SET FOREIGN_KEY_CHECKS = 1;"
    } > "$out"
    echo "wrote $out"

# Build the production release image locally (CI builds/publishes on release tags)
orbit-image:
    docker build -f orbit/Dockerfile -t dashboard:local .

# --- Stack (production: single combined image) -----------------------------

up: _sign-if-key
    docker compose up -d --build

down:
    docker compose down

logs:
    docker compose logs -f --tail=200

# --- Stack (development: orbit with src bind-mounted, hot reload) ----------

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

# Build the prod image LOCALLY and push straight to the registries (no CI).
# The ONLY path that produces an arm64 image — CI builds amd64 only.
# just publish        → amd64 + arm64   |   just publish amd64   → single arch
publish platforms="all":
    ./build-and-push.sh {{platforms}}

# Regenerate THIRD-PARTY-NOTICES.md AND sbom.cdx.json (CycloneDX 1.6) from the
# shipped runtime deps of the orbit release. Needs the orbit deps fetched
# (`just orbit-setup`) so the Hex license files are on disk. Run after changing
# any runtime dependency. Covers app dependencies only — for an SBOM that also
# includes base-image OS packages, scan the built image with syft.
notices:
    cd tools && uv run python ../scripts/gen_notices.py

# Alias: same generator, emphasises the SBOM artifact.
sbom: notices

# Generate a Fernet master key for DASH_MASTER_KEY
gen-key:
    cd tools && uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'

# Generate an ed25519 keypair for Securepoint SSH enrichment (private key → paste
# into the instance form; public key → install on the box, see docs/securepoint-ssh.md)
gen-ssh-key:
    cd tools && uv run python -c 'import asyncssh; k=asyncssh.generate_private_key("ssh-ed25519"); print(k.export_private_key().decode()); print(k.export_public_key().decode().strip())'
