# https://github.com/casey/just
set shell := ["bash", "-cu"]

default:
    @just --list

# --- Backend ---------------------------------------------------------------

backend-install:
    cd backend && python -m venv .venv && .venv/bin/pip install -e '.[dev]'

backend-run:
    cd backend && .venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

backend-test:
    cd backend && .venv/bin/pytest -q

backend-lint:
    cd backend && .venv/bin/ruff check app tests

backend-fmt:
    cd backend && .venv/bin/ruff format app tests

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

# --- Stack -----------------------------------------------------------------

up:
    docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build

down:
    docker compose -f deploy/docker-compose.yml --env-file deploy/.env down

logs:
    docker compose -f deploy/docker-compose.yml --env-file deploy/.env logs -f --tail=200

# Generate a Fernet master key for DASH_MASTER_KEY
gen-key:
    python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
