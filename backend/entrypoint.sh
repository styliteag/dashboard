#!/bin/sh
# Container entrypoint: run DB migrations, then hand off to uvicorn.
set -eu

echo "[entrypoint] running alembic migrations"
alembic upgrade head

echo "[entrypoint] starting uvicorn"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
