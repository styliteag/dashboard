#!/bin/bash
# Combined startup: alembic migrations -> uvicorn (background) -> nginx (foreground).
set -e

shutdown() {
    echo "Shutting down..."
    kill "$BACKEND_PID" 2>/dev/null || true
    nginx -s quit 2>/dev/null || true
    exit 0
}
trap shutdown SIGTERM SIGINT

# Read version
if [ -f /app/VERSION ]; then
    VERSION=$(cat /app/VERSION | tr -d '\n\r ')
else
    VERSION=${APP_VERSION:-unknown}
fi
echo "Starting STYLiTE Orbit dashboard ${VERSION}"

# Run migrations (retry: db may not be reachable on first boot)
echo "Running database migrations..."
for i in $(seq 1 30); do
    if alembic upgrade head; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "Database migrations failed after 30 attempts"
        exit 1
    fi
    echo "Migration attempt $i failed, retrying in 2s..."
    sleep 2
done

# Start backend in background
echo "Starting backend..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

# Wait for backend health
echo "Waiting for backend..."
for i in $(seq 1 30); do
    if wget -q -O - http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
        echo "Backend ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "Backend failed to start"
        exit 1
    fi
    sleep 1
done

# Start nginx in foreground
echo "Starting nginx..."
exec nginx -g "daemon off;"
