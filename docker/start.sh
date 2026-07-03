#!/bin/bash
# Combined startup: alembic migrations -> uvicorn (background) -> nginx (foreground).
set -e

STOP_FLAG=/tmp/orbit.stop

shutdown() {
    echo "Shutting down..."
    # Flag first so the supervisor loop below doesn't resurrect the backend.
    touch "$STOP_FLAG"
    pkill -TERM -f "uvicorn app.main:app" 2>/dev/null || true
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

# Start backend in background, dropped to the unprivileged 'orbit' user (migrations
# above ran as root; the long-lived server that parses untrusted input must not).
# The supervisor loop makes the admin "Restart backend" button work in this
# combined container: the endpoint SIGTERMs uvicorn and the loop starts a fresh
# one (nginx untouched). The stop flag keeps a real shutdown from resurrecting it.
echo "Starting backend..."
rm -f "$STOP_FLAG"
(
    while [ ! -f "$STOP_FLAG" ]; do
        gosu orbit uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log || true
        [ -f "$STOP_FLAG" ] && break
        echo "Backend exited — restarting in 1s..."
        sleep 1
    done
) &
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
