# Multi-stage build: combined frontend + backend production container.
#
# Frontend (React + Vite) is built and served by nginx on :80.
# Backend (FastAPI) runs locally on 127.0.0.1:8000; nginx proxies /api/.

ARG VERSION=unknown

# Stage 1: Frontend builder
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
COPY VERSION /app/VERSION

ARG VITE_API_BASE_URL
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL:-}

ARG VERSION=unknown
ARG VITE_APP_VERSION=${VERSION}
ENV VITE_APP_VERSION=${VITE_APP_VERSION}

RUN npm run build

# Stage 2: Backend builder
FROM python:3.12-slim AS backend-builder

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY backend/pyproject.toml backend/uv.lock ./
COPY backend/src ./src
RUN uv sync --no-dev --frozen || uv sync --no-dev

COPY backend/alembic.ini ./alembic.ini
COPY backend/alembic ./alembic

# Stage 3: Runtime
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    TZ=UTC

# Install nginx + wget (for healthcheck) + bash + tzdata
RUN apt-get update && \
    apt-get install -y --no-install-recommends nginx wget bash tzdata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy backend venv + source + alembic migrations
COPY --from=backend-builder /app/.venv /app/.venv
COPY --from=backend-builder /app/src /app/src
COPY --from=backend-builder /app/alembic.ini /app/alembic.ini
COPY --from=backend-builder /app/alembic /app/alembic

# Copy frontend build into nginx webroot
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# nginx config
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
RUN rm -f /etc/nginx/sites-enabled/default

# Combined startup script
COPY docker/start.sh /app/start.sh
RUN chmod +x /app/start.sh

# VERSION file (last layer for cache friendliness)
ARG VERSION=unknown
ENV APP_VERSION=${VERSION}
COPY VERSION /app/VERSION.build
RUN cp /app/VERSION.build /app/VERSION || echo "${VERSION:-unknown}" > /app/VERSION

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD wget -q -O - http://127.0.0.1/api/health >/dev/null 2>&1 || exit 1

CMD ["/app/start.sh"]
