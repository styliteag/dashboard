# Production release image (plan §6 M7, link-shortener pattern): multi-stage
# elixir builder → debian-slim runner, `mix release`, USER nobody. The release
# bundles ERTS, so the runner carries no Elixir/OTP — builder and runner MUST
# stay on the same debian generation for the shared libc. elixir:1.20 is
# debian 13 (trixie, glibc 2.41); a bookworm runner dies with
# "GLIBC_2.38 not found" (hit live on first boot).
#
# Build from the REPO ROOT (VERSION + agent/ live there):
#   docker build -f orbit/Dockerfile -t orbit .

FROM elixir:1.20 AS builder

# cmake: lazy_html/lexbor source build (same reason as Dockerfile.dev).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV MIX_ENV=prod

RUN mix local.hex --force && mix local.rebar --force

# Deps first for layer caching.
COPY orbit/mix.exs orbit/mix.lock ./
COPY VERSION ./VERSION
RUN mix deps.get --only prod && mix deps.compile

COPY orbit/config ./config
COPY orbit/lib ./lib
COPY orbit/priv ./priv
COPY orbit/assets ./assets

# compile first: LiveView colocated CSS is emitted at compile time and
# tailwind imports it; then digest + release.
RUN mix compile && mix assets.deploy && mix release

# --- runner ------------------------------------------------------------------

FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libstdc++6 openssl libncurses6 locales ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8

WORKDIR /app
RUN chown nobody /app

# Served agent code for the self-update relay (read-only path parity with
# the python image; the signed .sig ships beside the .py).
COPY --chown=nobody:root agent/orbit_agent.py agent/orbit_agent.py.sig /app/agent/
ENV AGENT_DIR=/app/agent

COPY --from=builder --chown=nobody:root /app/_build/prod/rel/orbit ./
COPY --chown=nobody:root VERSION ./VERSION
# License obligation: notices + SBOM ship inside the distributed image.
COPY --chown=nobody:root THIRD-PARTY-NOTICES.md sbom.cdx.json /app/

USER nobody

# Bandit listens on 4000 (PORT env); TLS terminates at nginx upstream.
EXPOSE 4000
ENV PHX_SERVER=true

CMD ["/app/bin/orbit", "start"]
