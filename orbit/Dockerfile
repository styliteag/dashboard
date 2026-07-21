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

# Deps first for layer caching. VERSION is deliberately NOT copied here even
# though mix.exs reads it: release.sh bumps it on every release, and the layer
# cache keys on file content, so a COPY VERSION above this line invalidates
# deps.compile on every single release. That is the most expensive step in the
# build (~7 min for the emulated arm64 arch alone). app_version/0 falls back to
# "0.0.0-dev" when the file is absent, which is all deps.get/deps.compile need —
# nothing about a dependency depends on the parent app's version. The real
# VERSION lands below, before mix compile, where it is baked into the release.
COPY orbit/mix.exs orbit/mix.lock ./
# --mount=type=cache on /root/.hex: the hex package download cache. The whole
# deps layer is also cached at the registry level (see release.yml), which
# covers the common case of an unchanged mix.lock — but when a dependency DOES
# change, this makes `mix deps.get` re-fetch only the new tarball instead of
# every package from hex.pm. Measured: deps.get+compile swung 16s–37s cold
# across releases purely on hex.pm download speed; this caps that tail.
# Carried across runners by the registry cache export (mode=max).
RUN --mount=type=cache,target=/root/.hex,sharing=locked \
    mix deps.get --only prod && mix deps.compile

COPY VERSION ./VERSION
COPY orbit/config ./config
COPY orbit/lib ./lib
COPY orbit/priv ./priv
COPY orbit/assets ./assets

# compile first: LiveView colocated CSS is emitted at compile time and
# tailwind imports it; then digest + release.
RUN mix compile && mix assets.deploy && mix release

# --- runner ------------------------------------------------------------------

FROM debian:trixie-slim

# curl: container HEALTHCHECK hits /api/health-ex (debian-slim ships neither
# curl nor wget; the release has no HTTP client of its own).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libstdc++6 openssl libncurses6 locales ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8

WORKDIR /app
RUN chown nobody /app

# Served agent code for the self-update relay (read-only path parity with
# the python image; the signed .sig ships beside the .py).
COPY --chown=nobody:root agent/orbit_agent.py agent/orbit_agent.py.sig /app/agent/
# The other four bootstrap downloads in AgentApiController.@downloads — the
# install guides curl/fetch these, so an image without them 404s every new
# enrollment. Copied as an explicit allowlist (not the whole agent/ dir the
# python image shipped) to keep tests/ and install scripts out of the image.
COPY --chown=nobody:root agent/run-agent.sh /app/agent/
COPY --chown=nobody:root agent/rc.d/orbit_agent /app/agent/rc.d/
COPY --chown=nobody:root agent/systemd/orbit-agent.service /app/agent/systemd/
COPY --chown=nobody:root agent/vendor/check_mk_agent.linux /app/agent/vendor/
ENV AGENT_DIR=/app/agent

COPY --from=builder --chown=nobody:root /app/_build/prod/rel/orbit ./
COPY --chown=nobody:root VERSION ./VERSION
# License obligation: notices + SBOM ship inside the distributed image.
COPY --chown=nobody:root THIRD-PARTY-NOTICES.md sbom.cdx.json /app/

USER nobody

# Bandit listens on 4000 (PORT env); TLS terminates at nginx upstream.
EXPOSE 4000
ENV PHX_SERVER=true
# No erl_crash.dump. In a container the file lands in a layer nobody keeps and
# writing it delays the restart; the orchestrator's restart IS the recovery
# mechanism. Its only appearance so far was a startup race against the database
# (now waited out in Orbit.Repo.Migrator), where it was pure noise on top of an
# already clear error.
ENV ERL_CRASH_DUMP_SECONDS=0

CMD ["/app/bin/orbit", "start"]
