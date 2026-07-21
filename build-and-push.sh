#!/bin/bash
set -euo pipefail

# Local multi-arch build & push for STYLiTE Orbit (the dashboard release image).
#
# Builds the production image (orbit/Dockerfile) for one or more platforms on
# THIS machine and pushes it straight to the registries — bypassing the GitHub
# Actions release workflow. This is the ONLY path that produces an arm64 image:
# CI builds amd64 only (the native arm64 runner is billed per minute). Use it
# for a real multi-arch release, a hotfix, or an air-gapped push.
#
# Usage:
#   ./build-and-push.sh                # both arches (amd64 + arm64)
#   ./build-and-push.sh amd64          # single arch
#   ./build-and-push.sh arm64
#   ./build-and-push.sh all            # explicit both
#   PLATFORMS=linux/amd64 ./build-and-push.sh    # override raw platform string
#   PUSH_DOCKERHUB=0 ./build-and-push.sh         # ghcr only
#   PUSH_DOCKERHUB=1 ./build-and-push.sh         # force docker hub too
#
# Requires:
#   - docker + buildx
#   - `docker login ghcr.io` (and `docker login` for docker.io if pushing there)
#
# Note: building a foreign architecture emulates via QEMU/binfmt. Docker Desktop
# ships binfmt; on plain Linux run once:
#   docker run --privileged --rm tonistiigi/binfmt --install all
# On Apple Silicon the arm64 image is native and amd64 is emulated (and slower).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GHCR_IMAGE="ghcr.io/styliteag/dashboard"
DOCKERHUB_IMAGE="docker.io/styliteag/dashboard"
BUILDER="dashboard-builder"
# The dashboard image builds from the REPO ROOT context (VERSION + agent/ live
# there) with the Dockerfile under orbit/. The version is read from the COPYed
# VERSION file, not a build-arg — do not pass --build-arg VERSION.
DOCKERFILE="orbit/Dockerfile"

# --- resolve platforms (env PLATFORMS wins, else the first argument) ---
#
# Multi-arch strategy = "Variant A": build ALL wanted arches locally in one
# `buildx build` so a single manifest list carries both. Pushing arches
# separately does NOT union — each push OVERWRITES the tag with only its own
# arch. So do not mix this with the CI amd64 build on the same tag: whichever
# runs last wins and the other arch drops out. For a real multi-arch image use
# `all`, and do NOT let the CI release run on that same tag afterwards. A
# single-arch invocation warns before pushing (see below).
ARG="${1:-all}"
if [[ -z "${PLATFORMS:-}" ]]; then
    case "$ARG" in
        all | both) PLATFORMS="linux/amd64,linux/arm64" ;;
        amd64 | x86_64 | linux/amd64) PLATFORMS="linux/amd64" ;;
        arm64 | aarch64 | linux/arm64) PLATFORMS="linux/arm64" ;;
        *)
            echo "Error: unknown platform '$ARG' (use amd64 | arm64 | all)."
            exit 1
            ;;
    esac
fi

# --- version from the VERSION file (same source of truth as the release flow) ---
if [[ ! -f VERSION ]]; then
    echo "Error: VERSION file not found."
    exit 1
fi
VERSION="$(tr -d '\n\r ' < VERSION)"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: invalid version in VERSION file: '$VERSION'"
    exit 1
fi

# --- preflight ---
command -v docker > /dev/null 2>&1 || {
    echo "Error: docker not found."
    exit 1
}
docker buildx version > /dev/null 2>&1 || {
    echo "Error: docker buildx not available."
    exit 1
}

logged_in() { grep -q "$1" "$HOME/.docker/config.json" 2> /dev/null; }

if ! logged_in "ghcr.io"; then
    echo "Warning: no ghcr.io login found in ~/.docker/config.json — push will fail."
    echo "  Run: echo \$GH_TOKEN | docker login ghcr.io -u <user> --password-stdin"
    echo ""
fi

# --- docker hub toggle (auto: only if logged in) ---
TAGS=(-t "$GHCR_IMAGE:$VERSION" -t "$GHCR_IMAGE:latest")
DOCKERHUB="skipped (set PUSH_DOCKERHUB=1 + 'docker login' to enable)"
case "${PUSH_DOCKERHUB:-auto}" in
    1 | yes | true) WANT_HUB=1 ;;
    0 | no | false) WANT_HUB=0 ;;
    auto) logged_in "index.docker.io" && WANT_HUB=1 || WANT_HUB=0 ;;
    *)
        echo "Error: PUSH_DOCKERHUB must be 0 or 1."
        exit 1
        ;;
esac
if [[ "$WANT_HUB" == "1" ]]; then
    TAGS+=(-t "$DOCKERHUB_IMAGE:$VERSION" -t "$DOCKERHUB_IMAGE:latest")
    DOCKERHUB="$DOCKERHUB_IMAGE:$VERSION (+ :latest)"
fi

echo "Version:    $VERSION"
echo "Platforms:  $PLATFORMS"
echo "GHCR:       $GHCR_IMAGE:$VERSION (+ :latest)"
echo "Docker Hub: $DOCKERHUB"
echo ""

# --- single-arch warning (overwrites the tag, does not merge — see Variant A) ---
if [[ "$PLATFORMS" != *,* ]]; then
    echo "!! WARNING: pushing a SINGLE architecture ($PLATFORMS)." >&2
    echo "!! Tags '$VERSION' and 'latest' will be OVERWRITTEN with a single-arch" >&2
    echo "!! manifest. This does NOT merge with an amd64 image built by CI (or a" >&2
    echo "!! previous push) — that architecture drops out of the tag." >&2
    echo "!! For a real multi-arch image run:  just publish all" >&2
    echo "" >&2
    read -r -p "Continue with single-arch push? (y/N) " REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# --- dedicated multi-arch builder (persistent local layer cache across runs) ---
if ! docker buildx inspect "$BUILDER" > /dev/null 2>&1; then
    echo "Creating buildx builder '$BUILDER'..."
    docker buildx create --name "$BUILDER" --driver docker-container --bootstrap > /dev/null
fi

# --- build all requested platforms in one shot and push the manifest list ---
# Context is the repo root ('.'); the Dockerfile lives under orbit/.
docker buildx build \
    --builder "$BUILDER" \
    --platform "$PLATFORMS" \
    --file "./$DOCKERFILE" \
    --provenance=false \
    --sbom=false \
    "${TAGS[@]}" \
    --push \
    .

echo ""
echo "Pushed $VERSION for [$PLATFORMS]."
