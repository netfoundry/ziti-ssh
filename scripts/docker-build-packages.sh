#!/usr/bin/env bash
# docker-build-packages.sh — build packages inside a Docker container.
#
# Usage:
#   ./scripts/docker-build-packages.sh
#   VERSION=1.2.3 FORMAT=deb ./scripts/docker-build-packages.sh
#   VERSION=1.2.3 FORMAT=rpm ARCHS=amd64,arm64 ./scripts/docker-build-packages.sh
#
# Environment variables:
#   VERSION  — package version (default: 0.1.0)
#   FORMAT   — comma-separated formats: deb, rpm, or deb,rpm (default: deb,rpm)
#   ARCHS    — comma-separated Go architectures (default: amd64)

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
FORMAT="${FORMAT:-deb,rpm}"
ARCHS="${ARCHS:-amd64}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="ziti-ssh-builder"

log() { printf '[docker-build-packages] %s\n' "$*"; }

log "Building Docker image (VERSION=${VERSION} FORMAT=${FORMAT} ARCHS=${ARCHS})..."
docker build \
    -f "${SCRIPT_DIR}/Dockerfile.packages" \
    --build-arg "VERSION=${VERSION}" \
    --build-arg "FORMAT=${FORMAT}" \
    --build-arg "ARCHS=${ARCHS}" \
    -t "${IMAGE_NAME}" \
    "${REPO_ROOT}"

log "Extracting packages and binaries..."
mkdir -p "${REPO_ROOT}/dist"

CONTAINER_ID=$(docker create "${IMAGE_NAME}")
trap 'docker rm "${CONTAINER_ID}" >/dev/null' EXIT

docker cp "${CONTAINER_ID}:/src/dist/." "${REPO_ROOT}/dist/"

for bin in ziti-ssh-ca ziti-ssh-host ziti-ssh ziti-scp; do
    docker cp "${CONTAINER_ID}:/src/${bin}" "${REPO_ROOT}/${bin}" 2>/dev/null || true
done

log "Done."
log ""
log "Packages:"
ls -lh "${REPO_ROOT}"/dist/*.deb "${REPO_ROOT}"/dist/*.rpm 2>/dev/null || true
