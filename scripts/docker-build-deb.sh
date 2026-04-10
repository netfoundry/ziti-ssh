#!/usr/bin/env bash
# docker-build-deb.sh — build .deb packages inside a Docker container
#
# Usage:
#   ./scripts/docker-build-deb.sh
#   VERSION=1.2.3 ./scripts/docker-build-deb.sh

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="ziti-ssh-deb-builder"

log() { printf '[docker-build-deb] %s\n' "$*"; }

log "Building Docker image (VERSION=${VERSION})..."
docker build \
    -f "${SCRIPT_DIR}/Dockerfile.deb" \
    --build-arg "VERSION=${VERSION}" \
    -t "${IMAGE_NAME}" \
    "${REPO_ROOT}"

log "Extracting .deb packages and binaries..."
mkdir -p "${REPO_ROOT}/dist"

CONTAINER_ID=$(docker create "${IMAGE_NAME}")
trap 'docker rm "${CONTAINER_ID}" >/dev/null' EXIT

# Copy dist/*.deb files
docker cp "${CONTAINER_ID}:/src/dist/." "${REPO_ROOT}/dist/"

# Copy binaries to repo root for local testing
for bin in ziti-ssh-ca ziti-ssh-host ziti-ssh ziti-scp; do
    docker cp "${CONTAINER_ID}:/src/${bin}" "${REPO_ROOT}/${bin}"
done

log "Done."
log ""
log "Packages:"
ls -lh "${REPO_ROOT}"/dist/*_"${VERSION}"_amd64.deb
log ""
log "Binaries (repo root):"
ls -lh "${REPO_ROOT}/ziti-ssh-ca" "${REPO_ROOT}/ziti-ssh-host" "${REPO_ROOT}/ziti-ssh" "${REPO_ROOT}/ziti-scp"
