#!/usr/bin/env bash
# scripts/build-packages.sh — build deb and/or rpm packages for all four ziti-ssh binaries.
#
# Usage:
#   ./scripts/build-packages.sh
#   VERSION=1.2.3 FORMAT=deb ./scripts/build-packages.sh
#   VERSION=1.2.3 FORMAT=rpm ./scripts/build-packages.sh
#   VERSION=1.2.3 ARCHS=amd64,arm64 ./scripts/build-packages.sh
#
# Environment variables:
#   VERSION  — package version (default: 0.0.0)
#   FORMAT   — comma-separated list of package formats: deb, rpm, or deb,rpm (default: deb,rpm)
#   ARCHS    — comma-separated list of Go architectures to build (default: native arch)
#
# Requires: go; nfpm (downloaded and checksum-verified for this run if not on PATH; Linux)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
BIN_DIR="${DIST_DIR}/binaries"

VERSION="${VERSION:-0.0.0}"
FORMAT="${FORMAT:-deb,rpm}"

# Default ARCHS to the native architecture.
NATIVE_ARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
ARCHS="${ARCHS:-${NATIVE_ARCH}}"

PACKAGES=(ziti-ssh ziti-scp ziti-ssh-ca ziti-ssh-host)

log() { printf '[build-packages] %s\n' "$*"; }

if ! command -v go >/dev/null 2>&1; then
    printf 'error: go is required but not found in PATH\n' >&2
    exit 1
fi
# nfpm: use the one on PATH, otherwise download the pinned release binary and
# verify it against the release checksums (as prerelease.yml does). It is put
# in a temporary directory for this run only. "go install" is not used: recent
# nfpm releases need a newer Go than this module's toolchain.
if ! command -v nfpm >/dev/null 2>&1; then
    NFPM_VERSION="${NFPM_VERSION:-2.49.0}"
    if [[ "$(uname -s)" != "Linux" ]]; then
        printf 'error: nfpm not found; install nfpm v%s (https://nfpm.goreleaser.com/install/)\n' "${NFPM_VERSION}" >&2
        exit 1
    fi
    case "$(uname -m)" in
        x86_64|amd64)  NFPM_ARCH_NAME=x86_64 ;;
        aarch64|arm64) NFPM_ARCH_NAME=arm64 ;;
        *) printf 'error: nfpm not found and no release binary for %s; install nfpm v%s\n' "$(uname -m)" "${NFPM_VERSION}" >&2
           exit 1 ;;
    esac
    for tool in curl tar sha256sum; do
        command -v "${tool}" >/dev/null 2>&1 || { printf 'error: %s is required to download nfpm\n' "${tool}" >&2; exit 1; }
    done
    NFPM_TMP="$(mktemp -d)"
    trap 'rm -rf "${NFPM_TMP}"' EXIT
    tarball="nfpm_${NFPM_VERSION}_Linux_${NFPM_ARCH_NAME}.tar.gz"
    base="https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}"
    log "nfpm not found — downloading v${NFPM_VERSION} (${tarball}) and verifying its checksum"
    curl -sfL -o "${NFPM_TMP}/${tarball}" "${base}/${tarball}"
    curl -sfL -o "${NFPM_TMP}/checksums.txt" "${base}/checksums.txt"
    (cd "${NFPM_TMP}" && grep " ${tarball}\$" checksums.txt | sha256sum -c -)
    tar -xzf "${NFPM_TMP}/${tarball}" -C "${NFPM_TMP}" nfpm
    export PATH="${NFPM_TMP}:${PATH}"
fi

IFS=',' read -ra FORMAT_LIST <<< "${FORMAT}"
IFS=',' read -ra ARCH_LIST <<< "${ARCHS}"

log "Version:  ${VERSION}"
log "Formats:  ${FORMAT}"
log "Archs:    ${ARCHS}"
log "Output:   ${DIST_DIR}/"

mkdir -p "${BIN_DIR}" "${DIST_DIR}"

# ---------------------------------------------------------------------------
# Build Go binaries for each arch
# ---------------------------------------------------------------------------

for arch in "${ARCH_LIST[@]}"; do
    for pkg in "${PACKAGES[@]}"; do
        log "Building ${pkg} (linux/${arch})..."
        GOARCH="${arch}" GOOS=linux CGO_ENABLED=0 go build \
            -trimpath \
            -ldflags "-s -w -X main.version=${VERSION}" \
            -o "${BIN_DIR}/${pkg}_${arch}" \
            "${REPO_ROOT}/cmd/${pkg}"
    done
done

# ---------------------------------------------------------------------------
# Package with nfpm
# ---------------------------------------------------------------------------

for arch in "${ARCH_LIST[@]}"; do
    export NFPM_ARCH="${arch}"
    for pkg in "${PACKAGES[@]}"; do
        # Stage binary at the fixed path the nfpm configs reference.
        cp "${BIN_DIR}/${pkg}_${arch}" "${BIN_DIR}/${pkg}"
        for fmt in "${FORMAT_LIST[@]}"; do
            log "Packaging ${pkg} (${fmt}/${arch})..."
            nfpm pkg \
                --packager "${fmt}" \
                --config "${REPO_ROOT}/packaging/nfpm-${pkg}.yaml" \
                --target "${DIST_DIR}/"
        done
        rm -f "${BIN_DIR}/${pkg}"
    done
done

# ---------------------------------------------------------------------------
# Copy native-arch binaries to repo root for local use
# ---------------------------------------------------------------------------

if [[ " ${ARCH_LIST[*]} " == *" ${NATIVE_ARCH} "* ]]; then
    log "Copying ${NATIVE_ARCH} binaries to repo root for local use..."
    for pkg in "${PACKAGES[@]}"; do
        cp "${BIN_DIR}/${pkg}_${NATIVE_ARCH}" "${REPO_ROOT}/${pkg}"
    done
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

log "Done."
log ""
log "Packages:"
ls -lh "${DIST_DIR}"/*.deb "${DIST_DIR}"/*.rpm 2>/dev/null || true
