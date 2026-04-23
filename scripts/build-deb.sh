#!/usr/bin/env bash
# build-deb.sh — build .deb packages for ziti-ssh-ca, ziti-ssh-host, ziti-ssh, and ziti-scp
#
# Usage:
#   ./scripts/build-deb.sh
#   VERSION=1.2.3 ./scripts/build-deb.sh
#
# Requires: go, dpkg-deb
# Produces: dist/ziti-ssh-ca_<version>_amd64.deb
#           dist/ziti-ssh-host_<version>_amd64.deb
#           dist/ziti-ssh_<version>_amd64.deb
#           dist/ziti-scp_<version>_amd64.deb

set -euo pipefail

VERSION="${VERSION:-0.0.0}"
ARCH="amd64"
MAINTAINER="Edward Moscardini[edward.moscardini@netfoundry.io]"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
STAGING_DIR="${REPO_ROOT}/.deb-staging"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[build-deb] %s\n' "$*"; }

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'error: %s is required but not found in PATH\n' "$1" >&2
        exit 1
    fi
}

require_cmd go
require_cmd dpkg-deb

# ---------------------------------------------------------------------------
# Preparation
# ---------------------------------------------------------------------------

log "Version: ${VERSION}"
log "Output:  ${DIST_DIR}/"

rm -rf "${STAGING_DIR}"
mkdir -p "${DIST_DIR}"

# ---------------------------------------------------------------------------
# Build Go binaries
# ---------------------------------------------------------------------------

log "Building ziti-ssh-ca..."
GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${STAGING_DIR}/binaries/ziti-ssh-ca" \
    "${REPO_ROOT}/cmd/ziti-ssh-ca"

log "Building ziti-ssh-host..."
GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${STAGING_DIR}/binaries/ziti-ssh-host" \
    "${REPO_ROOT}/cmd/ziti-ssh-host"

log "Building ziti-ssh..."
GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${STAGING_DIR}/binaries/ziti-ssh" \
    "${REPO_ROOT}/cmd/ziti-ssh"

log "Building ziti-scp..."
GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${STAGING_DIR}/binaries/ziti-scp" \
    "${REPO_ROOT}/cmd/ziti-scp"

# ---------------------------------------------------------------------------
# Package: ziti-ssh-ca
# ---------------------------------------------------------------------------

log "Packaging ziti-ssh-ca..."

PKG="ziti-ssh-ca"
PKG_DIR="${STAGING_DIR}/${PKG}"

# Binary
install -D -m 0755 \
    "${STAGING_DIR}/binaries/ziti-ssh-ca" \
    "${PKG_DIR}/usr/local/bin/ziti-ssh-ca"

# Config directory (empty placeholder so dpkg tracks it)
install -d -m 0755 "${PKG_DIR}/etc/ziti-ssh-ca"

# Systemd service file
install -D -m 0644 /dev/stdin \
    "${PKG_DIR}/lib/systemd/system/ziti-ssh-ca.service" <<'EOF'
[Unit]
Description=Ziti SSH Certificate Authority
Documentation=https://github.com/edwardm/ziti-ssh
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=ziti
EnvironmentFile=/etc/ziti-ssh-ca/env
ExecStart=/usr/local/bin/ziti-ssh-ca
Restart=on-failure
RestartSec=5
# The CA key is the Ziti controller's own PKI root CA private key.
# ziti-ssh-ca must run on the same host as the controller (same user)
# so it can read the key via the shared filesystem.

[Install]
WantedBy=multi-user.target
EOF

# Debian control file
install -d "${PKG_DIR}/DEBIAN"
cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Depends: systemd
Description: Ziti SSH Certificate Authority service
 Signs short-lived SSH certificates for callers authenticated via an
 OpenZiti network. Uses the Ziti controller CA private key so that the
 same trust root covers both Ziti identity certificates and SSH
 certificates. Runs co-located with the Ziti controller.
EOF

# postinst: create env file placeholder if absent, reload systemd
cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if [ ! -f /etc/ziti-ssh-ca/env ]; then
    cat > /etc/ziti-ssh-ca/env <<'ENVEOF'
# ziti-ssh-ca environment configuration
# Uncomment and set these variables before starting the service.
#ZITI_IDENTITY=/etc/ziti-ssh-ca/identity.json
#ZITI_CA_KEY=/var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key

# MODE controls how SSH certificates are issued:
#
#   shared (default): all users authenticate as a single shared Linux account.
#     Set ZITI_SSH_PRINCIPAL to the shared account name (e.g. ziggy).
#     Leave ZITI_SSH_MODE unset or set to "shared".
#
#   per-identity: each Ziti identity gets its own Linux account on the target
#     host (created automatically by ziti-ssh-host). Do not set
#     ZITI_SSH_PRINCIPAL — the username is derived from the identity name.
#     Set ZITI_SSH_MODE=per-identity on both ziti-ssh-ca AND ziti-ssh-host.
#
#ZITI_SSH_MODE=shared
#ZITI_SSH_PRINCIPAL=ziggy

# Certificate validity duration (default 8h). Examples: 4h, 12h, 24h.
#ZITI_CERT_TTL=8h
ENVEOF
    chmod 640 /etc/ziti-ssh-ca/env
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "${PKG_DIR}" \
    "${DIST_DIR}/${PKG}_${VERSION}_${ARCH}.deb"

log "Created ${DIST_DIR}/${PKG}_${VERSION}_${ARCH}.deb"

# ---------------------------------------------------------------------------
# Package: ziti-ssh-host
# ---------------------------------------------------------------------------

log "Packaging ziti-ssh-host..."

PKG="ziti-ssh-host"
PKG_DIR="${STAGING_DIR}/${PKG}"

# Binary
install -D -m 0755 \
    "${STAGING_DIR}/binaries/ziti-ssh-host" \
    "${PKG_DIR}/usr/local/bin/ziti-ssh-host"

# Config directory — mode 0700 because it will contain the identity JSON
# (private key material) after enrollment.
install -d -m 0700 "${PKG_DIR}/etc/ziti-ssh-host"

# Systemd service file
install -D -m 0644 /dev/stdin \
    "${PKG_DIR}/lib/systemd/system/ziti-ssh-host.service" <<'EOF'
[Unit]
Description=Ziti SSH Host Proxy
Documentation=https://github.com/edwardm/ziti-ssh
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
# Runs as root: writes /etc/ssh/ during enrollment and proxies connections
# to the local sshd. The identity file is stored in /etc/ziti-ssh-host/
# (mode 0700) and is only readable by root.
User=root
EnvironmentFile=-/etc/ziti-ssh-host/env
ExecStart=/usr/local/bin/ziti-ssh-host run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Debian control file
install -d "${PKG_DIR}/DEBIAN"
cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Depends: systemd, openssh-server
Description: Ziti SSH host proxy daemon
 Enrolls an SSH host into an OpenZiti network, configures sshd to trust
 the Ziti CA, and proxies inbound Ziti connections to the local sshd.
 Port 22 is never exposed externally; all access is through the Ziti
 overlay. Run "ziti-ssh-host enroll --jwt <path>" once, then start the
 service.
EOF

# postinst: create env file placeholder if absent, reload systemd
cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if [ ! -f /etc/ziti-ssh-host/env ]; then
    cat > /etc/ziti-ssh-host/env <<\ENVEOF
# ziti-ssh-host environment configuration
# Uncomment and set these variables before starting the service.

# Path to the enrolled Ziti identity file (written by: ziti-ssh-host enroll --jwt)
#ZITI_IDENTITY=/etc/ziti-ssh-host/identity.json

# Ziti service name to bind as SSH host (must match the service created on the controller)
#ZITI_SSH_SERVICE=ssh

# MODE controls how SSH connections are handled:
#
#   shared (default): all connections authenticate as a single shared Linux account.
#     The account (e.g. ziggy) must already exist on this host.
#     Set ZITI_SSH_MODE=shared (or leave unset).
#
#   per-identity: each connecting Ziti identity gets its own ephemeral Linux account,
#     created automatically on first connection and removed when the last session closes.
#     Set ZITI_SSH_MODE=per-identity on BOTH ziti-ssh-host AND ziti-ssh-ca.
#
#ZITI_SSH_MODE=shared

# SUDOERS — optional sudo rule granted to per-identity users on connect.
# Only applies when ZITI_SSH_MODE=per-identity.
# Leave unset for no sudo access. The rule is written to /etc/sudoers.d/<username>.
# Example (full passwordless sudo):
#ZITI_SUDOERS_RULE=ALL=(ALL) NOPASSWD:ALL

# USER_CLEANUP — whether to delete the Linux user and sudoers file on disconnect.
# false (default): persistent users — account remains after disconnect.
# true: ephemeral users — account removed when last session closes.
#ZITI_USER_CLEANUP=false
ENVEOF
    chmod 640 /etc/ziti-ssh-host/env
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "${PKG_DIR}" \
    "${DIST_DIR}/${PKG}_${VERSION}_${ARCH}.deb"

log "Created ${DIST_DIR}/${PKG}_${VERSION}_${ARCH}.deb"

# ---------------------------------------------------------------------------
# Package: ziti-ssh
# ---------------------------------------------------------------------------

log "Packaging ziti-ssh..."

PKG="ziti-ssh"
PKG_DIR="${STAGING_DIR}/${PKG}"

# Binary
install -D -m 0755 \
    "${STAGING_DIR}/binaries/ziti-ssh" \
    "${PKG_DIR}/usr/local/bin/ziti-ssh"

# Debian control file
install -d "${PKG_DIR}/DEBIAN"
cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Depends: openssh-client
Description: Ziti SSH client with certificate-based authentication
 A full SSH client that operates over an OpenZiti network. Certificates are
 obtained from the ziti-ssh-ca service and cached in ~/.ssh/<key>-cert.pub.
 They are refreshed automatically when fewer than 5 minutes of validity
 remain.
 .
 Subcommands: connect (default), sign, enroll, list, mfa.
 .
 Configuration is read from ~/.config/ziti-ssh/config.yaml (XDG_CONFIG_HOME
 is respected). No long-lived credentials are stored on SSH hosts.
EOF

# postinst: no systemd service for a CLI tool. The config directory cannot be
# created here reliably (we do not know the target user). Document it instead.
cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

# ziti-ssh stores its config in ~/.config/ziti-ssh/config.yaml.
# Create that directory the first time you run ziti-ssh, or manually:
#   mkdir -p ~/.config/ziti-ssh
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "${PKG_DIR}" \
    "${DIST_DIR}/${PKG}_${VERSION}_${ARCH}.deb"

log "Created ${DIST_DIR}/${PKG}_${VERSION}_${ARCH}.deb"

# ---------------------------------------------------------------------------
# Package: ziti-scp
# ---------------------------------------------------------------------------

log "Packaging ziti-scp..."

PKG="ziti-scp"
PKG_DIR="${STAGING_DIR}/${PKG}"

# Binary
install -D -m 0755 \
    "${STAGING_DIR}/binaries/ziti-scp" \
    "${PKG_DIR}/usr/local/bin/ziti-scp"

# Debian control file
install -d "${PKG_DIR}/DEBIAN"
cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Depends: openssh-client
Description: Ziti SCP file copy tool with certificate-based authentication
 A secure file copy tool that operates over an OpenZiti network using the SFTP
 subsystem. Mirrors scp(1) behaviour but all traffic flows through the Ziti
 overlay — port 22 is never exposed externally. Shares the same identity,
 certificate, and configuration infrastructure as ziti-ssh.
 .
 Usage: ziti-scp [flags] <src>... <dst>
 .
 Configuration is read from ~/.config/ziti-ssh/config.yaml (XDG_CONFIG_HOME
 is respected). No long-lived credentials are stored on SSH hosts.
EOF

# postinst: no systemd service for a CLI tool.
cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

# ziti-scp shares its config with ziti-ssh at ~/.config/ziti-ssh/config.yaml.
# Create that directory the first time you run ziti-ssh or ziti-scp, or manually:
#   mkdir -p ~/.config/ziti-ssh
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "${PKG_DIR}" \
    "${DIST_DIR}/${PKG}_${VERSION}_${ARCH}.deb"

log "Created ${DIST_DIR}/${PKG}_${VERSION}_${ARCH}.deb"

# ---------------------------------------------------------------------------
# Copy binaries to repo root for local testing
# ---------------------------------------------------------------------------

log "Copying binaries to repo root for local testing..."
cp "${STAGING_DIR}/binaries/ziti-ssh-ca"   "${REPO_ROOT}/ziti-ssh-ca"
cp "${STAGING_DIR}/binaries/ziti-ssh-host" "${REPO_ROOT}/ziti-ssh-host"
cp "${STAGING_DIR}/binaries/ziti-ssh"      "${REPO_ROOT}/ziti-ssh"
cp "${STAGING_DIR}/binaries/ziti-scp"      "${REPO_ROOT}/ziti-scp"

# ---------------------------------------------------------------------------
# Cleanup and summary
# ---------------------------------------------------------------------------

rm -rf "${STAGING_DIR}"

log "Done."
log ""
log "Packages:"
ls -lh "${DIST_DIR}/"*_"${VERSION}"_"${ARCH}".deb
log ""
log "Binaries (repo root):"
ls -lh "${REPO_ROOT}/ziti-ssh-ca" "${REPO_ROOT}/ziti-ssh-host" "${REPO_ROOT}/ziti-ssh" "${REPO_ROOT}/ziti-scp"
