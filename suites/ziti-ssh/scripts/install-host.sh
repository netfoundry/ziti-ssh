#!/usr/bin/env bash
# suites/ziti-ssh/scripts/install-host.sh
#
# WARNING: TEST SUITE ONLY — not for production use.
# curl calls use --insecure and credentials are passed in environment variables.
#
# Edge router post_install: installs and starts ziti-ssh-host on each ER.
#
# This script runs on each edge router VM.  With count: 2 in the suite
# topology, two ER instances each run this script independently.  Each ER
# creates its own Ziti identity (named "ssh-host-<hostname>") and registers
# as a terminator on the "ssh" service — giving clients two load-balanced
# targets to dial.
#
# ziti-ssh-host proxies inbound Ziti connections on the "ssh" service to the
# ER's own local sshd (127.0.0.1:22).  All connections authenticate via SSH
# certificate, so no SSH credentials are stored on the ER host.
#
# Prerequisites:
#   /tmp/ziti-ssh-host.deb — staged by the suite runner before this script runs
#
# Environment variables (injected by ziti-test-suite):
#   ZITI_CTRL_URL       — controller management API URL
#   ZITI_ADMIN_PASSWORD — controller admin password
#
# Exit codes: 0 on success; non-zero on any failure (set -euo pipefail).

set -euo pipefail

log() {
    printf '[%s] [install-host] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

# ---------------------------------------------------------------------------
# Validate required environment variables
# ---------------------------------------------------------------------------
: "${ZITI_CTRL_URL:?ZITI_CTRL_URL is required}"
: "${ZITI_ADMIN_PASSWORD:?ZITI_ADMIN_PASSWORD is required}"

JWT_FILE=/tmp/ssh-host.jwt
trap 'rm -f "${JWT_FILE}"' EXIT

# Use the EC2 short hostname as the identity name suffix so each ER gets a
# unique, stable identity even though all instances run the same script.
IDENTITY_NAME="ssh-host-$(hostname -s)"
log "Host identity name: ${IDENTITY_NAME}"

# ---------------------------------------------------------------------------
# 1) Ensure sshd is running.
#    EC2 Ubuntu 24.04 images ship with openssh-server; just confirm the
#    service is active (the framework already proved it by SSHing in).
# ---------------------------------------------------------------------------
sudo systemctl enable --now ssh

# ---------------------------------------------------------------------------
# 2) Create the shared "ziggy" Linux user.
#    In shared mode, ziti-ssh-ca signs every certificate with the principal
#    "ziggy".  sshd looks up this principal in authorized principals — so the
#    user must exist on every SSH host.
# ---------------------------------------------------------------------------
log "Ensuring 'ziggy' user exists"
sudo useradd --create-home --shell /bin/bash ziggy 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3) Install the ziti-ssh-host package staged by the suite runner.
# ---------------------------------------------------------------------------
log "Installing ziti-ssh-host"
sudo apt-get install -y /tmp/ziti-ssh-host.deb

# ---------------------------------------------------------------------------
# 4) Create the host identity on the controller.
#    Role attribute "ssh-hosts" matches the bind-ssh service policy so this
#    identity is authorised to bind (host) the "ssh" service.
# ---------------------------------------------------------------------------
log "Authenticating to controller ${ZITI_CTRL_URL}"
SESSION_TOKEN=$(curl --silent --fail --insecure \
    --request POST \
    --header "Content-Type: application/json" \
    --data "$(python3 -c "import json,sys; print(json.dumps({'username':'admin','password':sys.argv[1]}))" "${ZITI_ADMIN_PASSWORD}")" \
    "${ZITI_CTRL_URL}/edge/management/v1/authenticate?method=password" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['token'])")

log "Creating identity ${IDENTITY_NAME} (delete first for idempotency)"
EXISTING_ID=$(curl --silent --insecure \
    --header "zt-session: ${SESSION_TOKEN}" \
    "${ZITI_CTRL_URL}/edge/management/v1/identities?filter=name%3D%22${IDENTITY_NAME}%22" \
    | python3 -c "
import json,sys
d = json.load(sys.stdin).get('data') or []
print(d[0]['id'] if d else '')
" 2>/dev/null || echo "")
if [[ -n "${EXISTING_ID}" ]]; then
    curl --silent --insecure --request DELETE \
        --header "zt-session: ${SESSION_TOKEN}" \
        "${ZITI_CTRL_URL}/edge/management/v1/identities/${EXISTING_ID}" || true
fi

IDENTITY_ID=$(curl --silent --fail --insecure \
    --request POST \
    --header "Content-Type: application/json" \
    --header "zt-session: ${SESSION_TOKEN}" \
    --data "$(python3 -c "import json,sys; print(json.dumps({'name':sys.argv[1],'type':'Default','roleAttributes':['ssh-hosts'],'isAdmin':False,'enrollment':{'ott':True}}))" "${IDENTITY_NAME}")" \
    "${ZITI_CTRL_URL}/edge/management/v1/identities" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])")

log "Retrieving enrollment JWT for identity ${IDENTITY_ID}"
JWT=$(curl --silent --fail --insecure \
    --header "zt-session: ${SESSION_TOKEN}" \
    "${ZITI_CTRL_URL}/edge/management/v1/identities/${IDENTITY_ID}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['enrollment']['ott']['jwt'])")
printf '%s' "${JWT}" > "${JWT_FILE}"

# ---------------------------------------------------------------------------
# 5) Enroll the identity.
#    ziti-ssh-host enroll also fetches the CA public key from the controller
#    and writes TrustedUserCAKeys to sshd_config.d, then reloads sshd.
# ---------------------------------------------------------------------------
log "Enrolling ${IDENTITY_NAME}"
sudo mkdir -p /etc/ziti-ssh-host
# ziti-ssh-host enroll writes to /etc/ziti-ssh-host/identity.json by default.
# Use --identity to override or rely on the ZITI_IDENTITY env var; the default
# matches the EnvironmentFile entry in the systemd unit below, so no flag needed.
sudo ziti-ssh-host enroll \
    --jwt "${JWT_FILE}"

# ---------------------------------------------------------------------------
# 6) Write environment file and systemd unit, then start the service.
#    ZITI_SSH_MODE=shared must match ziti-ssh-ca's mode — both must agree on
#    whether certificates carry a shared principal ("ziggy") or a per-identity
#    derived username.
# ---------------------------------------------------------------------------
log "Writing ziti-ssh-host environment + systemd unit"
sudo tee /etc/ziti-ssh-host/env > /dev/null <<'ENVEOF'
ZITI_IDENTITY=/etc/ziti-ssh-host/identity.json
ZITI_SSH_SERVICE=ssh
ZITI_SSH_MODE=shared
ENVEOF

sudo tee /etc/systemd/system/ziti-ssh-host.service > /dev/null <<'UNITEOF'
[Unit]
Description=Ziti SSH Host
After=network-online.target ssh.service
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=-/etc/ziti-ssh-host/env
ExecStart=/usr/local/bin/ziti-ssh-host run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF

sudo systemctl daemon-reload
sudo systemctl enable --now ziti-ssh-host

log "install-host.sh complete — ziti-ssh-host running as ${IDENTITY_NAME}"
