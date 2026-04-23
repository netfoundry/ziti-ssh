#!/usr/bin/env bash
# suites/ziti-ssh/scripts/install-ca.sh
#
# Controller post_install: installs and starts ziti-ssh-ca on ctrl-0.
#
# This script runs DIRECTLY ON ctrl-0 (not via an intermediate VM), so it has
# filesystem access to the controller's PKI without any additional SSH hop.
# ziti-ssh-ca uses the controller's intermediate CA private key to sign
# short-lived SSH certificates for connecting clients.
#
# Prerequisites:
#   /tmp/ziti-ssh-ca.deb — staged by the suite runner before this script runs
#
# Environment variables (injected by ziti-test-suite):
#   ZITI_CTRL_URL       — controller management API URL (https://host:port)
#   ZITI_ADMIN_PASSWORD — controller admin password
#
# Exit codes: 0 on success; non-zero on any failure (set -euo pipefail).

set -euo pipefail

log() {
    printf '[%s] [install-ca] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

# ---------------------------------------------------------------------------
# Validate required environment variables
# ---------------------------------------------------------------------------
: "${ZITI_CTRL_URL:?ZITI_CTRL_URL is required}"
: "${ZITI_ADMIN_PASSWORD:?ZITI_ADMIN_PASSWORD is required}"

JWT_FILE=/tmp/ssh-ca-server.jwt
trap 'rm -f "${JWT_FILE}"' EXIT

# ---------------------------------------------------------------------------
# 1) Install the ziti-ssh-ca package staged by the suite runner.
# ---------------------------------------------------------------------------
log "Installing ziti-ssh-ca"
sudo apt-get install -y /tmp/ziti-ssh-ca.deb

# ---------------------------------------------------------------------------
# 2) Locate the intermediate CA private key.
#    openziti-controller bootstrap writes the PKI under /var/lib/ziti-controller.
#    Try known paths; fall back to a filesystem search if neither exists.
# ---------------------------------------------------------------------------
CA_KEY=""
for candidate in \
    "/var/lib/ziti-controller/pki/intermediate/keys/intermediate.key" \
    "/var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key"; do
    if sudo test -f "${candidate}"; then
        CA_KEY="${candidate}"
        break
    fi
done
if [[ -z "${CA_KEY}" ]]; then
    CA_KEY=$(sudo find /var/lib/ziti-controller/pki -name "*.key" 2>/dev/null \
        | grep -i intermediate | head -1 || true)
fi
if [[ -z "${CA_KEY}" ]]; then
    log "ERROR: could not find intermediate CA key under /var/lib/ziti-controller/pki"
    exit 1
fi
log "Using CA key: ${CA_KEY}"

# ---------------------------------------------------------------------------
# 3) Register the ziti-ssh-host.v1 config type on the controller.
#    Required so the controller can deliver per-host permission configs to
#    ziti-ssh-host instances.  One-time idempotent operation.
# ---------------------------------------------------------------------------
CTRL_HOST=$(echo "${ZITI_CTRL_URL}" | sed 's|https://||' | cut -d/ -f1)
log "Registering ziti-ssh-host.v1 config type on ${CTRL_HOST}"
ziti-ssh-ca config apply \
    --controller "${CTRL_HOST}" \
    --username admin \
    --password "${ZITI_ADMIN_PASSWORD}" \
    --insecure

# ---------------------------------------------------------------------------
# 4) Authenticate to the controller and create the ssh-ca-server identity.
#    Role attribute "ssh-ca-servers" matches the bind-ssh-ca service policy.
# ---------------------------------------------------------------------------
log "Authenticating to controller ${ZITI_CTRL_URL}"
SESSION_TOKEN=$(curl --silent --fail --insecure \
    --request POST \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"admin\",\"password\":\"${ZITI_ADMIN_PASSWORD}\"}" \
    "${ZITI_CTRL_URL}/edge/management/v1/authenticate?method=password" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['token'])")

log "Creating ssh-ca-server identity (delete first for idempotency)"
EXISTING_ID=$(curl --silent --insecure \
    --header "zt-session: ${SESSION_TOKEN}" \
    "${ZITI_CTRL_URL}/edge/management/v1/identities?filter=name%3D%22ssh-ca-server%22" \
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
    --data '{"name":"ssh-ca-server","type":"Default","roleAttributes":["ssh-ca-servers"],"isAdmin":false,"enrollment":{"ott":true}}' \
    "${ZITI_CTRL_URL}/edge/management/v1/identities" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])")

log "Retrieving enrollment JWT for identity ${IDENTITY_ID}"
JWT=$(curl --silent --fail --insecure \
    --header "zt-session: ${SESSION_TOKEN}" \
    "${ZITI_CTRL_URL}/edge/management/v1/identities/${IDENTITY_ID}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['enrollment']['ott']['jwt'])")
printf '%s' "${JWT}" > "${JWT_FILE}"

# ---------------------------------------------------------------------------
# 5) Enroll the identity and write configuration files.
# ---------------------------------------------------------------------------
log "Enrolling ssh-ca-server identity"
sudo mkdir -p /etc/ziti-ssh-ca
sudo ziti-ssh-ca enroll \
    --jwt "${JWT_FILE}" \
    --out /etc/ziti-ssh-ca/identity.json

# ziti-ssh-ca runs as the ziti-controller system user so it can read the
# intermediate CA private key (which bootstrap.bash owns by that user).
sudo chown -R ziti-controller: /etc/ziti-ssh-ca
sudo chmod 750 /etc/ziti-ssh-ca
sudo chmod 600 /etc/ziti-ssh-ca/identity.json

log "Writing environment file"
sudo tee /etc/ziti-ssh-ca/env > /dev/null <<ENVEOF
ZITI_IDENTITY=/etc/ziti-ssh-ca/identity.json
ZITI_CA_KEY=${CA_KEY}
ZITI_CA_SERVICE=ssh-ca
ZITI_SSH_MODE=shared
ZITI_SSH_PRINCIPAL=ziggy
ENVEOF
sudo chown ziti-controller: /etc/ziti-ssh-ca/env
sudo chmod 640 /etc/ziti-ssh-ca/env

# ---------------------------------------------------------------------------
# 6) Install and start the systemd unit.
# ---------------------------------------------------------------------------
log "Writing ziti-ssh-ca systemd unit"
sudo tee /etc/systemd/system/ziti-ssh-ca.service > /dev/null <<'UNITEOF'
[Unit]
Description=Ziti SSH Certificate Authority
After=network-online.target ziti-controller.service
Wants=network-online.target

[Service]
Type=notify
User=ziti-controller
EnvironmentFile=/etc/ziti-ssh-ca/env
ExecStart=/usr/local/bin/ziti-ssh-ca
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF

sudo systemctl daemon-reload
sudo systemctl enable --now ziti-ssh-ca

log "install-ca.sh complete — ziti-ssh-ca is running on ctrl-0"
