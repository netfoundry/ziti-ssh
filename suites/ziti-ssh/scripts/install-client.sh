#!/usr/bin/env bash
# suites/ziti-ssh/scripts/install-client.sh
#
# Client VM post_install: installs ziti-ssh and ziti-scp, enrolls an identity,
# and writes the client config file.
#
# The enrolled identity carries the "ssh-clients" role attribute, which grants
# it dial access to both the "ssh-ca" service (for cert signing) and the "ssh"
# service (for tunneled SSH sessions to the ER hosts).
#
# Prerequisites:
#   /tmp/ziti-ssh.deb  — staged by the suite runner before this script runs
#   /tmp/ziti-scp.deb  — staged by the suite runner before this script runs
#
# Environment variables (injected by ziti-test-suite):
#   ZITI_CTRL_URL       — controller management API URL
#   ZITI_ADMIN_PASSWORD — controller admin password
#
# Exit codes: 0 on success; non-zero on any failure (set -euo pipefail).

set -euo pipefail

log() {
    printf '[%s] [install-client] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

# ---------------------------------------------------------------------------
# Validate required environment variables
# ---------------------------------------------------------------------------
: "${ZITI_CTRL_URL:?ZITI_CTRL_URL is required}"
: "${ZITI_ADMIN_PASSWORD:?ZITI_ADMIN_PASSWORD is required}"

JWT_FILE=/tmp/ssh-client.jwt
trap 'rm -f "${JWT_FILE}"' EXIT

# ---------------------------------------------------------------------------
# 1) Install ziti-ssh and ziti-scp packages staged by the suite runner.
# ---------------------------------------------------------------------------
for BINARY in ziti-ssh ziti-scp; do
    log "Installing ${BINARY}"
    sudo apt-get install -y "/tmp/${BINARY}.deb"
done

# ---------------------------------------------------------------------------
# 2) Generate an Ed25519 SSH key pair for cert signing.
#    ziti-ssh sign reads the public key at ssh_key_path.pub and requests a
#    signed certificate from the CA.  ziti-ssh connect uses the private key
#    + cert to authenticate to sshd on the ER hosts.
# ---------------------------------------------------------------------------
log "Generating SSH key pair"
mkdir -p "${HOME}/.ssh"
chmod 700 "${HOME}/.ssh"
if [[ ! -f "${HOME}/.ssh/id_ed25519" ]]; then
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q
fi

# ---------------------------------------------------------------------------
# 3) Create the client identity on the controller.
#    "ssh-clients" grants dial access to both ssh-ca (cert signing) and ssh
#    (tunneled SSH sessions to ER hosts).
# ---------------------------------------------------------------------------
log "Authenticating to controller ${ZITI_CTRL_URL}"
SESSION_TOKEN=$(curl --silent --fail --insecure \
    --request POST \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"admin\",\"password\":\"${ZITI_ADMIN_PASSWORD}\"}" \
    "${ZITI_CTRL_URL}/edge/management/v1/authenticate?method=password" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['token'])")

log "Creating ssh-client-vm identity (delete first for idempotency)"
EXISTING_ID=$(curl --silent --insecure \
    --header "zt-session: ${SESSION_TOKEN}" \
    "${ZITI_CTRL_URL}/edge/management/v1/identities?filter=name%3D%22ssh-client-vm%22" \
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
    --data '{"name":"ssh-client-vm","type":"Default","roleAttributes":["ssh-clients"],"isAdmin":false,"enrollment":{"ott":true}}' \
    "${ZITI_CTRL_URL}/edge/management/v1/identities" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])")

log "Retrieving enrollment JWT for identity ${IDENTITY_ID}"
JWT=$(curl --silent --fail --insecure \
    --header "zt-session: ${SESSION_TOKEN}" \
    "${ZITI_CTRL_URL}/edge/management/v1/identities/${IDENTITY_ID}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['enrollment']['ott']['jwt'])")
printf '%s' "${JWT}" > "${JWT_FILE}"

# ---------------------------------------------------------------------------
# 4) Enroll the identity.
#    Store the identity JSON under ~/.config/ziti-ssh/ so non-root invocations
#    of ziti-ssh and ziti-scp can find it without sudo.
# ---------------------------------------------------------------------------
CONFIG_DIR="${HOME}/.config/ziti-ssh"
log "Enrolling ssh-client-vm identity into ${CONFIG_DIR}"
mkdir -p "${CONFIG_DIR}"
ziti-ssh enroll \
    --jwt "${JWT_FILE}" \
    --out "${CONFIG_DIR}/ssh-client-vm.json"

# ---------------------------------------------------------------------------
# 5) Write the ziti-ssh config file.
#    Fields:
#      identity     — path to the enrolled Ziti identity JSON
#      ca_service   — Ziti service name for the CA (cert signing)
#      ssh_key_path — Ed25519 key whose public key is submitted for signing
#      mode         — "shared" matches ziti-ssh-ca and ziti-ssh-host modes
#
#    Intentionally no ssh_service: without that field, the positional
#    argument to "ziti-ssh connect" is the Ziti service name to dial
#    directly (e.g. "ziti-ssh ziggy@ssh"), which is the simpler form and
#    lets the Ziti fabric load-balance across all ziti-ssh-host ERs.
# ---------------------------------------------------------------------------
log "Writing ziti-ssh config file"
cat > "${CONFIG_DIR}/config.yaml" <<CONFEOF
identity: ${HOME}/.config/ziti-ssh/ssh-client-vm.json
ca_service: ssh-ca
ssh_key_path: ${HOME}/.ssh/id_ed25519
mode: shared
CONFEOF

# ---------------------------------------------------------------------------
# 6) Discover ssh-host identity names and cache them for the test script.
#    ziti-ssh-host registers its Ziti identity name as its terminator address,
#    so these names are what the test passes to ziti-ssh connect.
#
#    ER post_install scripts run concurrently, so the identities may not yet
#    exist when this runs.  Retry until we find all expected hosts (up to 2 min).
# ---------------------------------------------------------------------------
log "Discovering ssh-host identities (waiting for all ERs to register)..."
SSH_HOSTS_FILE="${CONFIG_DIR}/ssh-hosts.txt"
MAX_WAIT_HOSTS=120
ELAPSED_HOSTS=0

while [[ ${ELAPSED_HOSTS} -lt ${MAX_WAIT_HOSTS} ]]; do
    HOSTS=$(curl --silent --fail --insecure \
        --header "zt-session: ${SESSION_TOKEN}" \
        "${ZITI_CTRL_URL}/edge/management/v1/identities?limit=100" \
        | python3 -c "
import json,sys
data = json.load(sys.stdin).get('data') or []
for d in data:
    if 'ssh-hosts' in (d.get('roleAttributes') or []):
        print(d['name'])
" 2>/dev/null || true)
    HOST_COUNT=$(echo "${HOSTS}" | grep -c '[^[:space:]]' || true)
    if [[ ${HOST_COUNT} -ge 2 ]]; then
        break
    fi
    log "  found ${HOST_COUNT} ssh-host(s), waiting for 2..."
    sleep 10
    ELAPSED_HOSTS=$((ELAPSED_HOSTS + 10))
done

printf '%s\n' "${HOSTS}" > "${SSH_HOSTS_FILE}"
log "Cached ssh-hosts: $(cat "${SSH_HOSTS_FILE}" | tr '\n' ' ')"

log "install-client.sh complete"
log "  identity:   ${CONFIG_DIR}/ssh-client-vm.json"
log "  config:     ${CONFIG_DIR}/config.yaml"
log "  ssh key:    ${HOME}/.ssh/id_ed25519"
log "  ssh-hosts:  ${SSH_HOSTS_FILE}"
