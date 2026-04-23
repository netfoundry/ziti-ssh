#!/usr/bin/env bash
# suites/ziti-ssh/tests/test.sh
#
# End-to-end test for ziti-ssh.  Runs on the GitHub Actions runner and
# exercises the full stack:
#
#   Service discovery — ziti-ssh list
#   CA signing        — ziti-ssh sign (client → ssh-ca → ctrl-0)
#   SSH connect       — ziti-ssh ziggy@<host> to each ER by terminator name
#   SCP transfer      — ziti-scp upload and download
#
# The test SSHs into the client VM (ZTS_TEST_TARGET_IP) and drives ziti-ssh
# from there.  ER identity names are read from ~/.config/ziti-ssh/ssh-hosts.txt
# on the client VM, written by install-client.sh during provisioning.
#
# Environment variables (injected by ziti-test-suite):
#   ZTS_TEST_TARGET_IP  — IP of the client VM (target: "client")
#   ZTS_SSH_PRIVATE_KEY — PEM private key for SSH to all VMs
#   ZTS_SSH_USER        — SSH user (ubuntu)
#
# Exit codes: 0 = all tests passed; 1 = one or more tests failed.

set -euo pipefail

log() {
    printf '[%s] [test] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

pass() { log "  PASS: $*"; }
fail() { log "  FAIL: $*"; FAILED=1; }
FAILED=0

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
: "${ZTS_TEST_TARGET_IP:?ZTS_TEST_TARGET_IP is required (target: client)}"
: "${ZTS_SSH_PRIVATE_KEY:?ZTS_SSH_PRIVATE_KEY is required}"
: "${ZTS_SSH_USER:=${ZTS_SSH_USER:-ubuntu}}"

CLIENT_IP="${ZTS_TEST_TARGET_IP}"
SSH_KEY=/tmp/zts-test-key.pem
printf '%s' "${ZTS_SSH_PRIVATE_KEY}" > "${SSH_KEY}"
chmod 600 "${SSH_KEY}"
trap 'rm -f "${SSH_KEY}"' EXIT

SSH_OPTS=(
    -i "${SSH_KEY}"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o ConnectTimeout=30
)

run_on_client() {
    ssh "${SSH_OPTS[@]}" "${ZTS_SSH_USER}@${CLIENT_IP}" "$@"
}

log "Client VM: ${CLIENT_IP}"

# ---------------------------------------------------------------------------
# Phase 1: wait for Ziti services to become visible.
#
# ziti-ssh list does not require a certificate — it just proves the client
# identity is enrolled and the Ziti fabric is routing.  Waiting for this
# before attempting cert signing or SSH avoids spurious "service not found"
# failures when the network is still converging.
# ---------------------------------------------------------------------------
log "Waiting for Ziti services to become visible (up to 5 min)..."
MAX_WAIT=300
ELAPSED=0
POLL=15
READY=0

while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    LIST=$(run_on_client 'ziti-ssh list 2>/dev/null' || true)
    if echo "${LIST}" | grep -q 'ssh-ca' && echo "${LIST}" | grep -q '^ssh'; then
        READY=1
        break
    fi
    log "  services not visible yet (${ELAPSED}s elapsed), retrying in ${POLL}s..."
    sleep ${POLL}
    ELAPSED=$((ELAPSED + POLL))
done

if [[ ${READY} -eq 0 ]]; then
    log "ERROR: Ziti services did not become visible within ${MAX_WAIT}s"
    exit 1
fi
log "Ziti services are visible"

# ---------------------------------------------------------------------------
# Phase 2: read ssh-host identity names cached by install-client.sh.
#
# install-client.sh queries the controller for identities with the ssh-hosts
# role attribute and writes their names to ~/.config/ziti-ssh/ssh-hosts.txt.
# Those names are also the terminator addresses registered by ziti-ssh-host.
# ---------------------------------------------------------------------------
log "Reading ssh-host identities from client VM..."
mapfile -t SSH_HOST_NAMES < <(run_on_client 'grep -v "^$" ~/.config/ziti-ssh/ssh-hosts.txt 2>/dev/null' || true)

if [[ ${#SSH_HOST_NAMES[@]} -eq 0 ]]; then
    log "ERROR: no ssh-host identities found in ~/.config/ziti-ssh/ssh-hosts.txt"
    exit 1
fi
log "Found ${#SSH_HOST_NAMES[@]} ssh-host(s): ${SSH_HOST_NAMES[*]}"

# ---------------------------------------------------------------------------
# Test 1: Service list
#
# Confirm both the ssh-ca signing service and the ssh host service are
# visible to the enrolled client identity.
# ---------------------------------------------------------------------------
log "Test 1: service discovery (ziti-ssh list)"
LIST_OUTPUT=$(run_on_client 'ziti-ssh list' 2>/tmp/list-err.txt) || {
    fail "ziti-ssh list failed"
    cat /tmp/list-err.txt >&2
}
if echo "${LIST_OUTPUT}" | grep -q 'ssh-ca' && echo "${LIST_OUTPUT}" | grep -q '^ssh'; then
    pass "both ssh-ca and ssh services visible"
    log "  output: $(echo "${LIST_OUTPUT}" | tr '\n' '  ')"
else
    fail "expected ssh-ca and ssh in list, got: '${LIST_OUTPUT}'"
fi

# ---------------------------------------------------------------------------
# Test 2: Certificate signing
#
# ziti-ssh sign dials the ssh-ca service on the controller, submits the
# client's Ed25519 public key, and writes the signed cert.  This must
# succeed before any connect test since ziti-ssh connect relies on the cert.
# ---------------------------------------------------------------------------
log "Test 2: certificate signing (ziti-ssh sign)"
if run_on_client 'ziti-ssh sign' > /tmp/sign-output.txt 2>&1; then
    if run_on_client 'test -f ~/.ssh/id_ed25519-cert.pub'; then
        pass "cert signed and written to ~/.ssh/id_ed25519-cert.pub"
    else
        fail "ziti-ssh sign succeeded but cert file not found"
    fi
else
    fail "ziti-ssh sign failed"
    cat /tmp/sign-output.txt >&2
fi

# ---------------------------------------------------------------------------
# Test 3+: SSH connect to each ER by terminator name
#
# Each ziti-ssh-host instance registers its Ziti identity name as its
# terminator address.  Dialing ziggy@<identity-name> routes to that
# specific ER — confirming per-host routing, not just load-balancing.
# ---------------------------------------------------------------------------
for HOST in "${SSH_HOST_NAMES[@]}"; do
    log "Test: SSH connect to ${HOST}"
    OUTPUT=$(run_on_client "ziti-ssh ziggy@${HOST} -- hostname" 2>/tmp/connect-err.txt) || {
        fail "SSH connect to ${HOST} failed"
        cat /tmp/connect-err.txt >&2
        continue
    }
    if [[ -n "${OUTPUT:-}" ]]; then
        pass "SSH connect to ${HOST}: remote hostname '${OUTPUT}'"
    else
        fail "SSH connect to ${HOST}: no output"
    fi
done

# ---------------------------------------------------------------------------
# SCP upload and content verification (using first ssh-host)
# ---------------------------------------------------------------------------
FIRST_HOST="${SSH_HOST_NAMES[0]}"
SCP_PAYLOAD="ziti-scp-test-$(date -u '+%Y%m%dT%H%M%SZ')"

log "Test: SCP upload to ${FIRST_HOST}"
run_on_client "echo '${SCP_PAYLOAD}' > /tmp/zts-upload.txt" || {
    fail "failed to create upload file on client VM"
    FAILED=1
}

run_on_client "ziti-scp /tmp/zts-upload.txt ziggy@${FIRST_HOST}:/tmp/zts-received.txt" > /tmp/scp-err.txt 2>&1 || {
    fail "ziti-scp upload to ${FIRST_HOST} failed"
    cat /tmp/scp-err.txt >&2
}

log "Test: verify uploaded file content via SSH"
RECEIVED=$(run_on_client "ziti-ssh ziggy@${FIRST_HOST} -- cat /tmp/zts-received.txt 2>/dev/null" || echo "") || true
if [[ "${RECEIVED:-}" == "${SCP_PAYLOAD}" ]]; then
    pass "SCP file content matches: '${RECEIVED}'"
else
    fail "SCP content mismatch: expected '${SCP_PAYLOAD}', got '${RECEIVED:-<empty>}'"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [[ ${FAILED} -eq 0 ]]; then
    log "All tests PASSED"
    exit 0
else
    log "One or more tests FAILED"
    exit 1
fi
