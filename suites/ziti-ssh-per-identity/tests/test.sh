#!/usr/bin/env bash
# suites/ziti-ssh-per-identity/tests/test.sh
#
# End-to-end tests for ziti-ssh per-identity mode. Runs on the test runner;
# drives the client VM and both SSH hosts (edge routers) over SSH, and manages
# ziti-ssh-host.v1 configs through the controller's management API.
#
# The client identity is "ssh-client-vm"; its derived Linux username (the
# certificate principal) is the same string.
#
# Covered:
#   1. Account creation: registry entry, ziti-ssh-managed, configured groups,
#      authorized_keys disabled; default SSH user = certificate principal.
#   2. A user name other than the principal is refused by sshd.
#   3. Pre-existing local account with the derived name is not adopted (H3).
#   4. Host grant policy: "sudo" refused via "ssh", allowed via "ssh-ops"
#      (ZITI_ALLOW_GROUPS=ssh-ops:sudo); sudoers_rule refused (no opt-in).
#   5. Live reload: changed config applies on the next connection.
#   6. Config that fails to load fails closed.
#   7. Cross-service permission conflict rejected while a session is open (M2).
#   8. Disconnect clears groups and sudoers; account kept by default.
#   9. ZITI_TERMINATE_ON_DISCONNECT=true removes the crontab, ends background
#      processes and expires the account; the next connection re-enables it.
#  10. ZITI_USER_CLEANUP=true deletes the account on disconnect.
#
# Environment (from ziti-test-suite):
#   ZTS_TEST_TARGET_IP, ZTS_SSH_PRIVATE_KEY, ZTS_SSH_USER,
#   ZTS_CONTROLLER_URLS, ZTS_CONTROLLER_ADMIN_PASSWORD, ZTS_EDGE_ROUTER_IPS
#
# Exit codes: 0 = all tests passed; 1 = one or more tests failed.

set -euo pipefail

log() { printf '[%s] [test] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
pass() { log "  PASS: $*"; }
fail() { log "  FAIL: $*"; FAILED=1; }
FAILED=0

: "${ZTS_TEST_TARGET_IP:?ZTS_TEST_TARGET_IP is required (target: client)}"
: "${ZTS_SSH_PRIVATE_KEY:?ZTS_SSH_PRIVATE_KEY is required}"
: "${ZTS_CONTROLLER_URLS:?ZTS_CONTROLLER_URLS is required}"
: "${ZTS_CONTROLLER_ADMIN_PASSWORD:?ZTS_CONTROLLER_ADMIN_PASSWORD is required}"
: "${ZTS_EDGE_ROUTER_IPS:?ZTS_EDGE_ROUTER_IPS is required}"
: "${ZTS_SSH_USER:=ubuntu}"

CLIENT_IP="${ZTS_TEST_TARGET_IP}"
U="ssh-client-vm" # client identity name == derived username
SSH_KEY=$(mktemp)
printf '%s' "${ZTS_SSH_PRIVATE_KEY}" > "${SSH_KEY}"
chmod 600 "${SSH_KEY}"
trap 'rm -f "${SSH_KEY}"' EXIT
SSH_OPTS=(-i "${SSH_KEY}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=30)

on() { local ip=$1; shift; ssh "${SSH_OPTS[@]}" "${ZTS_SSH_USER}@${ip}" "$@"; }
on_client() { on "${CLIENT_IP}" "$@"; }

# ---------------------------------------------------------------------------
# Management API helpers (curl --insecure: test network with a private CA)
# ---------------------------------------------------------------------------
CTRL=$(python3 -c 'import json,os;print(json.loads(os.environ["ZTS_CONTROLLER_URLS"])[0])')
API="${CTRL}/edge/management/v1"
TOKEN=$(curl -sf --insecure -H 'Content-Type: application/json' \
    --data "$(python3 -c 'import json,os;print(json.dumps({"username":"admin","password":os.environ["ZTS_CONTROLLER_ADMIN_PASSWORD"]}))')" \
    "${API}/authenticate?method=password" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["token"])')
api() { # method path [json]
    curl -sf --insecure -X "$1" -H "zt-session: ${TOKEN}" -H 'Content-Type: application/json' \
        ${3:+--data "$3"} "${API}$2"
}
id_by_name() { # collection name
    api GET "/$1?filter=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote("name=\""+sys.argv[1]+"\""))' "$2")" |
        python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d[0]["id"] if d else "")'
}
CFG_TYPE=$(id_by_name config-types ziti-ssh-host.v1)
[[ -n "${CFG_TYPE}" ]] || { log "ERROR: config type ziti-ssh-host.v1 not registered"; exit 1; }

declare -A CFG_ID
# set_perms SERVICE PERMISSIONS_JSON — create or replace the service's config.
set_perms() {
    local svc=$1 perms=$2 body
    body=$(python3 -c 'import json,sys;print(json.dumps({"name":"zssh-"+sys.argv[1],"configTypeId":sys.argv[2],"data":{"permissions":json.loads(sys.argv[3])}}))' "${svc}" "${CFG_TYPE}" "${perms}")
    if [[ -z "${CFG_ID[$svc]:-}" ]]; then
        CFG_ID[$svc]=$(api POST /configs "${body}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["id"])')
        api PATCH "/services/$(id_by_name services "${svc}")" "{\"configs\":[\"${CFG_ID[$svc]}\"]}" >/dev/null
    else
        api PATCH "/configs/${CFG_ID[$svc]}" "$(python3 -c 'import json,sys;print(json.dumps({"data":{"permissions":json.loads(sys.argv[1])}}))' "${perms}")" >/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Hosts: map each edge router IP to its terminator (identity) name.
# ---------------------------------------------------------------------------
mapfile -t ER_IPS < <(python3 -c 'import json,os;print("\n".join(json.loads(os.environ["ZTS_EDGE_ROUTER_IPS"])["er"]))')
H1_IP=${ER_IPS[0]}; H2_IP=${ER_IPS[1]}
H1="ssh-host-$(on "${H1_IP}" hostname -s)"; H2="ssh-host-$(on "${H2_IP}" hostname -s)"
log "Hosts: ${H1} (${H1_IP}), ${H2} (${H2_IP}); client ${CLIENT_IP}"

host_log() { on "$1" "sudo journalctl -u ziti-ssh-host --no-pager -o cat --since '-${2:-2min}'"; }

# zssh SERVICE HOST 'CMD' — connect as the default user (cert principal) and
# run CMD on the SSH host. CMD is single-quoted so a ';' runs remotely, not on
# the client VM. (CMD must not contain single quotes.)
# On failure the client's last error lines are logged.
zssh() {
    local svc=$1 host=$2 rc=0; shift 2
    on_client "timeout 60 ziti-ssh connect --service ${svc} ${host} -- '$*' 2>/tmp/zssh.err" || rc=$?
    if (( rc != 0 )); then on_client 'tail -2 /tmp/zssh.err' 2>/dev/null | sed 's/^/      [client] /' >&2 || true; fi
    return "${rc}"
}

# until_ok SECONDS CMD... — retry until the command succeeds.
until_ok() {
    local deadline=$((SECONDS + $1)); shift
    until "$@"; do (( SECONDS < deadline )) || return 1; sleep 5; done
}

# ---------------------------------------------------------------------------
# Readiness: both services visible to the client, both hosts running.
# ---------------------------------------------------------------------------
log "Waiting for services ssh, ssh-ops and ssh-ca (up to 5 min)..."
services_ready() { local l; l=$(on_client 'ziti-ssh list 2>/dev/null' || true)
    grep -q '^ssh-ca' <<< "$l" && grep -q '^ssh-ops' <<< "$l" && grep -qE '^ssh +' <<< "$l"; }
until_ok 300 services_ready || { log "ERROR: services not visible"; exit 1; }
for ip in "${H1_IP}" "${H2_IP}"; do
    until_ok 120 on "${ip}" 'systemctl is-active --quiet ziti-ssh-host' ||
        { log "ERROR: ziti-ssh-host not active on ${ip}"; exit 1; }
done

# Baseline configs (attached before the first connection).
set_perms ssh '{"*": {"groups": ["zt-dev"]}}'
set_perms ssh-ops '{"*": {"groups": ["zt-ops", "sudo"]}}'
sleep 20 # hosts refresh services every 10s (ZSSH_SERVICE_REFRESH)

# ---------------------------------------------------------------------------
# 3. Pre-existing account on H2 is not adopted (before any connection to H2).
# ---------------------------------------------------------------------------
log "Test 3: pre-existing account with the derived name is refused (${H2})"
on "${H2_IP}" "sudo useradd -m ${U}"
if zssh ssh "${H2}" true 2>/dev/null; then
    fail "connected to a pre-existing account on ${H2}"
elif host_log "${H2_IP}" | grep -q 'refusing to manage pre-existing account'; then
    pass "pre-existing account refused (host log)"
else
    fail "connection failed but no 'pre-existing account' log on ${H2}"
fi

# ---------------------------------------------------------------------------
# 1. Account creation and default user.
# ---------------------------------------------------------------------------
log "Test 1: first connection creates and registers the account (${H1})"
has_dev() { zssh ssh "${H1}" 'id -Gn' 2>/dev/null | grep -qw zt-dev; }
until_ok 60 has_dev || true
OUT=$(zssh ssh "${H1}" 'id -un; id -Gn' 2>/dev/null || true)
if [[ "$(head -1 <<< "${OUT}")" == "${U}" ]]; then pass "default user is the certificate principal (${U})"
else fail "unexpected user: ${OUT}"; fi
if grep -qw zt-dev <<< "${OUT}" && grep -qw ziti-ssh-managed <<< "${OUT}"; then pass "groups: $(tail -1 <<< "${OUT}")"
else fail "groups missing (want zt-dev, ziti-ssh-managed): ${OUT}"; fi
if on "${H1_IP}" "sudo ziti-ssh-host users list" | grep -q "${U}"; then pass "account in ownership registry"
else fail "account not in ownership registry"; fi
AKF=$(on "${H1_IP}" "sudo sshd -T -C user=${U},host=localhost,addr=127.0.0.1 | grep -i '^authorizedkeysfile'")
if [[ "${AKF,,}" == "authorizedkeysfile none" ]]; then pass "authorized_keys disabled for ${U}"
else fail "authorizedkeysfile for ${U}: ${AKF}"; fi

# ---------------------------------------------------------------------------
# 2. A user other than the principal is refused.
# ---------------------------------------------------------------------------
log "Test 2: explicit user other than the principal is refused"
if on_client "timeout 60 ziti-ssh connect --service ssh ubuntu@${H1} -- true" 2>/dev/null; then
    fail "logged in as ubuntu with a ${U} certificate"
else pass "ubuntu@${H1} refused"; fi

# ---------------------------------------------------------------------------
# 4. Host grant policy.
# ---------------------------------------------------------------------------
log "Test 4: host grant policy"
OUT=$(zssh ssh-ops "${H1}" 'id -Gn' 2>/dev/null || true)
if grep -qw sudo <<< "${OUT}"; then pass "sudo granted via ssh-ops (opted in): ${OUT}"
else fail "sudo not granted via ssh-ops: ${OUT}"; fi
set_perms ssh '{"*": {"groups": ["sudo"]}}'
refused_sudo() { ! zssh ssh "${H1}" true 2>/dev/null && host_log "${H1_IP}" 1min | grep -q 'rejecting connection: permissions refused by host grant policy'; }
if until_ok 60 refused_sudo; then pass "sudo via ssh refused by the host grant policy"
else fail "sudo via ssh not refused"; fi
set_perms ssh '{"*": {"groups": ["zt-dev"], "sudoers_rule": "ALL=(ALL) NOPASSWD: /usr/bin/true"}}'
refused_rule() { ! zssh ssh "${H1}" true 2>/dev/null && host_log "${H1_IP}" 1min | grep -q 'rejecting connection: permissions refused by host grant policy'; }
if until_ok 60 refused_rule; then pass "sudoers_rule refused without ZITI_ALLOW_SUDOERS"
else fail "sudoers_rule not refused"; fi

# ---------------------------------------------------------------------------
# 5. Live reload.
# ---------------------------------------------------------------------------
log "Test 5: config change applies on the next connection"
set_perms ssh '{"*": {"groups": ["zt-dev", "zt-ops"]}}'
reloaded() { zssh ssh "${H1}" 'id -Gn' 2>/dev/null | grep -qw zt-ops; }
if until_ok 90 reloaded; then pass "new groups applied after config update"
else fail "config update not applied within 90s"; fi

# ---------------------------------------------------------------------------
# 6. Config that fails to load fails closed.
# ---------------------------------------------------------------------------
log "Test 6: invalid config fails closed"
set_perms ssh '{"*": {"groups": ["zt-dev"], "sudoers_rule": "ALL=(ALL) ALL\nDefaults !authenticate"}}'
closed() { ! zssh ssh "${H1}" true 2>/dev/null && host_log "${H1_IP}" 1min | grep -q 'could not be loaded'; }
if until_ok 90 closed; then pass "connections rejected while the config is invalid"
else fail "invalid config did not fail closed"; fi
set_perms ssh '{"*": {"groups": ["zt-dev"]}}'
until_ok 90 zssh ssh "${H1}" true 2>/dev/null && pass "connections accepted again after fixing the config" ||
    fail "connections still rejected after fixing the config"

# ---------------------------------------------------------------------------
# 7. Cross-service permission conflict (M2).
# ---------------------------------------------------------------------------
log "Test 7: different permissions via another service while a session is open"
on_client "nohup timeout 90 ziti-ssh connect --service ssh ${H1} -- sleep 40 </dev/null >/tmp/hold.log 2>&1 &"
sleep 15
if zssh ssh-ops "${H1}" true 2>/dev/null; then
    fail "ssh-ops connection allowed while an ssh session with different permissions was open"
elif host_log "${H1_IP}" 1min | grep -q 'open sessions through another service'; then
    pass "ssh-ops connection rejected (permission conflict)"
else fail "ssh-ops connection failed without a conflict log"; fi
sleep 35
until_ok 60 zssh ssh-ops "${H1}" true 2>/dev/null && pass "ssh-ops allowed after the ssh session closed" ||
    fail "ssh-ops still rejected after the ssh session closed"

# ---------------------------------------------------------------------------
# 8. Disconnect clears privileges, keeps the account.
# ---------------------------------------------------------------------------
log "Test 8: last disconnect clears groups and sudoers"
sleep 5
G=$(on "${H1_IP}" "id -Gn ${U}" || true)
if grep -qw sudo <<< "${G}" || grep -qw zt-ops <<< "${G}" || grep -qw zt-dev <<< "${G}"; then
    fail "groups not cleared after disconnect: ${G}"
else pass "groups after disconnect: ${G}"; fi
if on "${H1_IP}" "sudo test -e /etc/sudoers.d/ziti-ssh-host-${U}"; then fail "sudoers file left behind"
else pass "no sudoers file"; fi
if on "${H1_IP}" "id ${U}" >/dev/null 2>&1; then pass "account kept (ZITI_USER_CLEANUP unset)"
else fail "account deleted although cleanup is off"; fi

# ---------------------------------------------------------------------------
# 9. ZITI_TERMINATE_ON_DISCONNECT=true: cron, processes, expiry.
# ---------------------------------------------------------------------------
log "Test 9: ZITI_TERMINATE_ON_DISCONNECT=true ends what the account can run"
on "${H1_IP}" "echo ZITI_TERMINATE_ON_DISCONNECT=true | sudo tee -a /etc/ziti-ssh-host/env >/dev/null && sudo systemctl restart ziti-ssh-host"
until_ok 120 on "${H1_IP}" 'systemctl is-active --quiet ziti-ssh-host'
sleep 10
until_ok 60 zssh ssh "${H1}" 'echo "* * * * * true" | crontab - && (setsid nohup sleep 600 </dev/null >/dev/null 2>&1 &) && crontab -l' >/dev/null ||
    fail "could not set up crontab / background process"
sleep 15
if on "${H1_IP}" "sudo crontab -u ${U} -l" >/dev/null 2>&1; then fail "crontab still present after disconnect"
else pass "crontab removed"; fi
if on "${H1_IP}" "pgrep -u ${U}" >/dev/null 2>&1; then fail "processes still running: $(on "${H1_IP}" "pgrep -a -u ${U}" || true)"
else pass "background processes ended"; fi
EXP=$(on "${H1_IP}" "sudo chage -l ${U} | grep -i '^account expires'" || true)
if grep -qi 'never' <<< "${EXP}"; then fail "account not expired: ${EXP}"
else pass "account expired after disconnect: ${EXP}"; fi
until_ok 60 zssh ssh "${H1}" true && pass "next authorized connection re-enables the account" ||
    fail "account not re-enabled on the next connection"

# ---------------------------------------------------------------------------
# 10. ZITI_USER_CLEANUP=true deletes the account.
# ---------------------------------------------------------------------------
log "Test 10: ZITI_USER_CLEANUP=true deletes the account on disconnect"
on "${H1_IP}" "echo ZITI_USER_CLEANUP=true | sudo tee -a /etc/ziti-ssh-host/env >/dev/null && sudo systemctl restart ziti-ssh-host"
until_ok 120 on "${H1_IP}" 'systemctl is-active --quiet ziti-ssh-host'
sleep 10
until_ok 60 zssh ssh "${H1}" true 2>/dev/null || fail "connect with cleanup on failed"
gone() { ! on "${H1_IP}" "id ${U}" >/dev/null 2>&1; }
if until_ok 30 gone; then pass "account deleted after the last session closed"
else fail "account still present with cleanup on"; fi

if [[ ${FAILED} -eq 0 ]]; then log "All tests PASSED"; exit 0; fi
log "One or more tests FAILED"; exit 1
