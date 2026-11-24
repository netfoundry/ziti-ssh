#!/bin/sh
set -e

# Paths (overridable only to allow testing this script outside a real install).
CONF_DIR="${ZITI_SSH_CA_CONF_DIR:-/etc/ziti-ssh-ca}"
DROPIN_DIR="${ZITI_SSH_CA_DROPIN_DIR:-/etc/systemd/system/ziti-ssh-ca.service.d}"
DROPIN_FILE="${DROPIN_DIR}/10-controller-user.conf"
DROPIN_MARKER="# Managed by the ziti-ssh-ca package"
SYSTEMD_DIR="${ZITI_SSH_SYSTEMD_DIR:-/run/systemd/system}"

# is_upgrade reports whether this run upgrades an installed package:
# deb postinst "configure <old-version>", rpm %post with $1 >= 2. Fresh
# installs, reconfigures without an old version and dpkg abort-* calls are not.
is_upgrade() {
    case "${1:-}" in
        configure) [ -n "${2:-}" ] ;;
        [2-9] | [1-9][0-9]*) true ;;
        *) false ;;
    esac
}

if [ ! -f "${CONF_DIR}/env" ]; then
    cat > "${CONF_DIR}/env" <<'ENVEOF'
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
#   per-identity: each ziti identity gets its own Linux account on the target
#     host (created automatically by ziti-ssh-host). Do not set
#     ZITI_SSH_PRINCIPAL — the username is derived from the identity name.
#     Set ZITI_SSH_MODE=per-identity on both ziti-ssh-ca AND ziti-ssh-host.
#
#ZITI_SSH_MODE=shared
#ZITI_SSH_PRINCIPAL=ziggy

# Certificate validity duration (default 5m). Examples: 5m, 15m, 1h.
#ZITI_CERT_TTL=5m
ENVEOF
    chmod 640 "${CONF_DIR}/env"
fi

# ---------------------------------------------------------------------------
# Run as the Ziti controller's service user.
#
# ziti-ssh-ca reads the controller's intermediate CA key, which is owned by the
# controller's service user with mode 0600, so it must run as that same user.
# That user differs between installs: the openziti-controller package (v2+)
# uses "ziti-controller", other deployments use e.g. "ziti". Detect it and
# write a systemd drop-in that overrides the unit's default (User=ziti).
# ---------------------------------------------------------------------------

controller_user() {
    # 1) The controller's systemd unit, if it names a static user.
    if command -v systemctl >/dev/null 2>&1; then
        u=$(systemctl show -p User --value ziti-controller.service 2>/dev/null || true)
        if [ -n "${u}" ]; then
            echo "${u}"
            return 0
        fi
    fi
    # 2) The owner of a running "ziti controller run" process.
    if command -v pgrep >/dev/null 2>&1; then
        pid=$(pgrep -f -o 'ziti controller run' 2>/dev/null || true)
        if [ -n "${pid}" ]; then
            # Resolve by UID: "ps -o user=" truncates long names
            # (e.g. "ziti-controller" becomes "ziti-co+").
            uid=$(ps -o uid= -p "${pid}" 2>/dev/null | tr -d ' ' || true)
            u=""
            if [ -n "${uid}" ]; then
                u=$(getent passwd "${uid}" 2>/dev/null | cut -d: -f1 || true)
            fi
            if [ -n "${u}" ]; then
                echo "${u}"
                return 0
            fi
        fi
    fi
    return 1
}

# An administrator's own override (e.g. "systemctl edit ziti-ssh-ca") wins:
# any drop-in other than ours that sets User= is left alone.
admin_override() {
    for f in "${DROPIN_DIR}"/*.conf; do
        [ -f "${f}" ] || continue
        [ "${f}" = "${DROPIN_FILE}" ] && continue
        if grep -q '^[[:space:]]*User=' "${f}"; then
            echo "${f}"
            return 0
        fi
    done
    return 1
}

if override=$(admin_override); then
    echo "ziti-ssh-ca: keeping existing service user override in ${override}" >&2
elif [ -f "${DROPIN_FILE}" ] && ! grep -q "^${DROPIN_MARKER}" "${DROPIN_FILE}"; then
    echo "ziti-ssh-ca: ${DROPIN_FILE} was edited locally; leaving it unchanged" >&2
elif svc_user=$(controller_user) && getent passwd "${svc_user}" >/dev/null 2>&1; then
    svc_group=$(id -gn "${svc_user}")
    mkdir -p "${DROPIN_DIR}"
    cat > "${DROPIN_FILE}" <<EOF
${DROPIN_MARKER}; delete this marker line to keep local edits.
# Runs ziti-ssh-ca as the Ziti controller's service user, which owns the
# controller PKI (the intermediate CA key is mode 0600).
[Service]
User=${svc_user}
Group=${svc_group}
EOF
    chmod 644 "${DROPIN_FILE}"
    # The service saves controller URL updates to its identity file, so it
    # needs to own the config directory and identity file. The env file stays
    # root-owned (it is read by systemd, not by the service).
    chown "${svc_user}:${svc_group}" "${CONF_DIR}"
    chmod 750 "${CONF_DIR}"
    if [ -f "${CONF_DIR}/identity.json" ]; then
        chown "${svc_user}:${svc_group}" "${CONF_DIR}/identity.json"
        chmod 600 "${CONF_DIR}/identity.json"
    fi
    if [ "${svc_user}" = "root" ]; then
        echo "ziti-ssh-ca: warning: the Ziti controller runs as root; ziti-ssh-ca will too" >&2
    fi
    echo "ziti-ssh-ca: will run as the Ziti controller's user '${svc_user}' (${DROPIN_FILE})" >&2
else
    cat >&2 <<EOF
ziti-ssh-ca: could not detect the Ziti controller's service user (is the
controller installed and running on this machine?). The service defaults to
User=ziti. If the controller runs as a different user, run:

    sudo systemctl edit ziti-ssh-ca
        [Service]
        User=<controller user>
        Group=<controller group>

    sudo chown <controller user>:<controller group> ${CONF_DIR}
EOF
fi

if [ -d "${SYSTEMD_DIR}" ]; then
    systemctl daemon-reload || true
    # On upgrade, restart the service if it is running so the new binary takes
    # effect (try-restart leaves a stopped service stopped). Without this, the
    # old daemon keeps running until the next restart or reboot.
    if is_upgrade "$@"; then
        if systemctl try-restart ziti-ssh-ca.service; then
            echo "ziti-ssh-ca: restarted ziti-ssh-ca.service (if it was running) to use the new version" >&2
        else
            echo "ziti-ssh-ca: warning: could not restart ziti-ssh-ca.service; run: systemctl restart ziti-ssh-ca.service" >&2
        fi
    fi
fi
