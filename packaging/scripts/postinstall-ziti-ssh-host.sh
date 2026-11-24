#!/bin/sh
set -e

# Paths (overridable only to allow testing this script outside a real install).
CONF_DIR="${ZITI_SSH_HOST_CONF_DIR:-/etc/ziti-ssh-host}"
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
# ziti-ssh-host environment configuration
# Uncomment and set these variables before starting the service.

# Path to the enrolled ziti identity file (written by: ziti-ssh-host enroll --jwt)
#ZITI_IDENTITY=/etc/ziti-ssh-host/identity.json

# ziti service name to bind as SSH host (must match the service created on the controller)
#ZITI_SSH_SERVICE=ssh

# MODE controls how SSH connections are handled:
#
#   shared (default): all connections authenticate as a single shared Linux account.
#     The account (e.g. ziggy) must already exist on this host.
#     Set ZITI_SSH_MODE=shared (or leave unset).
#
#   per-identity: each connecting ziti identity gets its own ephemeral Linux account,
#     created automatically on first connection and removed when the last session closes.
#     Set ZITI_SSH_MODE=per-identity on BOTH ziti-ssh-host AND ziti-ssh-ca.
#
#ZITI_SSH_MODE=shared

# SUDOERS — optional sudo rule granted to per-identity users on connect.
# Only applies when ZITI_SSH_MODE=per-identity.
# Leave unset for no sudo access. The rule is written to
# /etc/sudoers.d/ziti-ssh-host-<username>.
# Example (full passwordless sudo):
#ZITI_SUDOERS_RULE=ALL=(ALL) NOPASSWD:ALL

# USER_CLEANUP — whether to delete the Linux user and sudoers file on disconnect.
# false (default): persistent users — account remains after disconnect.
# true: ephemeral users — account removed when last session closes.
#ZITI_USER_CLEANUP=false

# TERMINATE_ON_DISCONNECT — with USER_CLEANUP=false, end all of the user's
# processes (nohup, tmux, systemd user services), remove their crontab and at
# jobs, and expire the account until its next authorized connection when the
# last session closes, keeping the account and home directory. Needed for revoked identities to lose
# running processes. No effect when USER_CLEANUP=true (deletion already ends them).
#ZITI_TERMINATE_ON_DISCONNECT=false

# How often to check the controller for service/config changes (default 30s,
# minimum 5s); a changed ziti-ssh-host.v1 config applies within this interval.
#ZITI_SERVICE_REFRESH=30s

# Maximum concurrent connections per service (default 128); further
# connections are closed immediately.
#ZITI_MAX_CONNECTIONS=128

# Host grant policy — what each service's ziti-ssh-host.v1 config may grant here.
# ALLOW_SUDOERS: services whose config may set sudoers_rule (comma list, or *).
#ZITI_ALLOW_SUDOERS=ssh-ops
# ALLOW_GROUPS: privileged groups (root, sudo, admin, wheel, docker, lxd, disk,
# shadow, libvirt) a service's config may grant, as <service>:<group> or *:<group>.
#ZITI_ALLOW_GROUPS=ssh-ops:sudo
# RESTRICT_GROUPS: true = config may grant only groups listed in ALLOW_GROUPS.
#ZITI_RESTRICT_GROUPS=false
ENVEOF
    chmod 640 "${CONF_DIR}/env"
fi

# Accounts in this group may only log in with a CA certificate (the sshd
# drop-in written by "ziti-ssh-host enroll" disables authorized_keys for them).
# Add the shared account to it in shared mode: usermod -aG ziti-ssh-managed <user>
if command -v groupadd >/dev/null 2>&1; then
    groupadd -f --system ziti-ssh-managed
fi

if [ -d "${SYSTEMD_DIR}" ]; then
    systemctl daemon-reload || true
    # On upgrade, restart the service if it is running so the new binary takes
    # effect (try-restart leaves a stopped service stopped). Without this, the
    # old daemon keeps running until the next restart or reboot.
    if is_upgrade "$@"; then
        if systemctl try-restart ziti-ssh-host.service; then
            echo "ziti-ssh-host: restarted ziti-ssh-host.service (if it was running) to use the new version" >&2
        else
            echo "ziti-ssh-host: warning: could not restart ziti-ssh-host.service; run: systemctl restart ziti-ssh-host.service" >&2
        fi
    fi
fi
