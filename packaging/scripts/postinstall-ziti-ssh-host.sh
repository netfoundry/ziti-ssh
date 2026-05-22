#!/bin/sh
set -e

if [ ! -f /etc/ziti-ssh-host/env ]; then
    cat > /etc/ziti-ssh-host/env <<'ENVEOF'
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
