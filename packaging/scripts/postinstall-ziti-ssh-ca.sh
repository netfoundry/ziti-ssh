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
    chmod 640 /etc/ziti-ssh-ca/env
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
