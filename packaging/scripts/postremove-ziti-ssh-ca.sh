#!/bin/sh
# Post-remove for ziti-ssh-ca.
#
# purge (deb): remove the systemd drop-in the postinstall wrote to run the CA
#   as the controller's user — only if it still carries the package's marker
#   (a hand-edited drop-in is left alone). /etc/ziti-ssh-ca (identity, env)
#   is kept.
set -e

DROPIN_DIR=/etc/systemd/system/ziti-ssh-ca.service.d
DROPIN_FILE="$DROPIN_DIR/10-controller-user.conf"

if [ "$1" = "purge" ]; then
    if [ -f "$DROPIN_FILE" ] && grep -q '^# Managed by the ziti-ssh-ca package' "$DROPIN_FILE"; then
        rm -f "$DROPIN_FILE"
        rmdir "$DROPIN_DIR" 2>/dev/null || true
    fi
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
