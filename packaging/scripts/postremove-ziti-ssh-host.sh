#!/bin/sh
# Post-remove for ziti-ssh-host.
#
# purge (deb): stop sshd trusting the Ziti CA by removing the two files
#   ziti-ssh-host writes (the sshd drop-in and the CA public key) and
#   reloading sshd. Identity files, /etc/ziti-ssh-host/env, the account
#   ownership registry and any Linux accounts are kept.
# rpm has no purge: after "rpm -e", remove those two files manually if the
#   host should stop trusting the CA (see docs/provisioning.md).
set -e

SSHD_DROPIN=/etc/ssh/sshd_config.d/ziti-ssh.conf
CA_PUBKEY=/etc/ssh/ziti_ca.pub

if [ "$1" = "purge" ]; then
    rm -f "$SSHD_DROPIN" "$CA_PUBKEY"
    if [ -d /run/systemd/system ]; then
        if systemctl is-active --quiet ssh.service; then
            systemctl reload ssh.service || true
        elif systemctl is-active --quiet sshd.service; then
            systemctl reload sshd.service || true
        fi
    fi
    # Leftover top-level sshd listeners (see host.ReloadSSHD).
    pkill -HUP -P 1 -x sshd 2>/dev/null || true
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
