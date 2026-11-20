#!/bin/sh
# Pre-remove for ziti-ssh-host: stop and disable the service when the package is
# removed (deb "remove", rpm "0"). Upgrades leave the service as it is.
set -e

case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now ziti-ssh-host.service >/dev/null 2>&1 || true
        fi
        ;;
esac
