#!/bin/sh
set -e

# ziti-scp shares its config with ziti-ssh at ~/.config/ziti-ssh/config.yaml.
# Create that directory the first time you run ziti-ssh or ziti-scp, or manually:
#   mkdir -p ~/.config/ziti-ssh
