# Operations

This guide covers operational topics: modes, CA key rotation, graceful shutdown, and the files written by `ziti-ssh-host`.

For installation procedures see [provisioning.md](provisioning.md). For configuration reference see [configuration.md](configuration.md).

---

## Modes

Both `ziti-ssh-ca` and `ziti-ssh-host run` accept a `--mode` flag (env: `ZITI_SSH_MODE`). They must be set to the same value. The CA is the authoritative source for what principal appears in the certificate; `ziti-ssh-host` needs to know the mode only to manage Linux user accounts.

### `shared` (default)

All SSH sessions authenticate as a single shared Linux user configured by `--principal` (default: `ziggy`). Simple to operate; audit trail relies entirely on the `KeyId` field in `sshd` logs.

```sh
# Create the shared account once:
useradd --create-home --shell /bin/bash ziggy

# Connect:
ziti-ssh ziggy@web-server-prod
```

### `per-identity`

The CA derives a Linux username from each caller's Ziti identity name and places it in the certificate's `ValidPrincipals`. `ziti-ssh-host` creates the Linux user on the first connection from that identity and deletes it (including home directory) when the last session closes.

**Username derivation rules** (`ca.DeriveUsername`):
1. Lowercase the entire identity name.
2. Replace any character outside `[a-z0-9_-]` with `_`.
3. If the result starts with a digit, prefix it with `z`.
4. Truncate to 32 characters.

Examples: `Alice` → `alice`, `alice@corp.com` → `alice_corp_com`, `123bot` → `z123bot`

**Ephemeral user lifecycle:**
- On first connection from an identity, `useradd -m -s /bin/bash <username>` runs.
- If `ZITI_SUDOERS_RULE` is set, a sudoers file is written to `/etc/sudoers.d/<username>` (validated with `visudo -c` before installation).
- Concurrent sessions from the same identity are reference-counted — `useradd` is only called once.
- When the last session from an identity closes, the cleanup sequence runs: `loginctl terminate-user <username>` drains the systemd session, the process list is polled until the user's processes exit (up to 5 seconds), and then `userdel -r <username>` removes the account and home directory. The sudoers file is removed unconditionally at this point.
- Set `ZITI_USER_CLEANUP=false` to keep the Linux account across disconnects (useful for persistent home-directory setups). The sudoers file is still removed on disconnect when this option is set.
- Active managed usernames are persisted to `/var/lib/ziti-ssh-host/managed-users`. On startup, `CleanupOrphans` reads this file and deletes any listed users (they had sessions open when the process was last killed), preventing accumulation of stale accounts after crashes.

**Connecting in per-identity mode:**
```sh
ziti-ssh alice_corp_com@web-server-prod
```
The username before `@` is the derived username for the caller's identity.

> **Important:** `--mode` must be set consistently on both `ziti-ssh-ca` and `ziti-ssh-host run`. If the CA issues certs with per-identity principals but the host is in shared mode (or vice versa), SSH authentication will fail.

---

## CA key rotation

The CA key used by `ziti-ssh-ca` is the Ziti controller's **intermediate CA private key**. Rotating it is a Ziti controller operation, not a `ziti-ssh-ca` operation. Consult the OpenZiti documentation for controller PKI rotation procedures.

After the controller intermediate CA key is rotated:

1. Restart `ziti-ssh-ca` so it loads the new key from disk.
2. Run `ziti-ssh-host enroll` again on each host (or distribute the new intermediate CA public key and update `/etc/ssh/ziti_ca.pub` manually, then reload sshd). Since `enroll` extracts the CA public key from the enrollment response, re-enrolling automatically picks up the new key.

Outstanding SSH certificates signed with the old intermediate CA key stop working once sshd no longer trusts the old CA public key. Issue new certificates to users after rotation.

---

## Graceful shutdown

Both `ziti-ssh-ca` and `ziti-ssh-host run` handle `SIGTERM` and `SIGINT` gracefully:

1. On receiving a signal the Ziti listener is closed, so no new connections are accepted.
2. All in-flight connections (active cert signing or SSH proxy sessions) are allowed to finish normally.
3. If in-flight connections do not finish within **30 seconds** of the signal, the process exits anyway with a warning log. Per-identity mode users whose sessions were severed by the timeout are cleaned up by `CleanupOrphans` on the next startup.

The services support `Type=notify` in systemd unit files — each process sends `READY=1` via `sd_notify` after the Ziti listener is bound and ready to accept connections, and `STOPPING=1` when a shutdown signal is received. To use this, set `Type=notify` in the systemd unit:

```ini
[Service]
Type=notify
```

See [provisioning.md](provisioning.md) for the full systemd unit file examples for `ziti-ssh-ca` and `ziti-ssh-host`.

---

## Files written by `ziti-ssh-host`

### `enroll`

| Path | Mode | Contents |
|---|---|---|
| `/etc/ziti-ssh-host/identity.json` | 0600 | Enrolled Ziti identity (private key material) |
| `/etc/ssh/ziti_ca.pub` | 0644 | CA public key in authorized_keys format |
| `/etc/ssh/sshd_config.d/ziti-ssh.conf` | 0644 | `TrustedUserCAKeys /etc/ssh/ziti_ca.pub` |

### `run` (per-identity mode only)

| Path | Mode | Contents |
|---|---|---|
| `/var/lib/ziti-ssh-host/managed-users` | 0644 | One derived username per line — the set of Linux users currently managed by the daemon. Used for orphan cleanup on restart. |
