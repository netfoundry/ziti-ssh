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
- If `ZITI_SSH_GROUPS` is set, `usermod -aG <groups> <username>` is run immediately after account creation. Groups must already exist on the host; failure is non-fatal and logged.
- If `ZITI_SUDOERS_RULE` is set, a sudoers file is written to `/etc/sudoers.d/<username>` (validated with `visudo -c` before installation).
- Concurrent sessions from the same identity are reference-counted — `useradd` is only called once.
- When the last session from an identity closes, the cleanup sequence runs: `loginctl terminate-user <username>` drains the systemd session, the process list is polled until the user's processes exit (up to 5 seconds), and then `userdel -r <username>` removes the account and home directory. The sudoers file is removed unconditionally at this point (group membership is implicit in account deletion).
- Set `ZITI_USER_CLEANUP=false` to keep the Linux account across disconnects (useful for persistent home-directory setups). The sudoers file is still removed on disconnect when this option is set.
- Active managed usernames are persisted to `/var/lib/ziti-ssh-host/managed-users`. On startup, `CleanupOrphans` reads this file and deletes any listed users (they had sessions open when the process was last killed), preventing accumulation of stale accounts after crashes.

**Connecting in per-identity mode:**
```sh
ziti-ssh alice_corp_com@web-server-prod
```
The username before `@` is the derived username for the caller's identity.

> **Important:** `--mode` must be set consistently on both `ziti-ssh-ca` and `ziti-ssh-host run`. If the CA issues certs with per-identity principals but the host is in shared mode (or vice versa), SSH authentication will fail.

### Per-identity permissions (`ziti-ssh-host.v1` config)

Fine-grained permissions — which Linux groups each identity joins, and what sudoers rule it receives — can be defined per-service using a **`ziti-ssh-host.v1` Ziti service config** attached to the SSH service in the controller. `ziti-ssh-host` reads the config automatically at startup and reloads it live when it changes.

For the full schema and worked example, see [`ziti-ssh-host.v1` config type](configuration.md#ziti-ssh-host-v1-config-type) in the configuration reference.

#### Permission resolution order

For each connecting identity, `ziti-ssh-host` resolves permissions as follows:

1. **Config attached, identity has an entry** — apply that entry's `groups` and `sudoers_rule`. Global fallbacks (`ZITI_SSH_GROUPS`, `ZITI_SUDOERS_RULE`) are ignored for this identity. An entry that omits a field means that field gets nothing — there is no merging with globals for matched identities.

2. **Config attached, identity not in it** — apply global fallbacks: groups from `ZITI_SSH_GROUPS` (if set) and the sudoers rule from `ZITI_SUDOERS_RULE` (if set). If neither is set, the user is created with no extra permissions.

3. **No config attached** — apply global fallbacks to all users (equivalent to the existing behaviour before per-identity permissions were introduced).

Identity keys in the config are the **Ziti identity names** exactly as they appear in the controller (case-sensitive). `ziti-ssh-host` derives the Linux username internally via `DeriveUsername`.

#### Live config reload

When a `ziti-ssh-host.v1` config is updated in the Ziti controller, the change propagates to all running `ziti-ssh-host` instances bound to that service within seconds via the service-changed event. Already-open sessions are not affected — the updated permissions apply only to connections established after the reload. No restart of `ziti-ssh-host` is required.

### Multi-service binding

`--ssh-service` accepts multiple values (the flag can be repeated, or the `ZITI_SSH_SERVICE` env var can be set to a comma-separated list). Each service gets its own Ziti listener and its own independent in-memory permissions map. The service a connection arrived on determines which permissions are applied to that identity.

This allows a single host to serve multiple access tiers simultaneously. For example, a DB server reachable by both the ops team (OS-level work) and the DBA team (database-level work) binds to both `ssh-ops` and `ssh-db`:

```sh
ziti-ssh-host run --ssh-service ssh-ops --ssh-service ssh-db
```

Ops identities are granted dial access to `ssh-ops` in Ziti service policy; DBA identities are granted dial access to `ssh-db`. An identity granted access to both gets whichever permission set corresponds to the service it dialled.

> **Note:** If the same Ziti identity connects through two different services to the same host at the same time, the Linux user is created once on the first connection and the permissions from that first connection are used for the lifetime of the account. The second service's config is not applied retroactively. This is a known limitation and is logged at info level.

### Deployment patterns

**Single shared service — uniform fleet:**
All hosts bind to one service (`ssh`). One `ziti-ssh-host.v1` config applies to all hosts. Appropriate when all hosts are equivalent and per-host permission differences are not needed.

**Per-role services — grouped fleet:**
Hosts are grouped into role-based services (e.g., `ssh-app`, `ssh-db`, `ssh-ops`). Each service has its own `ziti-ssh-host.v1` config. Hosts that span multiple roles bind to multiple services. This is the recommended pattern for most production deployments. The service boundary is also the permission scope boundary.

**Per-host services — maximum granularity:**
Each host has its own service (e.g., `ssh-web-01`, `ssh-web-02`) with a fully independent config. Maximum control; highest management overhead. Appropriate when hosts within a role need meaningfully different permission sets.

> **Note:** Fleets using per-identity permissions typically use multiple SSH services rather than a single `ssh` service. The service boundary in Ziti is the natural unit of both access control and permission scope.

### Constraints

- **Groups must exist on the host.** `ziti-ssh-host` does not create Linux groups. If a config entry references a group that does not exist, `usermod -aG` will fail. The failure is logged and the session proceeds with the user account created but without the requested group membership.
- **First-connection-wins for concurrent cross-service sessions.** If the same identity connects through two services simultaneously, the Linux account is created once with the permissions from the first connection. The second service's config is not applied retroactively.
- **A config entry suppresses global fallbacks entirely.** An identity matched by a config entry receives only what that entry specifies — globals are not merged in.
- **No config attached is not an error.** `ziti-ssh-host` logs a debug message and uses global fallbacks.
- **`shared` mode is unaffected.** The `ziti-ssh-host.v1` config is consulted only in `per-identity` mode.

---

## Inspecting per-identity permissions

The `ziti-ssh-host inspect` subcommand is a diagnostic tool for operators verifying their `ziti-ssh-host.v1` config before deploying or after a change.

### Usage

```sh
ziti-ssh-host inspect --service <service-name> [--service <service-name> ...]
```

Uses the same `--identity` flag (and `ZITI_IDENTITY` env var) as the `run` subcommand to authenticate. No listeners are opened; the command exits after printing.

### Output

For each named service, `inspect` prints:

- **Service availability** — whether the identity can see the service (has bind access to it).
- **Config presence** — whether a `ziti-ssh-host.v1` config is attached to the service.
- **Parsed permissions table** — the full identity-to-permissions map as `ziti-ssh-host` would load it, with columns for the Ziti identity name, derived Linux username, groups, and sudoers rule.
- **Global fallback values** — the current values of `ZITI_SSH_GROUPS` and `ZITI_SUDOERS_RULE` from the environment, shown alongside the config output so the complete effective permission picture is visible in one place.

Example:

```
Service: ssh-db
  Config type ziti-ssh-host.v1: present

  Identity             Linux username    Groups           Sudoers rule
  -------------------  ----------------  ---------------  ------------------------------------
  carol@corp.com       carol_corp_com    mysql            ALL=(ALL) NOPASSWD: /usr/bin/mysqld*
  dave@corp.com        dave_corp_com     mysql            (none)

  Global fallback groups:  (not set)
  Global fallback sudoers: (not set)

Service: ssh-ops
  Config type ziti-ssh-host.v1: present

  Identity             Linux username    Groups           Sudoers rule
  -------------------  ----------------  ---------------  ----------------------------
  alice@corp.com       alice_corp_com    sudo, adm        (none)
  bob@corp.com         bob_corp_com      sudo             (none)

  Global fallback groups:  (not set)
  Global fallback sudoers: ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *
```

If a service has no `ziti-ssh-host.v1` config attached, `inspect` reports that and shows only the global fallbacks that would apply. If the identity cannot see a service (no bind policy), `inspect` reports that clearly so the operator can distinguish a missing config from a missing service policy.

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
