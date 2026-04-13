# Operations

This guide covers operational topics: modes, high availability, CA key rotation, graceful shutdown, and the files written by `ziti-ssh-host`.

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

## Revoking access

Because `ziti-ssh` connections run over the Ziti overlay, revocation is enforced at the network layer. When an admin deletes an identity or removes its dial access to an SSH service, the Ziti control plane immediately invalidates that identity's API session. This cascades to all associated edge sessions: the edge router detects the invalidated sessions and closes the underlying data plane connections, which tears down the `net.Conn` that `ziti-ssh-host` is proxying to `localhost:22`. sshd sees EOF and terminates the SSH session.

This is stronger than an application-level kill command — it is enforced below the application by the edge router, takes effect within seconds, and covers every active SSH session for that identity across every SSH host simultaneously.

> **Note:** There is a brief drain window (typically a few seconds, depending on heartbeat intervals) between the admin action and the edge router fully closing the connection. The session is functionally dead immediately — no new channels can be opened — but existing channel traffic may drain briefly before the TCP-level close arrives.

### Permanent revocation

Delete the identity from the controller. All active sessions terminate within seconds. The identity cannot re-enroll without a new JWT.

```sh
# Look up the identity ID, then delete it
ziti edge list identities --filter 'name = "alice@corp.com"'
ziti edge delete identity <id>
```

### Temporary suspension

Remove the role attribute that grants dial access to the SSH service (e.g. `#ssh-clients`). Active sessions close; no re-enrollment is needed. Re-adding the attribute restores access immediately.

```sh
# Remove the dial-access attribute
ziti edge update identity alice@corp.com --role-attributes ''

# Or remove only the relevant attribute, keeping others
ziti edge update identity alice@corp.com --role-attributes 'other-attr'

# Restore access later
ziti edge update identity alice@corp.com --role-attributes 'ssh-clients,other-attr'
```

Alternatively, edit the service policy directly to remove the identity or its attribute from the dial list if you want to suspend access for a whole group.

### Service-scoped revocation

Remove the identity from the dial policy for a specific SSH service without affecting other services. Active sessions on that service close; sessions on other services are unaffected.

```sh
# Remove dial access to the production SSH service only
# (adjust the bind-policy or role attribute for that specific service's dial policy)
ziti edge update service-policy ssh-prod-dial \
  --identity-roles '@alice@corp.com'  # leave other identities unchanged
```

For attribute-based policies, the cleanest approach is to move the identity to a restricted attribute set that excludes production but retains staging:

```sh
ziti edge update identity alice@corp.com --role-attributes 'ssh-staging-clients'
```

### What happens on the host (per-identity mode)

When the connection closes, `ziti-ssh-host` sees EOF on the proxied `net.Conn`, decrements the session ref-count for the identity, and runs the normal cleanup sequence when the last session ends: the sudoers file is removed, `loginctl terminate-user` drains the systemd session, and `userdel -r` removes the account and home directory. No special handling is required — revocation flows through the same path as a normal disconnect.

### Outstanding SSH certificates

Revoking Ziti access does not invalidate the user's SSH certificate — it may still have up to 8 hours of validity remaining. However, the certificate is useless without a live Ziti connection to reach any SSH host, so this is not a practical concern in normal operation. The certificate cannot be used to connect directly to port 22 because that port is firewalled; it can only be used through the Ziti overlay.

If the CA itself needs to be rotated (for example, after a credential compromise), see [CA key rotation](#ca-key-rotation) below.

---

## High Availability

OpenZiti supports HA controller clusters where multiple controller nodes share state. `ziti-ssh` is designed to work correctly against an HA cluster at every stage — enrollment, runtime, and CA rotation — without manual intervention on SSH hosts.

### How HA clusters affect the CA trust model

Each controller node in an HA cluster has its own **intermediate CA private key**. That key is used to sign Ziti identity certificates for clients that authenticate through that specific controller. When `ziti-ssh-ca` runs against one controller node, the SSH certificates it issues carry the signature of that node's intermediate CA.

For SSH hosts to accept certificates issued by any node in the cluster, sshd must trust every controller's intermediate CA public key — not just the one the host happened to enroll against. `ziti-ssh` handles this automatically at both enrollment time and during the lifetime of the daemon.

### Enrollment against an HA cluster

When `ziti-ssh-host enroll` is run, it:

1. Parses the enrollment JWT and reads the `ctrls` claim, which lists every controller node in the cluster. Falls back to the JWT issuer URL for older controllers that omit the claim.
2. Opens a TLS connection to each controller node and extracts its intermediate CA certificate from the TLS handshake chain — no HTTP request or authentication is required.
3. Deduplicates intermediate CA public keys by actual public key bytes (not by `SubjectKeyId`, which is unreliable across HA nodes).
4. Writes all unique intermediate CA public keys — one per line — to `/etc/ssh/ziti_ca.pub` and reloads sshd.

The result is that a freshly enrolled host trusts every controller's CA simultaneously. SSH certificates issued by any node in the cluster are accepted immediately, with no further configuration.

### Runtime CA key tracking (`ziti-ssh-host run`)

Once running, `ziti-ssh-host run` continues to track the controller cluster membership and keeps `TrustedUserCAKeys` current without requiring a restart:

**Event-driven updates:** Before authenticating, `ziti-ssh-host run` subscribes to the `EventControllerUrlsUpdated` event. This event fires at startup (during `Authenticate`) and again at each hourly session renewal. When it fires, the daemon:

1. Persists the full controller URL list to the identity JSON file (`ztAPIs` field) via `config.PersistZtAPIs`. This atomic write (write-then-rename) ensures the identity file always reflects the live cluster membership so that a process restart can bootstrap from any cluster member, not just the one originally enrolled against.
2. Fetches the current intermediate CA public keys from the updated controller set and compares them (order-independent) against the contents of `/etc/ssh/ziti_ca.pub`. If the set has changed, the file is rewritten and sshd is reloaded. Additions are logged with the controller URL; removals are logged by count.

**Periodic poll:** Because `EventControllerUrlsUpdated` only fires at `Authenticate` and the hourly session renewal, the daemon also polls the controller's `/controllers` API endpoint every **5 minutes**. This means a newly added cluster node is trusted within 5 minutes of joining, without waiting up to an hour for the next session renewal.

The combined effect is that the set of trusted intermediate CA keys in `TrustedUserCAKeys` is eventually consistent with the live cluster membership, with a maximum lag of 5 minutes for additions and approximately 1 hour (worst case, before the next poll) for removals.

### Running multiple `ziti-ssh-ca` instances

In an HA deployment, run one `ziti-ssh-ca` instance per controller node, each configured with that node's intermediate CA private key:

```
Controller node A  →  ziti-ssh-ca --ca-key /path/to/node-a-intermediate.key
Controller node B  →  ziti-ssh-ca --ca-key /path/to/node-b-intermediate.key
```

All instances bind to the same Ziti service (default: `ssh-ca`). The Ziti fabric load-balances cert signing requests across the available instances. Because SSH hosts trust all intermediate CA public keys, certificates issued by any `ziti-ssh-ca` instance are accepted without any host-side configuration.

No session affinity or shared state is required between `ziti-ssh-ca` instances — each signs independently with its own key, and all resulting certificates are equally trusted.

### CA rotation via node replacement

In an HA cluster, the zero-downtime way to rotate the intermediate CA key is to replace a controller node:

1. **Add a new controller node** with a freshly generated intermediate CA key pair. The node joins the cluster.
2. `ziti-ssh-host run` daemons detect the new node within 5 minutes via the periodic poll. They fetch the new node's intermediate CA public key, append it to `/etc/ssh/ziti_ca.pub`, and reload sshd. The new CA is now trusted across all hosts — no `enroll` re-run, no maintenance window.
3. **Start `ziti-ssh-ca`** on the new node. It begins signing certificates with the new intermediate CA key. Hosts already trust it.
4. **Remove the old controller node.** The `EventControllerUrlsUpdated` event fires on the next session renewal (or within 5 minutes via the periodic poll). Daemons detect that the old node's CA key is no longer present, remove it from `/etc/ssh/ziti_ca.pub`, and reload sshd. Any outstanding SSH certificates signed by the old CA become invalid once sshd stops trusting that CA.
5. **Stop the old `ziti-ssh-ca` instance.** No further certificates will be issued with the old key.

This procedure requires no coordination with SSH hosts and no service interruption. Active SSH sessions continue unaffected through the entire rotation — they are already established and do not re-verify the CA.

> **Note:** Outstanding SSH certificates signed by the old intermediate CA stop being accepted by sshd once the old CA public key is removed from `TrustedUserCAKeys`. Users whose certificates were issued before the rotation will need to request a new certificate from the updated CA instance (or wait for `ziti-ssh` to auto-refresh).

### Operational caveats

- **Enrollment JWT must be issued by a healthy cluster member.** The `ctrls` claim is only as complete as the controller that issued the JWT. If a node is temporarily offline at enrollment time, its CA key will be missing from `TrustedUserCAKeys` until the first `EventControllerUrlsUpdated` fires or the 5-minute poll runs.

- **`rootPool` is built from the enrollment response.** TLS validation when fetching CA keys from peer controllers uses the CA chain embedded in the identity JSON. If a new controller node uses a CA cert that is not in that chain, the TLS connection will fail and the node's CA key will not be fetched. Ensure that all controller nodes share the same root CA hierarchy.

- **The periodic poll requires an authenticated Ziti session.** The 5-minute poll calls the controller's `/controllers` API. If the Ziti session is not yet established (startup) or authentication fails, the poll falls back to the last successfully cached URL list and logs at debug level.

- **Single-node deployments are unaffected.** If only one controller exists, the enrollment and runtime behaviour is identical to today — one CA public key, no polling overhead beyond the startup fetch.

---

## CA key rotation

The CA key used by `ziti-ssh-ca` is the Ziti controller's **intermediate CA private key**. Rotating it is a Ziti controller operation, not a `ziti-ssh-ca` operation. Consult the OpenZiti documentation for controller PKI rotation procedures.

**Single-node deployments:** After the controller intermediate CA key is rotated:

1. Restart `ziti-ssh-ca` so it loads the new key from disk.
2. Run `ziti-ssh-host enroll` again on each host (or distribute the new intermediate CA public key and update `/etc/ssh/ziti_ca.pub` manually, then reload sshd). Since `enroll` extracts the CA public key from the enrollment response, re-enrolling automatically picks up the new key.

Outstanding SSH certificates signed with the old intermediate CA key stop working once sshd no longer trusts the old CA public key. Issue new certificates to users after rotation.

**HA deployments:** Use the node-replacement procedure described in [CA rotation via node replacement](#ca-rotation-via-node-replacement) above. This avoids any maintenance window — hosts trust the new CA before the old one is removed.

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
