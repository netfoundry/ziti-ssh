# ziti-ssh

An SSH Certificate Authority service and host daemon for OpenZiti networks. Allows Ziti identities to obtain short-lived SSH certificates and connect to SSH hosts exclusively through the Ziti overlay — with no credentials stored on SSH hosts and no exposure of port 22.

## Problem

Standard SSH public key auth requires either:
- Per-user `authorized_keys` files on every host, or
- A service querying an identity provider at auth time — which requires credentials on every SSH host

Both approaches are operationally expensive. The credentials-on-host requirement is a security concern at scale. Additionally, exposing port 22 to any network is a persistent attack surface.

## Solution

Four cooperating binaries:

1. **`ziti-ssh-ca`** — a CA service hosted as a Ziti service that signs short-lived SSH certificates for authorized callers. SSH hosts trust only the CA's public key — not a credential. Also provides a `config` subcommand that installs and manages the `ziti-ssh-host.v1` config type on the Ziti controller.

2. **`ziti-ssh-host`** — a host daemon that enrolls the host into a Ziti network, configures sshd to trust the CA, and proxies Ziti connections to the local sshd. In `per-identity` mode, creates ephemeral Linux users and applies per-identity permissions (groups, sudoers rules) sourced from a `ziti-ssh-host.v1` config attached to the Ziti service. A single instance can bind to multiple Ziti services simultaneously, each with independent permissions.

3. **`ziti-ssh`** — a full SSH client over OpenZiti. Subcommands: `connect` (default), `sign`, `enroll`, `list`, `mfa`. Obtains and caches SSH certificates from the CA; auto-refreshes when fewer than 30 minutes of validity remain.

4. **`ziti-scp`** — a file copy tool over OpenZiti. Uses the SFTP subsystem over the same Ziti overlay. Mirrors `scp(1)` behaviour: upload, download, recursive directory copy, preserve mode. Shares the same identity, certificate, config infrastructure, and cert auto-refresh logic as `ziti-ssh`.

No credentials on SSH hosts. No API calls at auth time. Port 22 is never exposed externally.

## Architecture

```
User Machine                    Ziti Network              SSH Host
     │                               │                        │
     │  ziti-ssh sign                │                        │
     │  1. dial ssh-ca ──────────────┤   ziti-ssh-ca          │
     │  2. send public key           │   - extracts caller    │
     │                               │     Ziti identity      │
     │                               │   - signs SSH pubkey   │
     │  3. receive signed cert ───────┤                        │
     │     (written to               │                        │
     │      ~/.ssh/<key>-cert.pub)   │                        │
     │                               │                        │
     │  ziti-ssh [user@]<target>     │                        │
     │  4. dial ssh svc ─────────────┤   ziti-ssh-host run    │
     │     (terminator=target name)  │   - listens on Ziti    │
     │                               │   - creates Linux user │
     │                               │   - applies permissions│
     │                               │   - proxies to :22     │
     │  5. SSH with cert ────────────┼──────────────────────> │
     │     (ssh.CertSigner)          │       sshd (standard)  │
     │                               │       verifies cert    │
     │  shell session <──────────────┼────────────────────────│
     │                               │       against CA pubkey│
```

## Key Design Decisions

### No credentials on SSH hosts
Each SSH host stores only the CA's **public key** in `TrustedUserCAKeys`. This is not a credential — it cannot authenticate to anything. Verification is done locally by sshd with no network calls at auth time.

### No custom sshd on target hosts
Hosts run standard `sshd` unchanged (except `TrustedUserCAKeys`). `ziti-ssh-host run` exposes `localhost:22` as a named Ziti service by listening on a Ziti service and proxying connections to sshd. Port 22 stays firewalled externally.

### Identity via Ziti mTLS
The Ziti network proves the caller's identity through mutual TLS. The same Ziti identity:
- Authorizes cert issuance (dial policy on the `ssh-ca` service)
- Authorizes host access (dial policy on the per-host `ssh` service)
- Is embedded in the cert Key ID for audit trail

### Ziti service policy IS the access control
Any Ziti identity that can dial the `ssh-ca` service is authorized to receive a cert. Any Ziti identity that can dial the `ssh` service terminator for a given host is authorized to reach that host. Access control is managed entirely through Ziti service policies.

### Ziti service config IS the permission scope
Per-identity Linux permissions (groups, sudoers rules) are stored as a `ziti-ssh-host.v1` config attached to the Ziti service. The service boundary is therefore the permission scope boundary — the same boundary already used for access control. Different services can carry different permission sets, enabling role-tiered deployments where, for example, DB admins and ops teams can both reach a database host but with different Linux permissions.

### Short-lived certificates (8h TTL)
Certificates expire after 8 hours. No revocation infrastructure needed — compromised or removed identities lose access at expiry without any intervention on SSH hosts.

### `ziti-ssh` and `ziti-scp` as client tools
`ziti-ssh` is the interactive client. It handles Ziti dialing, SSH certificate management, and interactive SSH sessions. The `sign` subcommand fetches certs from the CA; the `connect` subcommand (default) auto-refreshes the cert if needed and then opens an SSH session. The `enroll`, `list`, and `mfa` subcommands cover the full Ziti identity lifecycle on user machines.

`ziti-scp` is the file copy companion. It uses the same identity, cert, and config infrastructure as `ziti-ssh` but opens an SFTP subsystem session instead of an interactive shell. The same cert auto-refresh logic applies (30-minute threshold), and the same Ziti service resolution (direct service name vs. terminator address on `--ssh-service`) is used.

### Addressable terminators for host routing
Each `ziti-ssh-host` instance listens on a Ziti service with its identity name as the terminator address. `ziti-ssh` dials the service specifying the target identity name — no hostname resolution, no config file required.

## Components

### SSH Client (`ziti-ssh`)

Five subcommands:

**`connect [user@]<target>`** (also the default when a bare argument is given):
- Auto-refreshes the SSH cert if missing or expiring within 30 min.
- Resolves whether the target is a direct Ziti service name or a terminator address on `--ssh-service`.
- Uses `ziti.DialOptions{Identity: terminatorAddr}` when dialling via a terminator.
- Wraps the private key and cert into an `ssh.CertSigner` via `client.NewCertSigner`.
- Runs a full interactive PTY session via `client.RunSession`.

**`sign`**: Dials `ssh-ca`, sends the SSH public key, writes the signed cert to `<key>-cert.pub`, prints cert details via `ssh-keygen -L`.

**`enroll --jwt <path>`**: Calls `enroll.Enroll` with `KeyAlg = "EC"`. Writes the identity JSON to `~/.config/ziti-ssh/<name>.json` by default.

**`list`**: Calls `ctx.GetServices()` and prints each service name and permissions.

**`mfa enable/verify/remove`**: Uses `zitiCtx.EnrollZitiMfa`, `VerifyZitiMfa`, `RemoveZitiMfa` with `AddMfaTotpCodeListener` / `AddAuthenticationStateFullListener` event hooks.

Config file at `~/.config/ziti-ssh/config.yaml` (XDG_CONFIG_HOME respected). Fields: `identity`, `ca_service`, `ssh_service`, `ssh_key_path`, `mode`, `oidc.*`. Three-tier precedence: CLI flag > config file > default.

### SSH Session / SFTP Library (`client/ssh.go`, `client/sftp.go`)

- `NewCertSigner(keyPath string) (ssh.Signer, error)` — loads key and cert; returns `ssh.CertSigner` if cert present.
- `CertNeedsRefresh(certPath string) bool` — true if cert absent or expires within 30 min.
- `RunSession(conn net.Conn, user, host string, signer ssh.Signer) error` — PTY SSH session over an existing `net.Conn`.
- `RunSFTP(conn, user, host, signer, isUpload, localPaths, remotePath, recursive, preserve, quiet) error` — SFTP file copy over an existing `net.Conn`; uses `github.com/pkg/sftp`.

### File Copy Tool (`ziti-scp`)

- Parses `[user@]host:path` remote specs and bare local paths from positional arguments (last arg is destination).
- Same cert auto-refresh (30-minute threshold) and Ziti dial logic as `ziti-ssh`.
- Flags: `-r` (recursive), `-p` (preserve timestamps/permissions), `-q` (quiet).
- `enroll` subcommand for identity enrollment (mirrors `ziti-ssh enroll`).
- Shared config file: `~/.config/ziti-ssh/config.yaml`.

### CA Service (`ziti-ssh-ca`)

Two modes of operation: a long-running service, and a one-shot `config` management command.

**Service (default / root command):**
- Binds to a named Ziti service (default: `ssh-ca`)
- Accepts incoming connections from Ziti clients
- Extracts the caller's Ziti identity name from the connection
- Accepts the caller's SSH public key (authorized_keys format) in the request body
- Signs it using the CA private key via `golang.org/x/crypto/ssh`
- Returns the signed certificate (authorized_keys format)
- If the request body is empty, returns the CA public key instead (used by hosts during enrollment)
- Embeds the Ziti identity name as the certificate Key ID (for audit logging)
- Issues certs with a configurable principal (default: `ziggy`) and 8h validity
- Enforces a per-identity token-bucket rate limit (default: 5 req/min, burst 3)

**`config` subcommand** — manages the `ziti-ssh-host.v1` config type on the Ziti controller via the management API (HTTPS, username/password auth):

- `config print` — prints the field table and JSON schema locally; no controller connection needed.
- `config apply` — idempotent install-or-update of the `ziti-ssh-host.v1` config type: checks whether it exists, then creates or replaces it.
- `config remove` — removes the `ziti-ssh-host.v1` config type if present.

Flags: `--controller <host[:port]>` (default port 443), `--username`, `--password`, `--insecure` (skip TLS verify), `--controller-ca <path>` (trust a specific CA cert). All have env var equivalents (`ZITI_CTRL_ADDRESS`, `ZITI_CTRL_USERNAME`, `ZITI_CTRL_PASSWORD`, `ZITI_CTRL_INSECURE`, `ZITI_CTRL_CA`). `--insecure` and `--controller-ca` are mutually exclusive.

### Host Daemon (`ziti-ssh-host`)

Three subcommands:

**`enroll --jwt <path>`:**
1. Enrolls the host Ziti identity from a JWT token
2. Extracts the intermediate CA public key from the enrollment response certificate chain (no network call to `ssh-ca` needed)
3. Writes sshd configuration (`TrustedUserCAKeys`) to `/etc/ssh/sshd_config.d/ziti-ssh.conf`
4. Reloads sshd

**`run`:**
1. Initializes Ziti context from the identity file; declares `ziti-ssh-host.v1` as a requested config type so the controller delivers it with the service detail
2. Accepts one or more `--ssh-service` values (flag may be repeated; `ZITI_SSH_SERVICE` accepts comma-separated list; defaults to `ssh`)
3. For each service: opens a separate Ziti listener, loads and parses the `ziti-ssh-host.v1` config, builds independent `ProxyHooks` carrying that service's permission map
4. Proxies incoming connections to `127.0.0.1:22`
5. In `per-identity` mode: on connect, creates an ephemeral Linux user and applies the resolved permissions (groups via `usermod -aG`, sudoers rule via `/etc/sudoers.d/<username>`); on disconnect, decrements the session ref-count and deletes the user when the last session closes
6. Subscribes to service-changed events and reloads each service's `ziti-ssh-host.v1` config atomically when it changes — no restart needed

**`inspect [--service <name>]...`:**
- Authenticates with the host identity; no listeners opened
- For each named service: reports whether the service is visible, whether a `ziti-ssh-host.v1` config is attached, and prints the full permissions table (Ziti identity name → derived Linux username → groups → sudoers rule)
- Also prints the global fallback values (`ZITI_SSH_GROUPS`, `ZITI_SUDOERS_RULE`) alongside each service block
- Useful for verifying configuration before putting a host into service or after a config change

## Per-Identity Permissions (`ziti-ssh-host.v1`)

In `per-identity` mode, Linux permissions for each connecting identity are resolved from two sources in order:

1. **`ziti-ssh-host.v1` Ziti service config** (per-identity, per-service): a config of this type attached to the Ziti service the connection arrived on. The config is a JSON object mapping exact Ziti identity names to a permissions entry:

```json
{
  "permissions": {
    "alice@corp.com": {
      "groups":       ["docker", "adm"],
      "sudoers_rule": "ALL=(ALL) NOPASSWD: /bin/systemctl status *"
    },
    "ops-automation": {
      "sudoers_rule": "ALL=(ALL) NOPASSWD: ALL"
    }
  }
}
```

2. **Global fallbacks** (apply when no config is attached, or when the identity has no entry in the config):
   - `ZITI_SSH_GROUPS` — comma-separated Linux group names
   - `ZITI_SUDOERS_RULE` — sudoers rule fragment

**Resolution:** if an identity has a config entry, that entry is its complete permission specification — global fallbacks are not merged in. If there is no config entry, global fallbacks apply in full.

**Scope:** the `ziti-ssh-host.v1` config is attached to a specific Ziti service. Because a host can bind to multiple services simultaneously, different permission sets can apply to the same physical host depending on which service a caller dials. This enables role-tiered deployments:

```
DB server running:  ziti-ssh-host run --ssh-service ssh-ops --ssh-service ssh-db

ssh-ops config: alice → [sudo, adm]    ← ops team, OS-level access
ssh-db  config: carol → [mysql]        ← DBA team, database-level access
```

**Config type registration:** `ziti-ssh-ca config apply` registers the `ziti-ssh-host.v1` schema on the controller as a one-time setup step. Subsequent `ziti edge update config` commands update individual permission configs; changes propagate live to all running `ziti-ssh-host` instances within seconds.

## Wire Protocol

Over a raw Ziti connection to `ssh-ca`:
- **Fetch CA public key:** send empty line (`\n`) → receive CA public key in authorized_keys format
- **Sign cert:** send SSH public key in authorized_keys format → receive signed cert in authorized_keys format

No HTTP, no framing beyond the newline.

## Certificate Fields

| Field | Value |
|---|---|
| Principal | Configurable (default: `ziggy`); derived from identity name in `per-identity` mode |
| Key ID | `ziti:<identity-name>` |
| Validity | 8 hours from signing time (configurable via `--cert-ttl`) |
| Extensions | `permit-pty`, `permit-port-forwarding`, `permit-agent-forwarding` |

The Key ID appears in `/var/log/auth.log` on every SSH host, providing a per-identity audit trail even though all users share the same account in `shared` mode.

## Configuration

All binaries accept configuration via flags and environment variables (flags take precedence).

### `ziti-ssh-ca`

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | — | Path to Ziti identity file |
| `--ca-key` | `ZITI_CA_KEY` | — | Path to CA private key (Ed25519) |
| `--service` | `ZITI_CA_SERVICE` | `ssh-ca` | Ziti service name to bind |
| `--principal` | `ZITI_SSH_PRINCIPAL` | `ziggy` | SSH certificate principal (shared mode only) |
| `--mode` | `ZITI_SSH_MODE` | `shared` | Principal mode: `shared` or `per-identity` |
| `--cert-ttl` | `ZITI_CERT_TTL` | `8h` | Certificate validity duration (e.g. `4h`, `12h`, `24h`); must be > 0 |
| `--rate-limit` | `ZITI_RATE_LIMIT` | `5` | Max cert signing requests per minute per identity |
| `--rate-burst` | `ZITI_RATE_BURST` | `3` | Burst allowance for the per-identity rate limiter |
| `--ziti-timeout` | `ZITI_TIMEOUT` | `30s` | Timeout for blocking Ziti network operations |

`config apply` / `config remove` additional flags:

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--controller` | `ZITI_CTRL_ADDRESS` | — | Controller host, optionally with port (default port: 443) |
| `--username` | `ZITI_CTRL_USERNAME` | — | Controller admin username |
| `--password` | `ZITI_CTRL_PASSWORD` | — | Controller admin password |
| `--insecure` | `ZITI_CTRL_INSECURE` | false | Skip TLS certificate verification |
| `--controller-ca` | `ZITI_CTRL_CA` | — | Path to PEM CA cert to trust for controller TLS |

### `ziti-ssh-host`

Persistent flags (accepted by all subcommands):

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | `/etc/ziti-ssh-host/identity.json` | Path to Ziti identity file |
| `--ziti-timeout` | `ZITI_TIMEOUT` | `30s` | Timeout for blocking Ziti network operations |

`run` subcommand flags and env vars:

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--ssh-service` | `ZITI_SSH_SERVICE` | `ssh` | Ziti service(s) to proxy; flag may be repeated, env var accepts comma-separated list |
| `--mode` | `ZITI_SSH_MODE` | `shared` | Principal mode: `shared` or `per-identity` |
| — | `ZITI_SUDOERS_RULE` | — | Global fallback sudoers rule (per-identity mode only) |
| — | `ZITI_SSH_GROUPS` | — | Global fallback Linux groups, comma-separated (per-identity mode only) |
| — | `ZITI_USER_CLEANUP` | `true` | Set to `false` to keep Linux accounts after the last session closes |

**Important:** `--mode` must be set consistently on both `ziti-ssh-ca` and `ziti-ssh-host run`. If the CA issues certs with per-identity principals but the host is in shared mode (or vice versa), SSH authentication will fail.

## Modes

### `shared` (default)

All connections authenticate as a single shared Linux user (e.g. `ziggy`). The CA signs every certificate with the same `--principal`. This is the simplest deployment and requires no special privileges beyond what sshd already provides.

### `per-identity`

The CA derives a Linux username from each caller's Ziti identity name using `ca.DeriveUsername` and uses it as the certificate principal. `ziti-ssh-host run` creates the Linux user on first connection and deletes it (including home directory) when the last session for that identity closes.

**Username sanitization rules** (applied by `ca.DeriveUsername`):
1. Lowercase the entire identity name.
2. Replace any character outside `[a-z0-9_-]` with `_`.
3. If the result starts with a digit, prefix it with `z`.
4. Truncate to 32 characters.

Example: `Alice@Corp` → `alice_corp`

**Ephemeral user lifecycle:**
- `ziti-ssh-host run` creates the user with `useradd -m -s /bin/bash <username>` on the first connection from that identity.
- Permissions are resolved (config entry → global fallback) and applied: `usermod -aG <groups>` for group membership, `/etc/sudoers.d/<username>` for sudoers (validated with `visudo -c` before installation). Group failures are non-fatal and logged.
- A reference count tracks concurrent sessions for the same identity.
- When the last session closes, the cleanup sequence runs: `loginctl terminate-user`, process poll (up to 5 s), `userdel -r`. The sudoers file is removed unconditionally at this point; group membership is removed implicitly by account deletion.
- The set of active managed usernames is persisted to `/var/lib/ziti-ssh-host/managed-users` (one username per line). On startup, `CleanupOrphans` reads this file and deletes any users still listed there (they had active sessions when the process was killed). This prevents accumulation of stale accounts after crashes.
- Set `ZITI_USER_CLEANUP=false` to keep the Linux account across disconnects (useful for persistent home-directory setups). The sudoers file is still removed on disconnect.

**Connecting in per-identity mode:**
```sh
ziti-ssh alice_corp@web-server-prod
```
The username before `@` must match the derived username for the caller's identity.

## SSH Host Configuration

Written by `ziti-ssh-host enroll` to `/etc/ssh/sshd_config.d/ziti-ssh.conf`:

```
TrustedUserCAKeys /etc/ssh/ziti_ca.pub
```

No other changes required. No SSSD, no NSS, no PAM modifications, no custom sshd.

## PKI Hierarchy

The Ziti controller uses a two-tier PKI:

```
Root CA (offline)
  └── Controller Intermediate CA  ← signs Ziti identity certificates
        └── Ziti Identity Certs   ← issued to clients, hosts, services
```

The root CA private key is kept offline and is not used at runtime. The controller's **intermediate CA private key** is the operational signing key — it issues every Ziti identity certificate.

## CA Private Key

The `--ca-key` argument to `ziti-ssh-ca` is the **controller's intermediate CA private key** — not the root CA key. This is the key that signs Ziti identity certificates, and it is therefore the key sshd must trust via `TrustedUserCAKeys`.

In production, `ziti-ssh-ca` runs on the same machine as the Ziti controller, as the same OS user (typically `ziti`). This gives it direct filesystem access to the controller's PKI. The intermediate CA key path is typically:

```
/var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key
```

The exact path depends on the controller installation — check the controller config file to confirm. Do not use the root CA key path.

The key file should remain mode 0600 and owned by the controller service user. `ziti-ssh-ca` reads it at startup only and holds the resulting `ssh.Signer` in memory. Rotation is a Ziti controller operation; after rotation, restart `ziti-ssh-ca` and re-enroll SSH hosts to distribute the new CA public key.

## Deployment

- **Language:** Go
- **Target OS:** Ubuntu 24.04+ (also the upcoming 26.04)
- **CA key type:** Ed25519
- **Shared Linux user:** `ziggy` (default, configurable)

## Project Structure

```
ziti-ssh/
├── cmd/
│   ├── ziti-ssh/
│   │   ├── main.go         # Full SSH client (connect, sign, enroll, list, mfa)
│   │   └── oidc.go         # Browser-based OIDC auth flow
│   ├── ziti-scp/
│   │   └── main.go         # SCP-style file copy tool (upload, download, recursive)
│   ├── ziti-ssh-ca/
│   │   ├── main.go         # CA service entry point and run loop
│   │   └── config.go       # config subcommand (print, apply, remove)
│   └── ziti-ssh-host/
│       └── main.go         # enroll, run (multi-service), inspect subcommands
├── ca/
│   └── ca.go               # CA key loading, cert signing, DeriveUsername
├── client/
│   ├── ssh.go              # NewCertSigner, CertNeedsRefresh, RunSession, RunCommand
│   └── sftp.go             # RunSFTP — SFTP file copy over net.Conn
├── host/
│   ├── host.go             # ProxyHooks, Proxy, UserManager, PermissionsConfig, sshd config
│   └── host_test.go        # Unit tests for PermissionsConfig.Resolve and UserManager
├── config/
│   └── config.go           # Shared configuration (flags + env vars)
├── internal/
│   └── ratelimit/          # Per-identity token-bucket rate limiter
├── go.mod
├── go.sum
└── CLAUDE.md
```

## Documentation

| File | Purpose |
|---|---|
| `README.md` | Project overview, prerequisites, building |
| `docs/provisioning.md` | Ziti network setup, per-component installation, `ziti-ssh-host.v1` config type admin setup |
| `docs/usage.md` | End-user guide: certs, connecting, file copy, MFA |
| `docs/configuration.md` | Full flag/env/config reference for all binaries, `ziti-ssh-host.v1` schema |
| `docs/operations.md` | Modes, per-identity permissions, multi-service binding, inspect tool, CA key rotation, graceful shutdown |
