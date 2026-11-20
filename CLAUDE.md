# ziti-ssh

An SSH Certificate Authority service and host daemon for OpenZiti networks. Allows Ziti identities to obtain short-lived SSH certificates and connect to SSH hosts exclusively through the Ziti overlay — with no credentials stored on SSH hosts and no exposure of port 22.

## Problem

Standard SSH public key auth requires either:
- Per-user `authorized_keys` files on every host, or
- A service querying an identity provider at auth time — which requires credentials on every SSH host

Both approaches are operationally expensive. The credentials-on-host requirement is a security concern at scale. Additionally, exposing port 22 to any network is a persistent attack surface.

## Solution

Four cooperating binaries:

1. **`ziti-ssh-ca`** — a CA service hosted as a Ziti service that signs short-lived SSH certificates for authorized callers. SSH hosts trust only the CA's public key — not a credential. Also provides an `enroll` subcommand for identity enrollment and a `config` subcommand that installs and manages the `ziti-ssh-host.v1` config type on the Ziti controller.

2. **`ziti-ssh-host`** — a host daemon that enrolls the host into a Ziti network, configures sshd to trust the CA, and proxies Ziti connections to the local sshd. In `per-identity` mode, creates ephemeral Linux users and applies per-identity permissions (groups, sudoers rules) sourced from a `ziti-ssh-host.v1` config attached to the Ziti service. A single instance can bind to multiple Ziti services simultaneously, each with independent permissions.

3. **`ziti-ssh`** — a full SSH client over OpenZiti. Subcommands: `connect` (default), `sign`, `enroll`, `list`, `mfa`. Obtains and caches SSH certificates from the CA; auto-refreshes when less than 20% of its lifetime remains (between 30 s and 5 min — 1 minute for the default 5-minute certificate); validates the CA reply (rejects `error:` replies and certs for another key) before writing it.

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

The caller's name is read **only** from `GetDialerIdentityName()` (set by the dialer's edge router; requires OpenZiti v2.0.0+). Never use `SourceIdentifier()` (the client-supplied `CallerId` header) for any authorization decision — a modified client can set it to anything. Connections with no dialer identity are rejected.

### Ziti service policy IS the access control
Any Ziti identity that can dial the `ssh-ca` service is authorized to receive a cert. Any Ziti identity that can dial the `ssh` service terminator for a given host is authorized to reach that host. Access control is managed entirely through Ziti service policies.

### Ziti service config IS the permission scope
Per-identity Linux permissions (groups, sudoers rules) are stored as a `ziti-ssh-host.v1` config attached to the Ziti service. The service boundary is therefore the permission scope boundary — the same boundary already used for access control. Different services can carry different permission sets, enabling role-tiered deployments where, for example, DB admins and ops teams can both reach a database host but with different Linux permissions.

### Short-lived certificates (5m TTL)
Certificates expire after 5 minutes by default (`--cert-ttl`). No revocation infrastructure needed — compromised or removed identities lose access at expiry without any intervention on SSH hosts.

### `ziti-ssh` and `ziti-scp` as client tools
`ziti-ssh` is the interactive client. It handles Ziti dialing, SSH certificate management, and interactive SSH sessions. The `sign` subcommand fetches certs from the CA; the `connect` subcommand (default) auto-refreshes the cert if needed and then opens an SSH session. The `enroll`, `list`, and `mfa` subcommands cover the full Ziti identity lifecycle on user machines.

`ziti-scp` is the file copy companion. It uses the same identity, cert, and config infrastructure as `ziti-ssh` but opens an SFTP subsystem session instead of an interactive shell. The same cert auto-refresh logic applies (`client.CertNeedsRefresh`), and the same Ziti service resolution (direct service name vs. terminator address on `--ssh-service`) is used.

### Addressable terminators for host routing
Each `ziti-ssh-host` instance listens on a Ziti service with its identity name as the terminator address. `ziti-ssh` dials the service specifying the target identity name — no hostname resolution, no config file required.

## Components

### SSH Client (`ziti-ssh`)

Seven subcommands:

**`connect [user@]<target>`** (also the default when a bare argument is given):
- Auto-refreshes the SSH cert if missing or less than 20% of its lifetime remains (between 30 s and 5 min — 1 minute for the default 5-minute certificate).
- Resolves whether the target is a direct Ziti service name or a terminator address on `--ssh-service`.
- Uses `ziti.DialOptions{Identity: terminatorAddr}` when dialling via a terminator.
- Wraps the private key and cert into an `ssh.CertSigner` via `client.NewCertSigner`. Falls back to `SSH_AUTH_SOCK` if the private key is passphrase-protected.
- Runs a full interactive PTY session via `client.RunSession` (no forwards) or via `client.NewSSHClient` + `runSSHClientSession` when `-L`/`-R`/`-D` forwards are active.
- `-A` / `--forward-agent` — forward the local SSH agent to the remote session; refused unless `--forward-agent-unverified` is also given (`checkAgentForwarding`: hosts cannot yet be verified, see H8) and the CA grants `permit-agent-forwarding`; calls `client.ForwardAgent(sshClient, session)` before `session.Shell()`; non-fatal if `SSH_AUTH_SOCK` is unset or agent unreachable.
- Accepts a trailing command (after `--`) for non-interactive execution via `client.RunCommand`; the remote exit code is propagated.
- `-L [bind:]localport:remotehost:remoteport` — local port forward; may be repeated; calls `client.RunLocalForward` in a goroutine. Specs are split by `splitForwardSpec` (bracketed IPv6, ports 1–65535); non-loopback `-L`/`-D` binds print a warning (`warnNonLoopbackBind`).
- `-R [bind:]remoteport:localhost:localport` — remote port forward; calls `client.RunRemoteForward` in a goroutine.
- `-D [bind:]port` — dynamic SOCKS5 proxy; calls `client.RunDynamicProxy` in a goroutine.
- `-N` / `--no-shell` — block without opening a shell; only runs the requested forwards until SIGINT/SIGTERM.
- When any forward is present: all forwards + (optionally) the shell session run concurrently under a shared `context.Context`; SIGINT/SIGTERM cancels the context and tears everything down.

**`proxy [user@]<target>`**:
- Auto-refreshes the SSH cert (same threshold as `connect`).
- Dials the Ziti service raw — no SSH handshake performed by `ziti-ssh`.
- Bridges `os.Stdin` ↔ conn and conn → `os.Stdout` via `io.Copy` in two goroutines; returns when either direction closes.
- Intended as a `ProxyCommand` in `~/.ssh/config` so that standard tools (`ssh`, `git`, `rsync`, VS Code Remote) work through the Ziti overlay without modification.
- The user@ portion of the argument is accepted for syntax compatibility but is not used.

**`sign`**: Dials `ssh-ca`, sends the SSH public key, writes the signed cert to `<key>-cert.pub`, prints cert details via `ssh-keygen -L`.

**`enroll --jwt <path>`**: Calls `enroll.Enroll` with `KeyAlg = "EC"`. Writes the identity JSON to `~/.config/ziti-ssh/<name>.json` by default (`--out` overrides).

**`list`**: Calls `ctx.GetServices()` and prints each service name and permissions.

**`known-hosts list|remove <address>`**: shows or forgets remembered SSH host keys (`client.KnownHosts`).

**`mfa enable/verify/remove`**: Uses `zitiCtx.EnrollZitiMfa`, `VerifyZitiMfa`, `RemoveZitiMfa` with `AddMfaTotpCodeListener` / `AddAuthenticationStateFullListener` event hooks.

**MFA during authentication** (`internal/mfa`): every authenticating command (`connect`, `sign`, `proxy`, `list`, `ziti-scp`) calls `mfa.RegisterTTY` before `Authenticate`, so `EventMfaTotpCode` is answered from `/dev/tty` (hidden; never stdin; 3 attempts; stops at EOF). The SDK emits it synchronously, so typing counts against `--ziti-timeout`. The `mfa` subcommands read stdin via `mfa.NewReader`.

**OIDC authentication**: When `--oidc-issuer` is set (or `oidc.issuer` in the config file), `connect`, `sign`, and `proxy` perform a browser-based OIDC authorization code flow (PKCE when no client secret) before authenticating with Ziti. The resulting JWT is added to the Ziti context via `AddJWT()`, satisfying ext-jwt-signer policies on the controller. Flow times out after 2 minutes. The callback port is claimed on loopback only (`127.0.0.1` and `::1`) before the IdP is contacted, and the flow aborts if either address is already in use (`listenLoopback`); the login URL is printed to stderr before a non-fatal browser launch. Implemented in `cmd/ziti-ssh/oidc.go` and `internal/oidc/oidc.go`.

Config file at `~/.config/ziti-ssh/config.yaml` (XDG_CONFIG_HOME respected). Fields: `identity`, `ca_service`, `ssh_service`, `ssh_key_path`, `mode`, `oidc.*`. Three-tier precedence: CLI flag > config file > default.

### SSH Session / SFTP Library (`client/ssh.go`, `client/sftp.go`)

- `NewCertSigner(keyPath string) (ssh.Signer, error)` — loads key and cert; returns `ssh.CertSigner` if cert present. `NewCertSignerPrompt(keyPath, prompt)` additionally asks for the passphrase (`TTYPassphrasePrompt`, `/dev/tty`) when the key is encrypted and no agent holds it; `connect` and `ziti-scp` use it.
- `config.CheckUserFile(path)` — refuses `config.yaml` / `known_hosts` that are world-writable, group-writable by a shared group (the owner's private group — Debian/Ubuntu umask 002 — is accepted, as in OpenSSH), or owned by another user.
- `CertNeedsRefresh(certPath string) bool` — true if cert absent or less than 20% of its lifetime remains (between 30 s and 5 min — 1 minute for the default 5-minute certificate).
- `ReadCAResponse(r) (string, error)` / `ValidateSignedCert(line, pubKeyLine) ([]byte, error)` (`client/certs.go`) — bounded read of the CA reply; returns `*CARejectedError` for `error: …` replies and rejects anything but a user cert for the caller's key, so a bad reply never overwrites a valid cert.
- `NewSSHClient(conn net.Conn, user, host string, signer ssh.Signer, hostKeyCallback ssh.HostKeyCallback) (*ssh.Client, error)` — performs the SSH handshake and returns a raw `*ssh.Client` for forwarding use cases.
- `RunSession(conn net.Conn, user, host string, signer ssh.Signer, forwardAgent bool, hostKeyCallback ssh.HostKeyCallback) error` — PTY SSH session over an existing `net.Conn`; when `forwardAgent` is true, calls `ForwardAgent` before `session.Shell()`.
- `ForwardAgent(sshClient *ssh.Client, session *ssh.Session) error` — connects to `SSH_AUTH_SOCK`, calls `agent.ForwardToAgent` on the client and `agent.RequestAgentForwarding` on the session; returns an error (non-fatal by convention) if `SSH_AUTH_SOCK` is unset or agent is unreachable.
- `RunCommand(conn net.Conn, user, host, cmd string, signer ssh.Signer, hostKeyCallback ssh.HostKeyCallback) error` — non-interactive command execution; propagates remote exit code via `os.Exit`.
- `RunLocalForward(ctx, sshClient, LocalForwardSpec) error` — local port forward (-L); listens locally, tunnels via `direct-tcpip`; runs until ctx cancelled.
- `RunRemoteForward(ctx, sshClient, RemoteForwardSpec) error` — remote port forward (-R); uses `sshClient.Listen`; runs until ctx cancelled.
- `RunDynamicProxy(ctx, sshClient, DynamicForwardSpec) error` — SOCKS5 proxy (-D); implements RFC 1928 CONNECT with no-auth; runs until ctx cancelled.
- `NewHostKeyCallback(service, terminator string) (ssh.HostKeyCallback, error)` (`client/hostkeys.go`) — trust-on-first-use host keys in `~/.config/ziti-ssh/known_hosts`, keyed by Ziti address (`<terminator>@<service>`, or `<service>` for a direct service dial). Terminator address: a changed key is refused. Direct service dial (any bound host may answer): the user is asked to trust an additional key (refused without a terminal). Replaces `InsecureIgnoreHostKey`; OpenZiti cannot tell the dialer which identity answered (H8).
- `RunSFTP(conn, user, host, signer, isUpload, localPaths, remotePath, recursive, preserve, quiet, hostKeyCallback) error` — SFTP file copy over an existing `net.Conn`; uses `github.com/pkg/sftp`.

### File Copy Tool (`ziti-scp`)

- Parses `[user@]host:path` remote specs and bare local paths from positional arguments (last arg is destination). Remote only if a `:` has no `/` before it (scp semantics); user split at the last `@` (also `ziti-ssh`'s `parseTarget`). `--service <svc>` forces terminator addressing (as in `ziti-ssh`).
- Same cert auto-refresh threshold and Ziti dial logic as `ziti-ssh`.
- Flags: `-r` (recursive), `-p` (preserve timestamps/permissions), `-q` (quiet).
- `enroll` subcommand for identity enrollment (mirrors `ziti-ssh enroll`).
- Shared config file: `~/.config/ziti-ssh/config.yaml`.

### CA Service (`ziti-ssh-ca`)

Three modes of operation: a long-running service, a one-shot `enroll` command, and a one-shot `config` management command.

**Service (default / root command):**
- Binds to a named Ziti service (default: `ssh-ca`)
- Accepts incoming connections from Ziti clients
- Extracts the caller's Ziti identity name from the connection
- Accepts the caller's SSH public key (authorized_keys format) in the request body
- Signs it using the CA private key via `golang.org/x/crypto/ssh`
- Returns the signed certificate (authorized_keys format)
- If the request body is empty, returns the CA public key instead (used by hosts during enrollment)
- Embeds the Ziti identity name as the certificate Key ID (for audit logging)
- Issues certs with a configurable principal (default: `ziggy`) and 5m validity
- Enforces a per-identity token-bucket rate limit (default: 5 req/min, burst 3) on every request, checked before the request is read
- Caps concurrent connections (`--max-connections`, default 64); further connections are closed immediately
- Only certifies ed25519, ECDSA (P-256/384/521), `sk-` security-key variants, and RSA ≥ 3072 bits (`ca.ValidateClientKey`); refuses certificates, DSA, short RSA and its own key with an `error:` reply

**`enroll` subcommand** — enrolls the CA server's Ziti identity from a one-time JWT file. Writes the identity JSON to `/etc/ziti-ssh-ca/identity.json` (mode 0600) by default; `--out` overrides the path. No CA-specific post-enrollment steps needed.

**`config` subcommand** — manages the `ziti-ssh-host.v1` config type on the Ziti controller via the management API (HTTPS, username/password auth):

- `config print` — prints the field table and JSON schema locally; no controller connection needed.
- `config apply` — idempotent install-or-update of the `ziti-ssh-host.v1` config type: checks whether it exists, then creates or replaces it.
- `config remove` — removes the `ziti-ssh-host.v1` config type if present.

Flags: `--controller <host[:port]>` (default port 443), `--username`, `--password` (warns; prefer `--password-file`, env, or the hidden prompt), `--password-file <file|->`, `--yes`, `--insecure` (skip TLS verify; warns), `--controller-ca <path>` (trust a specific CA cert). Controller TLS trust (`cmd/ziti-ssh-ca/ctrltrust.go`) mirrors `ziti edge login`: `--controller-ca` → saved bundle (`$XDG_CONFIG_HOME/ziti-ssh/controllers/<host>_<port>.pem`) → system roots → fetch `/.well-known/est/cacerts`, verify the server against it, confirm (or `--yes`) and save; a changed CA is refused unless confirmed interactively (`--yes` never replaces). All have env var equivalents (`ZITI_CTRL_ADDRESS`, `ZITI_CTRL_USERNAME`, `ZITI_CTRL_PASSWORD`, `ZITI_CTRL_INSECURE`, `ZITI_CTRL_CA`). `--insecure` and `--controller-ca` are mutually exclusive.

### Host Daemon (`ziti-ssh-host`)

Four subcommands:

**`enroll --jwt <path>`:**
1. Enrolls the host Ziti identity from a JWT token
2. Reads the `ctrls` claim from the JWT to discover all controllers in the cluster; falls back to the issuer URL for older controllers that omit the claim
3. Fetches the intermediate CA public key from each controller via `GET /edge/client/v1/.well-known/est/cacerts`, using the Root CA from the enrollment response as the TLS trust anchor
4. Writes all intermediate CA public keys (one per line) to `TrustedUserCAKeys` in `/etc/ssh/sshd_config.d/ziti-ssh.conf` — in an HA cluster each controller node has its own intermediate CA, and all must be trusted
5. Reloads sshd

**`run`:**
1. Initializes Ziti context from the identity file; declares `ziti-ssh-host.v1` as a requested config type so the controller delivers it with the service detail
2. Subscribes to `EventControllerUrlsUpdated` before authenticating; when the controller cluster membership changes: (a) persists the updated controller URL list to the identity JSON via `config.PersistZtAPIs`, and (b) fetches CA public keys from the new set of controllers and rewrites `TrustedUserCAKeys` + reloads sshd if the set changed. All four binaries call `PersistZtAPIs` on this event so the identity file always reflects the live cluster membership. Entries must pass `config.CheckControllerURL` (https, host, no userinfo/query/fragment); `FilterControllerURLs` drops the rest (also before CA-key refresh), dedupes, and an unchanged list is not rewritten.
3. Accepts one or more `--ssh-service` values (flag may be repeated; `ZITI_SSH_SERVICE` accepts comma-separated list; defaults to `ssh`)
4. For each service: opens a separate Ziti listener, loads and parses the `ziti-ssh-host.v1` config, builds independent `ProxyHooks` carrying that service's permission map
5. Proxies incoming connections to `127.0.0.1:22`
6. In `per-identity` mode: on connect, creates an ephemeral Linux user and applies the resolved permissions (groups via `usermod -G`, sudoers rule via `/etc/sudoers.d/ziti-ssh-host-<username>`); only accounts in the ownership registry are ever touched; on disconnect, decrements the session ref-count and deletes the user when the last session closes
7. Subscribes to service-changed events and reloads each service's `ziti-ssh-host.v1` config atomically when it changes — no restart needed; if a config cannot be loaded or parsed (at startup or on reload), per-identity connections on that service are rejected until a valid config loads (`serviceState.update/current`)

**`inspect [--service <name>]...`:**
- Authenticates with the host identity; no listeners opened
- For each named service: reports whether the service is visible, whether a `ziti-ssh-host.v1` config is attached, and prints the full permissions table (Ziti identity name → derived Linux username → groups → sudoers rule)
- Also prints the global fallback values (`ZITI_SSH_GROUPS`, `ZITI_SUDOERS_RULE`) alongside each service block
- Useful for verifying configuration before putting a host into service or after a config change

**`users list` / `users claim --username <u> --identity <id>`** (root; no Ziti connection):
- `list` prints the per-identity account ownership registry with each account's current status
- `claim` registers an existing account (UID ≥ 1000, username == `ca.DeriveUsername(identity)`) as owned by an identity — the migration path for accounts created before the registry existed

## Per-Identity Permissions (`ziti-ssh-host.v1`)

In `per-identity` mode, Linux permissions for each connecting identity are resolved from two sources in order:

1. **`ziti-ssh-host.v1` Ziti service config** (per-identity, per-service): a config of this type attached to the Ziti service the connection arrived on. The config is a JSON object mapping Ziti identity names (or patterns) to a permissions entry. Keys may be exact identity names, glob patterns (using `*` and `?` via `path.Match`), or the `"*"` catch-all:

```json
{
  "permissions": {
    "*":              { "groups": ["developers"] },
    "dba-*":          { "groups": ["developers", "docker"] },
    "alice@corp.com": { "groups": ["docker", "adm"], "sudoers_rule": "ALL=(ALL) NOPASSWD: /bin/systemctl status *" },
    "ops-automation": { "sudoers_rule": "ALL=(ALL) NOPASSWD: ALL" }
  }
}
```

   The `docker` group and the `sudoers_rule` entries above are applied only if the host opts the service in (`ZITI_ALLOW_GROUPS=<svc>:docker`, `ZITI_ALLOW_SUDOERS=<svc>`); see **Host grant policy** below.

2. **Global fallbacks** (apply when no config is attached, or when no config key matches the identity):
   - `ZITI_SSH_GROUPS` — comma-separated Linux group names
   - `ZITI_SUDOERS_RULE` — sudoers rule fragment

**Resolution order:** (1) exact key match; (2) most-specific glob pattern (longest literal prefix before the first wildcard wins, then most literals, then lexically smallest pattern); (3) `"*"` catch-all; (4) global fallbacks. Patterns use `host.MatchPattern`: `*` any run (incl. `/`), `?` one character, all else literal (`[`/`\` keys flagged by `PermissionsConfig.PatternWarnings`). Any matched config entry is the complete permission specification — global fallbacks are not merged in. The `"*"` catch-all is preferred over env var fallbacks because it lives in the Ziti config and propagates live without restarting hosts.

**Scope:** the `ziti-ssh-host.v1` config is attached to a specific Ziti service. Because a host can bind to multiple services simultaneously, different permission sets can apply to the same physical host depending on which service a caller dials. This enables role-tiered deployments:

```
DB server running:  ziti-ssh-host run --ssh-service ssh-ops --ssh-service ssh-db

ssh-ops config: ops-alice → [sudo, adm]    ← ops team, OS-level access
ssh-db  config: dba-carol → [mysql]        ← DBA team, database-level access

host env: ZITI_ALLOW_GROUPS=ssh-ops:sudo   ← host owner lets only ssh-ops grant sudo
```

**Host grant policy (`host.GrantPolicy`, `host/grant.go`):** the host owner limits, per service, what a config may grant: `ZITI_ALLOW_SUDOERS` (services whose config may set `sudoers_rule`; default none), `ZITI_ALLOW_GROUPS` (`<service>:<group>` opt-ins for privileged groups `root`, `sudo`, `admin`, `wheel`, `docker`, `lxd`, `disk`, `shadow`, `libvirt`; any other group is allowed by default), `ZITI_RESTRICT_GROUPS=true` (only listed groups). Refused entries reject the connection (`GrantPolicy.Enforce` in the connect hook), are logged at config load/reload, and are flagged by `inspect`. The host's own fallbacks (`ZITI_SSH_GROUPS`, `ZITI_SUDOERS_RULE`) are not subject to it (`ResolveWithSource`). Controller config write access alone therefore cannot grant root.

**Config type registration:** `ziti-ssh-ca config apply` registers the `ziti-ssh-host.v1` schema on the controller as a one-time setup step. Subsequent `ziti edge update config` commands update individual permission configs; changes reach running `ziti-ssh-host` instances at their next service refresh (`ZITI_SERVICE_REFRESH`, default 30 s; the SDK default would be 5 min — `newZitiContextWithConfigTypes` sets `Options.RefreshInterval`).

## Wire Protocol

Over a raw Ziti connection to `ssh-ca`:
- **Fetch CA public key:** send empty line (`\n`) → receive CA public key in authorized_keys format
- **Sign cert:** send SSH public key in authorized_keys format → receive signed cert in authorized_keys format
- **Refusal:** `error: <reason>` line (e.g. `error: rate limit exceeded`). Both request types count against the per-identity rate limit, which is checked before the request is read. Connections beyond `--max-connections` are closed without a reply; each connection has a 10 s deadline and a 4 KiB request cap.

No HTTP, no framing beyond the newline.

## Certificate Fields

| Field | Value |
|---|---|
| Principal | Configurable (default: `ziggy`); derived from identity name in `per-identity` mode |
| Key ID | `ziti:<identity-name>` |
| Serial | Random non-zero 64-bit value; logged by the CA at issue and by sshd at login |
| Validity | From 60 s before signing (`ca.ClockSkewAllowance`, clock-skew tolerance) until 5 minutes after signing by default (configurable via `--cert-ttl`) |
| Extensions | `permit-pty`, `permit-port-forwarding` by default (`--cert-extensions`; agent forwarding only if configured) |
| Critical options | `source-address=127.0.0.1/32,::1/128` (`--cert-source-address`): sshd accepts the cert only from loopback, i.e. via the local `ziti-ssh-host` proxy, so a cert cannot be used by connecting to port 22 directly |

The Key ID appears in `/var/log/auth.log` on every SSH host, providing a per-identity audit trail even though all users share the same account in `shared` mode.

## Configuration

All binaries accept configuration via flags and environment variables (flags take precedence).

### `ziti-ssh-ca`

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | — | Path to Ziti identity file |
| `--ca-key` | `ZITI_CA_KEY` | — | Path to the controller's intermediate CA private key (RSA, ECDSA or Ed25519; typically RSA) |
| `--service` | `ZITI_CA_SERVICE` | `ssh-ca` | Ziti service name to bind |
| `--principal` | `ZITI_SSH_PRINCIPAL` | `ziggy` | SSH certificate principal (shared mode only) |
| `--mode` | `ZITI_SSH_MODE` | `shared` | Principal mode: `shared` or `per-identity` |
| `--cert-ttl` | `ZITI_CERT_TTL` | `5m` | Certificate validity duration (e.g. `4h`, `12h`, `24h`); must be > 0 |
| `--cert-extensions` | `ZITI_CERT_EXTENSIONS` | `permit-pty,permit-port-forwarding` | Certificate extensions to grant, or `none` |
| `--cert-source-address` | `ZITI_CERT_SOURCE_ADDRESS` | `127.0.0.1/32,::1/128` | Comma-separated IPs/CIDRs written to each certificate's `source-address` critical option; sshd accepts the certificate only from those addresses. The default (loopback) means certificates work only through `ziti-ssh-host`'s local proxy. `none` disables it. |
| `--rate-limit` | `ZITI_RATE_LIMIT` | `5` | Max requests (cert signing and CA public key) per minute per identity |
| `--rate-burst` | `ZITI_RATE_BURST` | `3` | Burst allowance for the per-identity rate limiter |
| `--max-connections` | `ZITI_MAX_CONNECTIONS` | `64` | Maximum concurrent CA connections; further connections are closed immediately |
| `--ziti-timeout` | `ZITI_TIMEOUT` | `30s` | Timeout for blocking Ziti network operations |

`config apply` / `config remove` additional flags:

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--controller` | `ZITI_CTRL_ADDRESS` | — | Controller host, optionally with port (default port: 443) |
| `--username` | `ZITI_CTRL_USERNAME` | — | Controller admin username |
| `--password` | `ZITI_CTRL_PASSWORD` | — | Controller admin password (flag warns: visible in process list) |
| `--password-file` | `ZITI_CTRL_PASSWORD_FILE` | — | Password from a file (`-` = stdin) |
| `--yes` | — | false | Trust the controller CA bundle on first use without asking |
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
| `--max-connections` | `ZITI_MAX_CONNECTIONS` | `128` | Max concurrent connections per service (`host.ProxyLimited`); excess closed immediately |
| — | `ZITI_SUDOERS_RULE` | — | Global fallback sudoers rule (per-identity mode only) |
| — | `ZITI_SSH_GROUPS` | — | Global fallback Linux groups, comma-separated (per-identity mode only) |
| — | `ZITI_USER_CLEANUP` | `false` | Set to `true` to delete Linux accounts after the last session closes |
| — | `ZITI_ALLOW_SUDOERS` | — | Services (comma-separated, or `*`) whose config may set `sudoers_rule`; others are refused (connection rejected) |
| — | `ZITI_ALLOW_GROUPS` | — | `<service>:<group>` / `*:<group>` list of privileged groups (`root`, `sudo`, `admin`, `wheel`, `docker`, `lxd`, `disk`, `shadow`, `libvirt`) a service's config may grant |
| — | `ZITI_RESTRICT_GROUPS` | `false` | `true`: config may grant only groups listed in `ZITI_ALLOW_GROUPS` |
| — | `ZITI_SERVICE_REFRESH` | `30s` | How often `run` checks the controller for service changes (minimum `5s`); a changed `ziti-ssh-host.v1` config applies within this interval |
| — | `ZITI_TERMINATE_ON_DISCONNECT` | `false` | With cleanup off: set to `true` to end everything the account can run when the last session closes (account expired with `usermod -e 1`, crontab and `at` jobs removed, lingering disabled, `loginctl terminate-user`, SIGTERM/SIGKILL by UID), keeping the account; `accountOps.ReactivateAccount` (`usermod -e ""`) re-enables it on the next authorized connect (fail closed). Needed for revoked identities to lose background processes. |

**Important:** `--mode` must be set consistently on both `ziti-ssh-ca` and `ziti-ssh-host run`. If the CA issues certs with per-identity principals but the host is in shared mode (or vice versa), SSH authentication will fail.

## Modes

### `shared` (default)

All connections authenticate as a single shared Linux user (e.g. `ziggy`). The CA signs every certificate with the same `--principal`. This is the simplest deployment and requires no special privileges beyond what sshd already provides.

### `per-identity`

The CA derives a Linux username from each caller's Ziti identity name using `ca.DeriveUsername` and uses it as the certificate principal. `ziti-ssh-host run` creates the Linux user on first connection and deletes it (including home directory) when the last session for that identity closes.

**Username sanitization rules** (applied by `ca.DeriveUsername`):
1. Lowercase ASCII letters (`A`–`Z`); other characters are not case-folded, so non-ASCII lookalikes such as the Kelvin sign `K` never become ASCII letters.
2. Replace any character outside `[a-z0-9_-]` with `_`.
3. If the result starts with a digit, prefix it with `z`.
4. Truncate to 32 characters.

Example: `Alice` → `alice`, `dba-Alice` → `dba-alice`, `123bot` → `z123bot`

**Account ownership (security boundary):** `ziti-ssh-host` only creates, modifies, or deletes accounts recorded in `/var/lib/ziti-ssh-host/owned-users.json` (`host.OwnerRegistry`: username → identity, UID) for the connecting identity with a matching UID ≥ 1000. Never adopt a pre-existing account: `useradd` exit 9 is a rejection, not success. Reserved names (`root`, system accounts, `ubuntu`, …) and names starting with `-` are refused. Accounts from releases before the registry are adopted only via `ziti-ssh-host users claim --username <u> --identity <id>`; `users list` shows the registry. OS calls go through the `accountOps` interface (`host/accounts.go`) so this logic is unit-tested with a fake.

**Ephemeral user lifecycle:**
- `ziti-ssh-host run` creates the user with `useradd -m -s /bin/bash -- <username>` on the first connection from that identity and records it in the ownership registry.
- Permissions are resolved (config entry → global fallback) and applied on every connect: `usermod -G <groups>` (replaces supplementary groups) for group membership, `/etc/sudoers.d/ziti-ssh-host-<username>` for sudoers (validated with `visudo -c` before installation). If setting the groups, writing or removing the sudoers file, or removing a legacy sudoers file fails, the connection is **rejected** (fail closed); if a new sudoers rule cannot be installed, any existing sudoers file is removed first so an older rule cannot stay in force. The session is counted only after permissions are applied.
- A reference count tracks concurrent sessions for the same identity. One account means one permission set: while it has sessions open through one service, a connection through a different service with different resolved permissions is rejected (`UserManager.EnsureUserForService`, `ErrPermissionConflict`); same service always applies the current config.
- When the last session closes, the sudoers file is removed and supplementary groups are cleared; with `ZITI_USER_CLEANUP=true` the cleanup sequence then runs: `loginctl terminate-user`, process poll by UID with SIGTERM/SIGKILL escalation, `userdel -r`, and the registry record is removed.
- The set of usernames with active sessions is persisted to `/var/lib/ziti-ssh-host/managed-users` (one username per line). On startup, `CleanupOrphans` reads this file and, in cleanup mode, deletes listed accounts that are still registered (they had active sessions when the process was killed).
- By default the Linux account — and any background processes the user left running — is kept after disconnect (the daemon logs a startup warning). Set `ZITI_TERMINATE_ON_DISCONNECT=true` to end the account's processes at last disconnect while keeping the account (`UserManager.SetTerminateOnDisconnect`, `accountOps.TerminateProcesses`), or `ZITI_USER_CLEANUP=true` to delete the account (useful when ephemeral-only accounts are required). The sudoers file is removed and groups are cleared on disconnect in all cases.

**Connecting in per-identity mode:**
```sh
ziti-ssh web-server-prod
```
With no `user@`, `ziti-ssh` and `ziti-scp` use the certificate's principal — in per-identity mode the CA issues it for the identity's derived Linux username (`client.CertPrincipal`). An explicit user must be that derived name, not the Ziti identity name: identity `Alice@Corp.com` logs in as `alice_corp_com` (`ziti-ssh alice_corp_com@web-server-prod`); `alice@corp.com@web-server-prod` is refused by sshd because it does not match the certificate.

## SSH Host Configuration

Written by `ziti-ssh-host enroll` to `/etc/ssh/sshd_config.d/ziti-ssh.conf` (and refreshed by `run` at startup if it differs, e.g. after an upgrade — `host.EnsureSSHDDropIn`):

```
# Managed by ziti-ssh-host.
TrustedUserCAKeys /etc/ssh/ziti_ca.pub

# Accounts managed through Ziti may only log in with a CA certificate.
Match Group ziti-ssh-managed
    AuthorizedKeysFile none
    AuthorizedKeysCommand none
```

Members of `ziti-ssh-managed` (`host.ManagedGroup`) can only log in with a CA certificate: a key a user adds to their own authorized_keys cannot outlive their certificate or identity. Per-identity accounts are always kept in the group; in shared mode the administrator adds the shared account (`usermod -aG ziti-ssh-managed ziggy`), and `run` warns at startup if the group is empty. The group is created by the package postinstall, `enroll` and `run`. Verified on Ubuntu 24.04: the `Match` block ends with the included file (`sshd -t` passes; main-config settings stay global). No SSSD, no NSS, no PAM modifications, no custom sshd.

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

In production, `ziti-ssh-ca` runs on the same machine as the Ziti controller, as the same OS user as the controller (`ziti-controller` with the `openziti-controller` v2 package, `ziti` in other deployments). The package postinstall detects that user and writes the drop-in `/etc/systemd/system/ziti-ssh-ca.service.d/10-controller-user.conf`; the unit's default is `User=ziti`. This gives it direct filesystem access to the controller's PKI. The intermediate CA key path is typically:

```
/var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key
```

The exact path depends on the controller installation — check the controller config file to confirm. Do not use the root CA key path.

The key file should remain mode 0600 and owned by the controller service user. `ziti-ssh-ca` reads it at startup only and holds the resulting `ssh.Signer` in memory. Rotation is a Ziti controller operation; after rotation, restart `ziti-ssh-ca` and re-enroll SSH hosts to distribute the new CA public key.

## Deployment

- **Language:** Go
- **Target OS:** Ubuntu 24.04+ (also the upcoming 26.04)
- **CA key type:** whatever the controller's intermediate CA uses (RSA on stock controllers; ECDSA and Ed25519 also supported)
- **Shared Linux user:** `ziggy` (default, configurable)

## Project Structure

```
ziti-ssh/
├── cmd/
│   ├── ziti-ssh/
│   │   ├── main.go         # Full SSH client (connect, sign, enroll, list, mfa)
│   │   └── oidc.go         # Browser-based OIDC auth flow (browser launch, callback server)
│   ├── ziti-scp/
│   │   └── main.go         # SCP-style file copy tool (upload, download, recursive, enroll)
│   ├── ziti-ssh-ca/
│   │   ├── main.go         # CA service entry point, run loop, enroll subcommand
│   │   └── config.go       # config subcommand (print, apply, remove)
│   └── ziti-ssh-host/
│       ├── main.go         # enroll, run (multi-service), inspect subcommands
│       └── users.go        # users list / claim (ownership registry admin)
├── ca/
│   ├── ca.go               # CA key loading, cert signing, DeriveUsername
│   └── ca_test.go          # Unit tests for DeriveUsername
├── client/
│   ├── ssh.go              # NewCertSigner, CertNeedsRefresh, RunSession, RunCommand
│   └── sftp.go             # RunSFTP — SFTP file copy over net.Conn
├── host/
│   ├── host.go             # ProxyHooks, Proxy, UserManager, PermissionsConfig, sshd config
│   ├── accounts.go         # accountOps (useradd/usermod/userdel/getent…), username validation, deleteUser
│   ├── registry.go         # OwnerRegistry — persistent account ownership (owned-users.json)
│   ├── claim.go            # ClaimAccount — adopt pre-registry accounts
│   ├── accounts_test.go    # Account ownership tests using a fake accountOps
│   ├── caller_test.go      # Router-verified caller identity tests
│   └── host_test.go        # Unit tests for PermissionsConfig.Resolve and UserManager
├── config/
│   ├── config.go           # Shared configuration (flags + env vars)
│   └── ztapis.go           # Controller URL persistence (PersistZtAPIs, EventControllerUrlsUpdated)
├── internal/
│   ├── mfa/
│   │   └── mfa.go          # MFA TOTP prompt (terminal, hidden, bounded attempts)
│   ├── oidc/
│   │   └── oidc.go         # OIDC authorization code flow (PKCE, token exchange)
│   └── ratelimit/
│       ├── ratelimit.go    # Per-identity token-bucket rate limiter
│       └── ratelimit_test.go
├── scripts/
│   └── build-packages.sh   # Builds deb and/or rpm packages into dist/ (FORMAT=deb,rpm ARCHS=amd64,arm64)
├── go.mod
├── go.sum
├── ARCHITECTURE.md         # High-level architecture narrative
├── CHANGELOG.md            # Feature changelog by release
└── CLAUDE.md
```

## Documentation

| File | Purpose |
|---|---|
| `README.md` | Project overview, prerequisites, building |
| `ARCHITECTURE.md` | High-level architecture narrative and design rationale |
| `CHANGELOG.md` | Feature changelog by release |
| `docs/provisioning.md` | Ziti network setup, per-component installation, `ziti-ssh-host.v1` config type admin setup |
| `docs/usage.md` | End-user guide: certs, connecting, file copy, MFA |
| `docs/configuration.md` | Full flag/env/config reference for all binaries, `ziti-ssh-host.v1` schema |
| `docs/operations.md` | Modes, per-identity permissions, multi-service binding, inspect tool, CA key rotation, graceful shutdown |
