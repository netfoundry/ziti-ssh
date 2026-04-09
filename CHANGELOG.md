# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-04-09

### Added

#### `ziti-ssh connect` — SSH agent forwarding (`-A` / `--forward-agent`)

New `-A` / `--forward-agent` flag on `ziti-ssh connect`. When set, the local SSH agent (identified by `SSH_AUTH_SOCK`) is forwarded to the remote session so that processes on the remote host can use keys held by the local agent — for example, to make onward SSH hops without copying private keys to the remote.

**Behaviour:**
- On the fast path (no `-L`/`-R`/`-D` forwards), `forwardAgent` is passed directly to `client.RunSession`, which calls `client.ForwardAgent` before `session.Shell()`.
- On the forwarding path (has `-L`/`-R`/`-D` forwards, uses `NewSSHClient`), `runSSHClientSession` calls `client.ForwardAgent(sshClient, session)` before `session.Shell()`.
- If `SSH_AUTH_SOCK` is not set or the agent cannot be reached, a `WARN`-level log message is emitted and the session opens normally — agent forwarding failure is non-fatal.
- The SSH certificates issued by `ziti-ssh-ca` already include the `permit-agent-forwarding` extension, so no CA or sshd configuration changes are needed.

**New exported function in `client/ssh.go`:**
- `ForwardAgent(sshClient *ssh.Client, session *ssh.Session) error` — connects to the local SSH agent via `SSH_AUTH_SOCK`, calls `agent.ForwardToAgent(sshClient, agentClient)` to register the agent-channel handler, spawns a goroutine to close the agent connection when the SSH client closes, and calls `agent.RequestAgentForwarding(session)` to send the `auth-agent-req@openssh.com` channel request. Returns an error on any failure; the caller treats this as a warning.

**`RunSession` signature change:**
- `RunSession(conn, user, host, signer, forwardAgent bool)` — `forwardAgent bool` parameter added as the fifth argument. All call sites updated.

#### Documentation

- `docs/usage.md`: new "SSH agent forwarding (`-A`)" section with usage examples, agent setup instructions, and a note about combining with port forwarding.
- `docs/configuration.md`: `-A` / `--forward-agent` row added to the `ziti-ssh connect` flag table.
- `CLAUDE.md`: `connect` bullet updated to describe `-A` behaviour; `client/ssh.go` API section updated with `ForwardAgent` and updated `RunSession` signature.

#### `ziti-ssh connect` — port forwarding (`-L`, `-R`, `-D`, `-N`)

Port forwarding flags added to `ziti-ssh connect`, mirroring `ssh(1)` syntax. All flags may be repeated to open multiple forwards simultaneously.

**New flags on `connect`:**
- `-L` / `--local-forward` `[bind:]localport:remotehost:remoteport` — local port forward; `ziti-ssh` listens locally and forwards each accepted connection to `remotehost:remoteport` through the SSH tunnel via a `direct-tcpip` channel. Default bind: `127.0.0.1`.
- `-R` / `--remote-forward` `[bind:]remoteport:localhost:localport` — remote port forward; uses `(*ssh.Client).Listen` to ask sshd to bind on the remote side; each incoming connection is forwarded to `localhost:localport` on the client machine.
- `-D` / `--dynamic` `[bind:]port` — dynamic SOCKS5 proxy; implements RFC 1928 CONNECT with no-auth (`METHOD=0x00`); for each SOCKS5 CONNECT request a `direct-tcpip` channel is opened to the requested destination. Supports IPv4 (ATYP 0x01), domain name (ATYP 0x03), and IPv6 (ATYP 0x04). Default bind: `127.0.0.1`.
- `-N` / `--no-shell` — do not open a shell; only run the requested forwards; block until SIGINT/SIGTERM.

**Implementation:**
- When any forward flag is present, `runConnect` calls `client.NewSSHClient` to obtain a `*ssh.Client`, then starts each forward in a goroutine under a shared `context.Context`.
- SIGINT/SIGTERM cancels the context, closing all local listeners and unblocking all goroutines cleanly.
- Without `-N`, a shell (or remote command) runs concurrently; when the shell exits it cancels the context and terminates all forwards. A `sync.WaitGroup` ensures all goroutines finish before `runConnect` returns.
- Without any forward flags the previous fast path (`client.RunSession` / `client.RunCommand`) is used unchanged — no regression for existing users.
- Forward-spec parse helpers added to `cmd/ziti-ssh/main.go`: `parseLocalForward`, `parseRemoteForward`, `parseDynamicForward`.

**New functions in `client/ssh.go`:**
- `NewSSHClient(conn net.Conn, user, host string, signer ssh.Signer) (*ssh.Client, error)` — performs the SSH handshake and returns a `*ssh.Client` without opening any session.
- `RunLocalForward(ctx context.Context, sshClient *ssh.Client, spec LocalForwardSpec) error` — local forward loop; cancels cleanly on ctx.
- `RunRemoteForward(ctx context.Context, sshClient *ssh.Client, spec RemoteForwardSpec) error` — remote forward loop; uses `sshClient.Listen`.
- `RunDynamicProxy(ctx context.Context, sshClient *ssh.Client, spec DynamicForwardSpec) error` — SOCKS5 proxy loop.
- `LocalForwardSpec`, `RemoteForwardSpec`, `DynamicForwardSpec` — typed spec structs for each forwarding mode.
- `biCopy(ctx, a, b net.Conn)` — bidirectional `io.Copy` helper; half-closes the write side when one direction closes.

**New helper in `cmd/ziti-ssh/main.go`:**
- `runSSHClientSession(*ssh.Client) error` — PTY shell on a pre-built `*ssh.Client`; mirrors `client.RunSession` but avoids repeating the SSH handshake.
- `runSSHClientCommand(*ssh.Client, string) error` — non-interactive command on a pre-built `*ssh.Client`.

#### `ziti-ssh proxy` — ProxyCommand / stdio bridge subcommand

New `proxy [user@]<target>` subcommand. Dials the Ziti service raw (no SSH handshake) and bridges `os.Stdin`/`os.Stdout` to the connection via two `io.Copy` goroutines. Exits when either side closes (EOF).

Intended for use as a `ProxyCommand` in `~/.ssh/config`:

```
Host web-server-prod
    ProxyCommand ziti-ssh proxy %h
    User ziggy
```

With this entry, `ssh`, `git`, `rsync`, `ansible`, VS Code Remote SSH, and any other SSH-based tool work through the Ziti overlay transparently without any Ziti awareness.

- Auto-refreshes the SSH certificate (same 5-minute threshold as `connect`) so the caller's `ssh` process finds a valid cert in `~/.ssh/<key>-cert.pub`.
- Uses the same Ziti service resolution as `connect`: direct service name check, then terminator address on `--ssh-service`.
- Shares the same `--identity`, `--ssh-service`, `--ca-service`, `--key`, and `--oidc-issuer` flags as `connect`.
- The `user@` prefix is accepted for compatibility with `ProxyCommand ziti-ssh proxy %r@%h` but is not used.
- `proxyParams` struct and `runProxy` function added to `cmd/ziti-ssh/main.go`.

#### Documentation

- `docs/usage.md`: new "Port forwarding" section (local, remote, dynamic, `-N`, combined with shell) and "Using `ziti-ssh` as a ProxyCommand" section (config examples, wildcard patterns, VS Code/git/rsync/ansible usage).
- `docs/configuration.md`: `-N`, `-L`, `-R`, `-D` flags added to the `ziti-ssh connect` table; new `ziti-ssh proxy` flag table.
- `CLAUDE.md`: `connect` component description updated to cover all forwarding flags and `-N`; `proxy` subcommand added; `client/ssh.go` API section updated with new exported functions.

## [Unreleased] - 2026-04-06

### Added

#### `ziti-ssh-ca` — `config` subcommand for managing the `ziti-ssh-host.v1` Ziti config type

New file `cmd/ziti-ssh-ca/config.go` (package `main`). Adds a `config` cobra parent command registered with the root, containing three subcommands:

- **`config print`** — no flags, no controller connection. Prints the human-readable field table and the indented JSON schema to stdout.
- **`config apply`** — idempotent create-or-update. Authenticates to the controller, calls `ListConfigTypes` with a `name="ziti-ssh-host.v1"` filter, then either `CreateConfigType` (not found) or `UpdateConfigType` (found). Prints `created ...` or `updated ... (id: <id>)`.
- **`config remove`** — locates the type by name and calls `DeleteConfigType`. Exits 0 with a human-readable message if the type is not found.

Flags (`--controller`, `--username`, `--password`, `--insecure`, `--controller-ca`) are defined as PersistentFlags on the `config` parent so both `apply` and `remove` inherit them. All flags have corresponding env var overrides (`ZITI_CTRL_ADDRESS`, `ZITI_CTRL_USERNAME`, `ZITI_CTRL_PASSWORD`, `ZITI_CTRL_INSECURE`, `ZITI_CTRL_CA`). `--insecure` and `--controller-ca` are validated as mutually exclusive before any API call. Default controller port is 443 when no port is present in `--controller`. Uses `github.com/openziti/edge-api/rest_management_api_client` (promoted from indirect to direct dependency).

#### `ziti-ssh-host` — per-identity Linux permissions via `ziti-ssh-host.v1` Ziti service config

**New types in `host/host.go`:**
- `IdentityPermissions` struct: `Groups []string` + `SudoersRule string`; holds the resolved Linux permissions for one connecting identity
- `PermissionsConfig` struct: `Permissions map[string]IdentityPermissions`; parsed from a `ziti-ssh-host.v1` Ziti service config attached to a bound service
- `(*PermissionsConfig).Resolve(zitiIdentity string, globalGroups []string, globalSudoersRule string) IdentityPermissions`: returns the config entry for the identity if present (globals ignored), otherwise returns globals; handles nil receiver

**`UserManager` changes:**
- `NewUserManager` signature changed: `sudoersRule string` parameter removed; permissions are now passed per-call
- `EnsureUser(username string, perms IdentityPermissions) error`: accepts resolved permissions for this connection; on first session calls `usermod -aG <groups> <username>` when `perms.Groups` is non-empty (non-fatal logged error if a group does not exist), and writes `/etc/sudoers.d/<username>` when `perms.SudoersRule` is non-empty; subsequent sessions for the same username skip account setup (ref-count only)
- `ReleaseUser` now always attempts `removeSudoers` (was conditioned on `m.sudoersRule != ""`; idempotent with missing file)

**`run` subcommand changes:**
- `--ssh-service` flag changed from `StringVar` to `StringArrayVar`; may be specified multiple times; `ZITI_SSH_SERVICE` env var still supported as a comma-separated list; fallback to `"ssh"`
- `runProxy` now accepts `sshServices []string` and opens one `zitiEdge.Listener` per service; all listeners share one `UserManager` and one connection-level `sync.WaitGroup`
- Ziti context initialised via `ziti.NewConfigFromFile` + `ziti.NewContext` (rather than `ziti.NewContextFromFile`) so that `cfg.ConfigTypes` can include `"ziti-ssh-host.v1"` before `Authenticate`
- For each service, `loadPermissionsConfig` fetches and parses the `ziti-ssh-host.v1` config using `zitiEdge.ParseServiceConfig`; stores it in a `serviceState` with an `RWMutex` for safe concurrent reads and hot-reload writes
- `zitiCtx.Events().AddServiceChangedListener` subscribed after listeners open; on a changed event for a bound service, re-fetches and atomically swaps the in-memory `*PermissionsConfig`; logged at info level; existing sessions unaffected
- `ZITI_SSH_GROUPS` env var read at startup; parsed as comma-separated group names (whitespace-trimmed, empty strings skipped); passed as `globalGroups` to each service's `ProxyHooks`
- Signal handler closes all listeners on `SIGTERM`/`SIGINT`; per-connection `sync.WaitGroup` (`connWg`) passed to each `host.Proxy` call for graceful drain

**New `inspect` subcommand:**
- `ziti-ssh-host inspect --service <name> [--service <name> ...]`
- Authenticates with the same identity (same `--identity`/`ZITI_IDENTITY`) and `"ziti-ssh-host.v1"` in `ConfigTypes`
- For each named service: checks visibility (bind policy), parses `ziti-ssh-host.v1` config, prints a formatted table of Ziti identity → derived Linux username → groups → sudoers rule
- Prints global fallback values (`ZITI_SSH_GROUPS`, `ZITI_SUDOERS_RULE`) alongside each service block
- Exits without opening any listeners; safe to run while `run` is active on the same identity

**Tests added (`host/host_test.go`):**
- `TestResolve_*`: six table-driven cases covering nil config, empty config, matched identity, unmatched identity, case-sensitive matching, globals-not-merged-for-matched-entry, no-globals case
- `TestEnsureUser_AcceptsIdentityPermissions`: integration test (skipped without root) verifying new `IdentityPermissions` parameter
- `TestEnsureUser_RefCounting`: integration test (skipped without root) verifying session ref-count and deletion on last release
- `TestNewUserManager_Signature`: compile-time signature check embedded as runtime test

## [Unreleased] - 2026-04-03

### Added

#### All four binaries — configurable Ziti network operation timeouts

- `--ziti-timeout` / `ZITI_TIMEOUT` persistent flag added to all four binaries (`ziti-ssh`, `ziti-ssh-ca`, `ziti-ssh-host`, `ziti-scp`), following the existing `config.EnvOrFlag` pattern; accepts any `time.Duration` string (e.g. `30s`, `1m`); default `30s`; must be > 0
- `config.RunWithTimeout` helper added to `config/config.go`: runs a `func() error` in a goroutine with a `time.After` timeout; returns a clear user-facing error on timeout (not a raw context deadline error)
- `config.ZitiTimeoutErr` returns the standard timeout error message: `timed out after <duration> waiting for Ziti network during <op> — check that the controller is reachable and the identity is valid`
- `zitiCtx.Authenticate()` wrapped with `config.RunWithTimeout` in all four binaries
- `zitiCtx.Listen()` / `zitiCtx.ListenWithOptions()` wrapped with `config.RunWithTimeout` in `ziti-ssh-ca` and `ziti-ssh-host`
- `zitiCtx.Dial()` / `zitiCtx.DialWithOptions()` replaced with `zitiCtx.DialContext()` / `zitiCtx.DialContextWithOptions()` (context-aware SDK variants) in `ziti-ssh` and `ziti-scp`; context is a `context.WithTimeout` derived from the configured duration; a clear timeout error is returned if the context deadline fires
- `docs/configuration.md` updated with `--ziti-timeout` / `ZITI_TIMEOUT` in all four binary sections; new `ziti-scp` section added

### Added

#### `ziti-scp` — new binary: SCP-style file copy over the Ziti overlay
- New binary at `cmd/ziti-scp/main.go` mirroring `scp(1)` behaviour over the Ziti overlay using the SFTP subsystem
- Parses `[user@]host:path` remote specs and bare local paths from positional arguments; the last argument is always the destination (same convention as `scp` and `rsync`)
- Upload (local → remote) and download (remote → local) in a single binary; direction is determined by which side carries the `host:path` form
- `-r` / `--recursive` flag for recursive directory copy
- `-p` / `--preserve` flag to copy file timestamps and permissions (uses SFTP `Chtimes` on remote, `os.Chtimes` locally)
- `-q` / `--quiet` flag to suppress per-file progress output
- scp-style progress reporting to stderr: filename, percentage, bytes transferred, transfer rate, and ETA; updates at 500ms intervals, final line at 100%
- Same cert auto-refresh logic as `ziti-ssh connect`: calls `client.CertNeedsRefresh` and auto-signs via the CA when fewer than 5 minutes of validity remain
- Same Ziti service resolution: checks the service list for a direct service-name match, falls back to terminator address on `--ssh-service`
- Same config file (`~/.config/ziti-ssh/config.yaml`) and same flag/env/default precedence via `config.EnvOrFlag`
- `enroll` subcommand for identity enrollment (mirrors `ziti-ssh enroll`; writes identity JSON to `~/.config/ziti-ssh/<name>.json` by default)
- Flags: `--identity` / `ZITI_IDENTITY`, `--ca-service` / `ZITI_CA_SERVICE`, `--ssh-service` / `ZITI_SSH_SERVICE`, `--key`, `--config`

#### `client/sftp.go` — new library: SFTP file copy over net.Conn
- `RunSFTP(conn, user, host, signer, isUpload, localPaths, remotePath, recursive, preserve, quiet) error` added to the `client` package
- Establishes an SSH client connection over the pre-dialled `net.Conn` (same `ssh.ClientConfig` pattern as `RunSession` / `RunCommand`, with `InsecureIgnoreHostKey` — host identity is proven by Ziti mTLS)
- Opens SFTP subsystem via `sftp.NewClient(sshClient)` from `github.com/pkg/sftp v1.13.10`
- Upload path: walks local paths with `os.ReadDir`; creates remote directories with `sftp.MkdirAll`; writes files with `sftp.OpenFile(..., O_WRONLY|O_CREATE|O_TRUNC)`; applies chmod/chtimes when `preserve` is set
- Download path: reads remote directories with `sftpClient.ReadDir`; creates local directories with `os.MkdirAll`; writes files with `os.OpenFile(..., O_WRONLY|O_CREATE|O_TRUNC)`; applies `os.Chtimes` when `preserve` is set
- `progressWriter` wraps the destination `io.Writer`, tracks bytes written, and prints rate/ETA to stderr at 500ms intervals; `printFinalProgress` emits the 100% completion line
- Helper functions: `formatBytes` (SI prefixes), `formatBytesRate`, `formatDuration`

#### Build & packaging
- `github.com/pkg/sftp v1.13.10` added as a direct dependency (`go.mod`); `github.com/kr/fs v0.1.0` added as indirect
- `scripts/build-deb.sh` extended with a `ziti-scp` build step and a new `ziti-scp` Debian package section (control file, postinst); binary copied to repo root alongside the other three
- `dist/ziti-scp_<version>_amd64.deb` produced by the build script

#### Documentation
- README: four-binary introduction, `go build` example updated, new "Copying files with `ziti-scp`" section with upload/download/recursive examples, flags table, config file note, and `enroll` subcommand note; project structure updated
- CLAUDE.md: solution updated to four binaries; `ziti-ssh` and `ziti-scp` design rationale section; `client/sftp.go` added to component descriptions; project structure diagram updated

### Added

#### `ziti-ssh` — non-interactive remote command execution
- `client.RunCommand(conn, user, host, command, signer)` added to `client/ssh.go`: sets up the SSH client connection identically to `RunSession` but does not request a PTY; wires `os.Stdin`/`os.Stdout`/`os.Stderr` directly; executes the command via `session.Run`; propagates the remote exit code via `os.Exit` when the error is `*ssh.ExitError`, and returns other errors normally
- `connectParams.command` field added; `runConnect` branches on whether `command` is non-empty — calls `client.RunCommand` if so, `client.RunSession` otherwise
- `connect` cobra command updated from `cobra.ExactArgs(1)` to `cobra.MinimumNArgs(1)`: `args[0]` remains the target; any remaining args are joined with spaces and used as the remote command
- Root command updated from `cobra.MaximumNArgs(1)` to `cobra.ArbitraryArgs` so bare invocations such as `ziti-ssh alice@host -- ls -la` also work
- `Use` and `Long` help text on both the root command and `connect` subcommand updated to document the new `[-- <command> [args...]]` form
- README "Connecting to a host" section extended with a "Non-interactive command execution" subsection covering usage, piping, and exit-code propagation



### Added

#### `ziti-ssh-ca` and `ziti-ssh-host` — systemd sd_notify integration
- Both binaries now import `github.com/coreos/go-systemd/v22/daemon` (promoted from indirect to direct dependency, upgraded to v22.7.0)
- `ziti-ssh-ca`: calls `daemon.SdNotify(false, daemon.SdNotifyReady)` immediately after the Ziti listener is bound; calls `daemon.SdNotify(false, "STOPPING=1")` in the signal watcher goroutine before closing the listener
- `ziti-ssh-host run`: same pattern — `READY=1` after `ListenWithOptions` succeeds, `STOPPING=1` when SIGTERM/SIGINT is received
- Both calls are no-ops when `NOTIFY_SOCKET` is unset (i.e. when not running under systemd); errors are logged at Debug level only
- Systemd unit file examples in README updated from `Type=simple` to `Type=notify`

#### README — OIDC authentication documentation
- New [OIDC authentication](#oidc-authentication) section covering: how the browser flow works, what to provision on the Ziti controller side (ext-jwt-signer + auth policy), and how to configure `oidc.*` in the config file or via `--oidc-issuer`
- Config file example updated to show the `oidc:` block with all four fields (`issuer`, `client_id`, `client_secret`, `callback_port`)
- `--oidc-issuer` description in the configuration reference table corrected (was incorrectly marked "not yet implemented")

#### README — rate limiting documentation
- `--rate-limit` / `ZITI_RATE_LIMIT` and `--rate-burst` / `ZITI_RATE_BURST` added to the `ziti-ssh-ca` configuration reference table

#### README — graceful shutdown documentation
- New [Graceful shutdown](#graceful-shutdown) section describing the 30-second drain window and `Type=notify` support

---

### Added

#### `ziti-ssh-ca` — per-identity rate limiting
- `internal/ratelimit`: new package providing a per-identity token-bucket rate limiter backed by `golang.org/x/time/rate`
- Each Ziti identity gets an independent `rate.Limiter`; one abusive caller cannot exhaust the allowance of any other identity
- Idle entries are evicted by a background goroutine after 10 minutes of inactivity, bounding memory growth over long uptimes; the goroutine is stopped cleanly on graceful shutdown via a stop channel
- Rate limiting applies only to cert signing requests; CA public key fetches (empty-line requests) are not rate-limited
- When a request is denied, the client receives `error: rate limit exceeded\n` and a `Warn`-level log line records the identity name server-side
- Two new flags and env vars following the existing `EnvOrFlag` pattern:
  - `--rate-limit` / `ZITI_RATE_LIMIT`: maximum cert signing requests per minute per identity (default `5`; accepts decimal values for sub-minute rates)
  - `--rate-burst` / `ZITI_RATE_BURST`: burst allowance (default `3`)
- `golang.org/x/time v0.12.0` promoted from transitive to direct dependency in `go.mod`
- Unit tests in `internal/ratelimit/ratelimit_test.go`: within-burst, burst-exhaustion, per-identity isolation, and idle-eviction cases

#### `ziti-ssh` — OIDC authentication
- Browser-based OIDC authorization code flow (with PKCE when no client secret is set) implemented in `cmd/ziti-ssh/oidc.go`
- `runOIDCFlow` starts a local HTTP server on the callback port, opens the browser, and blocks until the user completes authentication or the 2-minute timeout elapses
- `addOIDCCredentials` wires the resulting access token into the Ziti context via `GetCredentials().AddJWT()` before `Authenticate()` — satisfies ext-jwt-signer secondary authentication on the controller
- Both `connect` and `sign` commands run the OIDC flow when `oidc.issuer` is configured (config file) or `--oidc-issuer` is passed; when no issuer is set the behavior is unchanged
- OIDC parameters (`issuer`, `client_id`, `client_secret`, `callback_port`) are read from the existing `oidc.*` config file block; `callback_port` defaults to `63275`
- `--oidc-issuer` flag on `connect` overrides `oidc.issuer` from the config file
- Dependencies promoted from indirect: `github.com/gorilla/securecookie`, `github.com/zitadel/oidc/v3`

#### `ziti-ssh-ca` and `ziti-ssh-host` — graceful shutdown
- Both binaries now catch `SIGTERM` and `SIGINT` via `signal.Notify`
- On signal: the Ziti listener is closed, stopping new connections from being accepted
- In-flight connections are tracked with a `sync.WaitGroup` and allowed up to 30 seconds to finish before the process exits
- `ziti-ssh-ca`: WaitGroup wraps each `handleConn` goroutine; drain happens in `run()` after the accept loop exits
- `ziti-ssh-host`: `host.Proxy` gains an optional `*sync.WaitGroup` parameter (nil-safe); `runProxy` passes a WaitGroup and drains it after the listener closes; signal handling is wired in `runProxy`
- Per-identity mode: active sessions call `OnDisconnect` via the existing `ProxyHooks` when connections close naturally during the drain window; orphaned users (if the drain timeout fires) are cleaned up by `CleanupOrphans` on the next startup

## [0.1.0] - 2026-04-01

### Added

#### `ziti-ssh-ca` — CA service
- Binds to a named Ziti service (default: `ssh-ca`) and signs short-lived SSH certificates for authorized callers
- Extracts caller Ziti identity from the mTLS connection via SPIFFE ID (cryptographically verified — not self-reported)
- Issues certificates with configurable principal (default: `ziggy`) and configurable TTL via `--cert-ttl` / `ZITI_CERT_TTL` (default: `8h`)
- Embeds Ziti identity name as certificate `KeyId` (`ziti:<identity>`) for per-identity audit trail in `/var/log/auth.log`
- Serves CA public key on empty request — allows hosts and clients to fetch the public key over Ziti
- `--mode shared|per-identity` (`ZITI_SSH_MODE`): in `per-identity` mode, derives a Linux username from the Ziti identity (`DeriveUsername`) and uses it as the cert principal
- Configured via `/etc/ziti-ssh-ca/env` (installed by `.deb` package)

#### `ziti-ssh-host` — host daemon
- `enroll --jwt <path>`: enrolls a Ziti identity from a JWT, extracts the intermediate CA public key from the enrollment certificate chain, writes `/etc/ssh/sshd_config.d/ziti-ssh.conf` and `/etc/ssh/ziti_ca.pub`, reloads sshd
- `run`: binds the `ssh` Ziti service with identity name as addressable terminator, proxies inbound connections to `127.0.0.1:22`
- Per-identity mode (`ZITI_SSH_MODE=per-identity`): creates ephemeral Linux accounts on connect via `useradd -m -s /bin/bash`, removes them on disconnect via `loginctl terminate-user` → process polling → `userdel -r`
- `ZITI_SUDOERS_RULE`: optional sudoers rule written to `/etc/sudoers.d/<username>` on connect; validated with `visudo -c` before installation; removed on disconnect
- `ZITI_USER_CLEANUP=false`: keeps user accounts after disconnect (sudoers still removed); orphan cleanup always runs on startup
- Reference-counted `UserManager` — safe for concurrent sessions from the same identity; state persisted at `/var/lib/ziti-ssh-host/managed-users` for crash recovery
- Configured via `/etc/ziti-ssh-host/env` (installed by `.deb` package)

#### `ziti-ssh` — client
- `connect [user@]<target>` (default command): opens an interactive SSH session over Ziti; auto-runs `sign` if cert is missing or expires within 5 minutes
- Target resolution: `--service` for explicit service name; otherwise checks service list for exact match, falls back to terminator address on `--ssh-service`
- `sign`: obtains a signed SSH certificate from `ziti-ssh-ca`; discovers SSH keys in standard order (`id_ed25519`, `id_ecdsa`, `id_rsa`); prompts to generate via `ssh-keygen` if none found; writes cert to `~/.ssh/<key>-cert.pub`; displays cert details via `ssh-keygen -L`
- `enroll --jwt <path>`: enrolls a Ziti identity from a JWT
- `list`: lists Ziti services accessible to the current identity
- `mfa enable/verify/remove`: manages TOTP MFA on the Ziti identity
- SSH agent fallback: passphrase-protected keys fall back to `SSH_AUTH_SOCK`; agent signer is wrapped with cert via `ssh.NewCertSigner`
- Config file at `~/.config/ziti-ssh/config.yaml` (XDG_CONFIG_HOME respected); three-tier precedence: CLI flag > config file > default

#### Infrastructure
- `ca/ca.go`: `LoadKey`, `SignCert`, `PublicKeyBytes`, `DeriveUsername` (identity → Linux username sanitization: lowercase, replace invalid chars, prefix `z` if digit-leading, truncate to 32 chars)
- `host/host.go`: `Proxy` with `ProxyHooks`, `UserManager`, `WriteSSHConfig`, `ReloadSSHD`, `createSudoers`, `removeSudoers`
- `client/ssh.go`: `NewCertSigner` (key + cert loading with agent fallback), `CertNeedsRefresh`, `RunSession` (PTY + interactive shell)
- `config/config.go`: `EnvOrFlag` — flag > env var > default
- Debian packages for all three binaries built by `scripts/build-deb.sh`; binaries also copied to repo root for local testing
- Unit tests: `ca/ca_test.go` — `SignCert` field validation, `DeriveUsername` sanitization rules (15 cases)

### Security notes
- Ziti identity name is cryptographically verified via SPIFFE ID in the mTLS certificate (not self-reported by the client SDK)
- CA key is the Ziti controller's intermediate CA private key — co-located deployment, no credential distribution required
- SSH host stores only the intermediate CA public key (`TrustedUserCAKeys`) — not a credential, cannot authenticate to anything
- Certificates are short-lived (default 8h); no revocation infrastructure required
- Port 22 is never exposed externally; all SSH traffic flows through the Ziti overlay
