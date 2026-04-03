# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-04-03

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
- `connect [user@]<target>` (default command): opens an interactive SSH session over Ziti; auto-runs `sign` if cert is missing or expires within 30 minutes
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
