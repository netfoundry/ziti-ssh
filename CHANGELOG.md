# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-11-19

### Security

See security advisory GHSA-TBD for details.

#### Certificates restricted to the Ziti path (`source-address`)

`ziti-ssh-ca` now adds the OpenSSH `source-address` critical option to every certificate, defaulting to `127.0.0.1/32,::1/128`. sshd accepts a certificate only from those addresses; `ziti-ssh-host` always proxies to `127.0.0.1:22`, so the same certificate keeps working on every host the caller's Ziti policies allow, but is rejected on any connection that reaches port 22 directly.

- New flag `--cert-source-address` / `ZITI_CERT_SOURCE_ADDRESS` (comma-separated IPs or CIDRs, or `none` to omit the option). Invalid values stop the CA at startup.
- If something other than the local `ziti-ssh-host` delivers connections to sshd, set this accordingly.

#### Host grant policy for `ziti-ssh-host.v1` configs (BREAKING)

- `ziti-ssh-host` now limits, per Ziti service, what a `ziti-ssh-host.v1` config may grant: `sudoers_rule` only from services listed in `ZITI_ALLOW_SUDOERS` (default: none); privileged groups (`root`, `sudo`, `admin`, `wheel`, `docker`, `lxd`, `disk`, `shadow`, `libvirt`) only when opted in via `ZITI_ALLOW_GROUPS` (`<service>:<group>` or `*:<group>`); optionally only listed groups (`ZITI_RESTRICT_GROUPS=true`). The host's own `ZITI_SSH_GROUPS` / `ZITI_SUDOERS_RULE` fallbacks are unaffected.
- An entry exceeding the policy rejects the connection (`rejecting connection: permissions refused by host grant policy`); violations are logged at config load/reload; `ziti-ssh-host inspect` shows the policy and refused entries. Invalid policy settings stop `run` in per-identity mode.
- **Action:** configs that grant `sudoers_rule` or privileged groups are refused until each host opts the service in. Run `ziti-ssh-host inspect --service <name>` before upgrading.

#### Host keys checked on every connection (trust on first use)

- `ziti-ssh` and `ziti-scp` no longer accept any SSH host key. They remember the key(s) seen for each Ziti address in `$XDG_CONFIG_HOME/ziti-ssh/known_hosts` (0600). A host dialed by name (`<host>@<service>`) with a changed key is refused; for a service dialed directly, where any bound host may answer, the user is asked before an additional key is trusted (refused without a terminal). OpenZiti does not tell the dialer which identity answered, so this detects impersonation after the first connection.
- New `ziti-ssh known-hosts list|remove <address>`.
- Dialing a service directly now prints `Dialing service "…" directly: any host bound to it may answer.` (`ziti-ssh`, `ziti-scp`, `ziti-ssh proxy`).
- **Action:** after rebuilding a host, users run `ziti-ssh known-hosts remove <host>@<service>`.

#### Certificate-only login for Ziti-managed accounts

- The sshd drop-in now contains `Match Group ziti-ssh-managed` with `AuthorizedKeysFile none` and `AuthorizedKeysCommand none`, so members of that group can only log in with a CA certificate; a key added to their own `authorized_keys` can no longer outlive their certificate or identity. Other accounts are unaffected.
- The group is created by the `ziti-ssh-host` package, `enroll` and `run`; `run` rewrites an outdated drop-in at startup and reloads sshd. Per-identity accounts are always kept in the group.
- **Action (shared mode):** add the shared account to the group — `usermod -aG ziti-ssh-managed <account>`. `run` warns at startup if the group is empty.

#### Agent forwarding off by default (BREAKING)

- `ziti-ssh-ca` grants certificate extensions from `--cert-extensions` / `ZITI_CERT_EXTENSIONS`, default `permit-pty,permit-port-forwarding` — **agent forwarding is no longer granted by default**.
- `ziti-ssh connect -A` is refused unless `--forward-agent-unverified` is also given: clients cannot yet verify which host answered on a terminator address (an OpenZiti limitation), and a forwarded agent can be used by that host while connected.
- **Action:** to keep agent forwarding, add `permit-agent-forwarding` to `ZITI_CERT_EXTENSIONS` on the CA and use `-A --forward-agent-unverified`.

#### Documentation: host identity and access scope

- Docs no longer present the terminator name as a per-host access boundary: access control is per Ziti service, and a terminator name is an address chosen by the binding identity. New section in `docs/operations.md` (host identity / terminator names) describing the limitation, Bind-policy guidance, and one-service-per-host for hosts needing a strong identity guarantee.

#### Temporary files removed with deleted accounts

- With `ZITI_USER_CLEANUP=true`, files a deleted user owned in `/tmp`, `/var/tmp` and `/dev/shm` are removed before `userdel` (symlinks are removed, never followed; directories only when empty), so they do not pass to the next account given the same UID.

#### Controller CA key tracking

- `ziti-ssh-host` takes each controller's intermediate CA from the TLS chain verified against the enrollment root CA (`VerifiedChains`) instead of the certificates the server presented, which could include an extra CA certificate that would have become an SSH trust anchor.
- If a controller does not answer during a CA key refresh, currently trusted keys are kept (previously its key was dropped from `TrustedUserCAKeys`, breaking logins during a transient outage). Keys are removed only when every controller answered.
- The event-driven and periodic refreshes are serialised; empty controller URL lists are ignored and never persisted to the identity file (applies to all binaries via `config.PersistZtAPIs`).

#### Permission configs that fail to load now fail closed

- If a service's `ziti-ssh-host.v1` config cannot be fetched or parsed at startup, per-identity connections on that service are rejected instead of falling back to the global defaults. A failed live reload marks the service unavailable instead of keeping the previous config. A config that is simply not attached still uses the global fallbacks.

#### `ziti-scp` download hardening

- Refuses to write through an existing local symlink at a download destination.
- Downloaded files take the remote file's permission bits reduced by the local umask (previously always 0644); with `-p` the mode is applied exactly except that files are never made world-writable. setuid/setgid/sticky are never applied.
- Recursive copies stop at 64 directory levels (the remote host controls download depth).
- Control characters in server-supplied file names are replaced before being printed in progress output.

#### `ziti-ssh proxy` never prompts

- In `ProxyCommand` mode, `ziti-ssh proxy` no longer offers to generate an SSH key when none is found (the prompt was written into the SSH data stream on stdout); it exits with an error asking for a key or `--key`.

#### CA key-type allowlist

- `ziti-ssh-ca` only certifies ed25519, ECDSA (P-256/384/521), the `sk-` security-key variants, and RSA keys of at least 3072 bits. Certificates, DSA keys, shorter RSA keys, and the CA's own key are refused with an `error: …` reply (shown by clients as `CA refused the request: …`). Malformed requests now also get an `error:` reply instead of a silent close.
- **Action:** users with RSA keys shorter than 3072 bits must generate a new key (e.g. `ssh-keygen -t ed25519`).

#### CA connection limits

- `ziti-ssh-ca` caps concurrent connections (`--max-connections` / `ZITI_MAX_CONNECTIONS`, default 64); connections beyond the cap are closed immediately.
- The per-identity rate limit is now checked before the request is read and applies to CA public key requests as well as certificate requests. A limited caller receives `error: rate limit exceeded`.
- The per-connection deadline is reduced from 30 s to 10 s.

#### Optional termination of a user's processes on disconnect

- New `ziti-ssh-host` setting `ZITI_TERMINATE_ON_DISCONNECT` (default `false`, per-identity mode with `ZITI_USER_CLEANUP=false`). When `true`, all of an account's processes are ended when its last session closes — lingering disabled, `loginctl terminate-user`, then SIGTERM/SIGKILL to the account's UID — while the account and home directory are kept. Also applied at startup to accounts that still had sessions open when the daemon stopped.
- With both settings at their defaults, background processes survive disconnect and identity revocation; the daemon now logs a warning at startup in that configuration.
- `docs/operations.md` revocation section now tabulates the behaviour of each combination.

#### Per-identity permissions are applied fail-closed (behaviour change)

- If `ziti-ssh-host` cannot set an account's supplementary groups, remove a legacy sudoers file, or write/remove its sudoers file, the connection is now **rejected** instead of continuing with the account's previous groups and sudoers rule. If a new sudoers rule cannot be installed, the existing file is removed first. Log line: `rejecting connection: could not apply permissions`.
- **Action:** a group named in a `ziti-ssh-host.v1` entry or `ZITI_SSH_GROUPS` that does not exist on the host now blocks that identity's logins on that host. Verify configs with `ziti-ssh-host inspect`.
- When the last session closes with `ZITI_USER_CLEANUP=false`, supplementary groups are cleared as well as the sudoers file (also after a restart following a crash).

#### OIDC callback server listens on loopback only and refuses an occupied port

- The temporary OIDC callback server now binds only `127.0.0.1` and `::1` (previously all interfaces), and claims the port before contacting the identity provider. If either address is already in use the flow stops with an error instead of opening the browser. The redirect URI (`http://localhost:<callback_port>/auth/callback`) and default port are unchanged; no identity-provider changes are needed.
- The login URL is printed to stderr before the browser is opened, and failing to launch a browser is no longer fatal (previously `ziti-ssh` exited on headless machines without showing the URL).
- Only the first authorization callback is used; the callback server has a read-header timeout.

#### Caller identity taken from the edge router (BREAKING)

`ziti-ssh-ca` and `ziti-ssh-host` now identify each caller only by the dialer identity name that the caller's edge router attaches to the connection (`GetDialerIdentityName()`). The client-supplied caller ID header is no longer used for any decision; if it differs, a warning is logged (`client-supplied caller id does not match router-verified dialer identity`).

- Connections without a router-supplied dialer identity are rejected (`rejected connection: edge router did not supply a dialer identity (OpenZiti v2.0.0+ routers required)`). In `per-identity` mode, `ziti-ssh-host` closes such connections without proxying them to sshd.
- **Breaking:** the controller and all edge routers must run **OpenZiti v2.0.0 or later**.
- Integration suite (`suites/ziti-ssh/suite.yml`) now runs against OpenZiti v2.0.8.

**Updated docs:** `ARCHITECTURE.md` §6 (identity flow, with diagram) and §12; `README.md` prerequisites; `docs/provisioning.md` version requirement; `docs/operations.md` new "Caller identity verification" section.

#### Per-identity account ownership registry

`ziti-ssh-host` now records the Linux accounts it creates in `/var/lib/ziti-ssh-host/owned-users.json` (username → Ziti identity, UID; mode 0600) and only creates, modifies, or deletes accounts recorded there for the connecting identity with a matching UID ≥ 1000.

- Existing accounts that `ziti-ssh-host` did not create are not managed; connections deriving their names are rejected. A corrupt registry stops `run` in per-identity mode.
- Two identities that derive the same username are detected across disconnects and restarts.
- Reserved names (`root`, common system accounts, `ubuntu`, `admin`, `ziti`) and names starting with `-` are refused.
- Sudoers files moved to `/etc/sudoers.d/ziti-ssh-host-<username>`; a legacy `/etc/sudoers.d/<username>` is removed only if it contains the single line `ziti-ssh-host` wrote.
- The session count is re-checked before account cleanup when a session is released.
- With cleanup disabled, sudoers files left by sessions open during a crash are removed on restart.
- `ziti-ssh-ca` refuses to sign a per-identity certificate whose derived principal is a reserved account name (the same list the host refuses) or starts with `-`.
- New `ziti-ssh-host users list` and `ziti-ssh-host users claim --username <u> --identity <id>` (root).

**Upgrade action required (per-identity hosts with persistent accounts):** accounts created by earlier releases are not in the registry, so their identities are rejected (`refusing to manage pre-existing account`) until claimed with `sudo ziti-ssh-host users claim --username <u> --identity <id>`. This mainly affects hosts with `ZITI_USER_CLEANUP=false` (the default), where accounts persist. With cleanup enabled, accounts are normally deleted at disconnect; an account whose session was still open during the upgrade is left in place (not deleted, since it is unregistered) and must be claimed or removed with `userdel -r` by an administrator.

**Updated docs:** `docs/operations.md` (account ownership flow diagram, lifecycle, new "Managing account ownership" section, files-written table), `docs/configuration.md` (`users` subcommands, sudoers path), `ARCHITECTURE.md` (`UserManager`, `deleteUser`, §12 account ownership boundary), `CLAUDE.md`.

### Fixed

#### `ziti-ssh-host` did not reload a running sshd on socket-activated systems

`host.ReloadSSHD` (used by `enroll` and by `run` when the CA key set changes) treated an active `ssh.socket` as "each connection starts a fresh sshd" and skipped both `systemctl reload ssh` and the SIGHUP to leftover sshd listeners. On Ubuntu 22.10+ `ssh.socket` uses `Accept=no`: the first connection starts a long-running `ssh.service`, which then serves all connections with the configuration it started with. On any host where sshd was already running when `enroll` wrote `TrustedUserCAKeys` — for example after an administrator had logged in — certificate logins failed until sshd was restarted.

- `ReloadSSHD` now reloads `ssh.service` whenever it is active and sends SIGHUP to top-level sshd listeners (PPID 1) unless `ssh.socket` uses `Accept=yes` (where per-connection sshd processes also have PPID 1). The decision is unit-tested (`planSSHDReload`).
- Integration suite: `install-ca.sh` no longer reports `ziti-ssh-ca` as running when its first start fails because the `ssh-ca` service has not been created yet; systemd restarts it until the service exists.
- Integration suite: `install-host.sh` no longer fails provisioning when `ziti-ssh-host` first exits with `service 'ssh' not found` (the service is created only after all edge routers are online); systemd restarts it until the service exists. Any other startup failure is still fatal.

#### Clients re-signed a certificate on every invocation and saved CA error replies as certificates

`ziti-ssh` and `ziti-scp` refreshed a certificate when fewer than 5 minutes of validity remained — which, with the CA's default 5-minute TTL, was always true. Every invocation requested a new certificate, so a fourth call within a few seconds exceeded the CA's default rate limit (5/min, burst 3). The CA's `error: rate limit exceeded` reply was then written to `<key>-cert.pub` as if it were a certificate, overwriting a valid one, and the login failed with `unable to authenticate`.

- A certificate is now refreshed when less than 20% of its lifetime remains, between 30 seconds and 5 minutes (1 minute for a 5-minute certificate; unchanged for certificates of 25 minutes or longer).
- The CA reply is read with a 16 KiB limit and validated before it is written: an `error: …` reply is reported as `CA refused the request: <reason>`, and anything other than a user certificate for the caller's own public key is rejected. The existing certificate file is left untouched on failure.
- Docs no longer state an 8-hour default TTL (`ARCHITECTURE.md`, `docs/usage.md`, `docs/operations.md`).

#### Per-identity hardening follow-ups

- `ziti-ssh-host`: a connection rejected by the ownership check (e.g. two identities deriving the same username) is no longer counted as a session while it is being checked; previously it could make the owner's final disconnect skip sudoers removal and account cleanup.
- `ziti-ssh-host`: `sudoers_rule` (and `ZITI_SUDOERS_RULE`) values starting with `,` — which would add users to the rule, e.g. `, ALL ALL=(ALL) NOPASSWD: ALL` — are rejected, as are values containing NUL bytes or lacking `=`.
- `ziti-ssh-host run`: at startup, legacy `/etc/sudoers.d/<username>` files are removed for registered accounts; legacy-format files for unregistered accounts are reported (log warning and `ziti-ssh-host users list`) but never removed automatically.
- `docs/operations.md`: revocation section corrected — with `ZITI_USER_CLEANUP=false` (default) the account and its processes are kept after the last session closes.

#### `ziti-ssh-ca` package runs as the controller's service user

- The postinstall script detects the Ziti controller's service user (from `ziti-controller.service`, otherwise the owner of a running `ziti controller run` process) and writes the systemd drop-in `/etc/systemd/system/ziti-ssh-ca.service.d/10-controller-user.conf`. The `openziti-controller` v2 package runs the controller as `ziti-controller`, so the unit's fixed `User=ziti` left the CA unable to read the intermediate key there. Administrator overrides that set `User=` are left unchanged; if no controller is detected, instructions are printed.
- `/etc/ziti-ssh-ca` is now owned by the service user (mode 0750) so controller URL updates can be saved to the identity file.

### Changed

#### `ziti-ssh-ca config`: controller trust and password handling

- Controller TLS trust works like `ziti edge login`: if the system CAs do not trust the controller, its CA bundle is fetched from `/.well-known/est/cacerts`, the controller's certificate is verified against it, the CAs are shown and the user is asked to trust them (`--yes` for scripts). The bundle is saved under `$XDG_CONFIG_HOME/ziti-ssh/controllers/` and reused. A changed CA is refused unless confirmed interactively (`--yes` never replaces it). `--insecure` remains but warns.
- The admin password can come from `--password-file <file|->`, `ZITI_CTRL_PASSWORD_FILE`, `ZITI_CTRL_PASSWORD`, or a hidden prompt. `--password` still works but warns that it is visible in the process list and shell history.

#### Packages install to `/usr/bin`; remove/purge scripts (behaviour change)

- All four packages install their binary to `/usr/bin` instead of `/usr/local/bin` (reserved for locally installed software); the systemd units are updated. Upgrades move the binary automatically; update any scripts or custom units that hard-code `/usr/local/bin/ziti-ssh*`.
- `ziti-ssh-ca` and `ziti-ssh-host` stop and disable their service on removal (not on upgrade).
- `apt purge ziti-ssh-host` removes the sshd drop-in and `/etc/ssh/ziti_ca.pub` and reloads sshd, so the host stops trusting the CA; identities, env files, the ownership registry and Linux accounts are kept. `apt purge ziti-ssh-ca` removes its managed systemd drop-in. rpm has no purge — see `docs/provisioning.md` (Uninstalling).

#### Docker package build

- Added `.dockerignore` so the build context excludes `.git`, `dist/`, local binaries, `*.jwt`, `*.json` (identity files), key material and local security notes (previously `COPY . .` could copy an enrollment JWT into the image).
- `scripts/Dockerfile.packages` pins `golang:1.26-bookworm` by digest; Dependabot now also tracks the Docker base image.

#### Documentation and cleanup

- The CA key is described correctly as the controller's intermediate CA key (RSA, ECDSA or Ed25519; RSA on stock controllers), not "Ed25519".
- Removed the unused `scripts/build-deb.sh`; packages are built with `scripts/build-packages.sh` (nfpm).

#### Dependency, toolchain, and CI refresh

- `github.com/openziti/sdk-golang` moved from v1.9.0 to **v1.8.4**. v1.9.0 was retracted upstream ("published from main before the module moved to `github.com/openziti/sdk-golang/v2`; the supported v1 line is 1.8.x").
- Direct dependencies updated: `edge-api` v0.36.1, `go-openapi/runtime` v0.33.5, `go-openapi/strfmt` v0.27.4, `pkg/sftp` v1.13.12, `zitadel/oidc/v3` v3.52.0, `go.yaml.in/yaml/v3` v3.0.6, `x/crypto` v0.59.0, `x/term` v0.48.0, `x/time` v0.16.0.
- `go.mod` now declares `go 1.26.0` (required by sdk-golang) and `toolchain go1.26.11`. `actions/setup-go` v6+ honours the `toolchain` directive, so release binaries are built with a patched standard library; previously `setup-go@v5` installed exactly the `go` directive version (1.25.0).
- CI vulnerability scan (`govulncheck-action`) now uses `go-version-file: go.mod` instead of the action's default `stable`, so it scans the toolchain that actually builds releases.
- GitHub Actions updated and pinned to commit SHAs: `checkout` v7.0.1, `setup-go` v7.1.0, `upload-artifact` v7.0.2, `govulncheck-action` v1.1.0, `setup-jfrog-cli` v5.3.5, `action-gh-release` v3.0.4. `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` removed (all actions now run on Node 24 natively).
- `ci.yml` declares `permissions: contents: read`.
- Default tool versions: nfpm 2.49.0 (prerelease download now verified against the release `checksums.txt`; `build-packages.sh` fallback pinned instead of `@latest`), jfrog-cli 2.133.0.
- `ziti-test.yml` builds packages with `build-packages.sh` (same nfpm path as releases) instead of `build-deb.sh`; `suites/ziti-ssh/suite.yml` paths updated to the nfpm filenames (`<pkg>_0.0.0-1_amd64.deb`).
- `scripts/Dockerfile.packages` base image moved to `golang:1.26-bookworm`.
- Added `.github/dependabot.yml` (weekly `gomod` and `github-actions` updates, minor/patch grouped).

---

## [Unreleased] - 2026-04-14

### Added

#### `ziti-ssh-ca enroll` subcommand

`ziti-ssh-ca` now has an `enroll` subcommand that mirrors `ziti-ssh enroll` and `ziti-scp enroll` exactly.

- Reads the one-time JWT file, calls `enroll.Enroll` with `KeyAlg = "EC"`, and writes the enrolled identity JSON to `/etc/ziti-ssh-ca/identity.json` (mode 0600) by default.
- `--out <path>` overrides the output path.
- `--jwt <path>` is required.
- No CA-specific post-enrollment steps are performed (unlike `ziti-ssh-host enroll`, which also fetches CA public keys and configures sshd).

**Updated docs:**
- `docs/provisioning.md`: "Setting up `ziti-ssh-ca`" step 3 now uses `ziti-ssh-ca enroll --jwt /tmp/ssh-ca-server.jwt` instead of the `ziti edge enroll` + `chmod` two-step.
- `docs/configuration.md`: `ziti-ssh-ca enroll` flag table added before the existing `config` subcommands section.
- `CLAUDE.md`: updated the `ziti-ssh-ca` description and component section to list `enroll` as a subcommand.

---

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
- `ZITI_USER_CLEANUP=true`: deletes user accounts on disconnect; default is `false` (accounts kept); orphan cleanup always runs on startup
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
