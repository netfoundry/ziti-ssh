# Changelog

All notable changes to this project will be documented in this file.

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
