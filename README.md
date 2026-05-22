# ziti-ssh

A complete SSH-over-Ziti system: short-lived certificate issuance, host proxy, a full SSH client, and a file copy tool — all operating over an [OpenZiti](https://openziti.io) zero-trust network. Four binaries make up the system:

- **`ziti-ssh-ca`** — an SSH Certificate Authority service. Ziti identities are used to issue short-lived SSH certificates; no credentials live on SSH hosts, no `authorized_keys` files, and port 22 is never exposed externally.
- **`ziti-ssh-host`** — enrolls a machine as a Ziti identity, configures `sshd` to trust the CA, and proxies inbound Ziti connections to the local `sshd`.
- **`ziti-ssh`** — the client binary. Handles identity enrollment, certificate signing, interactive SSH sessions, service listing, and MFA TOTP management — all over the Ziti overlay.
- **`ziti-scp`** — a file copy tool over the Ziti overlay. Uses the SFTP subsystem. Mirrors `scp(1)` behaviour (upload, download, recursive directory copy, preserve mode). Shares the same identity, certificate, and config infrastructure as `ziti-ssh`.

The Ziti network enforces who can reach which machines; `sshd` on each machine only needs to trust a single CA public key.

---

## How it works

1. A user's Ziti identity authorizes them to dial the `ssh-ca` service.
2. They send their SSH public key; the CA signs it and returns a short-lived certificate (default: 5 minutes, configurable via `--cert-ttl` / `ZITI_CERT_TTL` on `ziti-ssh-ca`).
3. The certificate's `ValidPrincipals` is set based on the configured mode (see [Modes](docs/operations.md#modes)). The Ziti identity name is embedded in the `KeyId` field for audit logging.
4. The user runs `ziti-ssh <host-identity-name>`. `ziti-ssh` dials the `ssh` Ziti service, specifying the target host's identity name as the terminator address.
5. `ziti-ssh-host run` on the target machine accepts the connection and proxies it to the local `sshd` on `127.0.0.1:22`.
6. `sshd` validates the certificate against the CA public key written during enrollment — no network call, no LDAP, no SSSD.

---

## Prerequisites

- An operational OpenZiti network (controller + at least one edge router). See the [OpenZiti quickstart](https://openziti.io/docs/learn/quickstarts/) if you do not have one yet.
- **On user machines:** `ziti-ssh` installed
- **On the controller:** `ziti-ssh-ca` installed
- **On each SSH target host:** `ziti-ssh-host` installed — Ubuntu 22.04 or later (or any distro with OpenSSH 8.2+ and systemd)

Install any component with:

```sh
curl -sSL https://get.netfoundry.io/linux-install.bash | sudo bash -s <package-name>
```

See [docs/building.md](docs/building.md) for all installation options including local builds.

---

## Building

See [docs/building.md](docs/building.md) for all installation and build options.

---

## Documentation

| File | Purpose |
|---|---|
| [docs/building.md](docs/building.md) | Getting binaries: download, Docker build, local build |
| [docs/provisioning.md](docs/provisioning.md) | Ziti network setup, per-component installation |
| [docs/usage.md](docs/usage.md) | End-user guide: certs, connecting, file copy, MFA |
| [docs/configuration.md](docs/configuration.md) | Full flag/env/config reference for all binaries |
| [docs/operations.md](docs/operations.md) | Modes, CA key rotation, graceful shutdown |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Internal architecture and design decisions |
