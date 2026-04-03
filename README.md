# ziti-ssh

A complete SSH-over-Ziti system: short-lived certificate issuance, host proxy, a full SSH client, and a file copy tool — all operating over an [OpenZiti](https://openziti.io) zero-trust network. Four binaries make up the system:

- **`ziti-ssh-ca`** — an SSH Certificate Authority service. Ziti identities are used to issue short-lived SSH certificates; no credentials live on SSH hosts, no `authorized_keys` files, and port 22 is never exposed externally.
- **`ziti-ssh-host`** — enrolls a machine as a Ziti identity, configures `sshd` to trust the CA, and proxies inbound Ziti connections to the local `sshd`.
- **`ziti-ssh`** — the client binary. Handles identity enrollment, certificate signing, interactive SSH sessions, service listing, and MFA TOTP management — all over the Ziti overlay.
- **`ziti-scp`** — a file copy tool over the Ziti overlay. Uses the SFTP subsystem. Mirrors `scp(1)` behaviour (upload, download, recursive directory copy, preserve mode). Shares the same identity, certificate, and config infrastructure as `ziti-ssh`.

The Ziti network enforces who can reach which machines; `sshd` on each machine only needs to trust a single CA public key.

For a detailed technical reference see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## How it works

1. A user's Ziti identity authorizes them to dial the `ssh-ca` service.
2. They send their SSH public key; the CA signs it and returns a short-lived certificate (default: 8 hours, configurable via `--cert-ttl` / `ZITI_CERT_TTL` on `ziti-ssh-ca`).
3. The certificate's `ValidPrincipals` is set based on the configured mode (see [Modes](#modes)). The Ziti identity name is embedded in the `KeyId` field for audit logging.
4. The user runs `ziti-ssh <host-identity-name>`. `ziti-ssh` dials the `ssh` Ziti service, specifying the target host's identity name as the terminator address.
5. `ziti-ssh-host run` on the target machine accepts the connection and proxies it to the local `sshd` on `127.0.0.1:22`.
6. `sshd` validates the certificate against the CA public key written during enrollment — no network call, no LDAP, no SSSD.

---

## Prerequisites

- An operational OpenZiti network (controller + at least one edge router). See the [OpenZiti quickstart](https://openziti.io/docs/learn/quickstarts/) if you do not have one yet.
- **On user machines:** `ziti-ssh` installed (from this repo) and a Ziti identity enrolled.
- **On the CA host:** Go 1.22 or later (to build from source), or the pre-built `ziti-ssh-ca` binary.
- **On each SSH target host:** Go 1.22 or later (to build from source), or the pre-built `ziti-ssh-host` binary. Ubuntu 22.04 or later (or any distro with OpenSSH 8.2+ and systemd).

---

## Building

```sh
git clone https://github.com/netfoundry/ziti-ssh.git
cd ziti-ssh
go build -o ziti-ssh-ca   ./cmd/ziti-ssh-ca
go build -o ziti-ssh-host ./cmd/ziti-ssh-host
go build -o ziti-ssh      ./cmd/ziti-ssh
go build -o ziti-scp      ./cmd/ziti-scp
```

All binaries are statically linked (no CGO). Copy each binary to the machine where it will run. `ziti-ssh` and `ziti-scp` belong on user machines; `ziti-ssh-ca` and `ziti-ssh-host` are server-side components.

---

## Network topology

The attribute model defines which identities can reach which services. Three attributes group identities by role:

| Attribute | Applied to |
|---|---|
| `#ssh-ca-servers` | The identity running `ziti-ssh-ca` |
| `#ssh-clients` | User identities (dial `ssh-ca` to get certs, dial `ssh` to reach hosts) |
| `#ssh-hosts` | Host identities (each runs `ziti-ssh-host`, binds the `ssh` service) |

Two services carry all traffic:

| Service | Purpose |
|---|---|
| `ssh-ca` | Certificate signing — clients send a public key, receive a signed cert |
| `ssh` | SSH host proxy — clients reach hosts via addressable terminators |

---

## Provisioning the Ziti network

The commands in this section assume `ziti edge login` has already been run against your controller. All commands use the `ziti` CLI.

### 1. Create the two services

```sh
ziti edge create service ssh-ca \
  --role-attributes ssh-ca

ziti edge create service ssh \
  --role-attributes ssh
```

The role attributes on the services are optional labels used only when writing service-role references in policies (e.g. `@ssh-ca` syntax). Using explicit service names in policy `--service-roles` is equally valid.

### 2. Create service policies

Four policies implement the access model:

```sh
# ziti-ssh-ca binds ssh-ca
ziti edge create service-policy bind-ssh-ca Bind \
  --service-roles "@ssh-ca" \
  --identity-roles "#ssh-ca-servers"

# clients dial ssh-ca to get certificates
ziti edge create service-policy dial-ssh-ca Dial \
  --service-roles "@ssh-ca" \
  --identity-roles "#ssh-clients"

# hosts bind ssh (one terminator per host, addressed by identity name)
ziti edge create service-policy bind-ssh Bind \
  --service-roles "@ssh" \
  --identity-roles "#ssh-hosts"

# clients dial ssh to reach hosts
ziti edge create service-policy dial-ssh Dial \
  --service-roles "@ssh" \
  --identity-roles "#ssh-clients"
```

### 3. Create service edge router policies

Both services must be reachable through edge routers. The `#all` attribute covers every edge router in the network:

```sh
ziti edge create service-edge-router-policy serp-ssh-ca \
  --service-roles "@ssh-ca" \
  --edge-router-roles "#all"

ziti edge create service-edge-router-policy serp-ssh \
  --service-roles "@ssh" \
  --edge-router-roles "#all"
```

### 4. Create identities

**CA server identity** (one per deployment):

```sh
ziti edge create identity ssh-ca-server \
  --role-attributes "ssh-ca-servers" \
  --jwt-output-file /tmp/ssh-ca-server.jwt
```

Copy the JWT to the CA host, then enroll it:

```sh
ziti edge enroll --jwt /tmp/ssh-ca-server.jwt --out /etc/ziti-ssh-ca/identity.json
```

See [Setting up `ziti-ssh-ca`](#setting-up-ziti-ssh-ca) for the full CA setup procedure.

**Host identity** (repeat for each SSH target host, using the host's desired reachability name):

```sh
ziti edge create identity web-server-prod \
  --role-attributes "ssh-hosts" \
  --jwt-output-file /tmp/web-server-prod.jwt
```

Copy the JWT to the target host. Enrollment for host identities is performed by `ziti-ssh-host enroll`, which wraps `ziti edge enroll` and also configures `sshd` automatically — see [Setting up `ziti-ssh-host`](#setting-up-ziti-ssh-host-on-a-target-machine) for the full procedure. If you need to enroll the identity file separately without configuring `sshd`:

```sh
ziti edge enroll --jwt /tmp/web-server-prod.jwt --out /etc/ziti-ssh-host/identity.json
```

**Client identity** (repeat for each user):

```sh
ziti edge create identity alice \
  --role-attributes "ssh-clients" \
  --jwt-output-file /tmp/alice.jwt
```

Copy the JWT to the user's machine, then enroll it:

```sh
ziti edge enroll --jwt /tmp/alice.jwt --out ~/.config/ziti/alice.json
```

See [Setting up a client identity](#setting-up-a-client-identity) for the full client setup procedure.

The identity name chosen for each host (`web-server-prod` above) is the address users pass to `ziti-ssh` — choose it carefully, as it is also the terminator address on the `ssh` service.

---

## Setting up `ziti-ssh-ca`

### 1. Locate the Ziti controller intermediate CA private key

The Ziti controller uses a two-tier PKI:

```
Root CA (offline)
  └── Controller Intermediate CA  ← signs Ziti identity certificates
        └── Ziti Identity Certs   ← issued to clients, hosts, services
```

`ziti-ssh-ca` uses the **controller's intermediate CA private key** — the key that signs Ziti identity certificates. Do not use the root CA key; the root CA private key is kept offline and never used at runtime.

In production, `ziti-ssh-ca` runs on the same machine as the Ziti controller, as the same OS user (typically `ziti`). This gives it direct filesystem access to the controller's PKI without any credential distribution.

The intermediate CA private key is typically found at a path like:

```
/var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key
```

The exact path depends on how the controller was installed. For controllers deployed via the `ziti` quickstart or the official Debian packages, check the controller config file (e.g. `/etc/ziti/controller/ctrl.yml`) for the intermediate CA paths to confirm the location.

Pass this path to `--ca-key` (or `ZITI_CA_KEY`):

```sh
--ca-key /var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key
```

The intermediate CA public key is derived from this private key at startup. During `ziti-ssh-host enroll`, the public key is extracted directly from the enrollment response certificate chain — no manual distribution required.

> **Deployment note:** Because `ziti-ssh-ca` must read the controller's intermediate CA private key, it must run on the same host as the Ziti controller, under the same user account (or another account with read permission on the key file). The key file should remain mode 0600 and owned by the controller service user — do not change its permissions.

### 2. Enroll the CA server identity

Copy the JWT produced in the provisioning step above to the CA host, then enroll it:

```sh
mkdir -p /etc/ziti-ssh-ca
ziti edge enroll \
  --jwt /tmp/ssh-ca-server.jwt \
  --out /etc/ziti-ssh-ca/identity.json
chmod 600 /etc/ziti-ssh-ca/identity.json
```

### 3. Run the CA service

```sh
ziti-ssh-ca \
  --identity  /etc/ziti-ssh-ca/identity.json \
  --ca-key    /etc/ziti-ssh-ca/ca_key \
  --service   ssh-ca \
  --mode      shared \
  --principal ziggy
```

All flags can be set via environment variables instead (useful for systemd units — see [Configuration reference](#configuration-reference)).

`--mode` defaults to `shared`. It must be set to the same value on both `ziti-ssh-ca` and `ziti-ssh-host run`. See [Modes](#modes) for a full explanation of the two modes.

**Example systemd unit** (`/etc/systemd/system/ziti-ssh-ca.service`):

```ini
[Unit]
Description=Ziti SSH Certificate Authority
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=ziti
EnvironmentFile=/etc/ziti-ssh-ca/env
ExecStart=/usr/local/bin/ziti-ssh-ca
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`Type=notify` is supported — `ziti-ssh-ca` sends `READY=1` via `sd_notify` once the listener is bound and ready to accept connections. systemd will not consider dependent units satisfied until the notification is received.

The Debian package creates `/etc/ziti-ssh-ca/env` (mode 0640) automatically on first install. Edit it to configure the service before starting:

```sh
# /etc/ziti-ssh-ca/env
ZITI_IDENTITY=/etc/ziti-ssh-ca/identity.json
ZITI_CA_KEY=/var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key
ZITI_CA_SERVICE=ssh-ca
ZITI_SSH_MODE=shared
ZITI_SSH_PRINCIPAL=ziggy
# ZITI_CERT_TTL=8h   # optional; 8h is the default
```

```sh
systemctl daemon-reload
systemctl enable --now ziti-ssh-ca
```

---

## Setting up `ziti-ssh-host` on a target machine

Repeat these steps on every machine you want to make reachable over Ziti.

### 1. Create the shared Linux account

```sh
useradd --create-home --shell /bin/bash ziggy
```

Or use an existing account — just set `--principal` on the CA to match.

### 2. Enroll a Ziti identity for the host

Create the host identity on the controller (if not already done in the provisioning step), copy the JWT to the target machine, then enroll:

```sh
# On the controller (if the identity was not already created):
ziti edge create identity web-server-prod \
  --role-attributes "ssh-hosts" \
  --jwt-output-file /tmp/web-server-prod.jwt

# Copy the JWT to the target host (scp, ansible, etc.), then on the host:
ziti-ssh-host enroll --jwt /tmp/web-server-prod.jwt
```

This command:
- Enrolls the identity and writes `/etc/ziti-ssh-host/identity.json` (mode 0600).
- Extracts the intermediate CA public key from the enrollment response certificate chain (no network call to the CA service required).
- Writes `/etc/ssh/ziti_ca.pub` and `/etc/ssh/sshd_config.d/ziti-ssh.conf`.
- Runs `systemctl reload ssh`.

After enrollment, `sshd` trusts certificates signed by your CA. No other changes to the SSH host are required.

### 3. Run the host proxy daemon

```sh
ziti-ssh-host run
```

**Example systemd unit** (`/etc/systemd/system/ziti-ssh-host.service`):

```ini
[Unit]
Description=Ziti SSH Host Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=root
EnvironmentFile=-/etc/ziti-ssh-host/env
ExecStart=/usr/local/bin/ziti-ssh-host run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`Type=notify` is supported — `ziti-ssh-host run` sends `READY=1` via `sd_notify` once the Ziti listener is bound.

The Debian package creates `/etc/ziti-ssh-host/env` (mode 0640) automatically on first install. Edit it to configure the service before starting:

```sh
# /etc/ziti-ssh-host/env
ZITI_IDENTITY=/etc/ziti-ssh-host/identity.json
ZITI_SSH_SERVICE=ssh
ZITI_SSH_MODE=shared
# ZITI_SUDOERS_RULE=ALL=(ALL) NOPASSWD:ALL   # per-identity mode only; leave unset for no sudo
# ZITI_USER_CLEANUP=true                      # per-identity mode only; set to false to keep accounts
```

```sh
systemctl daemon-reload
systemctl enable --now ziti-ssh-host
```

---

## Setting up a client identity

Each user needs a Ziti identity enrolled on their machine. The identity name becomes the SSH principal in `per-identity` mode and is recorded in the `KeyId` field of every certificate for audit purposes.

### 1. Create the identity on the controller

```sh
ziti edge create identity alice \
  --role-attributes "ssh-clients" \
  --jwt-output-file /tmp/alice.jwt
```

### 2. Enroll on the user's machine

Copy the JWT to the user's machine, then enroll using `ziti-ssh enroll`:

```sh
ziti-ssh enroll --jwt /tmp/alice.jwt
# Identity written to ~/.config/ziti-ssh/alice.json
```

Or specify an explicit output path:

```sh
ziti-ssh enroll --jwt /tmp/alice.jwt --out ~/.config/ziti-ssh/alice.json
```

Once enrolled, the user can obtain an SSH certificate and connect to hosts using `ziti-ssh sign` and `ziti-ssh connect`.

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

---

## Getting a certificate as a user

Use `ziti-ssh sign` to obtain a signed SSH certificate from the CA. It handles key discovery, CA communication, certificate writing, and immediate verification in a single command.

### Install

Download the pre-built binary or build from source:

```sh
go build -o ziti-ssh ./cmd/ziti-ssh
# Copy ziti-ssh to a directory on your PATH, e.g. /usr/local/bin/
```

Or install via the Debian package:

```sh
dpkg -i ziti-ssh_<version>_amd64.deb
```

The package depends on `openssh-client` for `ssh-keygen`.

### Enrolling a Ziti identity

Before connecting, enroll your Ziti identity from the JWT file provided by the administrator:

```sh
ziti-ssh enroll --jwt alice.jwt
# Identity written to ~/.config/ziti-ssh/alice.json
```

You can specify an explicit output path with `--out`:

```sh
ziti-ssh enroll --jwt alice.jwt --out ~/.config/ziti-ssh/alice.json
```

### Obtaining a certificate

```sh
ziti-ssh sign --identity ~/.config/ziti-ssh/alice.json
```

With explicit options:

```sh
ziti-ssh sign \
  --identity ~/.config/ziti-ssh/alice.json \
  --ca-service ssh-ca \
  --key ~/.ssh/id_ed25519
```

The `--identity` flag (or `ZITI_IDENTITY` environment variable) is required. All other flags have defaults.

### What to expect

1. `ziti-ssh sign` auto-detects your SSH key in `~/.ssh/` (tries `id_ed25519`, `id_ecdsa`, `id_rsa` in that order). If no key exists it offers to run `ssh-keygen -t ed25519` for you.
2. It connects to the `ssh-ca` Ziti service using your identity, sends your public key, and receives a signed certificate.
3. The certificate is written to `~/.ssh/<key>-cert.pub` (e.g. `~/.ssh/id_ed25519-cert.pub`).
4. `ssh-keygen -L` is run automatically so you can verify the certificate immediately:

```
/home/alice/.ssh/id_ed25519-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:...
        Signing CA: ED25519 SHA256:... (using ssh-ed25519)
        Key ID: "ziti:alice"
        Serial: 0
        Valid: from 2026-03-30T09:00:00 to 2026-03-30T17:00:00
        Principals:
                ziggy
        Critical Options: (none)
        Extensions:
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
```

The certificate expires after the TTL configured on the CA (default: 8 hours). Run `ziti-ssh sign` again to renew manually(automatically renew upon connecting).

---

## Connecting to a host

Once a certificate is present in `~/.ssh/id_ed25519-cert.pub`, open an SSH session with:

```sh
ziti-ssh ziggy@web-server-prod
```

Or use the explicit subcommand form:

```sh
ziti-ssh connect ziggy@web-server-prod
```

`web-server-prod` is the Ziti identity name of the target host. `ziti-ssh` resolves this as a Ziti service terminator address on the `ssh` service — no DNS, no IP address required.

If the certificate is missing or will expire within 30 minutes, `ziti-ssh connect` automatically runs the sign flow before opening the session.

If the SSH private key is passphrase-protected, `ziti-ssh connect` falls back to the SSH agent (`SSH_AUTH_SOCK`). It locates the matching key in the agent and, if a certificate is present on disk, wraps it as an `ssh.CertSigner` so the certificate is offered during authentication. The passphrase is never exposed to this process. If the key is passphrase-protected and `SSH_AUTH_SOCK` is not set (or the key has not been added with `ssh-add`), `ziti-ssh connect` exits with an actionable error.

### Non-interactive command execution

To run a single command on a remote host without opening an interactive shell, append the command after the target (use `--` to separate it from any `ziti-ssh` flags):

```sh
# Run a command non-interactively
ziti-ssh ziggy@web-server-prod "ls -al"
ziti-ssh ziggy@web-server-prod "ls -la /tmp"


# Explicit seperator form
ziti-ssh ziggy@web-server-prod -- df -h
ziti-ssh ziggy@web-server-prod -- systemctl status nginx
ziti-ssh ziggy@web-server-prod -- "echo hello world"
```

No PTY is allocated for non-interactive commands. `stdin`, `stdout`, and `stderr` are wired directly so you can pipe output normally:

```sh
ziti-ssh ziggy@web-server-prod -- cat /etc/os-release | grep VERSION
```

The remote process exit code is propagated: if the remote command exits non-zero, `ziti-ssh` exits with that same code. This makes it suitable for use in scripts.

---

## Copying files with `ziti-scp`

`ziti-scp` copies files to and from remote hosts over the same Ziti overlay, using the SFTP subsystem. It mirrors `scp(1)` behaviour. The same identity, SSH certificate, and `~/.config/ziti-ssh/config.yaml` config file are shared with `ziti-ssh` — no additional enrollment is needed.

Remote specifications use the same `[user@]host:path` format as `scp`. The host name is resolved the same way `ziti-ssh` resolves it: first checked against the Ziti service list for a direct match, then used as a terminator address on `--ssh-service` (default: `ssh`).

### Upload (local to remote)

```sh
# Copy a single file
ziti-scp /local/file.txt ziggy@web-server-prod:/remote/dir/

# Copy multiple files
ziti-scp file1.txt file2.txt ziggy@web-server-prod:/remote/dir/

# Recursive directory copy
ziti-scp -r /local/dir ziggy@web-server-prod:/remote/dir/
```

### Download (remote to local)

```sh
# Copy a single file
ziti-scp ziggy@web-server-prod:/remote/file.txt /local/dir/

# Recursive directory copy
ziti-scp -r ziggy@web-server-prod:/remote/dir /local/dir/
```

### Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--recursive` | `-r` | false | Recursively copy entire directories |
| `--preserve` | `-p` | false | Preserve file timestamps and permissions |
| `--quiet` | `-q` | false | Suppress progress output |
| `--identity` | — | `ZITI_IDENTITY` | Ziti identity file path |
| `--key` | — | auto-detect | SSH private key path |
| `--ca-service` | — | `ssh-ca` | CA service name |
| `--ssh-service` | — | `ssh` | SSH service name |
| `--config` | — | `~/.config/ziti-ssh/config.yaml` | Config file path |

If the certificate is missing or will expire within 30 minutes, `ziti-scp` automatically obtains a fresh certificate from the CA before connecting — the same auto-refresh behaviour as `ziti-ssh connect`.

### Enroll a Ziti identity

`ziti-scp` includes its own `enroll` subcommand for machines where only file copy is needed:

```sh
ziti-scp enroll --jwt alice.jwt
# Identity written to ~/.config/ziti-ssh/alice.json
```

### Config file

`ziti-scp` reads the same `~/.config/ziti-ssh/config.yaml` as `ziti-ssh`. No separate config file is required:

```yaml
identity: ~/.config/ziti-ssh/alice.json
ca_service: ssh-ca
ssh_service: ssh
```

---

### Listing accessible services

```sh
ziti-ssh list --identity ~/.config/ziti-ssh/alice.json
```

Prints all Ziti services accessible to this identity with their permission sets.

### Managing MFA

```sh
# Enable TOTP MFA on the identity
ziti-ssh mfa enable --identity ~/.config/ziti-ssh/alice.json

# Print the provisioning URL instead of just the secret
ziti-ssh mfa enable --identity ~/.config/ziti-ssh/alice.json --qr-code

# Verify that MFA authentication works
ziti-ssh mfa verify --identity ~/.config/ziti-ssh/alice.json

# Remove TOTP MFA
ziti-ssh mfa remove --identity ~/.config/ziti-ssh/alice.json
```

### Config file

Settings can be stored in `~/.config/ziti-ssh/config.yaml` (XDG_CONFIG_HOME is respected) to avoid repeating flags on every invocation:

```yaml
identity: ~/.config/ziti-ssh/alice.json
ca_service: ssh-ca
ssh_service: ssh
```

To enable OIDC authentication, add an `oidc` block (see [OIDC authentication](#oidc-authentication) below):

```yaml
identity: ~/.config/ziti-ssh/alice.json
ca_service: ssh-ca
ssh_service: ssh
oidc:
  issuer: https://your-idp.example.com
  client_id: ziti-ssh
  client_secret: ""        # leave empty for PKCE (public client)
  callback_port: "63275"   # optional; 63275 is the default
```

Precedence: CLI flag > config file > built-in default.

---

## OIDC authentication

`ziti-ssh` supports browser-based OIDC authentication as a secondary credential layer on top of the Ziti mTLS identity. This satisfies **ext-jwt-signer** policies on the Ziti controller — useful when your organization requires that SSH access also be gated by an SSO provider (e.g. Okta, Keycloak, Azure AD).

OIDC authentication is entirely optional. When no issuer is configured the behavior is unchanged.

### How it works

When an OIDC issuer is configured:

1. Before dialling any Ziti service, `ziti-ssh connect` (and `ziti-ssh sign`) starts a temporary HTTP server on `localhost:<callback_port>` and opens your browser to the authorization URL.
2. You log in through your identity provider's normal web UI.
3. The provider redirects to the local callback server with an authorization code.
4. `ziti-ssh` exchanges the code for an access token and adds it to the Ziti context via `GetCredentials().AddJWT()` before calling `Authenticate()`.
5. The Ziti controller validates the JWT against the configured ext-jwt-signer. If the JWT is accepted, the controller grants the session additional permissions beyond what the mTLS identity alone would receive.

The OIDC flow times out after 2 minutes. If the browser does not complete authentication within that window, `ziti-ssh` exits with an error.

If no client secret is provided (empty string or omitted), PKCE is used automatically — suitable for public clients that cannot safely store a secret.

### Provisioning the Ziti controller side

The controller must have an **ext-jwt-signer** configured and linked to the identities or service policies you want to protect. Using the `ziti` CLI:

```sh
# 1. Create an ext-jwt-signer referencing your OIDC issuer's JWKS endpoint
ziti edge create ext-jwt-signer my-oidc-signer \
  --issuer https://your-idp.example.com \
  --jwks-endpoint https://your-idp.example.com/.well-known/jwks.json \
  --audience ziti-ssh \
  --claims-property email

# 2. Create an auth policy that requires both the Ziti mTLS cert AND the JWT
ziti edge create auth-policy ssh-oidc-policy \
  --primary-cert-allowed \
  --secondary-req-ext-jwt-signer my-oidc-signer

# 3. Apply that auth policy to the identities that must use OIDC
ziti edge update identity alice --auth-policy ssh-oidc-policy
```

Consult the [OpenZiti ext-jwt-signer documentation](https://openziti.io/docs/reference/configuration/conventions#external-jwt-signers) for the full list of options.

Your OIDC provider must have `http://localhost:<callback_port>/auth/callback` registered as an allowed redirect URI. The default callback port is `63275`.

### Configuring `ziti-ssh` to use OIDC

Via the config file (`~/.config/ziti-ssh/config.yaml`):

```yaml
oidc:
  issuer: https://your-idp.example.com
  client_id: ziti-ssh
  client_secret: ""      # omit or leave empty to use PKCE
  callback_port: "63275" # optional
```

Or via the CLI flag (overrides the config file):

```sh
ziti-ssh connect --oidc-issuer https://your-idp.example.com alice@web-server-prod
```

`client_id` and `client_secret` can only be set through the config file. If `client_id` is not set the OIDC flow will fail; ensure it is present in the config when using OIDC.

---

## Configuration reference

All binaries resolve each setting in the same order: CLI flag > environment variable > built-in default. `ziti-ssh` additionally reads `~/.config/ziti-ssh/config.yaml` between the environment variable and the built-in default.

### `ziti-ssh` (persistent flags, available to all subcommands)

| Flag | Env | Default | Description |
|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | — | Path to Ziti identity JSON file |
| `--config` | — | `~/.config/ziti-ssh/config.yaml` | Config file path |

### `ziti-ssh connect` / root

| Flag | Env | Default | Description |
|---|---|---|---|
| `--ca-service` | `ZITI_CA_SERVICE` | `ssh-ca` | CA service name |
| `--ssh-service` | `ZITI_SSH_SERVICE` | `ssh` | SSH service name |
| `--service` | — | — | Explicit Ziti service to dial (overrides `--ssh-service`) |
| `--key` | — | auto-detect | SSH private key path |
| `--mode` | `ZITI_SSH_MODE` | `shared` | Mode hint (informational for client) |
| `--oidc-issuer` | — | — | OIDC issuer URL; triggers browser-based OIDC auth (overrides `oidc.issuer` in config) |

### `ziti-ssh sign`

| Flag | Env | Default | Description |
|---|---|---|---|
| `--ca-service` | `ZITI_CA_SERVICE` | `ssh-ca` | CA service name |
| `--key` | — | auto-detect | SSH private key path |

### `ziti-ssh enroll`

| Flag | Env | Default | Description |
|---|---|---|---|
| `--jwt` | — | — | Enrollment JWT file path (required) |
| `--out` | — | `~/.config/ziti-ssh/<name>.json` | Output path for identity JSON |

### `ziti-ssh mfa enable`

| Flag | Default | Description |
|---|---|---|
| `--qr-code` / `-q` | false | Print provisioning URL for use with a TOTP app |

### `ziti-ssh-ca`

| Flag | Environment variable | Default | Required | Description |
|---|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | — | Yes | Path to Ziti identity JSON file |
| `--ca-key` | `ZITI_CA_KEY` | — | Yes | Path to controller intermediate CA private key |
| `--service` | `ZITI_CA_SERVICE` | `ssh-ca` | No | Ziti service name to bind |
| `--principal` | `ZITI_SSH_PRINCIPAL` | `ziggy` | No | Linux username placed in `ValidPrincipals` (shared mode only) |
| `--mode` | `ZITI_SSH_MODE` | `shared` | No | Principal mode: `shared` or `per-identity` |
| `--cert-ttl` | `ZITI_CERT_TTL` | `8h` | No | Certificate validity duration (e.g. `4h`, `12h`, `24h`); must be > 0 |
| `--rate-limit` | `ZITI_RATE_LIMIT` | `5` | No | Maximum cert signing requests per minute per identity (decimal values accepted for sub-minute rates) |
| `--rate-burst` | `ZITI_RATE_BURST` | `3` | No | Burst allowance for the per-identity token-bucket rate limiter |

### `ziti-ssh-host`

These flags are persistent (accepted by both `enroll` and `run`):

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | `/etc/ziti-ssh-host/identity.json` | Path to Ziti identity JSON file |
| `--ca-service` | `ZITI_CA_SERVICE` | `ssh-ca` | Ziti service name for the CA (used during `enroll`) |
| `--ssh-service` | `ZITI_SSH_SERVICE` | `ssh` | Ziti service name to proxy (used during `run`) |

The `run` subcommand also accepts:

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--mode` | `ZITI_SSH_MODE` | `shared` | Principal mode: `shared` or `per-identity` |
| — | `ZITI_SUDOERS_RULE` | — | If set, a sudoers rule `<username> <value>` is written to `/etc/sudoers.d/<username>` on first connect (per-identity mode only) |
| — | `ZITI_USER_CLEANUP` | `true` | Set to `false` to keep the Linux account after the last session closes rather than running `userdel -r` (per-identity mode only) |

`enroll` also requires `--jwt <path>` (no environment variable equivalent).

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

The services support `Type=notify` in systemd unit files — each process sends `READY=1` via `sd_notify` after the Ziti listener is bound and ready to accept connections, and `STOPPING=1` when a shutdown signal is received. To use this, change `Type=simple` to `Type=notify` in the systemd unit:

```ini
[Service]
Type=notify
```

See [Setting up `ziti-ssh-ca`](#setting-up-ziti-ssh-ca) and [Setting up `ziti-ssh-host`](#setting-up-ziti-ssh-host-on-a-target-machine) for the full unit file examples.

---

## Project structure

```
ziti-ssh/
├── cmd/
│   ├── ziti-ssh/
│   │   ├── main.go         # Full SSH client (connect, sign, enroll, list, mfa)
│   │   └── oidc.go         # Browser-based OIDC auth flow
│   ├── ziti-scp/
│   │   └── main.go         # SCP-style file copy tool (upload, download, recursive)
│   ├── ziti-ssh-ca/
│   │   └── main.go         # CA service entry point
│   └── ziti-ssh-host/
│       └── main.go         # enroll + run subcommands
├── ca/
│   ├── ca.go               # CA key loading, cert signing, DeriveUsername
│   └── ca_test.go
├── client/
│   ├── ssh.go              # NewCertSigner, CertNeedsRefresh, RunSession, RunCommand
│   └── sftp.go             # RunSFTP — SFTP file copy over net.Conn
├── host/
│   └── host.go             # sshd config, TCP proxy, UserManager
├── config/
│   └── config.go           # Flag/env/default resolution
├── internal/
│   └── ratelimit/          # Per-identity token-bucket rate limiter
├── scripts/
│   └── build-deb.sh        # Produces .deb packages for all four binaries
├── go.mod
├── go.sum
├── README.md
├── ARCHITECTURE.md
└── CLAUDE.md
```
