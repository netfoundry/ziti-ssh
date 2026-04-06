# Provisioning

This guide covers everything an administrator needs to set up the full ziti-ssh system: network topology, Ziti provisioning, and per-component installation.

For end-user usage see [usage.md](usage.md). For a full flag and config reference see [configuration.md](configuration.md).

---

## Building the packages

The deb packages are not yet published to an apt repository. Build them locally from source.

**Prerequisites:**

- `go` 1.21 or later
- `dpkg-deb` (included in the `dpkg` package on Debian/Ubuntu)

**Build:**

```sh
# Default version (0.1.0):
./scripts/build-deb.sh

# Explicit version:
VERSION=1.2.0 ./scripts/build-deb.sh
```

Output lands in `dist/`:

```
dist/ziti-ssh-ca_<version>_amd64.deb
dist/ziti-ssh-host_<version>_amd64.deb
dist/ziti-ssh_<version>_amd64.deb
dist/ziti-scp_<version>_amd64.deb
```

Copy the relevant packages to their target machines before proceeding with the sections below.

---

## Network topology

The attribute model defines which identities can reach which services. Three attributes group identities by role:

| Attribute | Applied to |
|---|---|
| `#ssh-ca-servers` | The identity running `ziti-ssh-ca` |
| `#ssh-clients` | User identities (dial `ssh-ca` to get certs, dial `ssh` to reach hosts) |
| `#ssh-hosts` | Host identities (each runs `ziti-ssh-host`, binds the `ssh` service) |

Two service roles carry all traffic:

| Service | Purpose |
|---|---|
| `ssh-ca` | Certificate signing — clients send a public key, receive a signed cert |
| `ssh` (or multiple) | SSH host proxy — clients reach hosts via addressable terminators |

In simple deployments a single `ssh` service is sufficient. Fleets using per-identity permissions typically use multiple SSH services (e.g., `ssh-ops`, `ssh-db`) to separate access tiers. The service boundary is also the permission scope boundary — each service carries its own `ziti-ssh-host.v1` config defining what each identity may do on hosts bound to that service. A single `ziti-ssh-host run` process can bind to multiple services simultaneously.

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

`ziti-ssh-ca` runs on the same machine as the Ziti controller. The deb package installs the binary, a config directory, and a systemd unit.

### 1. Install the package

Build or copy `dist/ziti-ssh-ca_<version>_amd64.deb` to the controller host, then install it:

```sh
dpkg -i ziti-ssh-ca_<version>_amd64.deb
```

The postinst script creates `/etc/ziti-ssh-ca/env` (mode 0640) with all variables commented out, and runs `systemctl daemon-reload`.

### 2. Locate the Ziti controller intermediate CA private key

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

> **Deployment note:** Because `ziti-ssh-ca` must read the controller's intermediate CA private key, it must run on the same host as the Ziti controller, under the same user account (or another account with read permission on the key file). The key file should remain mode 0600 and owned by the controller service user — do not change its permissions.

### 3. Enroll the CA server identity

Copy the JWT produced in the provisioning step above to the CA host, then enroll it:

```sh
ziti edge enroll \
  --jwt /tmp/ssh-ca-server.jwt \
  --out /etc/ziti-ssh-ca/identity.json
chmod 600 /etc/ziti-ssh-ca/identity.json
```

### 4. Edit the env file

Open `/etc/ziti-ssh-ca/env` and uncomment the variables that apply to your deployment:

```sh
# /etc/ziti-ssh-ca/env
ZITI_IDENTITY=/etc/ziti-ssh-ca/identity.json
ZITI_CA_KEY=/var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key
ZITI_CA_SERVICE=ssh-ca
ZITI_SSH_MODE=shared
ZITI_SSH_PRINCIPAL=ziggy
# ZITI_CERT_TTL=8h   # optional; 8h is the default
```

`ZITI_SSH_MODE` must match the value set on `ziti-ssh-host run`. See [Modes](operations.md#modes) for a full explanation.

### 5. Enable and start the service

```sh
systemctl enable --now ziti-ssh-ca
```

`ziti-ssh-ca` sends `READY=1` via `sd_notify` once the listener is bound and ready to accept connections. The installed unit uses `Type=notify` so systemd will not consider the service started until the notification is received.

<details>
<summary>Alternative: build from source and run manually</summary>

```sh
go build -o /usr/local/bin/ziti-ssh-ca ./cmd/ziti-ssh-ca
```

Run directly:

```sh
ziti-ssh-ca \
  --identity  /etc/ziti-ssh-ca/identity.json \
  --ca-key    /var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key \
  --service   ssh-ca \
  --mode      shared \
  --principal ziggy
```

All flags can be set via environment variables instead (useful for systemd units — see [configuration.md](configuration.md)).

Example systemd unit (`/etc/systemd/system/ziti-ssh-ca.service`):

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

</details>

---

## Setting up `ziti-ssh-host` on a target machine

Repeat these steps on every machine you want to make reachable over Ziti.

### 1. Create the shared Linux account (`shared` mode only)

> **Skip this step if using `per-identity` mode.** In `per-identity` mode, `ziti-ssh-host` creates and removes Linux accounts automatically on each connection. No manual account setup is needed.

In `shared` mode, all SSH sessions authenticate as a single Linux user. Create it if it does not already exist:

```sh
useradd --create-home --shell /bin/bash ziggy
```

Use any existing account — just set `--principal` on the CA to match.

### 2. Install the package

Build or copy `dist/ziti-ssh-host_<version>_amd64.deb` to the target host, then install it:

```sh
dpkg -i ziti-ssh-host_<version>_amd64.deb
```

The postinst script creates `/etc/ziti-ssh-host/env` (mode 0640) with all variables commented out, and runs `systemctl daemon-reload`.

### 3. Enroll a Ziti identity for the host

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

### 4. Edit the env file

Open `/etc/ziti-ssh-host/env` and uncomment the variables that apply to your deployment:

```sh
# /etc/ziti-ssh-host/env
ZITI_IDENTITY=/etc/ziti-ssh-host/identity.json
ZITI_SSH_SERVICE=ssh
ZITI_SSH_MODE=shared
# ZITI_SSH_GROUPS=adm,systemd-journal   # per-identity mode only; global fallback groups
# ZITI_SUDOERS_RULE=ALL=(ALL) NOPASSWD:ALL   # per-identity mode only; global fallback sudoers
# ZITI_USER_CLEANUP=true                      # per-identity mode only; set to false to keep accounts
```

`ZITI_SSH_MODE` must match the value set on `ziti-ssh-ca`. See [Modes](operations.md#modes) for a full explanation.

### 5. Enable and start the service

```sh
systemctl enable --now ziti-ssh-host
```

`ziti-ssh-host run` sends `READY=1` via `sd_notify` once the Ziti listener is bound. The installed unit uses `Type=notify` so systemd will not consider the service started until the notification is received.

<details>
<summary>Alternative: build from source and run manually</summary>

```sh
go build -o /usr/local/bin/ziti-ssh-host ./cmd/ziti-ssh-host
```

Run the host proxy directly:

```sh
ziti-ssh-host run
```

Example systemd unit (`/etc/systemd/system/ziti-ssh-host.service`):

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

</details>

---

## Configuring per-identity permissions (`ziti-ssh-host.v1`)

The `ziti-ssh-host.v1` Ziti config type lets you attach per-identity Linux permissions (groups and sudoers rules) to an SSH service. `ziti-ssh-host run` fetches this config automatically — no extra flags are required on the host. This feature is only used in `per-identity` mode.

For background on permission resolution and deployment patterns, see [Per-identity permissions](operations.md#per-identity-permissions-ziti-ssh-hostv1-config) in the operations guide.

### 1. Register the config type (one-time per network)

Register the `ziti-ssh-host.v1` config type in the Ziti controller. This step is performed once per Ziti network, not once per host. Run it on the controller host where `ziti-ssh-ca` is installed:

```sh
ziti-ssh-ca config apply \
  --controller ctrl.example.com \
  --username admin \
  --password <password>
```

This creates the config type if it does not exist, or updates it to the current schema if it does. To preview the schema that will be registered without connecting to the controller:

```sh
ziti-ssh-ca config print
```

> **TLS note:** If your controller uses a self-signed certificate, add `--insecure` to skip verification, or `--controller-ca /path/to/ca.pem` to trust a specific CA. All flags can also be set via environment variables (`ZITI_CTRL_ADDRESS`, `ZITI_CTRL_USERNAME`, `ZITI_CTRL_PASSWORD`, `ZITI_CTRL_INSECURE`, `ZITI_CTRL_CA`) — useful for scripted provisioning.

### 2. Create a config for a service

Create a config object of type `ziti-ssh-host.v1` and attach it to the target SSH service. Identity names in the config are the Ziti identity names exactly as they appear in the controller (case-sensitive).

```sh
# Create the config
ziti edge create config ssh-prod-permissions ziti-ssh-host.v1 \
  '{"permissions":{"alice@corp.com":{"groups":["developers"]},"ops-automation":{"sudoers_rule":"ALL=(ALL) NOPASSWD: ALL"}}}'

# Attach it to the service
ziti edge update service ssh-prod \
  --configs ssh-prod-permissions
```

### 3. Verify the hosting identity can receive the config

The `ziti-ssh-host` identity must have access to the `ziti-ssh-host.v1` config type via a config policy. In most Ziti deployments the default policy is permissive enough. Check if config policies are restricted in your network and grant access if needed.

### 4. Update a config

Edit the config object in the controller to add, change, or remove identity entries. Changes propagate to all running `ziti-ssh-host` instances bound to that service within seconds — no restart required.

```sh
ziti edge update config ssh-prod-permissions \
  '{"permissions":{"alice@corp.com":{"groups":["sudo","developers"]},"ops-automation":{"sudoers_rule":"ALL=(ALL) NOPASSWD: ALL"}}}'
```

Run `ziti-ssh-host inspect --service ssh-prod` on the host to confirm what the running daemon sees after the update. See [Inspecting per-identity permissions](operations.md#inspecting-per-identity-permissions) in the operations guide for details.

---

## Setting up a client identity

Each user needs a Ziti identity enrolled on their machine and the `ziti-ssh` (and optionally `ziti-scp`) client installed. The identity name becomes the SSH principal in `per-identity` mode and is recorded in the `KeyId` field of every certificate for audit purposes.

### 1. Install the client packages

Build or copy `dist/ziti-ssh_<version>_amd64.deb` (and `dist/ziti-scp_<version>_amd64.deb` if needed) to the user's machine, then install:

```sh
dpkg -i ziti-ssh_<version>_amd64.deb
# Optional file copy tool:
dpkg -i ziti-scp_<version>_amd64.deb
```

Both packages depend on `openssh-client`. No systemd unit is installed — `ziti-ssh` and `ziti-scp` are CLI tools.

### 2. Create the identity on the controller

```sh
ziti edge create identity alice \
  --role-attributes "ssh-clients" \
  --jwt-output-file /tmp/alice.jwt
```

### 3. Enroll on the user's machine

Copy the JWT to the user's machine, then enroll using `ziti-ssh enroll`:

```sh
ziti-ssh enroll --jwt /tmp/alice.jwt
# Identity written to ~/.config/ziti-ssh/alice.json
```

Or specify an explicit output path:

```sh
ziti-ssh enroll --jwt /tmp/alice.jwt --out ~/.config/ziti-ssh/alice.json
```

Once enrolled, the user can obtain an SSH certificate and connect to hosts using `ziti-ssh sign` and `ziti-ssh connect`. See [usage.md](usage.md) for the end-user guide.

<details>
<summary>Alternative: build from source</summary>

```sh
go build -o /usr/local/bin/ziti-ssh  ./cmd/ziti-ssh
go build -o /usr/local/bin/ziti-scp  ./cmd/ziti-scp
```

</details>
