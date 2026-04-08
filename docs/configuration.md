# Configuration reference

All binaries resolve each setting in the same order: CLI flag > environment variable > built-in default. `ziti-ssh` additionally reads `~/.config/ziti-ssh/config.yaml` between the environment variable and the built-in default.

---

## `ziti-ssh`

### Persistent flags (available to all subcommands)

| Flag | Env | Default | Description |
|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | — | Path to Ziti identity JSON file |
| `--config` | — | `~/.config/ziti-ssh/config.yaml` | Config file path |
| `--ziti-timeout` | `ZITI_TIMEOUT` | `30s` | Timeout for blocking Ziti network operations (authenticate, dial). Accepts any `time.Duration` string, e.g. `30s`, `1m`. |
| `--verbose` / `-v` | — | false | Enable Info-level logging (plumbing details, key paths, service names) |

### `ziti-ssh connect` / root

| Flag | Env | Default | Description |
|---|---|---|---|
| `--ca-service` | `ZITI_CA_SERVICE` | `ssh-ca` | CA service name |
| `--ssh-service` | `ZITI_SSH_SERVICE` | `ssh` | SSH service name |
| `--service` | — | — | SSH service name to dial (alias for `--ssh-service`) |
| `--key` | — | auto-detect | SSH private key path |
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

---

## `ziti-ssh-ca`

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
| `--ziti-timeout` | `ZITI_TIMEOUT` | `30s` | No | Timeout for blocking Ziti network operations (authenticate, listen). Accepts any `time.Duration` string, e.g. `30s`, `1m`. |

---

## `ziti-ssh-host`

These flags are persistent (accepted by both `enroll` and `run`):

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | `/etc/ziti-ssh-host/identity.json` | Path to Ziti identity JSON file |
| `--ssh-service` | `ZITI_SSH_SERVICE` | `ssh` | Ziti service name(s) to proxy (used during `run`). The flag may be repeated for multiple services; the env var accepts a comma-separated list. |
| `--ziti-timeout` | `ZITI_TIMEOUT` | `30s` | Timeout for blocking Ziti network operations (authenticate, listen). Accepts any `time.Duration` string, e.g. `30s`, `1m`. |

The `run` subcommand also accepts:

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--mode` | `ZITI_SSH_MODE` | `shared` | Principal mode: `shared` or `per-identity` |
| — | `ZITI_SSH_GROUPS` | — | Comma-separated Linux groups applied (via `usermod -aG`) to users not matched by a `ziti-ssh-host.v1` config entry. Global fallback; per-identity mode only. Groups must already exist on the host. |
| — | `ZITI_SUDOERS_RULE` | — | If set, a sudoers rule `<username> <value>` is written to `/etc/sudoers.d/<username>` on first connect. Global fallback applied to users not matched by a `ziti-ssh-host.v1` config entry; per-identity mode only. |
| — | `ZITI_USER_CLEANUP` | `true` | Set to `false` to keep the Linux account after the last session closes rather than running `userdel -r` (per-identity mode only) |

`enroll` also requires `--jwt <path>` (no environment variable equivalent).

### `ziti-ssh-host inspect`

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--service` | — | — | Ziti service name to inspect. Required; may be repeated to inspect multiple services. |

Uses the same `--identity` flag (and `ZITI_IDENTITY` env var) as the other subcommands. See [Inspecting per-identity permissions](operations.md#inspecting-per-identity-permissions) in the operations guide for details and example output.

---

## `ziti-scp`

### Persistent flags (available to all subcommands)

| Flag | Env | Default | Description |
|---|---|---|---|
| `--identity` | `ZITI_IDENTITY` | — | Path to Ziti identity JSON file |
| `--config` | — | `~/.config/ziti-ssh/config.yaml` | Config file path |
| `--ziti-timeout` | `ZITI_TIMEOUT` | `30s` | Timeout for blocking Ziti network operations (authenticate, dial). Accepts any `time.Duration` string, e.g. `30s`, `1m`. |

### Copy flags (root command)

| Flag | Env | Default | Description |
|---|---|---|---|
| `--ca-service` | `ZITI_CA_SERVICE` | `ssh-ca` | CA service name |
| `--ssh-service` | `ZITI_SSH_SERVICE` | `ssh` | SSH service name |
| `--key` | — | auto-detect | SSH private key path |
| `-r` / `--recursive` | — | false | Recursively copy entire directories |
| `-p` / `--preserve` | — | false | Preserve file timestamps and permissions |
| `-q` / `--quiet` | — | false | Suppress per-file progress output |

### `ziti-scp enroll`

| Flag | Env | Default | Description |
|---|---|---|---|
| `--jwt` | — | — | Enrollment JWT file path (required) |
| `--out` | — | `~/.config/ziti-ssh/<name>.json` | Output path for identity JSON |

---

## `ziti-ssh-host.v1` config type

The `ziti-ssh-host.v1` Ziti service config type attaches per-identity Linux permissions to an SSH service. `ziti-ssh-host run` fetches it automatically via the Ziti SDK at startup — no extra flags are required. The config is declared as a requested config type when the Ziti context authenticates.

This config is only consulted in `per-identity` mode. It has no effect in `shared` mode.

### Schema

```json
{
  "permissions": {
    "<ziti-identity-name>": {
      "groups":       ["<linux-group>", ...],
      "sudoers_rule": "<sudoers rule fragment>"
    }
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `permissions` | object | yes | Map of Ziti identity name → permission entry. Keys are exact Ziti identity names (case-sensitive). |
| `permissions.<name>.groups` | array of strings | no | Linux groups to add the ephemeral user to via `usermod -aG` after account creation. Groups must already exist on the host. |
| `permissions.<name>.sudoers_rule` | string | no | The rule fragment placed after the username in `/etc/sudoers.d/<username>`. Validated with `visudo -c` before installation. Omit to grant no sudo access. |

### Example

```json
{
  "permissions": {
    "alice@corp.com": {
      "groups":       ["docker", "adm"],
      "sudoers_rule": "ALL=(ALL) NOPASSWD: /bin/systemctl status *"
    },
    "bob@corp.com": {
      "groups":       ["developers"]
    },
    "ops-automation": {
      "sudoers_rule": "ALL=(ALL) NOPASSWD: ALL"
    }
  }
}
```

Identity keys are the **Ziti identity names** as they appear in the controller — not the derived Linux usernames. `ziti-ssh-host` applies `DeriveUsername` internally to obtain the Linux username for `useradd`, `usermod`, and the sudoers filename.

### Interaction with global fallbacks

The resolution order for each connecting identity is:

1. Config attached and identity has an entry → apply that entry's `groups` and `sudoers_rule`. `ZITI_SSH_GROUPS` and `ZITI_SUDOERS_RULE` are ignored for this identity.
2. Config attached but identity not in it → apply global fallbacks (`ZITI_SSH_GROUPS`, `ZITI_SUDOERS_RULE`).
3. No config attached → apply global fallbacks to all users.

A config entry that omits a field means that field gets nothing — globals are not merged in for matched identities.

See [Per-identity permissions](operations.md#per-identity-permissions-ziti-ssh-hostv1-config) in the operations guide for the full lifecycle description, multi-service binding, and deployment patterns.

---

## Config file format

`ziti-ssh` and `ziti-scp` read `~/.config/ziti-ssh/config.yaml` (the directory respects `XDG_CONFIG_HOME`). All fields are optional — omit any that you prefer to pass via flag or environment variable.

```yaml
identity: ~/.config/ziti-ssh/alice.json
ca_service: ssh-ca
ssh_service: ssh
ssh_key_path: ~/.ssh/id_ed25519
```

| Field | Flag equivalent | Description |
|---|---|---|
| `identity` | `--identity` | Path to Ziti identity JSON file |
| `ca_service` | `--ca-service` | CA service name |
| `ssh_service` | `--ssh-service` | SSH service name |
| `ssh_key_path` | `--key` | SSH private key path |
| `oidc.*` | `--oidc-issuer` | OIDC configuration block (see below) |

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
