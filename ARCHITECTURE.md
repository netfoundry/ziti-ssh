# ziti-ssh — Architecture

This document is a technical reference for contributors and operators who need to understand how the system works below the surface. For installation and day-to-day operation see [README.md](README.md).

---

## 1. System Overview

Three participants interact at runtime:

- **`ziti-ssh-ca`** — the CA service. Runs on a machine with access to the CA private key. Binds to a named Ziti service (default: `ssh-ca`) and signs short-lived SSH certificates for callers it can identify.
- **`ziti-ssh-host`** — the host daemon. Runs on each SSH target machine. Enrolls the host as a Ziti identity, configures `sshd` to trust the CA, and proxies inbound Ziti connections to the local sshd.
- **`ziti-ssh`** — the client binary (in this repo). Handles Ziti identity enrollment, certificate signing, interactive SSH sessions, service listing, and MFA TOTP management on the user side. Picks up SSH certificates transparently via the `~/.ssh/<key>-cert.pub` naming convention.

```
User Machine                       Ziti Network             SSH Host
     |                                  |                       |
     |  ziti-ssh sign                   |                       |
     |  1. dial ssh-ca ─────────────────┤  ziti-ssh-ca          |
     |  2. send public key              |  - extracts caller    |
     |                                  |    Ziti identity      |
     |                                  |  - signs SSH cert     |
     |  3. receive signed cert ─────────┤                       |
     |                                  |                       |
     |  ziti-ssh [user@]<identity-name> |                       |
     |  4. dial ssh service ────────────┤  ziti-ssh-host run    |
     |     (terminator=identity-name)   |  - listens on Ziti    |
     |                                  |  - proxies to :22     |
     |  5. SSH handshake + cert ────────┼──────────────────────>|
     |                                  |      sshd (standard)  |
     |                                  |      verifies cert    |
     |  shell session <─────────────────┼───────────────────────|
     |                                  |      against CA pubkey|
```

---

## 2. Binary Interaction and Responsibilities

### `ziti-ssh-ca`

Entry point: `cmd/ziti-ssh-ca/main.go`

Startup sequence:

1. Resolve configuration (flags > env vars > defaults) via `config.EnvOrFlag`.
2. Load the Ed25519 CA private key from disk with `ca.LoadKey` — fail fast if the file is missing or unparseable.
3. Initialize a Ziti context from the identity file with `ziti.NewContextFromFile`, then call `zitiCtx.Authenticate()`.
4. Call `zitiCtx.Listen(serviceName)` to bind the named Ziti service and receive an `edge.Listener`.
5. Loop: `listener.Accept()` → `go handleConn(...)`.

Each connection handler (`handleConn`):

1. Type-asserts the `net.Conn` to `edge.Conn` to call `GetDialerIdentityName()` — the Ziti-verified identity name of the caller.
2. Reads one newline-terminated line from the connection.
3. Resolves the effective principal from the configured mode (see [Mode: shared vs per-identity](#mode-shared-vs-per-identity)).
4. Dispatches on line content: empty → write CA public key; non-empty → parse as SSH public key, sign, write certificate.
5. Logs every outcome with the identity name as a structured field.

The CA signer (`ssh.Signer`) is initialized once and passed to every handler. `ssh.Signer` wraps a Go `crypto.Signer` — the standard library's Ed25519 implementation is safe for concurrent use, so no mutex is required.

### `ziti-ssh-host`

Entry point: `cmd/ziti-ssh-host/main.go`

Two subcommands share persistent flags (`--identity`, `--ca-service`, `--ssh-service`).

**`enroll --jwt <path>`** (run once per host, as root):

1. Read and parse the enrollment JWT with `enroll.ParseToken`.
2. Call `enroll.Enroll(flags)` to perform the Ziti enrollment ceremony against the controller. The returned `*ziti.Config` contains the full certificate chain in `cfg.ID.CA` (PEM-encoded, `"pem:"` prefix) and the host's identity cert in `cfg.ID.Cert`.
3. Marshal the resulting config to JSON and write it to `/etc/ziti-ssh-host/identity.json` (mode 0600, parent dir mode 0700).
4. Call `intermediateCAPublicKey(cfg)` to extract the intermediate CA public key from the enrollment response (see below). No network call to `ssh-ca` is required.
5. Call `host.WriteSSHConfig` to write `/etc/ssh/ziti_ca.pub` and `/etc/ssh/sshd_config.d/ziti-ssh.conf`.
6. Call `host.ReloadSSHD` (`systemctl reload ssh`) to make sshd pick up the new config.

**Intermediate CA extraction:**

The Ziti controller uses a two-tier PKI:

```
Root CA (offline)
  └── Controller Intermediate CA  ← signs Ziti identity certs
        └── Ziti Identity Cert    ← issued to this host
```

After enrollment, `cfg.ID.CA` contains the PEM chain (root CA + intermediate CA) returned by the controller. `intermediateCAPublicKey` parses the identity cert's `Issuer` field, finds the cert in the chain whose `Subject` matches, and converts its public key to authorized_keys format via `ssh.NewPublicKey`. This is the intermediate CA public key written to `TrustedUserCAKeys` — it is the same key `ziti-ssh-ca` holds as its signer, so sshd will accept certificates signed by the CA service.

**`run`** (long-running daemon, managed by systemd):

1. Initialize Ziti context and authenticate.
2. Call `zitiCtx.ListenWithOptions(sshService, &ziti.ListenOptions{BindUsingEdgeIdentity: true})` — this registers a terminator on the `ssh` service whose address is the host's own Ziti identity name.
3. If `mode == "per-identity"`:
   a. Create a `host.UserManager` backed by `/var/lib/ziti-ssh-host/managed-users`.
   b. Call `manager.CleanupOrphans()` to remove any users left over from a previous crash.
   c. Build a `host.ProxyHooks` struct: `OnConnect` calls `ca.DeriveUsername` then `manager.EnsureUser`; `OnDisconnect` calls `manager.ReleaseUser`.
4. Call `host.Proxy(listener, "127.0.0.1:22", hooks)` which blocks, serving each accepted connection in a goroutine. `hooks` is nil in shared mode.

### `ziti-ssh`

Entry point: `cmd/ziti-ssh/main.go`

The client binary. It provides five subcommands (and a root shorthand for `connect`):

**`connect [user@]<target>`** (also the root default when a target argument is given):

1. Resolve the SSH private key (auto-detect from `~/.ssh/` or use `--key`).
2. Call `client.CertNeedsRefresh(certPath)` — if the cert is missing or will expire within 30 minutes, run the sign flow automatically before opening the session.
3. Call `client.NewCertSigner(privKeyPath)` to load the private key and, if a `<key>-cert.pub` file is present, wrap it in an `ssh.CertSigner`. If the key is passphrase-protected, fall back to the SSH agent (`SSH_AUTH_SOCK`).
4. Authenticate to Ziti and dial the `ssh` service, specifying the target identity name as the terminator address via `ziti.DialOptions{Identity: terminatorAddr}`. If the target matches a known Ziti service name directly, it is dialled without a terminator.
5. Call `client.RunSession(conn, username, host, signer)` to run an interactive PTY session over the Ziti connection.

**`sign`**: dials the `ssh-ca` Ziti service, sends the user's SSH public key, receives the signed certificate, writes it to `~/.ssh/<key>-cert.pub`, and displays certificate details via `ssh-keygen -L`.

**`enroll --jwt <path>`**: calls `enroll.Enroll` and writes the resulting identity JSON to `~/.config/ziti-ssh/<name>.json` (or an explicit `--out` path).

**`list`**: calls `zitiCtx.GetServices()` and prints all accessible services with their permission sets.

**`mfa enable|verify|remove`**: manages TOTP MFA on the Ziti identity using `zitiCtx.EnrollZitiMfa`, `zitiCtx.VerifyZitiMfa`, and `zitiCtx.RemoveZitiMfa`.

Config file `~/.config/ziti-ssh/config.yaml` (XDG_CONFIG_HOME respected) is loaded during `PersistentPreRunE` and provides defaults for all subcommands. Precedence: CLI flag > environment variable > config file > built-in default.

---

## 3. Mode: shared vs per-identity

The `ziti-ssh-ca` and `ziti-ssh-host` binaries accept `--mode` (env: `ZITI_SSH_MODE`, default: `shared`). The operator must set the same value on both. The CA is the authoritative source for the principal in the issued certificate; `ziti-ssh-host` only needs to know the mode to manage Linux user accounts.

### `shared`

The CA places the operator-configured `--principal` (default: `ziggy`) in `ValidPrincipals` for every certificate, regardless of caller identity. User management on the host is the operator's responsibility — a single shared account must exist before the daemon starts.

### `per-identity`

The CA calls `ca.DeriveUsername(callerIdentity)` to produce a Linux-safe username and places it in `ValidPrincipals`. `ziti-ssh-host run` uses `host.UserManager` to create and destroy Linux accounts on demand.

**`ca.DeriveUsername` rules:**
1. Lowercase the entire identity name.
2. Replace any character outside `[a-z0-9_-]` with `_`.
3. If the result starts with a digit, prefix it with `z`.
4. Truncate to 32 characters.

**`host.NewUserManager(stateFile, sudoersRule, cleanupOnDisconnect)`** returns a concurrent-safe reference counter. It is constructed in `runProxy` with:

- `stateFile` = `/var/lib/ziti-ssh-host/managed-users`
- `sudoersRule` = `os.Getenv("ZITI_SUDOERS_RULE")` (empty string disables sudoers file creation)
- `cleanupOnDisconnect` = `os.Getenv("ZITI_USER_CLEANUP") != "false"` (defaults to true)

**`host.UserManager`** tracks how many sessions are open for each derived username:

- `EnsureUser(username)` — increments the session count. If the count was 0, runs `useradd -m -s /bin/bash <username>`. Exit code 9 from `useradd` (user already exists, e.g. from a racing concurrent connection) is treated as success. If `sudoersRule` is non-empty, a sudoers file is written to `/etc/sudoers.d/<username>` with content `<username> <sudoersRule>`, validated by `visudo -c` before installation. The username is appended to the state file `/var/lib/ziti-ssh-host/managed-users`.
- `ReleaseUser(username)` — decrements the session count. If the count reaches 0 and `cleanupOnDisconnect` is true, calls `deleteUser(username)` and removes the username from the state file. If `cleanupOnDisconnect` is false, the account is kept but the sudoers file is still removed.
- `CleanupOrphans()` — reads the state file and calls `deleteUser` on each entry. Called once at startup before accepting connections. If the process was killed while sessions were open, orphaned accounts are cleaned up on the next start.

**`host.deleteUser(username)`** — the internal cleanup sequence:

1. Remove `/etc/sudoers.d/<username>` if present.
2. Run `loginctl terminate-user <username>` to drain the systemd user session (errors are logged but ignored — the session may already be gone).
3. Poll with `pgrep -u <username>` until no processes remain or a 5-second timeout elapses.
4. Run `userdel -r <username>` to remove the account and home directory.

**`host.ProxyHooks`** wires `UserManager` into the proxy loop:

```go
type ProxyHooks struct {
    OnConnect    func(username string) error
    OnDisconnect func(username string)
}
```

`proxyConn` extracts the caller's Ziti identity name via the `dialerNamer` interface (same pattern as `ziti-ssh-ca`), then calls `OnConnect` before proxying and `OnDisconnect` in a deferred call after the connection closes. If `OnConnect` returns an error, the connection is closed without proxying.

---

## 5. Wire Protocol

The protocol between a client and `ziti-ssh-ca` runs over a raw Ziti connection (no HTTP, no TLS beyond what Ziti provides, no custom framing).

```
Client                         ziti-ssh-ca
  |                                 |
  |── "\n"  ──────────────────────> |   (request CA public key)
  |<─ "<type> <base64> <comment>\n" |   (authorized_keys format)
  |                                 |
  |── "<type> <base64> <comment>\n" |   (send own public key for signing)
  |<─ "<type> <base64> <comment>\n" |   (signed cert, authorized_keys format)
```

**Request encoding:** A single line terminated by `\n`.
- Empty line (just `\n`): requests the CA public key.
- Non-empty line: treated as an SSH public key in authorized_keys format (`ssh-ed25519 AAAA...`).

**Response encoding:** A single line in authorized_keys format, terminated by `\n`.
- CA public key response: `ssh-ed25519 AAAA... <comment>\n`
- Signed certificate response: `ssh-ed25519-cert-v01@openssh.com AAAA...\n`

Both are produced by `ssh.MarshalAuthorizedKey` from `golang.org/x/crypto/ssh`.

The connection is closed by the server after each response. There is no persistent session or multiplexing.

---

## 6. Ziti Identity Flow

The Ziti network provides mutual TLS for all connections. Every Ziti identity has a certificate issued by the Ziti controller. When a client dials a service, the edge router verifies the client's certificate and forwards the verified identity name to the listener side.

### Extraction

In `cmd/ziti-ssh-ca/main.go`, `callerIdentity` performs the extraction:

```go
func callerIdentity(conn net.Conn) string {
    if ec, ok := conn.(zitiEdge.Conn); ok {
        return ec.GetDialerIdentityName()
    }
    // Fallback narrow interface for flexibility
    type dialerNamer interface {
        GetDialerIdentityName() string
    }
    if dn, ok := conn.(dialerNamer); ok {
        return dn.GetDialerIdentityName()
    }
    return ""
}
```

`zitiEdge.Conn` is from `github.com/openziti/sdk-golang/ziti/edge`. The `edge.Listener.Accept()` returns values that implement this interface. If the assertion fails (e.g. in unit tests using a plain `net.Conn`), the function returns `""` and the connection is rejected.

### Identity as SSH Certificate Key ID

The extracted identity name is embedded in the `KeyId` field of every certificate issued to that identity:

```
KeyId = "ziti:" + identityName
```

`sshd` logs the Key ID on every successful authentication to `/var/log/auth.log`. This provides a per-identity audit trail on every SSH host without any server-side storage — the identity is bound to the ephemeral certificate, not to a persistent account record.

### Identity as Terminator Address

On the host side, `ziti-ssh-host run` uses `BindUsingEdgeIdentity: true`. This causes the Ziti SDK to register the terminator with the identity name as its address. When `ziti-ssh connect` dials the `ssh` service and specifies a target identity name (e.g. `web-server-prod`), the Ziti fabric routes the connection to the terminator registered by the host with that identity — no DNS, no IP addresses, no SSH config files required.

---

## 7. Addressable Terminators for Host Routing

The `ssh` Ziti service has multiple terminators — one per enrolled host. Each `ziti-ssh-host run` instance adds a terminator with its identity name as the address:

```
ssh service
  terminators:
    address=web-server-prod  → ziti-ssh-host on web-server-prod → 127.0.0.1:22
    address=db-primary       → ziti-ssh-host on db-primary      → 127.0.0.1:22
    address=build-agent-01   → ziti-ssh-host on build-agent-01  → 127.0.0.1:22
```

A client dials: `service=ssh, terminator=web-server-prod`. The Ziti fabric selects the matching terminator. There is no load-balancing across terminators with different addresses — each address is unique to one host. Load-balancing across multiple hosts with the same identity name is theoretically possible but not a current use case.

This design means:
- No SSH jump hosts or bastion servers.
- No DNS entries needed for SSH targets.
- No firewall rules or VPN routes needed.
- Host identity (the Ziti cert) proves which machine you are connecting to.

---

## 8. sshd Trust Model

The only change to `sshd` on each target host is the addition of one configuration directive:

```
TrustedUserCAKeys /etc/ssh/ziti_ca.pub
```

Written to `/etc/ssh/sshd_config.d/ziti-ssh.conf` (the drop-in directory, available in OpenSSH 8.2+ and standard on Ubuntu 22.04+). The CA public key itself is written to `/etc/ssh/ziti_ca.pub`.

The key written to `ziti_ca.pub` is the **controller's intermediate CA public key** — the public counterpart of the intermediate CA private key passed to `ziti-ssh-ca --ca-key`. This is the key `ziti-ssh-ca` uses to sign SSH certificates, so sshd correctly validates those certificates. The root CA public key is not written here (it would not match the signing key).

**What this achieves:**

- `sshd` accepts any valid SSH user certificate signed by the CA, where the certificate's `ValidPrincipals` list contains a local Linux username.
- No `authorized_keys` files on any host.
- No SSSD, NSS, PAM, or LDAP integration.
- No network calls at authentication time — verification is local and offline using the public key.
- The CA public key is not a credential. It cannot authenticate to anything. Compromising a host does not yield anything useful for attacking the CA or other hosts.

**What sshd does not know:**

- Which Ziti identity the user holds.
- Whether the user's Ziti identity is still valid.

Both of these are enforced by the Ziti network before the connection ever reaches `sshd`. The certificate TTL (default 8 hours, configurable via `--cert-ttl` / `ZITI_CERT_TTL` on `ziti-ssh-ca`) provides a backstop: a revoked or expired Ziti identity loses access once any outstanding certificate expires, without any changes on SSH hosts.

---

## 9. Certificate Lifecycle

Certificates are issued on demand and are ephemeral. There is no certificate store or revocation list.

### Fields

| Field | Value | Source |
|---|---|---|
| `CertType` | `ssh.UserCert` (1) | Hardcoded |
| `Key` | Client's submitted public key | Wire protocol request |
| `KeyId` | `ziti:<identity-name>` | Extracted from Ziti connection |
| `ValidPrincipals` | `[]string{principal}` | shared mode: `--principal` flag (default: `ziggy`); per-identity mode: `ca.DeriveUsername(callerIdentity)` |
| `ValidAfter` | `time.Now().Unix()` | Signing time |
| `ValidBefore` | `time.Now().Add(ttl).Unix()` | Signing time + TTL (default 8h, configurable via `--cert-ttl` / `ZITI_CERT_TTL`) |
| `Extensions["permit-pty"]` | `""` | Hardcoded |
| `Extensions["permit-port-forwarding"]` | `""` | Hardcoded |
| `Extensions["permit-agent-forwarding"]` | `""` | Hardcoded |

### TTL and Revocation

The TTL defaults to 8 hours and is configurable via `--cert-ttl` (flag) or `ZITI_CERT_TTL` (environment variable) on `ziti-ssh-ca`. Any positive `time.Duration` string is accepted (e.g. `4h`, `12h`, `24h`). There is no revocation mechanism. Access control is handled upstream:

- **While TTL is active:** A user whose Ziti identity is revoked at the controller can no longer dial the `ssh` service — they cannot open new SSH sessions. Any existing SSH session (TCP connection already established) continues until it closes naturally.
- **After TTL expires:** The certificate is no longer accepted by `sshd`. The user must obtain a new certificate, which requires a live Ziti identity.

For most operational scenarios this is sufficient. If immediate hard revocation of active sessions is required, the Ziti edge router's connection termination features can be used independently of this system.

### Signing Implementation

```go
// ttl is time.Duration resolved from --cert-ttl / ZITI_CERT_TTL (default 8h).
cert := &ssh.Certificate{
    CertType:        ssh.UserCert,
    Key:             pubKey,
    KeyId:           "ziti:" + identity,
    ValidPrincipals: []string{principal},
    ValidAfter:      uint64(now.Unix()),
    ValidBefore:     uint64(now.Add(ttl).Unix()),
    Permissions: ssh.Permissions{
        Extensions: map[string]string{
            "permit-pty":              "",
            "permit-port-forwarding":  "",
            "permit-agent-forwarding": "",
        },
    },
}
cert.SignCert(rand.Reader, signer)
```

`ssh.Certificate.SignCert` serializes the certificate in OpenSSH wire format, signs the serialized bytes with the CA key using Ed25519, and attaches the signature. The result is marshaled to authorized_keys format by `ssh.MarshalAuthorizedKey`.

---

## 10. Package Dependency Graph

```
cmd/ziti-ssh-ca/main.go
    ├── ca/           (LoadKey, SignCert, PublicKeyBytes, DeriveUsername)
    ├── config/       (EnvOrFlag)
    ├── github.com/openziti/sdk-golang/ziti       (NewContextFromFile, Listen)
    ├── github.com/openziti/sdk-golang/ziti/edge  (Conn, GetDialerIdentityName)
    ├── github.com/spf13/cobra
    └── golang.org/x/crypto/ssh

cmd/ziti-ssh-host/main.go
    ├── ca/           (DeriveUsername — per-identity mode only)
    ├── host/         (Proxy, ProxyHooks, WriteSSHConfig, ReloadSSHD, NewUserManager)
    ├── config/       (EnvOrFlag)
    ├── github.com/openziti/sdk-golang/ziti        (NewContextFromFile, ListenWithOptions, Config)
    ├── github.com/openziti/sdk-golang/ziti/edge   (Conn — compile-time interface check)
    ├── github.com/openziti/sdk-golang/ziti/enroll (ParseToken, Enroll)
    ├── github.com/spf13/cobra
    ├── golang.org/x/crypto/ssh                    (NewPublicKey, MarshalAuthorizedKey)
    └── stdlib: crypto/x509, encoding/pem

cmd/ziti-ssh/main.go
    ├── client/       (NewCertSigner, CertNeedsRefresh, RunSession)
    ├── config/       (EnvOrFlag)
    ├── github.com/openziti/sdk-golang/ziti        (NewContextFromFile, Dial, DialWithOptions)
    ├── github.com/openziti/sdk-golang/ziti/enroll (ParseToken, Enroll)
    ├── github.com/openziti/edge-api/rest_model    (AuthQueryDetail)
    ├── github.com/spf13/cobra
    ├── go.yaml.in/yaml/v3
    └── golang.org/x/crypto/ssh

ca/ca.go
    └── golang.org/x/crypto/ssh

client/ssh.go
    ├── golang.org/x/crypto/ssh
    ├── golang.org/x/crypto/ssh/agent
    └── golang.org/x/term

host/host.go
    └── (stdlib only: bufio, net, os, os/exec, log/slog, sync, strings, time)

config/config.go
    └── (stdlib only: os)
```

`ca`, `client`, and `host` have no dependency on each other or on the Ziti SDK. They are pure-logic packages testable without any Ziti infrastructure. `cmd/ziti-ssh-host` imports `ca` for `DeriveUsername` in per-identity mode — this is a binary-level dependency, not a package-level one.

---

## 11. Key SDK Calls

### Ziti context initialization

```go
zitiCtx, err := ziti.NewContextFromFile(identityFile)
// identityFile: path to enrolled identity JSON (produced by enroll.Enroll)
zitiCtx.Authenticate()
defer zitiCtx.Close()
```

### Binding a service (CA side)

```go
listener, err := zitiCtx.Listen(serviceName)
// Returns edge.Listener which implements net.Listener
conn, err := listener.Accept()
// conn implements net.Conn and edge.Conn
```

### Binding with identity as terminator address (host side)

```go
listenOpts := &ziti.ListenOptions{BindUsingEdgeIdentity: true}
listener, err := zitiCtx.ListenWithOptions(sshService, listenOpts)
// Terminator address = this host's Ziti identity name
```

### Dialing a service

```go
conn, err := zitiCtx.Dial(caService)
// Returns net.Conn over the Ziti overlay
```

### Identity extraction from an accepted connection

```go
import zitiEdge "github.com/openziti/sdk-golang/ziti/edge"

if ec, ok := conn.(zitiEdge.Conn); ok {
    identityName := ec.GetDialerIdentityName()
}
```

### Enrollment

```go
import "github.com/openziti/sdk-golang/ziti/enroll"

token, jwtToken, err := enroll.ParseToken(jwtString)
flags := enroll.EnrollmentFlags{Token: token, JwtToken: jwtToken, JwtString: jwtString}
cfg, err := enroll.Enroll(flags)
cfgJSON, _ := json.Marshal(cfg)
os.WriteFile(identityFile, cfgJSON, 0600)
```

---

## 12. Security Considerations

**CA private key source:** The CA private key used by `ziti-ssh-ca` is the **Ziti controller's intermediate CA private key** — the key that signs Ziti identity certificates. The Ziti PKI has two tiers: a root CA (kept offline) and an intermediate CA (the operational signing key). `ziti-ssh-ca` uses the intermediate CA key, not the root. The path is typically `/var/lib/ziti-controller/pki/intermediate-ca/keys/intermediate-ca.key`, but depends on the controller installation.

This is possible because `ziti-ssh-ca` runs on the same host as the Ziti controller, under the same OS user (e.g. `ziti`). Shared filesystem access eliminates credential distribution: there is no need to copy or transfer the key. The key file remains mode 0600 and owned by the controller service user — `ziti-ssh-ca` reads it at startup only.

**CA private key exposure:** The CA private key is loaded once at startup and held in memory as an `ssh.Signer`. It is never written to a log or returned over the wire. The key file must be owned by the service user with mode 0600.

**Identity validation:** `callerIdentity` returns `""` for any connection where the Ziti identity cannot be asserted. `handleConn` rejects such connections immediately before reading any data from them.

**Principal derivation:** In `shared` mode, `ValidPrincipals` is set from the operator-configured `--principal` flag — a client cannot influence which Linux user they get. In `per-identity` mode, the principal is derived deterministically from the Ziti-verified identity name via `ca.DeriveUsername`. The identity name is attested by the Ziti network's mutual TLS and cannot be spoofed by the client. The derivation function (lowercase, replace non-`[a-z0-9_-]` with `_`, prefix `z` if digit-leading, truncate to 32) is purely defensive — it sanitizes the identity name for use as a POSIX username and is not a security boundary.

**Ziti as the authorization boundary:** Any identity that can dial `ssh-ca` receives a certificate. Any identity that can dial `ssh` with a given terminator address reaches that host. Access control is managed entirely in Ziti service policies (dial policies, service policies). This is intentional — the CA is a dumb signing service; the access control lives in Ziti.

**No credentials on hosts:** The only file written to each SSH host is the CA public key (`/etc/ssh/ziti_ca.pub`). This is not a credential. An attacker who reads it gains nothing — it is the CA's public key and is not secret.
