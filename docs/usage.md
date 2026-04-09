# Usage

This guide covers day-to-day use of `ziti-ssh` and `ziti-scp` as an end user. It assumes a Ziti identity has already been enrolled on your machine — if not, see [provisioning.md](provisioning.md).

For a full flag and config reference see [configuration.md](configuration.md).

---

## Connecting to a host (`ziti-ssh connect`)

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

### Connecting

```sh
ziti-ssh ziggy@web-server-prod
```

Or use the explicit subcommand form:

```sh
ziti-ssh connect ziggy@web-server-prod
```

`web-server-prod` is the Ziti identity name of the target host. `ziti-ssh` resolves this as a Ziti service terminator address on the `ssh` service — no DNS, no IP address required.

If a certificate is missing or will expire within 5 minutes, `ziti-ssh connect` automatically obtains a fresh one from the CA before opening the session. On first use it auto-detects your SSH key in `~/.ssh/` (tries `id_ed25519`, `id_ecdsa`, `id_rsa` in that order). If no key exists it offers to run `ssh-keygen -t ed25519` for you.

If the SSH private key is passphrase-protected, `ziti-ssh connect` falls back to the SSH agent (`SSH_AUTH_SOCK`). It locates the matching key in the agent and, if a certificate is present on disk, wraps it as an `ssh.CertSigner` so the certificate is offered during authentication. The passphrase is never exposed to this process. If the key is passphrase-protected and `SSH_AUTH_SOCK` is not set (or the key has not been added with `ssh-add`), `ziti-ssh connect` exits with an actionable error.

### Non-interactive command execution

To run a single command on a remote host without opening an interactive shell, append the command after the target (use `--` to separate it from any `ziti-ssh` flags):

```sh
# Run a command non-interactively
ziti-ssh ziggy@web-server-prod "ls -al"
ziti-ssh ziggy@web-server-prod "ls -la /tmp"

# Explicit separator form
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

## Managing certificates manually (`ziti-ssh sign`)

`ziti-ssh connect` handles certificate renewal automatically. Use `ziti-ssh sign` directly if you want to obtain or inspect a certificate without connecting — for example to verify CA details or pre-warm a certificate before a session.

```sh
ziti-ssh sign --identity ~/.config/ziti-ssh/alice.json
```

The certificate is written to `~/.ssh/<key>-cert.pub` and its details are printed immediately:

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

The certificate expires after the TTL configured on the CA (default: 8 hours). `ziti-ssh connect` auto-renews when fewer than 5 minutes of validity remain.

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

If the certificate is missing or will expire within 5 minutes, `ziti-scp` automatically obtains a fresh certificate from the CA before connecting — the same auto-refresh behaviour as `ziti-ssh connect`.

### Enroll a Ziti identity

`ziti-scp` includes its own `enroll` subcommand for machines where only file copy is needed:

```sh
ziti-scp enroll --jwt alice.jwt
# Identity written to ~/.config/ziti-ssh/alice.json
```

---

## Listing accessible services

```sh
ziti-ssh list --identity ~/.config/ziti-ssh/alice.json
```

Prints all Ziti services accessible to this identity with their permission sets.

---

## Managing MFA

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

---

## Config file usage

Settings can be stored in `~/.config/ziti-ssh/config.yaml` (XDG_CONFIG_HOME is respected) to avoid repeating flags on every invocation:

```yaml
identity: ~/.config/ziti-ssh/alice.json
ca_service: ssh-ca
ssh_service: ssh
```

To enable OIDC authentication, add an `oidc` block (see [configuration.md — OIDC authentication](configuration.md#oidc-authentication)):

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
