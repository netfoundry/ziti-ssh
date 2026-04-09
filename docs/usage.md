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

## Port forwarding

`ziti-ssh connect` supports the same `-L`, `-R`, and `-D` forwarding flags as `ssh(1)`. All forwards run over the Ziti overlay — no port 22 exposure required.

### Local port forward (`-L`)

Listens on a local port and forwards each connection to a remote host:port through the SSH tunnel.

```sh
# Forward localhost:8080 → db.internal:5432 on the remote network
ziti-ssh connect ziggy@web-server-prod -L 8080:db.internal:5432

# Bind on all interfaces (e.g. for container-to-host forwarding)
ziti-ssh connect ziggy@web-server-prod -L 0.0.0.0:8080:db.internal:5432
```

Syntax: `-L [bind:]localport:remotehost:remoteport`

The remote hostname is resolved by sshd on the target host, so it can be a name on the remote's internal network (not reachable from your machine).

### Remote port forward (`-R`)

Asks sshd on the remote host to listen on a port and forward each incoming connection back to a local host:port on your machine.

```sh
# Remote host:9000 → localhost:3000 on your machine
ziti-ssh connect ziggy@web-server-prod -R 9000:localhost:3000
```

Syntax: `-R [bind:]remoteport:localhost:localport`

### Dynamic SOCKS5 proxy (`-D`)

Listens locally as a SOCKS5 proxy. Each connection's destination is determined by the SOCKS5 client — useful for routing browser traffic or tools through the remote network.

```sh
# SOCKS5 proxy on localhost:1080
ziti-ssh connect ziggy@web-server-prod -D 1080

# Configure your browser to use SOCKS5 proxy at localhost:1080
```

Syntax: `-D [bind:]port`

### Forwarding without a shell (`-N`)

Use `-N` to forward ports without opening an interactive shell. The process blocks until you press Ctrl-C.

```sh
# Only forward, no shell
ziti-ssh connect -N ziggy@web-server-prod -L 8080:db.internal:5432 -D 1080

# Multiple forwards
ziti-ssh connect -N ziggy@web-server-prod \
    -L 5432:db.internal:5432 \
    -L 6379:redis.internal:6379 \
    -D 1080
```

### Combining forwards with a shell session

All forwarding flags can be used alongside an interactive session. The forwards run in the background; closing the shell also terminates them.

```sh
ziti-ssh connect ziggy@web-server-prod -L 8080:db.internal:5432
# Opens a shell AND forwards port 8080 simultaneously
```

---

## SSH agent forwarding (`-A`)

The `-A` / `--forward-agent` flag forwards your local SSH agent to the remote session. This lets processes running on the remote host use keys held by your local agent — for example, to make onward SSH hops to other machines without copying private keys to the remote host.

```sh
ziti-ssh connect -A ziggy@web-server-prod
```

Agent forwarding requires `SSH_AUTH_SOCK` to be set in your environment (i.e. a running SSH agent). If it is not set, or the agent cannot be reached, `ziti-ssh` logs a warning and opens the session normally without forwarding — the connection is not aborted.

```sh
# Start an agent and add your key if not already running
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Now connect with agent forwarding
ziti-ssh connect -A ziggy@web-server-prod

# On the remote host you can SSH onward using your local agent keys:
# ssh another-internal-host
```

Agent forwarding can be combined with port forwarding flags:

```sh
ziti-ssh connect -A -L 5432:db.internal:5432 ziggy@web-server-prod
```

The SSH certificates issued by `ziti-ssh-ca` already include the `permit-agent-forwarding` extension, so no CA or sshd configuration changes are needed.

---

## Using `ziti-ssh` as a ProxyCommand

The `proxy` subcommand dials the Ziti service and bridges `stdin`/`stdout` to the raw TCP connection. The caller's own `ssh` process handles authentication, which means any tool that speaks SSH over stdio can use Ziti transparently.

```sh
ziti-ssh proxy [user@]<target>
```

### `~/.ssh/config` integration

Add a `ProxyCommand` entry to `~/.ssh/config`:

```
Host web-server-prod
    ProxyCommand ziti-ssh proxy %h
    User ziggy
```

Now all standard SSH tooling connects through the Ziti overlay automatically:

```sh
# Standard ssh
ssh web-server-prod

# VS Code Remote SSH — works via the config entry above
# (select "Remote-SSH: Connect to Host..." and pick web-server-prod)

# rsync
rsync -avz /local/dir/ web-server-prod:/remote/dir/

# git over SSH
git clone web-server-prod:/repos/myrepo.git

# ansible
ansible web-server-prod -m ping
```

### Wildcard host patterns

You can use a wildcard pattern to route a group of hosts through Ziti:

```
Host *.ziti
    ProxyCommand ziti-ssh proxy %h
    User ziggy

Host prod-*.internal
    ProxyCommand ziti-ssh proxy %h
    User ops
```

### Identity and certificate

`ziti-ssh proxy` uses the same `--identity` flag, `ZITI_IDENTITY` environment variable, and `~/.config/ziti-ssh/config.yaml` as the `connect` subcommand. It auto-refreshes the SSH certificate if it is missing or will expire within 5 minutes — so the `ssh` process that reads `ProxyCommand` output will find a valid cert in `~/.ssh/<key>-cert.pub`.

The user@ part in `ProxyCommand ziti-ssh proxy %h` is accepted for syntax compatibility but is not used by `ziti-ssh proxy` — the connection happens at the TCP level below SSH authentication.

### Using with specific identity or service

```sh
# Explicit identity and service
ziti-ssh proxy --identity ~/.config/ziti-ssh/alice.json --ssh-service ssh web-server-prod

# From ~/.ssh/config with flags
Host web-server-prod
    ProxyCommand ziti-ssh proxy --identity /etc/ziti-ssh/alice.json %h
    User ziggy
```

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
