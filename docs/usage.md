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

The target is split at the **last** `@`, as with OpenSSH, so a user name that contains `@` works: `ziti-ssh alice@corp.com@web-server-prod` logs in as `alice@corp.com`. If the target name is also a Ziti service name, that service is dialed directly (see the host key table below); `--service <name>` always treats the target as a terminator address on `<name>`.

If a certificate is missing or less than 20% of its lifetime remains (between 30 s and 5 min — 1 minute for the default 5-minute certificate), `ziti-ssh connect` automatically obtains a fresh one from the CA before opening the session. On first use it auto-detects your SSH key in `~/.ssh/` (tries `id_ed25519`, `id_ecdsa`, `id_rsa` in that order). If no key exists it offers to run `ssh-keygen -t ed25519` for you; `ssh-keygen` asks for a passphrase (recommended; press Enter for none).

If the SSH private key is passphrase-protected, `ziti-ssh connect` falls back to the SSH agent (`SSH_AUTH_SOCK`). It locates the matching key in the agent and, if a certificate is present on disk, wraps it as an `ssh.CertSigner` so the certificate is offered during authentication. With the agent the passphrase is never exposed to this process. If no agent holds the key (`SSH_AUTH_SOCK` unset, or the key not added with `ssh-add`), `ziti-ssh connect` and `ziti-scp` ask for the passphrase on the terminal (`Enter passphrase for key '…':`, not echoed); without a terminal they exit with an error.

`ziti-ssh` and `ziti-scp` refuse to use `config.yaml` or the Ziti `known_hosts` file if it is writable by others, writable by a group other than your own private group (on Debian/Ubuntu each user has one, and files are created group-writable by default — that is accepted), or owned by another user (as OpenSSH does for its own config): another user could otherwise point you at a different identity, key or host. Fix with `chmod go-w <file>`.

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

### Host keys (trust on first use)

OpenZiti does not tell `ziti-ssh` which identity answered on a host's address, so `ziti-ssh` and `ziti-scp` remember the SSH host key(s) they have seen for each Ziti address in `$XDG_CONFIG_HOME/ziti-ssh/known_hosts` (default under `~/.config/ziti-ssh/`, mode 0600) and check them on every connection:

| You connect to | First connection | Same key later | Different key later |
|---|---|---|---|
| A host by name (`ziggy@web-server-prod`; address `web-server-prod@ssh`) | Key saved; `Permanently added host key …` printed | Connects | **Refused** with a warning showing both fingerprints |
| A service directly (`ziggy@ssh-db-pool`, when `ssh-db-pool` is a service; address `ssh-db-pool`) — any host bound to it may answer | Key saved | Connects | Warning, then **asked** `Trust this additional key for ssh-db-pool? [y/N]`. Yes adds it, so each member of a pool is accepted once. Without a terminal (scripts, pipes) it is refused — connect interactively once. |

When a target is a service name, `ziti-ssh` prints `Dialing service "…" directly: any host bound to it may answer.`

After a host was legitimately rebuilt (new host key):

```sh
ziti-ssh known-hosts list                       # address, key type, SHA256 fingerprint
ziti-ssh known-hosts remove web-server-prod@ssh # then reconnect to save the new key
```

This catches a host being impersonated **after** you have connected to it once; it cannot verify the very first connection. `ziti-ssh proxy` (OpenSSH `ProxyCommand`) is not affected: OpenSSH applies its own known_hosts checks, keyed by the `Host` name.

## Port forwarding

`ziti-ssh connect` supports the same `-L`, `-R`, and `-D` forwarding flags as `ssh(1)`. All forwards run over the Ziti overlay — no port 22 exposure required.

Write IPv6 addresses in brackets, as with `ssh`: `-L [::1]:8080:[2001:db8::1]:80`, `-D [::1]:1080`. Ports must be 1–65535.

Local listeners (`-L`, `-D`) bind to `127.0.0.1` by default. They have no authentication of their own: when you bind them to any other address, `ziti-ssh` prints a warning, because anyone who can reach that address can use your session.

### Local port forward (`-L`)

Listens on a local port and forwards each connection to a remote host:port through the SSH tunnel.

```sh
# Forward localhost:8080 → db.internal:5432 on the remote network
ziti-ssh connect ziggy@web-server-prod -L 8080:db.internal:5432

# Bind on all interfaces (e.g. for container-to-host forwarding) — prints a warning:
# anyone who can reach this machine on port 8080 can use the tunnel
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

**Agent forwarding is off by default and needs two opt-ins**, because `ziti-ssh` cannot yet verify which host answered on a terminator address (an OpenZiti limitation, see [operations.md](operations.md#host-identity-terminator-names)), and a forwarded agent can be used by the remote host for as long as you are connected:

1. The CA must grant the `permit-agent-forwarding` extension (`--cert-extensions` / `ZITI_CERT_EXTENSIONS` on `ziti-ssh-ca`; the default grants only `permit-pty,permit-port-forwarding`).
2. You must pass `--forward-agent-unverified` together with `-A`; `-A` alone is refused with an explanation.

```sh
ziti-ssh connect -A --forward-agent-unverified ziggy@web-server-prod
```

Agent forwarding requires `SSH_AUTH_SOCK` to be set in your environment (i.e. a running SSH agent). If it is not set, or the agent cannot be reached, `ziti-ssh` logs a warning and opens the session normally without forwarding — the connection is not aborted.

```sh
# Start an agent and add your key if not already running
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Now connect with agent forwarding
ziti-ssh connect -A --forward-agent-unverified ziggy@web-server-prod

# On the remote host you can SSH onward using your local agent keys:
# ssh another-internal-host
```

Agent forwarding can be combined with port forwarding flags:

```sh
ziti-ssh connect -A --forward-agent-unverified -L 5432:db.internal:5432 ziggy@web-server-prod
```

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

`ziti-ssh proxy` uses the same `--identity` flag, `ZITI_IDENTITY` environment variable, and `~/.config/ziti-ssh/config.yaml` as the `connect` subcommand. It auto-refreshes the SSH certificate if it is missing or less than 20% of its lifetime remains (between 30 s and 5 min — 1 minute for the default 5-minute certificate) — so the `ssh` process that reads `ProxyCommand` output will find a valid cert in `~/.ssh/<key>-cert.pub`.

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
        Serial: 7294018234810342811
        Valid: from 2026-03-30T09:00:00 to 2026-03-30T17:00:00
        Principals:
                ziggy
        Critical Options: (none)
        Extensions:
                permit-port-forwarding
                permit-pty
```

The certificate expires after the TTL configured on the CA (default: 5 minutes). `ziti-ssh connect` auto-renews when less than 20% of its lifetime remains (between 30 s and 5 min — 1 minute for the default 5-minute certificate). If the CA refuses a request (for example `CA refused the request: rate limit exceeded`), the existing certificate file is left untouched.

---

## Copying files with `ziti-scp`

`ziti-scp` copies files to and from remote hosts over the same Ziti overlay, using the SFTP subsystem. It mirrors `scp(1)` behaviour. The same identity, SSH certificate, and `~/.config/ziti-ssh/config.yaml` config file are shared with `ziti-ssh` — no additional enrollment is needed.

Remote specifications use the same `[user@]host:path` format as `scp`. The host name is resolved the same way `ziti-ssh` resolves it: first checked against the Ziti service list for a direct match, then used as a terminator address on `--ssh-service` (default: `ssh`); `--service <name>` skips the service-name check. As with `scp`, an argument is remote only if it contains `:` with no `/` before it — `/data/a:b`, `./a:b` and `dir/a:b` are local paths. The user part is split at the last `@` (`alice@corp.com@web1:/tmp`).

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
| `--preserve` | `-p` | false | Preserve file timestamps and permissions (on download, never world-writable) |
| `--quiet` | `-q` | false | Suppress progress output |
| `--identity` | — | `ZITI_IDENTITY` | Ziti identity file path |
| `--key` | — | auto-detect | SSH private key path |
| `--ca-service` | — | `ssh-ca` | CA service name |
| `--ssh-service` | — | `ssh` | SSH service name |
| `--service` | — | — | Treat the remote host as a terminator address on this service, even if it is also a service name |
| `--config` | — | `~/.config/ziti-ssh/config.yaml` | Config file path |

**Downloads are defensive about what the remote host sends:** a downloaded file takes the remote file's permission bits reduced by your umask (never setuid, setgid or sticky; with `-p`, never world-writable); `ziti-scp` refuses to write through an existing local symlink at the destination; remote entry names containing `/`, `\` or `..` are rejected; recursion stops at 64 directory levels; and control characters in file names are replaced before being printed.

If the certificate is missing or less than 20% of its lifetime remains (between 30 s and 5 min — 1 minute for the default 5-minute certificate), `ziti-scp` automatically obtains a fresh certificate from the CA before connecting — the same auto-refresh behaviour as `ziti-ssh connect`.

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

Once MFA is enabled, every command that authenticates — `connect`, `sign`, `proxy`, `list` and `ziti-scp` — asks for a code when the controller requires one (`MFA TOTP code:`). The code is read from your terminal (`/dev/tty`) without echo, never from stdin, so piped input and `proxy`'s SSH stream are left alone. Three wrong codes, or no terminal, end authentication. Entering the code counts against `--ziti-timeout` (default 30s). The `mfa` subcommands read codes from stdin (hidden when it is a terminal).

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
