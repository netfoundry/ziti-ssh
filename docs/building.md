# Getting binaries

Four options are available, from simplest to most hands-on.

---

## Download pre-built binaries (recommended)

Pre-built `.tar.gz` archives for linux/amd64 and linux/arm64 are published on the [GitHub releases page](https://github.com/netfoundry/ziti-ssh/releases). No Go toolchain or Docker installation required.

Download the archive for the component you need and extract it to a directory on your `PATH`.

---

## Build .deb packages with Docker

`scripts/docker-build-deb.sh` builds all four `.deb` packages inside a Docker container. Docker is the only prerequisite — no Go toolchain is needed on the host.

```sh
# Default version (0.1.0):
./scripts/docker-build-deb.sh

# Explicit version:
VERSION=1.2.3 ./scripts/docker-build-deb.sh
```

Output lands in `dist/`:

```
dist/ziti-ssh-ca_<version>_amd64.deb
dist/ziti-ssh-host_<version>_amd64.deb
dist/ziti-ssh_<version>_amd64.deb
dist/ziti-scp_<version>_amd64.deb
```

The script also copies the raw binaries to the repository root for local testing.

---

## Build .deb packages locally

`scripts/build-deb.sh` builds all four `.deb` packages directly on the host.

**Prerequisites:** Go 1.22 or later, `dpkg-deb` (included in the `dpkg` package on Debian/Ubuntu).

```sh
# Default version (0.1.0):
./scripts/build-deb.sh

# Explicit version:
VERSION=1.2.3 ./scripts/build-deb.sh
```

Output lands in `dist/`:

```
dist/ziti-ssh-ca_<version>_amd64.deb
dist/ziti-ssh-host_<version>_amd64.deb
dist/ziti-ssh_<version>_amd64.deb
dist/ziti-scp_<version>_amd64.deb
```

The script also copies the raw binaries to the repository root for local testing.

Copy each `.deb` to its target machine:

| Package | Destination |
|---|---|
| `ziti-ssh-ca_<version>_amd64.deb` | Ziti controller host |
| `ziti-ssh-host_<version>_amd64.deb` | Each target SSH host |
| `ziti-ssh_<version>_amd64.deb` | Each user's machine |
| `ziti-scp_<version>_amd64.deb` | Each user's machine (optional) |

---

## Build individual binaries (development)

For one-off builds or development work, build individual binaries directly with `go build`:

```sh
go build -o ziti-ssh-ca   ./cmd/ziti-ssh-ca
go build -o ziti-ssh-host ./cmd/ziti-ssh-host
go build -o ziti-ssh      ./cmd/ziti-ssh
go build -o ziti-scp      ./cmd/ziti-scp
```

All binaries are statically linked (no CGO). Copy each binary to the machine where it will run.
