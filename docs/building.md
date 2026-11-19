# Getting binaries

Three options are available, from simplest to most hands-on.

---

## Install from the package repository (recommended)

Packages are published to the NetFoundry package repository for linux/amd64 and linux/arm64. Use the install script — no manual package management required:

```sh
# CA service (install on the Ziti controller host)
curl -sSL https://get.netfoundry.io/linux-install.bash | sudo bash -s ziti-ssh-ca

# Host proxy (install on each SSH target host)
curl -sSL https://get.netfoundry.io/linux-install.bash | sudo bash -s ziti-ssh-host

# SSH client (install on each user's machine)
curl -sSL https://get.netfoundry.io/linux-install.bash | sudo bash -s ziti-ssh

# SCP file copy tool (optional, install on each user's machine)
curl -sSL https://get.netfoundry.io/linux-install.bash | sudo bash -s ziti-scp
```

The install script configures the repository and installs the latest stable package. Subsequent upgrades are handled by the system package manager (`apt upgrade` / `yum update`).

### Verifying packages

Packages from the repository are verified automatically by `apt` / `dnf`: the repository index is GPG-signed and lists each package's checksum. The packages themselves are not individually signed.

Each release built from a tag also publishes:

- **`SHA256SUMS`** — attached to the GitHub release; the checksums of every `.deb` and `.rpm` the release workflow built.
- **Build provenance attestations** — signed by GitHub Actions, linking each package to the commit and workflow run that built it.

To check a package file (for example one fetched with `apt-get download ziti-ssh` or `dnf download ziti-ssh`):

```sh
# Checksum (run in the directory holding the package and SHA256SUMS)
sha256sum --check --ignore-missing SHA256SUMS

# Provenance (needs a GitHub CLI that has the `attestation` command)
gh attestation verify ziti-ssh_<version>-1_amd64.deb --repo netfoundry/ziti-ssh
```

---

## Build packages locally

`scripts/build-packages.sh` builds `.deb` and/or `.rpm` packages directly on the host. Go is the only prerequisite — `nfpm` is installed automatically on first run.

```sh
# Build all formats for the native arch (default):
VERSION=1.2.3 ./scripts/build-packages.sh

# Build deb only:
VERSION=1.2.3 FORMAT=deb ./scripts/build-packages.sh

# Build rpm only:
VERSION=1.2.3 FORMAT=rpm ./scripts/build-packages.sh

# Build for a specific arch:
VERSION=1.2.3 FORMAT=deb ARCHS=amd64 ./scripts/build-packages.sh

# Build for multiple arches:
VERSION=1.2.3 ARCHS=amd64,arm64 ./scripts/build-packages.sh
```

Output lands in `dist/`:

```
dist/ziti-ssh-ca_<version>-1_amd64.deb
dist/ziti-ssh-host_<version>-1_amd64.deb
dist/ziti-ssh_<version>-1_amd64.deb
dist/ziti-scp_<version>-1_amd64.deb
```

The script also copies the native-arch binaries to the repository root for local use.

| Package | Destination |
|---|---|
| `ziti-ssh-ca_<version>-1_<arch>.deb` | Ziti controller host |
| `ziti-ssh-host_<version>-1_<arch>.deb` | Each target SSH host |
| `ziti-ssh_<version>-1_<arch>.deb` | Each user's machine |
| `ziti-scp_<version>-1_<arch>.deb` | Each user's machine (optional) |

---

## Build packages with Docker

`scripts/docker-build-packages.sh` builds packages inside a Docker container. Docker is the only prerequisite — no Go toolchain is needed on the host. Supports the same `FORMAT` and `ARCHS` variables as the local build.

```sh
# Default (deb+rpm, amd64):
./scripts/docker-build-packages.sh

# Explicit version and format:
VERSION=1.2.3 FORMAT=deb ./scripts/docker-build-packages.sh

# Multiple arches:
VERSION=1.2.3 ARCHS=amd64,arm64 ./scripts/docker-build-packages.sh
```

Output lands in `dist/` and binaries are copied to the repository root, same as the local build.

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
