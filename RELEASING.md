# Release Process

## Overview

Releases are created automatically when a version tag is pushed. Every automated release starts as a **pre-release** — it must be manually promoted to stable before GitHub marks it as the latest release.

This two-step flow allows pre-release binaries to be tested (and, in future, published to a test package repository) before they reach users who pull the latest stable release.

## Creating a Release

1. Ensure the `main` branch is in the state you want to ship.

2. Tag the commit:
   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. The [Release workflow](.github/workflows/release.yml) will trigger automatically and:
   - Cross-compile all four binaries for `linux/amd64` and `linux/arm64`
   - Package each binary as `<binary>_<version>_<os>_<arch>.tar.gz`
   - Create a GitHub Release marked as **pre-release**, with auto-generated release notes

4. Verify the release on the [Releases page](../../releases):
   - Check that all eight tarballs are attached (`4 binaries × 2 architectures`)
   - Download and smoke-test the binaries against your target environment

## Promoting to Stable

Once you are satisfied the pre-release is good:

1. Open the release on GitHub.
2. Click **Edit** (pencil icon).
3. Uncheck **Set as a pre-release**.
4. Check **Set as the latest release**.
5. Click **Update release**.

GitHub will now surface this version as the latest release. Users and tooling that fetch the latest release URL will see it from this point forward.

**Do not skip the pre-release stage.** Pushing a tag goes straight to pre-release by design — there is no way to accidentally ship a release as latest without the manual promotion step.

## Future: Package Repositories

When `.deb` packages are added, the flow will extend as follows:

1. Tag push → CI builds binaries + packages → published to **test package repository** as a pre-release.
2. Manual validation against the test repository.
3. Promote GitHub release to stable → packages copied from test repository to **stable repository**.

The same manual promotion step that controls the GitHub "latest" marker will gate the package repository promotion.

## Version Format

Versions follow [Semantic Versioning](https://semver.org/): `vMAJOR.MINOR.PATCH`.

Tags must be prefixed with `v` (e.g. `v0.1.0`) for the release workflow to trigger.
