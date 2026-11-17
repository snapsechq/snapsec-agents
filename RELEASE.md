# Release Process

This repository is a monorepo that contains Go-based agents (e.g., `snapsec-sensor`). We use **GoReleaser** with **Tag Prefixes** to ensure deterministic and decoupled releases for each agent.

## Automated Release (Recommended)

You can use the root `./release.sh` script to automatically detect the current version, bump the version across code and configuration files, create the annotated Git tag, and push to origin:

```bash
# 1. Interactive release (prompts for agent, bump type, confirmation)
./release.sh

# 2. Bump patch version for snapsec-sensor (e.g. 4.0.1 -> 4.0.2)
./release.sh snapsec-sensor patch

# 3. Bump minor or major version
./release.sh snapsec-sensor minor
./release.sh snapsec-sensor major

# 4. Release a specific version
./release.sh snapsec-sensor 4.0.2

# 5. Non-interactive release with auto-push
./release.sh snapsec-sensor patch --push

# 6. Dry run (simulate without modifying files, committing, or pushing)
./release.sh snapsec-sensor patch --dry-run
```

## Manual Release

To manually trigger a release for an agent, push a git tag formatted as `<agent-directory>/v<version>`. 

For example, to release version `v4.0.2` of `snapsec-sensor`:

```bash
# 1. Update version in snapsec-sensor/internal/config/config.go
# 2. Commit the bump
git commit -am "chore(snapsec-sensor): bump version to v4.0.2"

# 3. Create the annotated tag locally
git tag -a snapsec-sensor/v4.0.2 -m "Release snapsec-sensor v4.0.2"

# 4. Push commit and tag to GitHub
git push origin master
git push origin snapsec-sensor/v4.0.2
```

When the tag is pushed to GitHub, the `.github/workflows/release.yaml` workflow will automatically start. It will:
1. Detect that `snapsec-sensor` is being released based on the tag prefix.
2. Extract the agent name and version (`snapsec-sensor` and `v4.0.2`).
3. Set `GORELEASER_CURRENT_TAG=v4.0.2` and force-create the local tag so GoReleaser's validation passes.
4. Change into the `snapsec-sensor` directory.
5. Run `goreleaser release --clean` using the `.goreleaser.yaml` config in that specific directory.
6. Build binaries across all supported OS/Arch targets (Linux, Windows, macOS on AMD64 and ARM64).
7. Publish the release to GitHub Releases with checksums and raw binaries.

## Notes & Best Practices

- **Tag format**: The tag must match the glob pattern `*/v*` (e.g., `snapsec-sensor/v4.0.2`).
- **Semantic Versioning**: Always use semantic versioning with a `v` prefix for the version part (e.g., `v4.0.2`, `v4.1.0`).
- **Local Testing**: You can test builds locally without publishing a release by changing into the agent's directory and running `go vet ./...` or `go build ./cmd/agent`.
