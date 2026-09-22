# Release Process

This repository is a monorepo that contains multiple Go-based agents (e.g., `aim-agent`, `vs-agent`). We use **GoReleaser** with **Tag Prefixes** to ensure deterministic and decoupled releases for each agent.

## How to Release

To trigger a release for an agent, you need to push a git tag formatted as `<agent-directory>/<version>`. 

For example, to release version `v1.2.0` of the `aim-agent`:

```bash
# 1. Create the tag locally
git tag aim-agent/v1.2.0

# 2. Push the tag to GitHub
git push origin aim-agent/v1.2.0
```

When the tag is pushed to GitHub, a GitHub Actions workflow will automatically start. It will:
1. Detect that `aim-agent` is being released based on the tag prefix.
2. Change into the `aim-agent` directory.
3. Run `goreleaser release --clean` using the `.goreleaser.yaml` config in that specific directory.

## Releasing Multiple Agents

Because releases are decoupled, you can release multiple agents at the exact same time by pushing multiple tags. 

```bash
git tag aim-agent/v1.2.0
git tag vs-agent/v1.1.0

# Push all local tags
git push --tags
```

This will trigger **multiple, parallel** GitHub Actions workflow runs—one for each agent, keeping their builds entirely isolated.

## Notes & Best Practices

- **Tag format**: The tag must match the glob pattern `*-agent/v*` (e.g., `aim-agent/v1.2.3`).
- **Semantic Versioning**: Always use semantic versioning with a `v` prefix for the version part (e.g., `v1.0.0`, `v1.2.3-rc1`).
- **Local Testing**: You can test a build locally without publishing a release by changing into the agent's directory and running `goreleaser build --snapshot --clean`.
