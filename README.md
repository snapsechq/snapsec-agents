# Snapsec Agents Monorepo

Welcome to the **Snapsec Agents** repository. This is a Go-based monorepo that houses the official endpoint agents for the Snapsec platform.

---

## Agents

### [Snapsec Sensor](./snapsec-sensor/)
The **Snapsec Sensor** is a unified, lightweight, cross-platform host security and asset discovery agent for Linux, Windows, and macOS endpoints. It unifies asset inventory profiling with host security auditing into a single daemon binary:

- **Asset Inventory Profiling**: Continuously gathers hardware specs, OS details, network interfaces, installed system packages, running processes, active services, logged-in users, and security controls.
- **Embedded Security Audits**: Directly runs internal detector modules on the endpoint without pulling external binaries or dependencies:
  - **Hardening (`hardening`)**: Evaluates SSH configuration, kernel `sysctl` security settings, ASLR, firewall, and LSM status (UFW, AppArmor, SELinux).
  - **Configuration Issues (`configuration`)**: Detects insecure file permissions (`/etc/shadow`, `/etc/sudoers`), leaked SSH keys, cloud credentials (`.aws`, `.kube`), and open daemon sockets (Docker, Redis).
  - **Privilege Escalation (`privilege_escalation`)**: Audits `sudoers` rules (`NOPASSWD`, `LD_PRELOAD`), dangerous GTFOBins SUID binaries, writable cron jobs, and insecure `PATH` entries.
  - **Vulnerabilities (`vulnerability`)**: Identifies known critical OS and kernel CVEs (Dirty Pipe, Dirty COW, Baron Samedit) and pending security patches.
- **Dual-Upstream Reporting**:
  - `asset_upstream`: Ingests hardware, system, and package inventory into the Asset Inventory database.
  - `issues_upstream`: Reports detected security issues and vulnerability findings mapped to the standard vulnerability taxonomy.
- **Dynamic Vulnerability Scanning**: Vulnerability scanning remains disabled by default until configured dynamically by the backend via heartbeat responses.
- **Native Service Management**: Seamlessly installs and manages itself as a native daemon (`systemd` on Linux, Windows Service on Windows, `launchd` on macOS).

For detailed documentation, configuration schema, and installation instructions, see the [snapsec-sensor README](./snapsec-sensor/README.md).

---

## Repository Structure

```text
snapsec-agent/
├── snapsec-sensor/          # Snapsec Sensor source code and configuration
│   ├── cmd/agent/           # Entry point and CLI commands
│   ├── internal/            # Core agent logic, detectors, inventory modules, and updater
│   ├── pkg/api/             # Dual-upstream HTTP communication client
│   ├── scripts/             # Native platform install scripts (install.sh, install.ps1)
│   ├── snapsec-sensor.yaml.example
│   └── .goreleaser.yaml     # GoReleaser build and artifact packaging configuration
├── .github/workflows/
│   └── release.yaml         # GitHub Actions GoReleaser release pipeline
├── scripts/
│   └── release.sh           # Automated agent version bumping and release script
├── release.sh               # Symlink to scripts/release.sh
├── RELEASE.md               # Detailed release documentation
└── README.md
```

---

## Development

### Prerequisites
- **Go 1.24+**
- **Git**

### Building Locally

To build the sensor for your current operating system and architecture:

```bash
cd snapsec-sensor
go build -o snapsec-sensor ./cmd/agent
```

### Cross-Compilation

To verify cross-compilation across all supported platforms:

```bash
cd snapsec-sensor

# Linux
GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/agent
GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/agent

# Windows
GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/agent
GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/agent

# macOS
GOOS=darwin GOARCH=amd64 go build -o /dev/null ./cmd/agent
GOOS=darwin GOARCH=arm64 go build -o /dev/null ./cmd/agent
```

### Code Quality

Run code verification before pushing changes:

```bash
cd snapsec-sensor
go vet ./...
```

---

## Releasing

We use a **Tag Prefix** pattern (`<agent>/v<version>`) with **GoReleaser** to deliver decoupled, deterministic releases for agents in this monorepo.

### Automated Release (Recommended)

Use the `./release.sh` tool at the root of the repository to bump versions, create annotated tags, and trigger GitHub Actions builds:

```bash
# Interactive release wizard (selects agent, prompts for bump type)
./release.sh

# Bump patch version (e.g. v4.0.1 -> v4.0.2)
./release.sh snapsec-sensor patch

# Bump minor or major version
./release.sh snapsec-sensor minor
./release.sh snapsec-sensor major

# Release an explicit version
./release.sh snapsec-sensor 4.0.2

# Preview actions without modifying files or Git
./release.sh snapsec-sensor patch --dry-run

# Run non-interactively with auto-push
./release.sh snapsec-sensor patch --push
```

### Manual Release

To trigger a release manually, push a Git tag matching `<agent-directory>/v<version>`:

```bash
git commit -am "chore(snapsec-sensor): bump version to v4.0.2"
git tag -a snapsec-sensor/v4.0.2 -m "Release snapsec-sensor v4.0.2"
git push origin master
git push origin snapsec-sensor/v4.0.2
```

For full details on the release pipeline and monorepo release mechanics, see [RELEASE.md](./RELEASE.md).
