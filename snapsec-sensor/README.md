# Snapsec Sensor

Snapsec Sensor is a lightweight, cross-platform host security and asset discovery agent written in Go. It performs automated system inventory profiling, host security audits, hardening compliance checks, and local privilege escalation detection across Linux, Windows, and macOS endpoints.

---

## Capabilities & Architecture

- **Asset Inventory Profiling**: Gathers deep host hardware, OS, network interfaces, installed packages, active processes, system services, logged-in users, and security settings.
- **Host Security Audits**: Directly executes internal detector modules on the endpoint without downloading external binaries:
  - **Hardening Detector (`hardening`)**: Evaluates SSH daemon configurations, kernel `sysctl` hardening (ASLR, SYN cookies, eBPF, dmesg, core dumps), and LSM/firewall status (UFW, iptables, AppArmor, SELinux).
  - **Configuration Issues Detector (`configuration`)**: Detects world-writable or insecure permissions on sensitive files (`/etc/shadow`, `/etc/sudoers`, `/etc/passwd`), SSH keys, cloud credentials (`.aws/credentials`, `.kube/config`, `.docker/config.json`), and unauthenticated daemon exposures (Docker TCP socket, Redis `0.0.0.0`).
  - **Privilege Escalation Detector (`privilege_escalation`)**: Audits sudoers rules for dangerous `NOPASSWD` directives and `LD_PRELOAD` preservation, checks for misplaced or GTFOBin SUID binaries, world-writable cron/systemd unit files, and insecure `PATH` entries.
  - **Vulnerabilities Detector (`vulnerability`)**: Detects prominent Linux kernel CVEs (Dirty Pipe, Dirty COW), critical system binary vulnerabilities (Sudo Baron Samedit, OpenSSL buffer overflows), and pending OS security patches.
- **Dual Upstream Architecture**:
  - `asset_upstream`: Receives system inventory payloads and creates/updates host assets in the inventory database.
  - `issues_upstream`: Receives detected vulnerability and hardening findings, mapped to the standard vulnerability taxonomy.
- **Dynamic Vulnerability Scanning**: Vulnerability scanning remains disabled by default until the agent sends a heartbeat to the `issues_upstream` and receives an active scanning configuration.
- **Cross-Platform Service Daemon**: Automatically installs and registers itself as a native system service (`systemd` on Linux, Windows Service on Windows, `launchd` on macOS).
- **Automated Registration**: Registers with the Snapsec backend on first execution using the organization API key and persists the assigned `agent.id`.

---

## Directory Structure

```text
snapsec-sensor/
├── cmd/
│   └── agent/             # Main application entry point & CLI flags
├── internal/
│   ├── agent/             # Core agent lifecycle, loops, and upstream sync
│   ├── config/            # YAML configuration loader, defaults, and persistence
│   ├── detector/          # Security detectors (hardening, config, privesc, vulns)
│   ├── modules/           # Inventory modules (host, network, packages, services, etc.)
│   ├── service/           # Native OS service manager (kardianos/service)
│   └── updater/           # In-place auto-update mechanism
├── pkg/
│   └── api/               # HTTP client for dual upstreams and heartbeats
├── scripts/
│   ├── install.sh         # Linux/macOS curl-to-bash deployment script
│   └── install.ps1        # Windows PowerShell deployment script
├── snapsec-sensor.yaml.example
└── README.md
```

---

## Configuration Reference

The configuration file is expected at:
- **Linux/macOS**: `/etc/snapsec.d/snapsec-sensor.yaml`
- **Windows**: `C:\ProgramData\snapsec.d\snapsec-sensor.yaml`

```yaml
agent:
  enabled: true
  version: "4.0.2"
  update_channel: stable
  id: "assigned-by-backend" # Automatically populated after initial registration

inventory:
  enabled: true
  interval: 300 # Seconds between full system inventory pushes (default: 5 min)

vulnerability_scanning:
  enabled: false # Activated automatically by the backend via issues_upstream heartbeat
  interval: 3600 # Seconds between host security detector runs (default: 1 hour)

communication:
  backend_url: "https://your-backend.com"
  asset_upstream: "/asset-inventory/api/v1/agents"
  issues_upstream: "/autopentest/api/v1/agents"
  api_key: "your-organization-api-key"
  heartbeat_interval: 60 # Seconds between heartbeat pings
```

---

## Deployment

### Automated Deployment (Backend-Driven)

Snapsec provides one-liner installation commands from the dashboard:

#### Linux & macOS
```bash
curl -L "https://your-backend.com/asset-inventory/api/v1/agents/download/linux/install?token=YOUR_ORG_ID" | sudo bash
```

#### Windows (PowerShell Run as Administrator)
```powershell
powershell -ExecutionPolicy ByPass -Command "iwr -useb 'https://your-backend.com/asset-inventory/api/v1/agents/download/windows/install?token=YOUR_ORG_ID' | iex"
```

The installation script:
1. Creates the configuration directory and populates `snapsec-sensor.yaml` with your organization's API key and endpoints.
2. Downloads the official sensor binary matching your OS and architecture (`amd64`, `arm64`, `386`).
3. Executes the binary, which automatically performs initial registration and installs the native system service.

---

### Manual Installation & CLI Options

1. Build or download the binary:
   ```bash
   go build -o snapsec-sensor ./cmd/agent
   ```
2. Copy `snapsec-sensor.yaml.example` to `/etc/snapsec.d/snapsec-sensor.yaml` (or `C:\ProgramData\snapsec.d\snapsec-sensor.yaml`) and enter your `backend_url` and `api_key`.
3. Run the binary as root / Administrator:
   ```bash
   sudo ./snapsec-sensor
   ```
   The agent will register with the backend, write `agent.id` into the configuration file, and install itself as a system daemon.

#### CLI Flags
- `-config <path>`: Specify custom configuration file path (default: `/etc/snapsec.d/snapsec-sensor.yaml`).
- `-foreground` / `-f`: Run in the foreground without daemonizing (useful for debugging and container environments).

---

## Service Management

### Linux (Systemd)
```bash
sudo systemctl status snapsec-sensor    # Check status
sudo journalctl -u snapsec-sensor -f    # View live logs
sudo systemctl restart snapsec-sensor   # Restart service
sudo systemctl stop snapsec-sensor      # Stop service
```

### Windows (PowerShell)
```powershell
Get-Service snapsec-sensor              # Check status
Restart-Service snapsec-sensor          # Restart service
Stop-Service snapsec-sensor             # Stop service
```

### macOS
```bash
sudo brew services list | grep snapsec-sensor
sudo brew services restart snapsec-sensor
```

---

## Backend API Endpoints

The sensor communicates with the following endpoints:

| Endpoint | Method | Upstream | Purpose |
| :--- | :--- | :--- | :--- |
| `/register` | `POST` | `asset_upstream` | Initial host registration (returns `agent_id`) |
| `/heartbeat` | `POST` | `asset_upstream` | Periodic status ping & general configuration sync |
| `/results` | `POST` | `asset_upstream` | Full system inventory telemetry (hardware, OS, packages, network) |
| `/heartbeat` | `POST` | `issues_upstream` | Vulnerability scanning capability check & scan configuration |
| `/results` | `POST` | `issues_upstream` | Host detector findings (hardening, config, privesc, vulns) |
