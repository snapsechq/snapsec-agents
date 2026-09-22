# Agent CLI Commands Reference

The `aim-agent` has several built-in commands and flags that developers can use for testing, local scanning, and debugging.

## Core Daemon Commands

These commands start the core agent service, which communicates with the AssetInventory (AIM) backend via heartbeats and runs scheduled background scans.

### `aim-agent`
Runs the agent as a background daemon (default behavior). It automatically reads the configuration file from `/etc/snapsec-agent.yaml` (Linux/Mac) or `C:\ProgramData\snapsec-agent.yaml` (Windows).

### `aim-agent -f` (or `-foreground`)
Runs the agent in the foreground (interactive mode). This is highly recommended for developers so you can see live logs of the heartbeats and scheduled jobs in your terminal.

### `aim-agent -config=/path/to/config.yaml`
Overrides the default configuration path. Use this if you are testing with a custom configuration file.

---

## On-Demand Scanning (`scan`)

The `scan` subcommand allows you to trigger vulnerability scanners immediately from the CLI without waiting for the backend scheduler. 

*Note: By default, the `scan` command dynamically detects your Operating System and scans known configuration directories. It checks if the following directories exist before passing them to the scanner:*

**🐧 Linux:**
- `/etc`, `/usr/local/etc`, `/opt`, `/var/www`, `/home`
- `/var/lib/docker` *(if Docker is installed)*
- `/etc/kubernetes` *(if Kubernetes is installed)*

**🪟 Windows:**
- `C:\Windows\System32\drivers\etc`, `C:\ProgramData`, `C:\Users`
- `C:\inetpub` *(if IIS is installed)*
- `C:\Program Files`, `C:\Program Files (x86)`

**🍎 macOS:**
- `/etc`, `/Library`, `/Applications`, `/Users`, `/usr/local/etc`

*The scanner will also filter explicitly for exposed secrets and misconfigurations.*

### `aim-agent scan`
Runs **all** available vulnerability scanning tools registered in the agent (e.g., Nuclei, Trivy).
- The output is automatically bundled and pushed over the network to the AIM backend.

### `aim-agent scan --tool=<name>`
Runs a specific tool rather than all tools.
- **Example:** `aim-agent scan --tool=nuclei`

### `aim-agent scan --target=<path>`
Overrides the dynamic OS-specific targets and forces the scanner to run against a specific directory or URL.
- **Example:** `aim-agent scan --tool=nuclei --target=/var/www/html`

### `aim-agent scan --output=<filename.json>`
Outputs the raw, un-normalized findings directly to a local JSON file **instead** of sending them to the backend. This is useful for developers who want to inspect the raw data structure of the scanner's findings.
- **Example:** `aim-agent scan --tool=nuclei --output=nuclei-results.json`

### `aim-agent scan -config=<path>`
Specifies a custom configuration path, which is required if your backend URL or API key is not stored in the default location.
- **Example:** `aim-agent scan --tool=nuclei -config=./test-config.yaml`

---

## Example Developer Workflows

**1. Test a full scan and view raw JSON results locally:**
```bash
sudo ./aim-agent scan --tool=nuclei --target=/etc --output=local-test.json
```

**2. Test the full End-to-End backend ingestion (Agent -> AIM -> RabbitMQ -> VS):**
```bash
# This will perform the scan and push the payload directly to the running backend
sudo ./aim-agent scan --tool=nuclei
```
