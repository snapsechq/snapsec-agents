# Contributing to Snapsec Agent

Welcome! This guide will help you understand the architecture of the Snapsec Agent and how you can contribute to its development.

## Architecture Overview

The Snapsec Agent is designed to be modular, cross-platform, and easy to extend. It is written in Go and follows a clean separation of concerns.

### Directory Structure

- **`cmd/agent/`**: The main entry point. It handles command-line flags and initializes the service management logic.
- **`internal/agent/`**: The core "brain" of the agent. It manages the lifecycle (Start/Stop), handles automatic registration, and runs the periodic reporting loops (heartbeats and results).
- **`internal/config/`**: Manages the YAML configuration file. It handles loading, default paths for different OSs, and persisting the `agent_id` after registration.
- **`internal/modules/`**: This is where the data gathering logic lives. Each sub-directory is a self-contained module (e.g., `host`, `network`, `processes`).
- **`internal/service/`**: A wrapper around the `kardianos/service` library, providing a unified way to install and run the agent as a system service on Linux, Windows, and macOS.
- **`pkg/api/`**: The HTTP client used to communicate with the Snapsec backend.

## Data Gathering Flow

1. **Initialization**: The agent loads its configuration. If no `agent_id` is found, it triggers the registration flow.
2. **Registration**: The agent calls `/register` with the hostname and API key. The backend returns a unique `agent_id`, which the agent saves to its config file.
3. **Reporting Loop**: Every 5 seconds (configurable), the agent:
    - Sends a heartbeat to `/heartbeat`.
    - Iterates through all registered modules to gather system data.
    - Assembles a unified payload and sends it to `/results`.

## Result Payload Structure

The payload sent to the `/results` endpoint is a JSON object with the following top-level keys:

| Key | Description |
| :--- | :--- |
| `agent` | ID and Version of the agent. |
| `host` | Hostname, FQDN, Machine ID, and Uptime. |
| `os` | OS name, distribution, kernel version, and architecture. |
| `hardware` | CPU details, Memory usage, and Storage partitions. |
| `network` | Interfaces (MAC, IPs, MTU), Routes, and DNS. |
| `processes` | Count and list of running processes with resource usage. |
| `packages` | Software inventory (apt, rpm, brew, etc.) and versions. |
| `services` | List of system services and their current status. |
| `users` | System user accounts, UIDs, and shells. |
| `devices` | Discovered USB and PCI devices. |
| `security` | Firewall (UFW) and SELinux status. |

## How to Add a New Module

Adding a new data gathering capability is straightforward:

### 1. Create the Module
Create a new directory in `internal/modules/` (e.g., `internal/modules/vulnerabilities/`).
Implement the `Module` interface defined in `internal/modules/modules.go`:

```go
package vulnerabilities

type VulnerabilitiesModule struct{}

func (m *VulnerabilitiesModule) Name() string {
    return "vulnerabilities" // This will be the key in the JSON payload
}

func (m *VulnerabilitiesModule) Gather() (interface{}, error) {
    // Implement your data gathering logic here
    // Return a struct or map that can be marshaled to JSON
    return []string{"vuln-1", "vuln-2"}, nil
}
```

### 2. Register the Module
Open `internal/agent/agent.go` and add your new module to the `NewAgent` function:

```go
func NewAgent(cfg *config.Config, configPath string) *Agent {
    return &Agent{
        // ...
        modules: []modules.Module{
            &host.HostModule{},
            // ...
            &vulnerabilities.VulnerabilitiesModule{}, // Add your module here
        },
        // ...
    }
}
```

### 3. Test Your Changes
Build the agent and run it interactively to see the output:

```bash
go build -ldflags="-X main.version=$(git describe --tags --always)" -o bin/snapsec-agent ./cmd/agent
sudo ./bin/snapsec-agent
```

## Best Practices

- **Cross-Platform**: Always check `runtime.GOOS` if your logic is platform-specific.
- **Error Handling**: Modules should log errors but return partial data if possible, rather than failing the entire reporting loop.
- **Performance**: Data gathering should be efficient. Avoid long-running blocking calls inside the `Gather()` method.
- **Dependencies**: Prefer using existing libraries like `gopsutil` for system metrics to keep the binary lightweight.

## Coding Standards

- Follow standard Go formatting (`go fmt`).
- Use descriptive names for structs and fields (they map directly to JSON keys).
- Document complex logic, especially when parsing system command outputs.
