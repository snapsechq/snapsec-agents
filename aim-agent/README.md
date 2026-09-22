# Snapsec Sensor (aim-agent)

A cross-platform security agent written in Go, focusing on Asset Inventory Management (AIM).

## Features

- **Cross-platform Service**: Supports Linux, Windows, and macOS service registration as `snapsec-sensor`.
- **Modular Architecture**: Easy to add new data gathering modules.
- **Automated Registration**: Registers itself with the backend on first run.
- **Periodic Reporting**: Sends asset data and heartbeats periodically.

## Project Structure

- `cmd/agent/`: Entry point and CLI handling.
- `internal/agent/`: Core agent logic and loops.
- `internal/config/`: Configuration loading and OS-specific paths.
- `internal/modules/`: Data gathering modules (host, network, etc.).
- `internal/service/`: Service management wrapper.
- `pkg/api/`: Backend API client.

## Installation & Configuration

The configuration file is expected to be at:
- Linux/Mac: `/etc/snapsec.d/snapsec-sensor.yaml`
- Windows: `C:\ProgramData\snapsec.d\snapsec-sensor.yaml`

To run manually:
```bash
sudo ./snapsec-agent
```
It will automatically detect it's not installed, register with the backend, and install itself as a system service.

## Backend-Driven Installation

For automated deployments, use the provided scripts in the `scripts/` directory. These are designed to be served by your backend with template variables populated.

### Linux/macOS
```bash
curl -L https://your-backend.com/install.sh?token=XYZ | bash
```

### Windows (PowerShell)
```powershell
iwr https://your-backend.com/install.ps1?token=XYZ | iex
```

## Development

### Adding a new module
1. Create a new file in `internal/modules/yourmodule/yourmodule.go`.
2. Implement the `Module` interface:
   ```go
   type Module interface {
       Name() string
       Gather() (interface{}, error)
   }
   ```
3. Register the module in `internal/agent/agent.go` in the `NewAgent` function.

## API Endpoints
The agent expects the following endpoints on the backend:
- `POST /register`: Initial registration with host details.
- `POST /heartbeat`: Periodic heartbeat.
- `POST /assets`: Periodic asset data reporting.
