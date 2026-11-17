# Contributing to Snapsec Sensor

Welcome! This guide outlines the architecture of Snapsec Sensor and explains how to extend it with new inventory modules and security detectors.

---

## Architecture Overview

Snapsec Sensor is modular, cross-platform, and follows a clean separation of concerns:

### Directory Structure

- **`cmd/agent/`**: Entry point handling CLI flags (`-config`, `-foreground`) and triggering the service manager.
- **`internal/agent/`**: Core lifecycle coordinator. Manages periodic sync loops for inventory pushes to `asset_upstream` and vulnerability scanning to `issues_upstream`.
- **`internal/config/`**: Configuration loading, validation, YAML parsing, and state persistence (`agent.id`).
- **`internal/modules/`**: System inventory data gathering modules (host, network, packages, processes, hardware, services, etc.).
- **`internal/detector/`**: Host security detector modules (`hardening`, `configuration`, `privilege_escalation`, `vulnerabilities`).
- **`internal/service/`**: Native OS daemon wrapper around `kardianos/service` (supports systemd, Windows Service, launchd).
- **`internal/updater/`**: In-place binary auto-updater.
- **`pkg/api/`**: HTTP client communicating with backend endpoints (`asset_upstream` and `issues_upstream`).

---

## Extending Inventory Modules

Each inventory module is responsible for profiling a specific system domain and returning structured data for the asset database.

### Implementing a Module

1. Create a directory in `internal/modules/<yourmodule>/<yourmodule>.go`.
2. Implement the `Module` interface defined in `internal/modules/modules.go`:

```go
package yourmodule

type YourModule struct{}

func (m *YourModule) Name() string {
    return "your_module_name" // Becomes a top-level key in the inventory payload
}

func (m *YourModule) Gather() (interface{}, error) {
    // Collect system data
    return data, nil
}
```

3. Register your module in `internal/agent/agent.go` in `NewAgent()`:
```go
a.modules = append(a.modules, yourmodule.New())
```

---

## Extending Security Detectors

Detectors perform host-level security audits, compliance checks, and vulnerability analysis directly on the host endpoint without external dependencies.

### Implementing a Detector

1. Add your detector in `internal/detector/<detector_name>.go`.
2. Implement the `Detector` interface defined in `internal/detector/types.go`:

```go
package detector

import "context"

type CustomDetector struct{}

func NewCustomDetector() *CustomDetector {
    return &CustomDetector{}
}

func (d *CustomDetector) Name() string {
    return "custom_audit"
}

func (d *CustomDetector) Category() string {
    return CategoryConfiguration // One of: CategoryHardening, CategoryConfiguration, CategoryPrivilegeEscalation, CategoryVulnerability
}

func (d *CustomDetector) Run(ctx context.Context) ([]Finding, error) {
    var findings []Finding

    // Perform security inspection...
    findings = append(findings, Finding{
        UniversalVulnID:  "snapsec:config:example-issue",
        Title:            "Insecure Service Configuration Detected",
        Description:      "Detailed explanation of why this configuration is vulnerable.",
        Severity:         "high",              // critical, high, medium, low, info
        VulnType:         VulnTypeConfiguration, // linux, windows, configuration, secret, container, database
        Category:         CategoryConfiguration,
        Type:             "configuration",
        SourceClassifier: "config",
        MatchedAt:        "/etc/example.conf: line 42",
        MatcherName:      "custom_rule_id",
        Remediation:      "Steps to remediate the vulnerability.",
        References:       []string{"https://example.com/security-guideline"},
        DetectedAt:       time.Now(),
    })

    return findings, nil
}
```

3. Register your detector in `internal/detector/detector.go` in `NewManager()`:
```go
m.Register(NewCustomDetector())
```

---

## Building & Verification

Verify changes using Go tools:

```bash
# Verify code correctness
go vet ./...

# Build local agent binary
go build -o snapsec-sensor ./cmd/agent

# Run in foreground for testing
sudo ./snapsec-sensor -foreground
```
