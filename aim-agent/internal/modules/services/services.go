package services

import (
	"os/exec"
	"runtime"
	"strings"
)

type ServicesModule struct{}

type ServiceInfo struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
}

func (m *ServicesModule) Name() string {
	return "services"
}

func (m *ServicesModule) Gather() (interface{}, error) {
	var services []ServiceInfo

	if runtime.GOOS == "linux" {
		// Use systemctl if available
		if _, err := exec.LookPath("systemctl"); err == nil {
			out, _ := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-legend").Output()
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				parts := strings.Fields(line)
				if len(parts) >= 4 {
					name := strings.TrimSuffix(parts[0], ".service")
					status := parts[3]
					services = append(services, ServiceInfo{
						Name:   name,
						Status: status,
						// Enabled check would require 'systemctl is-enabled'
					})
				}
			}
		}
	}

	return services, nil
}
