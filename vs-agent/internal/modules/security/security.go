package security

import (
	"os/exec"
	"runtime"
	"strings"
)

type SecurityModule struct{}

type FirewallData struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type SELinuxData struct {
	Status string `json:"status"`
}

type SecurityData struct {
	Firewall FirewallData `json:"firewall"`
	SELinux  SELinuxData  `json:"selinux"`
}

func (m *SecurityModule) Name() string {
	return "security"
}

func (m *SecurityModule) Gather() (interface{}, error) {
	var data SecurityData

	if runtime.GOOS == "linux" {
		// Firewall (UFW)
		if _, err := exec.LookPath("ufw"); err == nil {
			out, _ := exec.Command("sudo", "ufw", "status").Output()
			if strings.Contains(string(out), "Status: active") {
				data.Firewall = FirewallData{Type: "ufw", Status: "enabled"}
			} else {
				data.Firewall = FirewallData{Type: "ufw", Status: "disabled"}
			}
		}

		// SELinux
		if _, err := exec.LookPath("sestatus"); err == nil {
			out, _ := exec.Command("sestatus").Output()
			if strings.Contains(string(out), "SELinux status:                 enabled") {
				data.SELinux = SELinuxData{Status: "enabled"}
			} else {
				data.SELinux = SELinuxData{Status: "disabled"}
			}
		}
	}

	return data, nil
}
