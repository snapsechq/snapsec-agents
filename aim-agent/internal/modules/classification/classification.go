package classification

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

type ClassificationModule struct{}

type ClassificationData struct {
	Type       string             `json:"type"`       // workstation or server
	Confidence float64            `json:"confidence"` // 0.0 to 1.0
	Signals    map[string]float64 `json:"signals"`    // Signal names and their weight/contribution
}

func (m *ClassificationModule) Name() string {
	return "classification"
}

func (m *ClassificationModule) Gather() (interface{}, error) {
	data := ClassificationData{
		Signals: make(map[string]float64),
	}

	serverScore := 0.0
	workstationScore := 0.0

	// 1. Check for Battery (Strong Workstation Signal)
	if hasBattery() {
		data.Signals["battery_present"] = 0.9
		workstationScore += 0.9
	}

	// 2. Check for GUI Processes (Strong Workstation Signal)
	if hasGUI() {
		data.Signals["gui_detected"] = 0.7
		workstationScore += 0.7
	}

	// 3. Check Chassis Type (Linux Only - if available)
	if chassis := getChassisType(); chassis != "" {
		switch chassis {
		case "rack_mount", "blade", "tower":
			data.Signals["chassis_"+chassis] = 0.6
			serverScore += 0.6
		case "laptop", "notebook", "portable", "tablet":
			data.Signals["chassis_"+chassis] = 0.8
			workstationScore += 0.8
		}
	}

	// 4. Check for Common Server Packages/Services
	if serverApps := checkServerApps(); len(serverApps) > 0 {
		weight := float64(len(serverApps)) * 0.2
		if weight > 0.8 {
			weight = 0.8
		}
		data.Signals["server_apps_detected"] = weight
		serverScore += weight
	}

	// 5. Check for Common Workstation Packages/Services
	if wsApps := checkWorkstationApps(); len(wsApps) > 0 {
		weight := float64(len(wsApps)) * 0.2
		if weight > 0.6 {
			weight = 0.6
		}
		data.Signals["workstation_apps_detected"] = weight
		workstationScore += weight
	}

	// 6. OS Distribution Hints
	if dist := getDistroHint(); dist != "" {
		if strings.Contains(dist, "server") {
			data.Signals["os_distribution_hint"] = 0.5
			serverScore += 0.5
		} else if strings.Contains(dist, "desktop") || strings.Contains(dist, "mac") {
			data.Signals["os_distribution_hint"] = 0.4
			workstationScore += 0.4
		}
	}

	// Final Classification
	if workstationScore >= serverScore {
		data.Type = "workstation"
		if workstationScore+serverScore > 0 {
			data.Confidence = workstationScore / (workstationScore + serverScore)
		} else {
			data.Confidence = 0.5
		}
	} else {
		data.Type = "server"
		data.Confidence = serverScore / (workstationScore + serverScore)
	}

	return data, nil
}

func hasBattery() bool {
	if runtime.GOOS == "linux" {
		matches, _ := filepath.Glob("/sys/class/power_supply/BAT*")
		return len(matches) > 0
	}
	// For Windows/macOS we could use gopsutil or specific commands
	// but keeping it simple for now
	return false
}

func hasGUI() bool {
	procs, err := process.Processes()
	if err != nil {
		return false
	}

	guiProcesses := map[string]bool{
		"Xorg":          true,
		"wayland":       true,
		"gnome-shell":   true,
		"kwin":          true,
		"explorer.exe":  true,
		"WindowServer":  true,
		"LoginWindow":   true,
		"dwm.exe":       true,
	}

	for _, p := range procs {
		name, _ := p.Name()
		if guiProcesses[name] {
			return true
		}
	}
	return false
}

func getChassisType() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	data, err := os.ReadFile("/sys/class/dmi/id/chassis_type")
	if err != nil {
		return ""
	}

	// Reference: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0.pdf
	t := strings.TrimSpace(string(data))
	switch t {
	case "3", "4", "6", "13", "15", "16", "24":
		return "desktop"
	case "8", "9", "10", "11", "14", "30", "31", "32":
		return "laptop"
	case "23", "25", "28", "29":
		return "rack_mount"
	case "7":
		return "tower"
	}
	return ""
}

func checkServerApps() []string {
	var detected []string
	serverApps := []string{"nginx", "httpd", "apache2", "mysql", "postgres", "mongod", "docker", "kubelet", "sshd"}
	
	for _, app := range serverApps {
		if _, err := exec.LookPath(app); err == nil {
			detected = append(detected, app)
		}
	}
	return detected
}

func checkWorkstationApps() []string {
	var detected []string
	wsApps := []string{"slack", "discord", "chrome", "firefox", "code", "spotify", "zoom"}
	
	for _, app := range wsApps {
		if _, err := exec.LookPath(app); err == nil {
			detected = append(detected, app)
		}
	}
	return detected
}

func getDistroHint() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	
	if runtime.GOOS == "linux" {
		f, err := os.Open("/etc/os-release")
		if err != nil {
			return ""
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.ToLower(line)
			}
		}
	}
	return ""
}
