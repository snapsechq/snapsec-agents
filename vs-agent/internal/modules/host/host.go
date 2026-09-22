package host

import (
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/host"
)

type HostModule struct{}

type HostData struct {
	Hostname      string `json:"hostname"`
	FQDN          string `json:"fqdn"`
	MachineID     string `json:"machine_id"`
	Timezone      string `json:"timezone"`
	UptimeSeconds uint64 `json:"uptime_seconds"`
}

type OSData struct {
	Name         string `json:"name"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
}

func (m *HostModule) Name() string {
	return "host_os"
}

func (m *HostModule) Gather() (interface{}, error) {
	info, err := host.Info()
	if err != nil {
		return nil, err
	}

	hostname, _ := os.Hostname()
	timezone, _ := time.Now().Zone()

	// Simplified FQDN for now, could be improved with net.LookupAddr
	fqdn := hostname

	hostData := HostData{
		Hostname:      hostname,
		FQDN:          fqdn,
		MachineID:     info.HostID,
		Timezone:      timezone,
		UptimeSeconds: info.Uptime,
	}

	osData := OSData{
		Name:         runtime.GOOS,
		Distribution: info.Platform,
		Version:      info.PlatformVersion,
		Kernel:       info.KernelVersion,
		Architecture: runtime.GOARCH,
	}

	return map[string]interface{}{
		"host": hostData,
		"os":   osData,
	}, nil
}
