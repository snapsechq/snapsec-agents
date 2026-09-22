package hardware

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type HardwareModule struct{}

type CPUData struct {
	Model        string  `json:"model"`
	Cores        int     `json:"cores"`
	Threads      int     `json:"threads"`
	FrequencyMHz float64 `json:"frequency_mhz"`
}

type MemoryData struct {
	TotalMB     uint64 `json:"total_mb"`
	AvailableMB uint64 `json:"available_mb"`
}

type StorageData struct {
	Device     string `json:"device"`
	Type       string `json:"type"`
	SizeGB     uint64 `json:"size_gb"`
	Mountpoint string `json:"mountpoint"`
}

type HardwareData struct {
	CPU     CPUData       `json:"cpu"`
	Memory  MemoryData    `json:"memory"`
	Storage []StorageData `json:"storage"`
}

func (m *HardwareModule) Name() string {
	return "hardware"
}

func (m *HardwareModule) Gather() (interface{}, error) {
	// CPU
	cpuInfo, _ := cpu.Info()
	var cpuData CPUData
	if len(cpuInfo) > 0 {
		cpuData = CPUData{
			Model:        cpuInfo[0].ModelName,
			Cores:        int(cpuInfo[0].Cores),
			Threads:      len(cpuInfo), // Simplified
			FrequencyMHz: cpuInfo[0].Mhz,
		}
	}

	// Memory
	vMem, _ := mem.VirtualMemory()
	memData := MemoryData{
		TotalMB:     vMem.Total / 1024 / 1024,
		AvailableMB: vMem.Available / 1024 / 1024,
	}

	// Storage
	partitions, _ := disk.Partitions(false)
	var storageData []StorageData
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		storageData = append(storageData, StorageData{
			Device:     p.Device,
			Type:       p.Fstype,
			SizeGB:     usage.Total / 1024 / 1024 / 1024,
			Mountpoint: p.Mountpoint,
		})
	}

	return HardwareData{
		CPU:     cpuData,
		Memory:  memData,
		Storage: storageData,
	}, nil
}
