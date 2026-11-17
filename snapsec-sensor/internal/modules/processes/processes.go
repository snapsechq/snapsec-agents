package processes

import (
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

type ProcessesModule struct{}

type ProcessInfo struct {
	Pid        int32   `json:"pid"`
	PPid       int32   `json:"ppid"`
	Name       string  `json:"name"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   uint64  `json:"memory_mb"`
	StartedAt  string  `json:"started_at"`
}

type ProcessesData struct {
	Count int           `json:"count"`
	List  []ProcessInfo `json:"list"`
}

func (m *ProcessesModule) Name() string {
	return "processes"
}

func (m *ProcessesModule) Gather() (interface{}, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var list []ProcessInfo
	for _, p := range procs {
		ppid, _ := p.Ppid()
		name, _ := p.Name()
		user, _ := p.Username()
		cpu, _ := p.CPUPercent()
		mem, _ := p.MemoryInfo()
		createTime, _ := p.CreateTime()

		startedAt := ""
		if createTime > 0 {
			startedAt = time.Unix(createTime/1000, 0).Format(time.RFC3339)
		}

		var memMB uint64
		if mem != nil {
			memMB = mem.RSS / 1024 / 1024
		}

		list = append(list, ProcessInfo{
			Pid:        p.Pid,
			PPid:       ppid,
			Name:       name,
			User:       user,
			CPUPercent: cpu,
			MemoryMB:   memMB,
			StartedAt:  startedAt,
		})
	}

	return ProcessesData{
		Count: len(list),
		List:  list,
	}, nil
}
