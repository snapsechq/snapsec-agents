//go:build linux
// +build linux

package cpulimit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func applyOSSpecific() error {
	pid := os.Getpid()
	
	// We attempt to create a cgroup v2 for this process to enforce CPU quota.
	// This usually requires root privileges.
	cgBase := "/sys/fs/cgroup"
	cgPath := filepath.Join(cgBase, fmt.Sprintf("snapsec-agent-%d", pid))
	
	if err := os.MkdirAll(cgPath, 0755); err != nil {
		// Cgroups v2 might not be mounted here, or we lack permissions.
		return fmt.Errorf("failed to create cgroup v2 directory: %v", err)
	}
	
	// Calculate 20% of the total system CPU capacity.
	// cpu.max uses format: <quota> <period>
	// Quota is the total time allowed in the given period across all CPUs.
	// To get 20% of total system capacity, quota = 20% of period * number of cores.
	period := 100000
	quota := (20 * period / 100) * runtime.NumCPU()
	
	cpuMaxStr := fmt.Sprintf("%d %d", quota, period)
	if err := os.WriteFile(filepath.Join(cgPath, "cpu.max"), []byte(cpuMaxStr), 0644); err != nil {
		return fmt.Errorf("failed to set cpu.max: %v", err)
	}
	
	// Add current process to the cgroup. Child processes will inherit this automatically.
	if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		return fmt.Errorf("failed to add process to cgroup.procs: %v", err)
	}
	
	return nil
}
