//go:build darwin
// +build darwin

package cpulimit

import (
	"syscall"
)

func applyOSSpecific() error {
	// macOS lacks a programmatic API for strict process-tree CPU capping like Windows Job Objects.
	// The best effort here is to run the process at the lowest priority (nice value 19),
	// which effectively yields CPU whenever the system has other tasks to run.
	
	// 19 is the lowest priority (max nice).
	return syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)
}
