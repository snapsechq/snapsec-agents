//go:build windows
// +build windows

package cpulimit

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type JOBOBJECT_CPU_RATE_CONTROL_INFORMATION struct {
	ControlFlags uint32
	Value        uint32
}

const (
	JobObjectCpuRateControlInformation = 15
	JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
	JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4
)

func applyOSSpecific() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("CreateJobObject failed: %w", err)
	}

	// 20% CPU hard cap. Value is in units of 1/100th of a percent (20 * 100 = 2000).
	info := JOBOBJECT_CPU_RATE_CONTROL_INFORMATION{
		ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
		Value:        2000,
	}

	_, err = windows.SetInformationJobObject(
		job,
		JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		// Just log or return error; won't close job yet because the process needs to stay in it
		return fmt.Errorf("SetInformationJobObject failed: %w", err)
	}

	currentProcess := windows.CurrentProcess()
	if err := windows.AssignProcessToJobObject(job, currentProcess); err != nil {
		return fmt.Errorf("AssignProcessToJobObject failed: %w", err)
	}

	return nil
}
