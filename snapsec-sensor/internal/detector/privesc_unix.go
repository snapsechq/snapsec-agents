//go:build !windows

package detector

import (
	"os"
	"syscall"
)

// getFileOwnerUID extracts the owner UID from an os.FileInfo on POSIX/Unix systems.
func getFileOwnerUID(info os.FileInfo) (uint32, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid, true
	}
	return 0, false
}
