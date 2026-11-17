//go:build windows

package detector

import "os"

// getFileOwnerUID returns false on Windows where POSIX numeric UIDs are not applicable.
func getFileOwnerUID(info os.FileInfo) (uint32, bool) {
	return 0, false
}
