package updater

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// Update replaces the current executable with a new one downloaded from the given URL.
func Update(url string) error {
	// 1. Get the current executable path
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// 2. Resolve symlinks to get the actual binary path
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("failed to eval symlinks: %w", err)
	}

	// 3. Create a temporary file for the download
	newExe := exe + ".new"
	out, err := os.Create(newExe)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer out.Close()

	// 4. Download the new binary
	resp, err := http.Get(url)
	if err != nil {
		os.Remove(newExe)
		return fmt.Errorf("failed to download binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		os.Remove(newExe)
		return fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(newExe)
		return fmt.Errorf("failed to save binary: %w", err)
	}
	out.Close()

	// 5. Set executable permissions
	if err := os.Chmod(newExe, 0755); err != nil {
		os.Remove(newExe)
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// 6. Atomic swap (best effort)
	oldExe := exe + ".old"
	
	// On Windows, you can't rename a running file to a different name easily if it's open,
	// but you can often rename it to .old.
	if err := os.Rename(exe, oldExe); err != nil {
		// If rename fails, try removing it first (unlikely to work if rename failed)
		if runtime.GOOS != "windows" {
			if err := os.Remove(exe); err != nil {
				os.Remove(newExe)
				return fmt.Errorf("failed to remove old binary: %w", err)
			}
		} else {
			os.Remove(newExe)
			return fmt.Errorf("failed to rename current binary: %w", err)
		}
	}

	if err := os.Rename(newExe, exe); err != nil {
		// Rollback if possible
		os.Rename(oldExe, exe)
		os.Remove(newExe)
		return fmt.Errorf("failed to move new binary into place: %w", err)
	}

	// 7. Cleanup old binary
	// On some OS (like Windows), we might not be able to delete the .old file while the process is running.
	// But we don't strictly need to.
	os.Remove(oldExe)

	return nil
}
