package detector

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
	"snapsec-agent/pkg/api"
)

type DetectorConfig struct {
	BackendURL       string   `yaml:"backend_url"`
	APIKey           string   `yaml:"api_key"`
	AgentID          string   `yaml:"agent_id,omitempty"`
	VulnScanInterval int      `yaml:"vuln_scan_interval,omitempty"`
	IncludeDirs      []string `yaml:"include_dirs,omitempty"`
	ExcludeDirs      []string `yaml:"exclude_dirs,omitempty"`
}

type Manager struct {
	configDir string
	binDir    string
	mu        sync.Mutex
	scanning  bool
}

func NewManager(configPath string) *Manager {
	dir := filepath.Dir(configPath)
	binDir := filepath.Join(dir, "bin")
	_ = os.MkdirAll(binDir, 0755)

	return &Manager{
		configDir: dir,
		binDir:    binDir,
	}
}

func (m *Manager) BinaryPath() string {
	name := "snapsec-detector"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(m.binDir, name)
}

func (m *Manager) ConfigPath() string {
	return filepath.Join(m.configDir, "snapsec-detector.yaml")
}

func (m *Manager) versionFilePath() string {
	return filepath.Join(m.binDir, ".detector_version")
}

func (m *Manager) IsInstalled() bool {
	bin := m.BinaryPath()
	info, err := os.Stat(bin)
	return err == nil && !info.IsDir()
}

func (m *Manager) InstalledVersion() string {
	data, err := os.ReadFile(m.versionFilePath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// EnsureBinary checks if the detector binary exists and matches targetVersion;
// if not, it pulls (downloads) it from downloadURL.
func (m *Manager) EnsureBinary(downloadURL, targetVersion string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if targetVersion != "" && m.IsInstalled() && m.InstalledVersion() == targetVersion {
		return nil
	}

	if downloadURL == "" {
		return fmt.Errorf("download URL for detector is empty")
	}

	log.Printf("[DetectorManager] Pulling scan agent binary (version: %s) from %s...", targetVersion, downloadURL)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download detector: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download detector: HTTP %d", resp.StatusCode)
	}

	destPath := m.BinaryPath()
	tmpPath := destPath + ".tmp"

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create temp binary: %w", err)
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to save detector binary: %w", err)
	}
	out.Close()

	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0755); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to set detector permissions: %w", err)
		}
	}

	// Atomic rename to final binary path
	if err := os.Rename(tmpPath, destPath); err != nil {
		// On Windows, if destination exists, remove first then rename
		_ = os.Remove(destPath)
		if err := os.Rename(tmpPath, destPath); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to place detector binary: %w", err)
		}
	}

	_ = os.WriteFile(m.versionFilePath(), []byte(targetVersion), 0644)
	log.Printf("[DetectorManager] Scan agent (snapsec-detector %s) successfully pulled to %s", targetVersion, destPath)
	return nil
}

// SyncConfig writes the snapsec-detector.yaml configuration file for the detector
func (m *Manager) SyncConfig(backendURL, apiKey, agentID string, targets api.ScanTargets, interval int) error {
	cfg := DetectorConfig{
		BackendURL:       backendURL,
		APIKey:           apiKey,
		AgentID:          agentID,
		VulnScanInterval: interval,
		IncludeDirs:      targets.IncludeDirs,
		ExcludeDirs:      targets.ExcludeDirs,
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal detector config: %w", err)
	}

	return os.WriteFile(m.ConfigPath(), data, 0644)
}

// RunScan triggers the pulled snapsec-detector binary in CLI mode
func (m *Manager) RunScan() error {
	m.mu.Lock()
	if m.scanning {
		m.mu.Unlock()
		log.Println("[DetectorManager] Scan already in progress, skipping")
		return nil
	}
	if !m.IsInstalled() {
		m.mu.Unlock()
		return fmt.Errorf("detector binary not installed at %s", m.BinaryPath())
	}
	m.scanning = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.scanning = false
		m.mu.Unlock()
	}()

	binPath := m.BinaryPath()
	cfgPath := m.ConfigPath()

	log.Printf("[DetectorManager] Starting vulnerability scan using %s...", binPath)

	args := []string{"scan", "-config", cfgPath}
	cmd := exec.Command(binPath, args...)
	cmd.Dir = m.binDir // keeps tool bin & templates sandboxed inside detector's bin directory
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("detector execution failed: %w", err)
	}

	log.Println("[DetectorManager] Vulnerability scan finished successfully")
	return nil
}
